//! SSDF evidence sink with durable outbox and delivery ledger.
//!
//! This sink delivers closed evidence segments to a ClickHouse SSDF instance via
//! HTTP INSERT. Segments are spooled to a durable outbox file before delivery,
//! and delivery status is tracked in a separate ledger. Sink failures are
//! non-fatal to the serving process (fail-open ship, fail-closed record).
//!
//! ## Deduplication
//!
//! A high-water mark, read before each delivery, **not** an in-statement guard.
//!
//! The guard this sink used to send — `INSERT … WHERE NOT EXISTS (SELECT …)` —
//! could never have executed: ClickHouse runs it as the inserting identity, and
//! SSDF grants `ssdf_audit` INSERT and nothing else, deliberately, so a stolen
//! writer credential can append but not enumerate. Every delivery would have
//! been refused for missing SELECT.
//!
//! Instead the sink asks, as the separate `ssdf_audit_verify` identity SSDF
//! provisions for chain-seeding, what the highest `segment_seq` for this run
//! already is, and sends only what is above it. Parameters are still bound via
//! `param_X=value` / `{X:Type}`, so the read is injection-safe. Resolved in
//! ssdf#47.
//!
//! ## Background Delivery
//!
//! This sink does NOT spawn a background thread. Callers must invoke
//! `attempt_delivery()` explicitly (e.g., on SIGHUP, periodic timer, or shutdown).
//! Recommended cadence: every 5-60 seconds during normal operation, plus
//! shutdown_flush() on graceful stop.
//!
//! ## Documented Deferrals
//!
//! - **No background thread**: Callers schedule `attempt_delivery` (see above).
//! - **No outbox compaction**: Delivered segments accumulate in outbox file.
//!   Follow-up: filter out delivered segments on startup or rotation.
//! - **No metrics**: Delivery success/failure/retry counts not emitted.
//!   Follow-up: add `metrics::counter!()` for observability.

use crate::evidence::ClosedSegment;
use crate::sinks::delivery_ledger::{DeliveryLedger, DeliveryStatus, SegmentId};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;

/// Configuration for the SSDF sink.
#[derive(Debug, Clone)]
pub struct SsdfSinkConfig {
    /// ClickHouse HTTP endpoint (e.g., "http://192.168.1.104:8123").
    /// HTTPS not supported by StdHttpTransport; use HTTP or a TLS proxy.
    pub endpoint: String,
    /// ClickHouse database name (e.g., "ssdf").
    pub database: String,
    /// ClickHouse username (e.g., "ssdf_audit").
    pub username: String,
    /// ClickHouse password.
    pub password: String,
    /// Read identity used only for the dedup high-water mark.
    ///
    /// `ssdf_audit` is INSERT-only by design, so it cannot perform the read that
    /// tells the sink what already landed. SSDF provisions `ssdf_audit_verify`
    /// for exactly this — its migration calls it "startup chain-seeding and
    /// verify_audit" (ssdf#47).
    pub verify_username: String,
    /// Password for [`verify_username`](Self::verify_username).
    pub verify_password: String,
    /// Path to the durable outbox spool file.
    pub outbox_path: PathBuf,
    /// Path to the delivery ledger.
    pub ledger_path: PathBuf,
    /// Initial retry backoff duration.
    pub initial_backoff: Duration,
    /// Maximum retry backoff duration.
    pub max_backoff: Duration,
}

/// Errors that can occur in the SSDF sink.
#[derive(Debug, Error)]
pub enum SsdfSinkError {
    /// Outbox I/O error.
    #[error("outbox I/O error: {0}")]
    OutboxIo(#[from] io::Error),
    /// Ledger error.
    #[error("ledger error: {0}")]
    Ledger(#[from] crate::sinks::delivery_ledger::LedgerError),
    /// HTTP delivery error.
    #[error("HTTP delivery error: {0}")]
    Http(String),
    /// Invalid segment encoding.
    #[error("invalid segment encoding: {0}")]
    InvalidSegment(String),
}

/// SSDF row format for ClickHouse JSONEachRow insertion.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SsdfRow {
    ts: String,
    principal: String,
    tier: String,
    tool: String,
    args: String,
    data_classes: Vec<String>,
    decision: String,
    row_count: u32,
    error: String,
    prev_hash: String,
    row_hash: String,
}

/// SSDF evidence sink.
///
/// Delivers closed evidence segments to ClickHouse via HTTP INSERT, with:
/// - Durable outbox (append-only spool file with fsync)
/// - Separate delivery ledger (delivery status never mutates hashed records)
/// - Retry with exponential backoff + jitter
/// - Idempotency via server-side INSERT guard with (server_id, run_id, segment_seq)
/// - Fail-open ship, fail-closed record (sink failure is non-fatal to serving)
/// - Shutdown flush
/// - Crash recovery via outbox replay with dedup
pub struct SsdfSink {
    config: SsdfSinkConfig,
    outbox: Arc<Mutex<OutboxState>>,
    ledger: Arc<Mutex<DeliveryLedger>>,
    transport: Arc<dyn HttpTransport>,
    sleep_fn: Arc<dyn Fn(Duration) + Send + Sync>,
}

struct OutboxState {
    file: File,
    path: PathBuf,
}

impl SsdfSink {
    /// Create a new SSDF sink with the given configuration.
    ///
    /// The outbox and ledger files are created if they don't exist. Existing
    /// outbox entries are loaded and will be retried on the next delivery attempt.
    pub fn new(config: SsdfSinkConfig) -> Result<Self, SsdfSinkError> {
        Self::new_with_transport(
            config,
            Arc::new(StdHttpTransport),
            Arc::new(std::thread::sleep),
        )
    }

    /// Create a new SSDF sink with a custom HTTP transport and sleep function (for testing).
    pub fn new_with_transport(
        config: SsdfSinkConfig,
        transport: Arc<dyn HttpTransport>,
        sleep_fn: Arc<dyn Fn(Duration) + Send + Sync>,
    ) -> Result<Self, SsdfSinkError> {
        // Anchor paths.
        let outbox_path = std::path::absolute(&config.outbox_path)?;
        let ledger_path = std::path::absolute(&config.ledger_path)?;

        // Open outbox for append.
        let outbox_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&outbox_path)?;

        let outbox = Arc::new(Mutex::new(OutboxState {
            file: outbox_file,
            path: outbox_path,
        }));

        // Open ledger.
        let ledger = Arc::new(Mutex::new(DeliveryLedger::open(&ledger_path)?));

        Ok(Self {
            config,
            outbox,
            ledger,
            transport,
            sleep_fn,
        })
    }

    /// Spool a closed segment to the durable outbox.
    ///
    /// The segment is written to the outbox file and fsynced. Delivery is
    /// attempted in the background (not implemented here; caller must call
    /// `attempt_delivery` periodically or on shutdown).
    pub fn spool(&self, segment: ClosedSegment) -> Result<(), SsdfSinkError> {
        let mut outbox = self.outbox.lock().expect("outbox mutex not poisoned");
        let mut line = serde_json::to_string(&segment).map_err(|e| {
            SsdfSinkError::InvalidSegment(format!("failed to serialize segment: {}", e))
        })?;
        line.push('\n');
        outbox.file.write_all(line.as_bytes())?;
        // Fsync to ensure durability: if the process crashes after this returns,
        // the segment is guaranteed to be in the outbox and will be replayed.
        outbox.file.sync_all()?;

        // Mark as pending in the ledger.
        let id = SegmentId {
            server_id: segment.server_id.clone(),
            run_id: segment.run_id.clone(),
            segment_seq: segment.segment_seq,
        };
        self.ledger
            .lock()
            .expect("ledger mutex not poisoned")
            .mark_pending(id)?;

        Ok(())
    }

    /// Attempt delivery of all pending segments in the outbox.
    ///
    /// Returns the number of successfully delivered segments. Failures are
    /// retried with exponential backoff + jitter (capped at max_backoff).
    pub fn attempt_delivery(&self) -> Result<usize, SsdfSinkError> {
        // Load all segments from the outbox, oldest sequence first per run.
        // Order is not cosmetic here: dedup asks SSDF for the highest
        // `segment_seq` it holds and treats everything at or below as landed.
        // That is only true if segments go in ascending order and none is
        // skipped — otherwise delivering N+1 after N failed makes the maximum
        // claim N landed, and the chain acquires a gap that still verifies as a
        // chain. Which is the exact failure this sink exists to prevent.
        let mut segments = self.load_outbox()?;
        segments.sort_by(|left, right| {
            (&left.server_id, &left.run_id, left.segment_seq).cmp(&(
                &right.server_id,
                &right.run_id,
                right.segment_seq,
            ))
        });
        let mut delivered_count = 0;
        // Runs with a segment that failed this pass. Later segments of the same
        // run must wait: they would otherwise overtake it.
        let mut blocked_runs: std::collections::HashSet<(String, String)> =
            std::collections::HashSet::new();

        for segment in segments {
            let run = (segment.server_id.clone(), segment.run_id.clone());
            if blocked_runs.contains(&run) {
                continue;
            }
            let id = SegmentId {
                server_id: segment.server_id.clone(),
                run_id: segment.run_id.clone(),
                segment_seq: segment.segment_seq,
            };

            // Check if already delivered.
            let status = self
                .ledger
                .lock()
                .expect("ledger mutex not poisoned")
                .status(&id)
                .cloned();

            if matches!(status, Some(DeliveryStatus::Delivered { .. })) {
                continue;
            }

            // Compute backoff delay based on attempt count.
            let attempts = match &status {
                Some(DeliveryStatus::Failed { attempts, .. }) => *attempts,
                _ => 0,
            };

            if attempts > 0 {
                let delay = self.compute_backoff(attempts);
                (self.sleep_fn)(delay);
            }

            // Attempt delivery.
            match self.deliver_segment(&segment) {
                Ok(()) => {
                    let delivered_at = chrono::Utc::now().to_rfc3339();
                    self.ledger
                        .lock()
                        .expect("ledger mutex not poisoned")
                        .mark_delivered(id, delivered_at)?;
                    delivered_count += 1;
                }
                Err(e) => {
                    let failed_at = chrono::Utc::now().to_rfc3339();
                    let new_attempts = attempts + 1;
                    self.ledger
                        .lock()
                        .expect("ledger mutex not poisoned")
                        .mark_failed(id, failed_at, e.to_string(), new_attempts)?;
                    // Hold the rest of this run back until this segment lands.
                    blocked_runs.insert(run);
                }
            }
        }

        Ok(delivered_count)
    }

    /// Compute exponential backoff delay with jitter, capped at max_backoff.
    fn compute_backoff(&self, attempts: u64) -> Duration {
        use std::cmp::min;

        let base_ms = self.config.initial_backoff.as_millis() as u64;
        let max_ms = self.config.max_backoff.as_millis() as u64;

        // Exponential: 2^(attempts-1) * base, capped at max.
        let exp_ms = base_ms.saturating_mul(2u64.saturating_pow(attempts.saturating_sub(1) as u32));
        let capped_ms = min(exp_ms, max_ms);

        // Jitter: +/- 10%
        let jitter_range = capped_ms / 10;
        let jitter = (getrandom_u64() % (jitter_range * 2)).saturating_sub(jitter_range);
        let final_ms = capped_ms.saturating_add(jitter);

        Duration::from_millis(final_ms)
    }

    /// Flush all pending deliveries on shutdown.
    ///
    /// This is a best-effort attempt to deliver all spooled segments before
    /// the process exits. Failures are logged but do not prevent shutdown.
    pub fn shutdown_flush(&self) -> Result<(), SsdfSinkError> {
        let _ = self.attempt_delivery();
        Ok(())
    }

    /// Load all segments from the outbox.
    fn load_outbox(&self) -> Result<Vec<ClosedSegment>, SsdfSinkError> {
        let outbox = self.outbox.lock().expect("outbox mutex not poisoned");
        let file = File::open(&outbox.path)?;
        let reader = BufReader::new(file);
        let mut segments = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let segment: ClosedSegment = serde_json::from_str(&line).map_err(|e| {
                SsdfSinkError::InvalidSegment(format!("failed to parse segment: {}", e))
            })?;
            segments.push(segment);
        }

        Ok(segments)
    }

    /// Deliver a single segment to SSDF via HTTP INSERT.
    ///
    /// Dedup happens first, as a separate read under a separate identity — see
    /// [`high_water_mark`](Self::high_water_mark).
    /// Highest `segment_seq` SSDF already holds for this run.
    ///
    /// Read as the **verify** identity, because the writer has no SELECT. This
    /// is the same read the sink needs for chain-seeding, so dedup costs nothing
    /// extra: a segment at or below the mark was already accepted and a retry
    /// would append a duplicate row to a hash chain.
    ///
    /// Returns `None` when SSDF holds nothing for this run, or when the answer
    /// cannot be read — an unreadable mark must not be treated as "nothing
    /// landed", so the caller keeps the segment spooled rather than risking a
    /// duplicate.
    fn high_water_mark(&self, segment: &ClosedSegment) -> Result<Option<u64>, SsdfSinkError> {
        // `count()` alongside `max()` because `max()` over no rows and `max()`
        // over a run whose only landed segment is sequence **0** both render as
        // `0`. Treating the second as the first re-inserts segment 0 after a
        // crash between the insert and the ledger write.
        let query = format!(
            "SELECT count(), max(JSONExtractUInt(args, 'segment_seq')) FROM {}.audit \
             WHERE tier = 'evidence' \
               AND JSONExtractString(args, 'server_id') = {{server_id:String}} \
               AND JSONExtractString(args, 'run_id') = {{run_id:String}} \
             FORMAT TabSeparated",
            self.config.database
        );
        let url = format!(
            "{}/?query={}&param_server_id={}&param_run_id={}",
            self.config.endpoint,
            urlencoding::encode(&query),
            urlencoding::encode(&segment.server_id),
            urlencoding::encode(&segment.run_id),
        );
        let request = HttpRequest {
            url,
            method: "POST".to_string(),
            headers: vec![(
                "Authorization".to_string(),
                format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(format!(
                        "{}:{}",
                        self.config.verify_username, self.config.verify_password
                    ))
                ),
            )],
            body: Vec::new(),
        };

        // A read that fails is **not** "nothing landed". Expired verify
        // credentials or a transient 5xx would otherwise green-light a plain
        // INSERT and append a duplicate on a lost-ack replay. The error
        // propagates, the segment stays spooled, and the next pass tries again.
        let body = self.transport.send(&request)?;

        let mut fields = body.split_whitespace();
        let count: u64 = fields
            .next()
            .and_then(|field| field.parse().ok())
            .ok_or_else(|| {
                SsdfSinkError::Http(format!("unreadable high-water response: {body:?}"))
            })?;
        if count == 0 {
            return Ok(None);
        }
        let max: u64 = fields
            .next()
            .and_then(|field| field.parse().ok())
            .ok_or_else(|| {
                SsdfSinkError::Http(format!("unreadable high-water maximum: {body:?}"))
            })?;
        Ok(Some(max))
    }

    fn deliver_segment(&self, segment: &ClosedSegment) -> Result<(), SsdfSinkError> {
        // Dedup, before anything is sent. A retry after a lost acknowledgement
        // carries the identical rows and identical `row_hash`; appending them
        // again would put a duplicate into a chain whose whole value is that it
        // can be verified.
        if let Some(mark) = self.high_water_mark(segment)?
            && segment.segment_seq <= mark
        {
            return Ok(());
        }

        // Convert segment records to SSDF rows.
        let rows: Vec<SsdfRow> = segment
            .records()
            .iter()
            .map(|record| self.record_to_ssdf_row(record, segment))
            .collect::<Result<Vec<_>, _>>()?;

        if rows.is_empty() {
            return Ok(());
        }

        // Serialize rows as JSONEachRow (one JSON object per line).
        let body = rows
            .iter()
            .map(|row| serde_json::to_string(row).expect("SsdfRow must serialize"))
            .collect::<Vec<_>>()
            .join("\n");

        // A plain INSERT. It carries no guard clause, and that is not a style
        // choice: ClickHouse runs a guard's SELECT as the *inserting* identity,
        // and `ssdf_audit` has no SELECT — SSDF gives it away deliberately so a
        // stolen writer credential can append but not enumerate. A guarded
        // insert is refused outright. Dedup happens before this, in
        // `high_water_mark` (ssdf#47).
        let query = format!(
            "INSERT INTO {}.audit FORMAT JSONEachRow",
            self.config.database
        );

        let url = format!(
            "{}/?query={}",
            self.config.endpoint,
            urlencoding::encode(&query)
        );

        // Send HTTP request.
        let request = HttpRequest {
            url,
            method: "POST".to_string(),
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "application/x-ndjson".to_string(),
                ),
                (
                    "Authorization".to_string(),
                    format!(
                        "Basic {}",
                        base64::prelude::BASE64_STANDARD
                            .encode(format!("{}:{}", self.config.username, self.config.password))
                    ),
                ),
            ],
            body: body.into_bytes(),
        };

        self.transport.send(&request)?;
        Ok(())
    }

    /// Compute the hash of a single evidence record.
    ///
    /// This uses the same canonical digest logic as the evidence chain: the record
    /// is serialized to JSON with its prev_hash included, then hashed with SHA-256.
    fn compute_record_hash(
        record: &crate::evidence::EvidenceRecord,
    ) -> Result<String, SsdfSinkError> {
        // Build envelope: record + prev_hash for linking (prev_hash is already in the record)
        let envelope = serde_json::to_value(record).map_err(|e| {
            SsdfSinkError::InvalidSegment(format!("record serialization failed: {}", e))
        })?;
        crate::canonical::digest_of(&envelope)
            .map_err(|e| SsdfSinkError::InvalidSegment(format!("hash computation failed: {}", e)))
    }

    /// Convert an evidence record to an SSDF row.
    fn record_to_ssdf_row(
        &self,
        record: &crate::evidence::EvidenceRecord,
        _segment: &ClosedSegment,
    ) -> Result<SsdfRow, SsdfSinkError> {
        use crate::evidence::EvidenceRecord;

        // Extract common fields and serialize args as JSON string.
        match record {
            EvidenceRecord::Proposal(r) => {
                let args = serde_json::to_string(&serde_json::json!({
                    "request_id": r.request_id,
                    "changeset_id": r.changeset_id,
                    "device_id": r.device_id,
                    "diff_hash": r.diff_hash,
                    "run_id": r.run_id,
                    "server_id": r.server_id,
                    "segment_seq": r.segment_seq,
                    "prev_hash": r.prev_hash,
                    "metadata": r.metadata,
                }))
                .expect("args must serialize");

                Ok(SsdfRow {
                    ts: r.timestamp.clone(),
                    principal: r.principal.clone(),
                    tier: "evidence".to_string(),
                    tool: "evidence:proposal".to_string(),
                    args,
                    data_classes: vec![format!("device:{}", r.device_id)],
                    decision: "".to_string(),
                    row_count: 1,
                    error: "".to_string(),
                    prev_hash: r.prev_hash.clone(),
                    row_hash: Self::compute_record_hash(record)?,
                })
            }
            EvidenceRecord::Approval(r) => {
                let args = serde_json::to_string(&serde_json::json!({
                    "request_id": r.request_id,
                    "changeset_id": r.changeset_id,
                    "device_id": r.device_id,
                    "diff_hash": r.diff_hash,
                    "run_id": r.run_id,
                    "server_id": r.server_id,
                    "segment_seq": r.segment_seq,
                    "prev_hash": r.prev_hash,
                    "approver": r.approver,
                    "metadata": r.metadata,
                }))
                .expect("args must serialize");

                Ok(SsdfRow {
                    ts: r.timestamp.clone(),
                    principal: r.principal.clone(),
                    tier: "evidence".to_string(),
                    tool: "evidence:approval".to_string(),
                    args,
                    data_classes: vec![format!("device:{}", r.device_id)],
                    decision: r.decision.clone(),
                    row_count: 1,
                    error: "".to_string(),
                    prev_hash: r.prev_hash.clone(),
                    row_hash: Self::compute_record_hash(record)?,
                })
            }
            EvidenceRecord::ApplyIntent(r) => {
                let args = serde_json::to_string(&serde_json::json!({
                    "request_id": r.request_id,
                    "changeset_id": r.changeset_id,
                    "device_id": r.device_id,
                    "diff_hash": r.diff_hash,
                    "run_id": r.run_id,
                    "server_id": r.server_id,
                    "segment_seq": r.segment_seq,
                    "prev_hash": r.prev_hash,
                    "metadata": r.metadata,
                }))
                .expect("args must serialize");

                Ok(SsdfRow {
                    ts: r.timestamp.clone(),
                    principal: r.principal.clone(),
                    tier: "evidence".to_string(),
                    tool: "evidence:apply_intent".to_string(),
                    args,
                    data_classes: vec![format!("device:{}", r.device_id)],
                    decision: "".to_string(),
                    row_count: 1,
                    error: "".to_string(),
                    prev_hash: r.prev_hash.clone(),
                    row_hash: Self::compute_record_hash(record)?,
                })
            }
            EvidenceRecord::ResultReceipt(r) => {
                let args = serde_json::to_string(&serde_json::json!({
                    "request_id": r.request_id,
                    "changeset_id": r.changeset_id,
                    "device_id": r.device_id,
                    "diff_hash": r.diff_hash,
                    "run_id": r.run_id,
                    "server_id": r.server_id,
                    "segment_seq": r.segment_seq,
                    "prev_hash": r.prev_hash,
                    "metadata": r.metadata,
                }))
                .expect("args must serialize");

                Ok(SsdfRow {
                    ts: r.timestamp.clone(),
                    principal: r.principal.clone(),
                    tier: "evidence".to_string(),
                    tool: "evidence:result_receipt".to_string(),
                    args,
                    data_classes: vec![format!("device:{}", r.device_id)],
                    decision: "".to_string(),
                    row_count: 1,
                    error: r.error.clone().unwrap_or_default(),
                    prev_hash: r.prev_hash.clone(),
                    row_hash: Self::compute_record_hash(record)?,
                })
            }
        }
    }
}

/// Get a random u64 for jitter using getrandom.
fn getrandom_u64() -> u64 {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("getrandom failed");
    u64::from_le_bytes(bytes)
}

/// HTTP transport abstraction for testing.
pub trait HttpTransport: Send + Sync {
    /// Send an HTTP request and return its response body.
    ///
    /// The body matters: dedup reads a high-water mark back from ClickHouse, so
    /// a transport that discards responses cannot support it.
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError>;
}

/// HTTP request.
#[derive(Clone)]
pub struct HttpRequest {
    /// Request URL.
    pub url: String,
    /// HTTP method (e.g., "POST").
    pub method: String,
    /// Request headers.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
}

/// Largest response body this transport will read.
///
/// Enough for a high-water answer (`count\tmax`) or a ClickHouse error message,
/// and small enough that a malformed or hostile response cannot be turned into
/// an allocation.
const MAX_RESPONSE_BYTES: usize = 4096;

/// Standard HTTP transport using std::net::TcpStream.
///
/// This is a minimal blocking HTTP/1.1 client for INSERT requests to ClickHouse.
/// Only HTTP is supported; for HTTPS, use a TLS-terminating proxy.
struct StdHttpTransport;

impl HttpTransport for StdHttpTransport {
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpStream;
        use std::time::Duration;

        // Parse URL to extract host, port, and path.
        let url = &request.url;
        if !url.starts_with("http://") {
            return Err(SsdfSinkError::Http(format!(
                "only http:// URLs supported, got: {}",
                url
            )));
        }

        let url_without_scheme = url
            .strip_prefix("http://")
            .expect("URL starts with http://");
        let (host_port, path) = url_without_scheme
            .split_once('/')
            .unwrap_or((url_without_scheme, ""));

        let (host, port) = if let Some((h, p)) = host_port.split_once(':') {
            (
                h,
                p.parse::<u16>()
                    .map_err(|e| SsdfSinkError::Http(format!("invalid port: {}", e)))?,
            )
        } else {
            (host_port, 80u16)
        };

        // Connect with timeout.
        let addr = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect_timeout(
            &addr
                .parse()
                .map_err(|e| SsdfSinkError::Http(format!("invalid address {}: {}", addr, e)))?,
            Duration::from_secs(10),
        )
        .map_err(|e| SsdfSinkError::Http(format!("connection failed: {}", e)))?;

        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| SsdfSinkError::Http(format!("set_read_timeout failed: {}", e)))?;
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .map_err(|e| SsdfSinkError::Http(format!("set_write_timeout failed: {}", e)))?;

        // Build HTTP/1.1 request.
        let path_with_slash = if path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", path)
        };

        let mut http_request = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Connection: close\r\n\
             Content-Length: {}\r\n",
            request.method,
            path_with_slash,
            host,
            request.body.len()
        );

        for (name, value) in &request.headers {
            http_request.push_str(&format!("{}: {}\r\n", name, value));
        }

        http_request.push_str("\r\n");

        // Send request and body.
        stream
            .write_all(http_request.as_bytes())
            .map_err(|e| SsdfSinkError::Http(format!("write request failed: {}", e)))?;
        stream
            .write_all(&request.body)
            .map_err(|e| SsdfSinkError::Http(format!("write body failed: {}", e)))?;
        stream
            .flush()
            .map_err(|e| SsdfSinkError::Http(format!("flush failed: {}", e)))?;

        // Read response.
        let mut reader = BufReader::new(&stream);
        let mut status_line = String::new();
        reader
            .read_line(&mut status_line)
            .map_err(|e| SsdfSinkError::Http(format!("read status line failed: {}", e)))?;

        // Parse status code.
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| {
                SsdfSinkError::Http(format!("invalid status line: {}", status_line.trim()))
            })?;

        // Read headers until blank line.
        let mut _content_length = None;
        let mut chunked = false;
        loop {
            let mut header_line = String::new();
            reader
                .read_line(&mut header_line)
                .map_err(|e| SsdfSinkError::Http(format!("read header failed: {}", e)))?;
            if header_line == "\r\n" || header_line == "\n" {
                break;
            }
            if let Some((name, value)) = header_line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    _content_length = value.trim().parse::<usize>().ok();
                } else if name.trim().eq_ignore_ascii_case("transfer-encoding")
                    && value.to_ascii_lowercase().contains("chunked")
                {
                    // ClickHouse returns query results chunked. Without
                    // decoding, a body of `3` arrives as `2\r\n3\n\r\n0\r\n\r\n`
                    // and every high-water read fails to parse — which, before
                    // this, silently meant "nothing landed".
                    chunked = true;
                }
            }
        }

        // Read response body (up to 4KB for error messages).
        let mut body = Vec::new();
        if chunked {
            loop {
                let mut size_line = String::new();
                reader
                    .read_line(&mut size_line)
                    .map_err(|e| SsdfSinkError::Http(format!("read chunk size failed: {}", e)))?;
                // A chunk header may carry extensions after a `;`.
                let size_text = size_line.trim().split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(size_text, 16).map_err(|_| {
                    SsdfSinkError::Http(format!("invalid chunk size: {size_text:?}"))
                })?;
                if size == 0 {
                    break;
                }
                // Refuse before allocating. The declared size is attacker- or
                // fault-controlled — an on-path responder can claim gigabytes —
                // and allocating first would make the 4 KiB body limit a limit
                // on what is *kept* rather than on what is *reserved*.
                let remaining = MAX_RESPONSE_BYTES.saturating_sub(body.len());
                if size > remaining {
                    return Err(SsdfSinkError::Http(format!(
                        "chunked response declares {size} bytes, over the \
                         {MAX_RESPONSE_BYTES}-byte response limit"
                    )));
                }
                let mut chunk = vec![0u8; size];
                reader
                    .read_exact(&mut chunk)
                    .map_err(|e| SsdfSinkError::Http(format!("read chunk failed: {}", e)))?;
                body.extend_from_slice(&chunk);
                let mut terminator = String::new();
                reader.read_line(&mut terminator).map_err(|e| {
                    SsdfSinkError::Http(format!("read chunk terminator failed: {}", e))
                })?;
            }
            if !(200..300).contains(&status_code) {
                let body_str = String::from_utf8_lossy(&body);
                return Err(SsdfSinkError::Http(format!(
                    "HTTP {} {}",
                    status_code,
                    body_str.chars().take(200).collect::<String>()
                )));
            }
            return Ok(String::from_utf8_lossy(&body).into_owned());
        }
        let mut buf = [0u8; 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    body.extend_from_slice(&buf[..n]);
                    if body.len() >= MAX_RESPONSE_BYTES {
                        body.truncate(MAX_RESPONSE_BYTES);
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(SsdfSinkError::Http(format!("read body failed: {}", e)));
                }
            }
        }

        // Check status code.
        if !(200..300).contains(&status_code) {
            let body_str = String::from_utf8_lossy(&body);
            return Err(SsdfSinkError::Http(format!(
                "HTTP {} {}",
                status_code,
                body_str.chars().take(200).collect::<String>()
            )));
        }

        Ok(String::from_utf8_lossy(&body).into_owned())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::evidence::{
        ChainSegment, EvidenceRecord, GENESIS_PREV_HASH, ProposalRecord, append, close,
    };
    use std::sync::Mutex as StdMutex;
    use tempfile::TempDir;

    /// Mock HTTP transport that records all requests.
    struct MockHttpTransport {
        requests: Arc<StdMutex<Vec<HttpRequest>>>,
        should_fail: bool,
    }

    impl MockHttpTransport {
        fn new() -> Self {
            Self {
                requests: Arc::new(StdMutex::new(Vec::new())),
                should_fail: false,
            }
        }

        fn failing() -> Self {
            Self {
                requests: Arc::new(StdMutex::new(Vec::new())),
                should_fail: true,
            }
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests
                .lock()
                .expect("mock transport mutex not poisoned")
                .clone()
        }
    }

    /// Requests that actually insert, as opposed to the high-water read that
    /// precedes each delivery. Counting raw requests would make every one of
    /// these tests assert the shape of the dedup protocol by accident.
    fn inserts(requests: &[HttpRequest]) -> Vec<&HttpRequest> {
        requests
            .iter()
            .filter(|request| {
                urlencoding::decode(&request.url)
                    .map(|url| url.contains("INSERT"))
                    .unwrap_or(false)
            })
            .collect()
    }

    impl HttpTransport for MockHttpTransport {
        fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
            if self.should_fail {
                return Err(SsdfSinkError::Http("mock transport failure".to_string()));
            }
            self.requests
                .lock()
                .expect("mock transport mutex not poisoned")
                .push(request.clone());
            // The high-water read expects `count\tmax`. `0\t0` is "SSDF holds
            // nothing for this run", which is what these tests assume; an empty
            // body would now be an unreadable answer and correctly block
            // delivery rather than allow it.
            if urlencoding::decode(&request.url)
                .map(|url| url.contains("SELECT"))
                .unwrap_or(false)
            {
                return Ok("0\t0\n".to_string());
            }
            Ok(String::new())
        }
    }

    /// Mock sleep function that records delays.
    struct MockSleep {
        delays: Arc<StdMutex<Vec<Duration>>>,
    }

    impl MockSleep {
        fn new() -> Self {
            Self {
                delays: Arc::new(StdMutex::new(Vec::new())),
            }
        }

        fn as_fn(&self) -> Arc<dyn Fn(Duration) + Send + Sync> {
            let delays = self.delays.clone();
            Arc::new(move |d| {
                delays.lock().expect("sleep mutex not poisoned").push(d);
            })
        }

        fn delays(&self) -> Vec<Duration> {
            self.delays
                .lock()
                .expect("sleep mutex not poisoned")
                .clone()
        }
    }

    fn make_test_config(dir: &TempDir) -> SsdfSinkConfig {
        SsdfSinkConfig {
            endpoint: "http://test.clickhouse:8123".to_string(),
            database: "ssdf".to_string(),
            username: "ssdf_audit".to_string(),
            password: "test_password".to_string(),
            verify_username: "ssdf_audit_verify".to_string(),
            verify_password: "test_verify_password".to_string(),
            outbox_path: dir.path().join("outbox.jsonl"),
            ledger_path: dir.path().join("ledger.jsonl"),
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(60),
        }
    }

    fn make_test_segment() -> ClosedSegment {
        let mut seg = ChainSegment::new(
            "run_test".to_string(),
            "server_test".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(
            &mut seg,
            EvidenceRecord::Proposal(ProposalRecord {
                request_id: "req_test".to_string(),
                changeset_id: "cs_test".to_string(),
                device_id: "dev_test".to_string(),
                principal: "agent:test".to_string(),
                diff_hash: "sha256:abcd1234".to_string(),
                timestamp: "2026-08-09T12:00:00Z".to_string(),
                run_id: String::new(),
                server_id: String::new(),
                segment_seq: 0,
                prev_hash: String::new(),
                metadata: None,
            }),
        )
        .unwrap();
        close(seg).unwrap()
    }

    #[test]
    fn spool_writes_to_outbox_and_marks_pending() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::new());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();

        let segment = make_test_segment();
        sink.spool(segment.clone()).unwrap();

        // Verify outbox contains the segment.
        let outbox_content = std::fs::read_to_string(&config.outbox_path).unwrap();
        assert!(outbox_content.contains(&segment.run_id));

        // Verify ledger marks it as pending.
        let id = SegmentId {
            server_id: segment.server_id.clone(),
            run_id: segment.run_id.clone(),
            segment_seq: segment.segment_seq,
        };
        let status = sink
            .ledger
            .lock()
            .expect("ledger mutex not poisoned")
            .status(&id)
            .cloned();
        assert_eq!(status, Some(DeliveryStatus::Pending));
    }

    #[test]
    fn attempt_delivery_sends_a_plain_insert() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::new());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();

        let segment = make_test_segment();
        sink.spool(segment.clone()).unwrap();

        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // One insert, preceded by the high-water read that replaces the old
        // in-statement guard (ssdf#47).
        let requests = transport.requests();
        let inserts = inserts(&requests);
        assert_eq!(inserts.len(), 1);
        assert_eq!(inserts[0].method, "POST");

        let decoded_query = urlencoding::decode(&inserts[0].url).unwrap();
        assert!(
            !decoded_query.contains("NOT EXISTS"),
            "the writer identity has no SELECT, so a guarded insert is refused \
             outright: {decoded_query}"
        );
        assert!(decoded_query.contains("INSERT INTO ssdf.audit"));

        // Verify ledger marks it as delivered.
        let id = SegmentId {
            server_id: segment.server_id.clone(),
            run_id: segment.run_id.clone(),
            segment_seq: segment.segment_seq,
        };
        let status = sink
            .ledger
            .lock()
            .expect("ledger mutex not poisoned")
            .status(&id)
            .cloned();
        assert!(matches!(status, Some(DeliveryStatus::Delivered { .. })));
    }

    #[test]
    fn ssdf_unreachable_continues_serving_and_retains_spool() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::failing());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();

        let segment = make_test_segment();
        sink.spool(segment.clone()).unwrap();

        // Delivery fails but spool succeeds (fail-open ship).
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 0);

        // Verify outbox still contains the segment.
        let outbox_content = std::fs::read_to_string(&config.outbox_path).unwrap();
        assert!(outbox_content.contains(&segment.run_id));

        // Verify ledger marks it as failed.
        let id = SegmentId {
            server_id: segment.server_id.clone(),
            run_id: segment.run_id.clone(),
            segment_seq: segment.segment_seq,
        };
        let status = sink
            .ledger
            .lock()
            .expect("ledger mutex not poisoned")
            .status(&id)
            .cloned();
        assert!(matches!(status, Some(DeliveryStatus::Failed { .. })));
    }

    #[test]
    fn redelivery_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::new());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();

        let segment = make_test_segment();
        sink.spool(segment.clone()).unwrap();

        // First delivery.
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // Second delivery (idempotent replay).
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 0);

        // Only one insert was sent; the replay found the segment delivered.
        let requests = transport.requests();
        assert_eq!(inserts(&requests).len(), 1);
    }

    #[test]
    fn crash_recovery_replays_outbox() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);

        let segment = make_test_segment();
        {
            let transport = Arc::new(MockHttpTransport::new());
            let sleep = MockSleep::new();
            let sink =
                SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn())
                    .unwrap();
            sink.spool(segment.clone()).unwrap();
            // Crash before delivery (drop sink).
        }

        // Reopen sink and replay.
        let transport = Arc::new(MockHttpTransport::new());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // Verify HTTP request was sent.
        let requests = transport.requests();
        assert_eq!(inserts(&requests).len(), 1);
    }

    #[test]
    fn injection_safety_via_parameter_binding() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::new());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();

        // Create a segment with SQL injection attempt in server_id.
        let mut seg = ChainSegment::new(
            "run_test".to_string(),
            "'; DROP TABLE audit; --".to_string(), // Injection in server_id
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(
            &mut seg,
            EvidenceRecord::Proposal(ProposalRecord {
                request_id: "req_test".to_string(),
                changeset_id: "cs_test".to_string(),
                device_id: "dev_test".to_string(),
                principal: "agent:test".to_string(),
                diff_hash: "sha256:abcd1234".to_string(),
                timestamp: "2026-08-09T12:00:00Z".to_string(),
                run_id: String::new(),
                server_id: String::new(),
                segment_seq: 0,
                prev_hash: String::new(),
                metadata: None,
            }),
        )
        .unwrap();
        let segment = close(seg).unwrap();

        sink.spool(segment.clone()).unwrap();
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // Verify the injection attempt is URL-encoded in parameters (inert).
        let requests = transport.requests();
        let url = &requests[0].url;
        // urlencoding uses %20 for spaces, not +
        assert!(url.contains("param_server_id=%27%3B%20DROP%20TABLE%20audit%3B%20--"));
        // ClickHouse will receive this as a literal string parameter, not executable SQL.
    }

    #[test]
    fn exponential_backoff_with_jitter_follows_config() {
        let dir = TempDir::new().unwrap();
        let mut config = make_test_config(&dir);
        config.initial_backoff = Duration::from_millis(100);
        config.max_backoff = Duration::from_millis(1000);

        let transport = Arc::new(MockHttpTransport::failing());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();

        let segment = make_test_segment();
        sink.spool(segment.clone()).unwrap();

        // First attempt (no delay before first try).
        sink.attempt_delivery().unwrap();
        assert_eq!(sleep.delays().len(), 0);

        // Second attempt (delay before retry).
        sink.attempt_delivery().unwrap();
        let delays = sleep.delays();
        assert_eq!(delays.len(), 1);
        // First retry: 2^0 * 100ms = 100ms, with +/- 10% jitter -> [90ms, 110ms]
        assert!(delays[0] >= Duration::from_millis(90));
        assert!(delays[0] <= Duration::from_millis(110));

        // Third attempt (exponential growth).
        sink.attempt_delivery().unwrap();
        let delays = sleep.delays();
        assert_eq!(delays.len(), 2);
        // Second retry: 2^1 * 100ms = 200ms, with +/- 10% jitter -> [180ms, 220ms]
        assert!(delays[1] >= Duration::from_millis(180));
        assert!(delays[1] <= Duration::from_millis(220));

        // Fourth attempt (capped at max_backoff).
        for _ in 0..10 {
            sink.attempt_delivery().unwrap();
        }
        let delays = sleep.delays();
        // All delays after cap should be <= max_backoff + 10% jitter
        for delay in &delays[5..] {
            assert!(*delay <= Duration::from_millis(1100)); // 1000ms + 10% jitter
        }
    }

    #[test]
    fn std_http_transport_formats_request_correctly() {
        use std::io::{BufRead, BufReader, Read, Write};
        use std::net::TcpListener;
        use std::thread;

        // Start a local TCP listener to act as a stub ClickHouse server.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn a thread to handle one connection.
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(&stream);

            // Read request line.
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            assert!(request_line.starts_with("POST /?query="));
            assert!(request_line.contains("INSERT+INTO+test"));

            // Read headers.
            let mut headers = Vec::new();
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" || line == "\n" {
                    break;
                }
                headers.push(line);
            }

            // Verify Authorization header exists.
            assert!(
                headers
                    .iter()
                    .any(|h| h.starts_with("Authorization: Basic"))
            );

            // Read body (must read what the client sends).
            let mut body = vec![0u8; 9]; // "test body" is 9 bytes
            reader.read_exact(&mut body).unwrap();

            // Send HTTP 200 OK response.
            let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        // Create a request and send it to the stub server.
        let request = HttpRequest {
            url: format!("http://{}/?query=INSERT+INTO+test", addr),
            method: "POST".to_string(),
            headers: vec![
                (
                    "Content-Type".to_string(),
                    "application/x-ndjson".to_string(),
                ),
                (
                    "Authorization".to_string(),
                    "Basic dGVzdDp0ZXN0".to_string(),
                ),
            ],
            body: b"test body".to_vec(),
        };

        let transport = StdHttpTransport;
        transport.send(&request).unwrap();

        // Wait for the server thread to finish.
        handle.join().unwrap();
    }

    #[test]
    fn per_record_row_hash_chains_correctly() {
        use crate::evidence::ApprovalRecord;

        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::new());
        let sleep = MockSleep::new();
        let sink =
            SsdfSink::new_with_transport(config.clone(), transport.clone(), sleep.as_fn()).unwrap();

        // Create a segment with TWO records to verify they get different row_hash values.
        let mut seg = ChainSegment::new(
            "run_test".to_string(),
            "server_test".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        let hash1 = append(
            &mut seg,
            EvidenceRecord::Proposal(ProposalRecord {
                request_id: "req_test".to_string(),
                changeset_id: "cs_test".to_string(),
                device_id: "dev_test".to_string(),
                principal: "agent:test".to_string(),
                diff_hash: "sha256:abcd1234".to_string(),
                timestamp: "2026-08-09T12:00:00Z".to_string(),
                run_id: String::new(),
                server_id: String::new(),
                segment_seq: 0,
                prev_hash: String::new(),
                metadata: None,
            }),
        )
        .unwrap();

        let hash2 = append(
            &mut seg,
            EvidenceRecord::Approval(ApprovalRecord {
                request_id: "req_test".to_string(),
                changeset_id: "cs_test".to_string(),
                device_id: "dev_test".to_string(),
                principal: "approver:test".to_string(),
                approver: "approver:test".to_string(),
                decision: "approved".to_string(),
                diff_hash: "sha256:abcd1234".to_string(),
                timestamp: "2026-08-09T12:01:00Z".to_string(),
                run_id: String::new(),
                server_id: String::new(),
                segment_seq: 0,
                prev_hash: String::new(),
                metadata: None,
            }),
        )
        .unwrap();

        let segment = close(seg).unwrap();

        // Verify the chain hashes are different.
        assert_ne!(hash1, hash2, "two records must have different hashes");

        sink.spool(segment.clone()).unwrap();
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // Parse the NDJSON body and verify each row has its own row_hash.
        let requests = transport.requests();
        let inserts = inserts(&requests);
        assert_eq!(inserts.len(), 1);

        let body = String::from_utf8(inserts[0].body.clone()).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "should have 2 SSDF rows");

        let row1: SsdfRow = serde_json::from_str(lines[0]).unwrap();
        let row2: SsdfRow = serde_json::from_str(lines[1]).unwrap();

        // Each row should have its own hash, not the segment head_hash.
        assert_eq!(
            row1.row_hash, hash1,
            "first row must use first record's hash"
        );
        assert_eq!(
            row2.row_hash, hash2,
            "second row must use second record's hash"
        );
        assert_ne!(
            row1.row_hash, row2.row_hash,
            "two rows must have different row_hash values"
        );

        // Verify prev_hash chains correctly: second row's prev_hash = first row's row_hash.
        assert_eq!(
            row2.prev_hash, hash1,
            "second row's prev_hash must equal first row's hash"
        );
    }

    /// ClickHouse returns query results chunked. Without decoding, a body of
    /// `1\t3` arrives as `5\r\n1\t3\n\r\n0\r\n\r\n` and the high-water read
    /// cannot parse it — which, before the surrounding fixes, silently meant
    /// "nothing landed" and duplicated every delivery.
    #[test]
    fn std_http_transport_decodes_a_chunked_response() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            {
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header == "\n" {
                        break;
                    }
                }
            }
            // Two chunks, to prove the decoder reassembles rather than reading
            // only the first.
            let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
                            2\r\n1\t\r\n2\r\n3\n\r\n0\r\n\r\n";
            stream.write_all(response.as_bytes()).unwrap();
            stream.flush().unwrap();
        });

        let request = HttpRequest {
            url: format!("http://{}/?query=SELECT+1", addr),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let body = StdHttpTransport.send(&request).unwrap();
        handle.join().unwrap();

        assert_eq!(
            body, "1\t3\n",
            "both chunks must be reassembled, framing removed"
        );
    }

    /// A declared chunk size is attacker- or fault-controlled. Allocating it
    /// before applying the response limit turns a malformed reply into an
    /// arbitrary allocation.
    #[test]
    fn std_http_transport_refuses_an_oversized_chunk_before_allocating() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            {
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).unwrap();
                    if header == "\r\n" || header == "\n" {
                        break;
                    }
                }
            }
            // Declares 256 MiB and sends nothing. A decoder that allocates on
            // the declaration hangs or dies here.
            let response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000\r\n";
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        });

        let request = HttpRequest {
            url: format!("http://{}/?query=SELECT+1", addr),
            method: "POST".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let result = StdHttpTransport.send(&request);
        let _ = handle.join();

        let error = result.expect_err("an oversized chunk must be refused");
        assert!(
            error.to_string().contains("response limit"),
            "the refusal must name the limit rather than fail obscurely: {error}"
        );
    }
}
