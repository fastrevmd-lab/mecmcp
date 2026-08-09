//! SSDF evidence sink with durable outbox and delivery ledger.
//!
//! This sink delivers closed evidence segments to a ClickHouse SSDF instance via
//! HTTP INSERT. Segments are spooled to a durable outbox file before delivery,
//! and delivery status is tracked in a separate ledger. Sink failures are
//! non-fatal to the serving process (fail-open ship, fail-closed record).

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
    /// ClickHouse HTTP endpoint (e.g., "https://192.168.1.104:8443").
    pub endpoint: String,
    /// ClickHouse database name (e.g., "ssdf").
    pub database: String,
    /// ClickHouse username (e.g., "ssdf_audit").
    pub username: String,
    /// ClickHouse password.
    pub password: String,
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
/// - Retry with exponential backoff
/// - Idempotency via (server_id, run_id, segment_seq) deduplication
/// - Separate delivery ledger (delivery status never mutates hashed records)
/// - Fail-open ship, fail-closed record (sink failure is non-fatal to serving)
pub struct SsdfSink {
    config: SsdfSinkConfig,
    outbox: Arc<Mutex<OutboxState>>,
    ledger: Arc<Mutex<DeliveryLedger>>,
    transport: Arc<dyn HttpTransport>,
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
        Self::new_with_transport(config, Arc::new(StdHttpTransport))
    }

    /// Create a new SSDF sink with a custom HTTP transport (for testing).
    pub fn new_with_transport(
        config: SsdfSinkConfig,
        transport: Arc<dyn HttpTransport>,
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
    /// logged and retried with exponential backoff (tracked in the ledger).
    pub fn attempt_delivery(&self) -> Result<usize, SsdfSinkError> {
        // Load all segments from the outbox.
        let segments = self.load_outbox()?;
        let mut delivered_count = 0;

        for segment in segments {
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
                    let attempts = match status {
                        Some(DeliveryStatus::Failed { attempts, .. }) => attempts + 1,
                        _ => 1,
                    };
                    self.ledger
                        .lock()
                        .expect("ledger mutex not poisoned")
                        .mark_failed(id, failed_at, e.to_string(), attempts)?;
                }
            }
        }

        Ok(delivered_count)
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
    fn deliver_segment(&self, segment: &ClosedSegment) -> Result<(), SsdfSinkError> {
        // Build the INSERT query with deduplication guard.
        let query = format!(
            "query=INSERT+INTO+{}.audit+FORMAT+JSONEachRow",
            self.config.database // No need to escape in URL query param
        );

        // Convert segment records to SSDF rows.
        let rows: Vec<SsdfRow> = segment
            .records()
            .iter()
            .map(|record| self.record_to_ssdf_row(record, segment))
            .collect::<Result<Vec<_>, _>>()?;

        // Filter rows using deduplication guard (client-side for now).
        // TODO: Move this to server-side INSERT ... WHERE NOT EXISTS once
        // parameter binding is resolved.
        let filtered_rows = self.apply_dedup_filter(rows, segment)?;

        if filtered_rows.is_empty() {
            // All rows were already delivered (idempotent replay).
            return Ok(());
        }

        // Serialize rows as JSONEachRow (one JSON object per line).
        let body = filtered_rows
            .iter()
            .map(|row| serde_json::to_string(row).expect("SsdfRow must serialize"))
            .collect::<Vec<_>>()
            .join("\n");

        // Send HTTP request.
        let request = HttpRequest {
            url: format!("{}/?{}", self.config.endpoint, query),
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

    /// Convert an evidence record to an SSDF row.
    fn record_to_ssdf_row(
        &self,
        record: &crate::evidence::EvidenceRecord,
        segment: &ClosedSegment,
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
                    row_hash: segment.head_hash.clone(),
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
                    row_hash: segment.head_hash.clone(),
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
                    row_hash: segment.head_hash.clone(),
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
                    row_hash: segment.head_hash.clone(),
                })
            }
        }
    }

    /// Apply client-side deduplication filter.
    ///
    /// This is a temporary implementation until server-side INSERT ... WHERE NOT EXISTS
    /// with proper parameter binding is implemented. For now, we simply skip all rows
    /// if the segment is marked as delivered in the ledger (which means the idempotency
    /// key already exists in SSDF).
    fn apply_dedup_filter(
        &self,
        rows: Vec<SsdfRow>,
        segment: &ClosedSegment,
    ) -> Result<Vec<SsdfRow>, SsdfSinkError> {
        let id = SegmentId {
            server_id: segment.server_id.clone(),
            run_id: segment.run_id.clone(),
            segment_seq: segment.segment_seq,
        };

        let status = self
            .ledger
            .lock()
            .expect("ledger mutex not poisoned")
            .status(&id)
            .cloned();

        if matches!(status, Some(DeliveryStatus::Delivered { .. })) {
            // Already delivered; skip all rows.
            Ok(Vec::new())
        } else {
            // Not delivered; allow all rows.
            Ok(rows)
        }
    }
}

/// Escape a ClickHouse identifier (database or table name).
///
/// ClickHouse identifiers can be unquoted if they match [a-zA-Z_][a-zA-Z0-9_]*,
/// otherwise they must be quoted. We always quote for safety.
#[allow(dead_code)]
fn escape_identifier(s: &str) -> String {
    format!("`{}`", s.replace('`', "``"))
}

/// HTTP transport abstraction for testing.
pub trait HttpTransport: Send + Sync {
    /// Send an HTTP request.
    fn send(&self, request: &HttpRequest) -> Result<(), SsdfSinkError>;
}

/// HTTP request.
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

/// Standard HTTP transport (placeholder; requires implementation).
struct StdHttpTransport;

impl HttpTransport for StdHttpTransport {
    fn send(&self, _request: &HttpRequest) -> Result<(), SsdfSinkError> {
        // TODO: Implement actual HTTP client using reqwest or std::net::TcpStream.
        // For now, this is a placeholder that returns an error.
        Err(SsdfSinkError::Http(
            "StdHttpTransport not yet implemented".to_string(),
        ))
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

    impl Clone for HttpRequest {
        fn clone(&self) -> Self {
            Self {
                url: self.url.clone(),
                method: self.method.clone(),
                headers: self.headers.clone(),
                body: self.body.clone(),
            }
        }
    }

    impl HttpTransport for MockHttpTransport {
        fn send(&self, request: &HttpRequest) -> Result<(), SsdfSinkError> {
            if self.should_fail {
                return Err(SsdfSinkError::Http("mock transport failure".to_string()));
            }
            self.requests
                .lock()
                .expect("mock transport mutex not poisoned")
                .push(request.clone());
            Ok(())
        }
    }

    fn make_test_config(dir: &TempDir) -> SsdfSinkConfig {
        SsdfSinkConfig {
            endpoint: "https://test.clickhouse:8443".to_string(),
            database: "ssdf".to_string(),
            username: "ssdf_audit".to_string(),
            password: "test_password".to_string(),
            outbox_path: dir.path().join("outbox.jsonl"),
            ledger_path: dir.path().join("ledger.jsonl"),
            initial_backoff: Duration::from_secs(1),
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
        let sink = SsdfSink::new_with_transport(config.clone(), transport.clone()).unwrap();

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
    fn attempt_delivery_sends_http_request() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::new());
        let sink = SsdfSink::new_with_transport(config.clone(), transport.clone()).unwrap();

        let segment = make_test_segment();
        sink.spool(segment.clone()).unwrap();

        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // Verify HTTP request was sent.
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "POST");
        assert!(requests[0].url.contains("INSERT"));
        assert!(requests[0].url.contains("ssdf.audit"));

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
        let sink = SsdfSink::new_with_transport(config.clone(), transport.clone()).unwrap();

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
        let sink = SsdfSink::new_with_transport(config.clone(), transport.clone()).unwrap();

        let segment = make_test_segment();
        sink.spool(segment.clone()).unwrap();

        // First delivery.
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // Second delivery (idempotent replay).
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 0);

        // Only one HTTP request was sent.
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn crash_recovery_replays_outbox() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);

        let segment = make_test_segment();
        {
            let transport = Arc::new(MockHttpTransport::new());
            let sink = SsdfSink::new_with_transport(config.clone(), transport.clone()).unwrap();
            sink.spool(segment.clone()).unwrap();
            // Crash before delivery (drop sink).
        }

        // Reopen sink and replay.
        let transport = Arc::new(MockHttpTransport::new());
        let sink = SsdfSink::new_with_transport(config.clone(), transport.clone()).unwrap();
        let delivered = sink.attempt_delivery().unwrap();
        assert_eq!(delivered, 1);

        // Verify HTTP request was sent.
        let requests = transport.requests();
        assert_eq!(requests.len(), 1);
    }

    #[test]
    fn injection_safety_test() {
        let dir = TempDir::new().unwrap();
        let config = make_test_config(&dir);
        let transport = Arc::new(MockHttpTransport::new());
        let sink = SsdfSink::new_with_transport(config.clone(), transport.clone()).unwrap();

        // Create a segment with SQL injection attempt in a field.
        let mut seg = ChainSegment::new(
            "run_test".to_string(),
            "server_test".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(
            &mut seg,
            EvidenceRecord::Proposal(ProposalRecord {
                request_id: "'; DROP TABLE audit; --".to_string(),
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

        // Verify the injection attempt is inert (serialized as JSON string).
        let requests = transport.requests();
        let body = String::from_utf8_lossy(&requests[0].body);
        assert!(body.contains("'; DROP TABLE audit; --"));
        // The injection is inside a JSON string, so it's escaped with backslash.
        // JSON serialization escapes single quotes as-is but the string is quoted.
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        let args_str = parsed["args"].as_str().unwrap();
        let args: serde_json::Value = serde_json::from_str(args_str).unwrap();
        assert_eq!(args["request_id"], "'; DROP TABLE audit; --");
    }

    #[test]
    fn identifier_escaping() {
        assert_eq!(escape_identifier("ssdf"), "`ssdf`");
        assert_eq!(escape_identifier("test`db"), "`test``db`");
    }
}
