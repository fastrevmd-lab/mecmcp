//! The spool needs a drain, and the startup reads need an order.
//!
//! `attempt_delivery` and `shutdown_flush` existed and were called only by
//! tests, so a deployed server would have spooled evidence to disk forever and
//! delivered none of it — a failure that looks like success from inside the
//! process, since every record is durably written. `EvidenceService` is the
//! part that turns the sink from a spool into a pipeline.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::sinks::ssdf::{HttpRequest, HttpTransport, SsdfSinkConfig, SsdfSinkError};
use mecmcp_audit::{EvidenceConfig, EvidenceService};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct CountingTransport {
    inserts: AtomicUsize,
    reads: AtomicUsize,
    /// Bodies handed back to SELECTs, in order: high-water, then tail.
    reads_return: Mutex<Vec<String>>,
    /// Ordered log of what was sent, so a test can assert sequence rather than
    /// merely that something happened.
    log: Mutex<Vec<&'static str>>,
}

impl HttpTransport for CountingTransport {
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
        let url = urlencoding::decode(&request.url)
            .unwrap_or_default()
            .into_owned();
        if url.contains("SELECT") {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.log.lock().unwrap().push(if url.contains("NOT IN") {
                "read-tail"
            } else {
                "read-high-water"
            });
            let mut queued = self.reads_return.lock().unwrap();
            if queued.is_empty() {
                return Ok("0\t0\n".to_string());
            }
            return Ok(queued.remove(0));
        }
        self.inserts.fetch_add(1, Ordering::SeqCst);
        self.log.lock().unwrap().push("insert");
        Ok(String::new())
    }
}

fn sink_config(dir: &std::path::Path) -> SsdfSinkConfig {
    SsdfSinkConfig {
        endpoint: "http://ch.example:8123".to_string(),
        database: "ssdf".to_string(),
        username: "ssdf_audit".to_string(),
        password: "w".to_string(),
        verify_username: "ssdf_audit_verify".to_string(),
        verify_password: "v".to_string(),
        outbox_path: dir.join("outbox.ndjson"),
        ledger_path: dir.join("ledger.json"),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    }
}

/// A record written through the service reaches ClickHouse without anyone
/// calling `attempt_delivery` by hand.
#[test]
fn spooled_evidence_is_delivered_by_the_service() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(CountingTransport::default());
    let service = EvidenceService::start_with_transport(
        EvidenceConfig {
            server_id: "junos-950".to_string(),
            run_id: "run-1".to_string(),
            records_per_segment: 1,
            delivery_interval: Duration::from_millis(20),
            sink: sink_config(dir.path()),
        },
        transport.clone(),
    )
    .unwrap();

    let recorder = service.recorder();
    recorder.proposal("req-1", "cs-1", "vsrx-ci", "alice", "sha256:d");
    recorder
        .apply_intent("req-2", "cs-1", "vsrx-ci", "alice")
        .unwrap();

    // The pump runs on its own; nothing here drives it. The count is taken
    // *before* shutdown on purpose -- shutdown flushes too, so asserting
    // afterwards would pass with no background drain at all.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while transport.inserts.load(Ordering::SeqCst) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let delivered_by_the_pump = transport.inserts.load(Ordering::SeqCst);
    service.shutdown().unwrap();

    assert!(
        delivered_by_the_pump > 0,
        "nothing delivered while the service was running: the sink is a spool \
         with no drain, which looks identical to success from inside the process"
    );
}

/// Shutdown must flush what the interval has not yet taken.
#[test]
fn shutdown_delivers_what_is_still_pending() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(CountingTransport::default());
    let service = EvidenceService::start_with_transport(
        EvidenceConfig {
            server_id: "junos-950".to_string(),
            run_id: "run-1".to_string(),
            // Large enough that the record below never rolls a segment, so it
            // is still in the *open* one at shutdown. That is the part only
            // shutdown can save: the worker's final delivery pass ships what is
            // already spooled, and an unrolled segment is not.
            records_per_segment: 64,
            // Long enough that the pump cannot be what delivers it.
            delivery_interval: Duration::from_secs(3600),
            sink: sink_config(dir.path()),
        },
        transport.clone(),
    )
    .unwrap();

    service
        .recorder()
        .proposal("req-1", "cs-1", "vsrx-ci", "alice", "sha256:d");
    assert_eq!(
        transport.inserts.load(Ordering::SeqCst),
        0,
        "nothing has rolled or ticked, so nothing should have gone yet"
    );

    service.shutdown().unwrap();

    assert!(
        transport.inserts.load(Ordering::SeqCst) > 0,
        "the record was still in the open segment, so a shutdown that only \
         drains what is already spooled loses it -- and a restart cannot \
         replay what was never written"
    );
}

/// The tail read must come after replay, or a restart forks the chain.
///
/// A segment still in flight when the process died has not landed, so a tail
/// read taken first returns its predecessor; the next record attaches there and
/// produces two branches with no duplicate for the verifier to catch. The
/// contract states the ordering; this asserts the code obeys it.
#[test]
fn the_tail_is_read_after_replay_not_before() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(CountingTransport::default());

    // First run leaves an undelivered segment in the outbox.
    {
        let failing = Arc::new(CountingTransport::default());
        let service = EvidenceService::start_with_transport(
            EvidenceConfig {
                server_id: "junos-950".to_string(),
                run_id: "run-1".to_string(),
                records_per_segment: 1,
                delivery_interval: Duration::from_secs(3600),
                sink: sink_config(dir.path()),
            },
            failing,
        )
        .unwrap();
        service
            .recorder()
            .proposal("req-1", "cs-1", "vsrx-ci", "alice", "sha256:d");
        // `apply_intent` is what spools -- it closes and persists before
        // returning. A `close_current` alone would leave the segment in memory,
        // so nothing would be stranded in the outbox and this test would prove
        // nothing about replay.
        service
            .recorder()
            .apply_intent("req-2", "cs-1", "vsrx-ci", "alice")
            .unwrap();
        assert!(
            std::fs::read_to_string(dir.path().join("outbox.ndjson"))
                .unwrap()
                .contains("apply_intent"),
            "the first run must leave an undelivered segment behind"
        );
        std::mem::forget(service); // die without flushing
    }

    let service = EvidenceService::start_with_transport(
        EvidenceConfig {
            server_id: "junos-950".to_string(),
            run_id: "run-2".to_string(),
            records_per_segment: 1,
            delivery_interval: Duration::from_secs(3600),
            sink: sink_config(dir.path()),
        },
        transport.clone(),
    )
    .unwrap();
    service.shutdown().unwrap();

    // Sequence, not totals. Delivery happens either way -- what matters is that
    // the stranded segment went *before* the tail was read, because a tail read
    // first returns that segment's predecessor and the new run forks from it.
    let log = transport.log.lock().unwrap().clone();
    let first_insert = log.iter().position(|entry| *entry == "insert");
    let tail_read = log.iter().position(|entry| *entry == "read-tail");
    assert!(
        first_insert.is_some() && tail_read.is_some(),
        "expected both a replay and a tail read at startup: {log:?}"
    );
    assert!(
        first_insert < tail_read,
        "the tail was read before the stranded segment was replayed, so it \
         predates that segment and the new run will fork: {log:?}"
    );
}
