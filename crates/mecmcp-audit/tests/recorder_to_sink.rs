//! The recorder and the sink must actually be connected.
//!
//! Both halves of mecmcp#292 existed and were tested in isolation: the recorder
//! produced closed segments, the sink delivered them. Nothing joined the two, so
//! a deployment could configure both correctly and still write nothing —
//! `ssdf.audit` would hold zero `evidence` rows however the sink was pointed.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::recorder::{EvidenceRecorder, RecorderConfig};
use mecmcp_audit::{SsdfSink, SsdfSinkConfig};
use std::sync::Arc;
use std::time::Duration;

fn sink_config(dir: &std::path::Path) -> SsdfSinkConfig {
    SsdfSinkConfig {
        endpoint: "http://127.0.0.1:1".to_string(),
        database: "ssdf".to_string(),
        username: "ssdf_audit".to_string(),
        password: "unused".to_string(),
        verify_username: "ssdf_audit_verify".to_string(),
        verify_password: "unused".to_string(),
        outbox_path: dir.join("outbox.jsonl"),
        ledger_path: dir.join("ledger.jsonl"),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    }
}

/// An apply intent must be on disk in the sink's outbox before it returns.
///
/// The endpoint here points at a closed port on purpose: delivery is expected
/// to be impossible, and the record must still be durable. That is the whole
/// distinction the sink documents as "fail-open ship, fail-closed record".
#[test]
fn an_apply_intent_reaches_the_sink_outbox() {
    let dir = tempfile::tempdir().unwrap();
    let config = sink_config(dir.path());
    let outbox = config.outbox_path.clone();
    let sink = Arc::new(SsdfSink::new(config).unwrap());

    let recorder = EvidenceRecorder::new(RecorderConfig {
        server_id: "mecmcp-test".to_string(),
        run_id: "run-001".to_string(),
        resume_from: None,
        records_per_segment: 64,
    })
    .spooling_to(Arc::clone(&sink));

    recorder.proposal("req-1", "cs-1", "vsrx-ci", "agent:planner", "sha256:diff");
    recorder
        .apply_intent("req-2", "cs-1", "vsrx-ci", "agent:planner")
        .expect("a writable outbox must accept the intent");

    let spooled = std::fs::read_to_string(&outbox).unwrap();
    assert!(
        spooled.contains("apply_intent"),
        "the intent must be on disk before the device is touched, not merely \
         queued in memory: {spooled}"
    );
    assert!(
        spooled.contains("\"changeset_id\":\"cs-1\""),
        "the spooled record must be the one that was written: {spooled}"
    );
}

/// The resume head must come from the outbox, not from whatever the caller had
/// to hand.
///
/// Renaming the argument does not prevent the fork: any caller can still pass a
/// pending tail. The head has to be *derived* from the durable record of what
/// this writer produced, which only the sink holds.
#[test]
fn the_produced_head_comes_from_the_outbox_in_production_order() {
    let dir = tempfile::tempdir().unwrap();
    let config = sink_config(dir.path());
    let sink = Arc::new(SsdfSink::new(config).unwrap());

    let recorder = EvidenceRecorder::new(RecorderConfig {
        server_id: "srv-a".to_string(),
        run_id: "run-1".to_string(),
        resume_from: None,
        records_per_segment: 1,
    })
    .spooling_to(Arc::clone(&sink));

    recorder.proposal("req-1", "cs-1", "vsrx-ci", "alice", "sha256:diff");
    recorder
        .apply_intent("req-2", "cs-1", "vsrx-ci", "alice")
        .unwrap();

    let newest = sink
        .produced_head("srv-a")
        .expect("reading the outbox must work")
        .expect("this writer has produced segments");

    let other = sink
        .produced_head("srv-b")
        .expect("reading the outbox works");
    assert_eq!(
        other, None,
        "another writer's chain must not be offered as this one's head"
    );

    // The last segment this writer appended is the newest it produced; the
    // outbox is append-only, so file order *is* production order.
    let spooled = std::fs::read_to_string(dir.path().join("outbox.jsonl")).unwrap();
    let last = spooled
        .lines()
        .rfind(|line| line.contains("\"server_id\":\"srv-a\""))
        .expect("a segment was spooled");
    let last: serde_json::Value = serde_json::from_str(last).unwrap();
    assert_eq!(
        newest.as_str(),
        last["head_hash"].as_str().unwrap(),
        "the head must be the last segment produced, not the first or the lowest"
    );
}

/// Segments must reach the outbox in production order, even when two devices
/// flush the same recorder at once.
///
/// The recorder is shared across devices while the coordinator's guards are
/// per device, so two commits genuinely run here in parallel. If the flush
/// releases its lock before spooling, a later segment can overtake an earlier
/// one: the durable chain then has N+1 without N, the later commit proceeds
/// having "persisted" its intent, and `produced_head` reads the wrong tip
/// because outbox order no longer means production order.
#[test]
fn concurrent_flushes_reach_the_outbox_in_order() {
    use std::sync::Mutex;

    let seen: Arc<Mutex<Vec<u64>>> = Arc::new(Mutex::new(Vec::new()));
    let recording = Arc::clone(&seen);
    let recorder = Arc::new(
        EvidenceRecorder::new(RecorderConfig {
            server_id: "srv-a".to_string(),
            run_id: "run-1".to_string(),
            resume_from: None,
            records_per_segment: 1,
        })
        .with_spool(move |segment| {
            // Hold the first segment long enough that an unserialised second
            // one would sail past it.
            if segment.segment_seq == 0 {
                std::thread::sleep(Duration::from_millis(150));
            }
            recording.lock().unwrap().push(segment.segment_seq);
            Ok(())
        }),
    );

    let first = Arc::clone(&recorder);
    let one = std::thread::spawn(move || {
        first
            .apply_intent("req-1", "cs-1", "dev-1", "alice")
            .unwrap();
    });
    std::thread::sleep(Duration::from_millis(30));
    let second = Arc::clone(&recorder);
    let two = std::thread::spawn(move || {
        second
            .apply_intent("req-2", "cs-2", "dev-2", "bob")
            .unwrap();
    });
    one.join().unwrap();
    two.join().unwrap();

    let order = seen.lock().unwrap().clone();
    assert_eq!(
        order,
        vec![0, 1],
        "a later segment overtook an earlier one, so the durable chain has a \
         gap and outbox order no longer means production order"
    );
}

/// A receipt must be durable too, not merely appended in memory.
///
/// Moving the receipt ahead of the local state write only helps if the record
/// survives the process. `result_receipt` is the terminal record for a change,
/// and the case it exists for — the device acted, local state did not follow —
/// is exactly the case where nothing later comes along to flush it.
#[test]
fn a_receipt_is_persisted_not_just_appended() {
    let dir = tempfile::tempdir().unwrap();
    let config = sink_config(dir.path());
    let outbox = config.outbox_path.clone();
    let sink = Arc::new(SsdfSink::new(config).unwrap());

    let recorder = EvidenceRecorder::new(RecorderConfig {
        server_id: "srv-a".to_string(),
        run_id: "run-1".to_string(),
        resume_from: None,
        records_per_segment: 64,
    })
    .spooling_to(Arc::clone(&sink));

    recorder.proposal("req-1", "cs-1", "vsrx-ci", "alice", "sha256:diff");
    recorder
        .apply_intent("req-2", "cs-1", "vsrx-ci", "alice")
        .unwrap();
    recorder
        .result_receipt("req-3", "cs-1", "vsrx-ci", true, "")
        .unwrap();

    let spooled = std::fs::read_to_string(&outbox).unwrap();
    assert!(
        spooled.contains("result_receipt"),
        "the outbox still ends at apply intent, which is the gap this ordering \
         was meant to close: {spooled}"
    );
}

/// A ledger failure after the outbox fsync is not a spool failure.
///
/// `SsdfSink::spool` writes and fsyncs the segment, *then* marks it pending in
/// the ledger — two independently configured files. If only the ledger write
/// fails, the record is already durable and `attempt_delivery` will still find
/// it, because delivery reads the outbox rather than the ledger. Refusing the
/// device operation at that point would fail closed on a record that was
/// safely written, and requeue an already-durable segment for a duplicate
/// append on the next flush.
#[test]
fn a_ledger_failure_after_fsync_is_not_a_spool_failure() {
    use mecmcp_audit::SsdfSinkError;
    use mecmcp_audit::recorder::spool_outcome;
    use mecmcp_audit::sinks::delivery_ledger::LedgerError;

    let ledger_only = SsdfSinkError::Ledger(LedgerError::InvalidEntry("ledger full".to_owned()));
    assert!(
        spool_outcome(Err(ledger_only)).is_ok(),
        "the segment was fsynced before the ledger was touched, so it is durable"
    );

    let outbox_failed = SsdfSinkError::OutboxIo(std::io::Error::other("disk full"));
    assert!(
        spool_outcome(Err(outbox_failed)).is_err(),
        "an outbox failure means nothing was written and must still fail closed"
    );
}

/// Every insert must carry a deduplication token derived from the segment's
/// identity.
///
/// The high-water read makes a *replay* idempotent, but it cannot help when an
/// insert is already in flight: a request that times out while ClickHouse is
/// still committing leaves the sink unable to tell whether the row landed, its
/// pre-retry read can answer "nothing", and the original then commits alongside
/// the retry. The hash chain cannot see the pair — identical content means an
/// identical `row_hash` — so the fix has to be server-side, and the token is
/// what lets ClickHouse recognise the retry as the same block (ssdf#49).
#[test]
fn an_insert_carries_a_dedup_token_for_its_segment() {
    use mecmcp_audit::sinks::ssdf::dedup_token;

    let token = dedup_token("junos-950", "run-7", 42);

    assert_eq!(
        token, "junos-950:run-7:42",
        "the token must identify exactly one segment: two writers, or two runs \
         of one writer, must never collide on it"
    );
    assert_ne!(
        dedup_token("junos-950", "run-7", 42),
        dedup_token("junos-950", "run-70", 4),
        "a token built by concatenation without separators would collide here"
    );
}
