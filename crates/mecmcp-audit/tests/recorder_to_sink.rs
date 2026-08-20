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
