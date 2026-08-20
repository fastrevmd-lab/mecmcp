//! Evidence must be emitted at the four lifecycle points, chained, and closed.
//!
//! Until now nothing in this family produced an evidence record: the types, the
//! chain and the sink all existed, and no code path created one. `ssdf.audit`
//! holds 20,193 `sovereign` rows and **zero** `evidence` rows, which is why
//! (mecmcp#292).
//!
//! The recorder is the missing piece. It owns one chain per run, appends at
//! each lifecycle point, and hands closed segments to whatever ships them.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::evidence::EvidenceRecord;
use mecmcp_audit::recorder::{EvidenceRecorder, RecorderConfig};

fn recorder_of(records_per_segment: usize) -> EvidenceRecorder {
    EvidenceRecorder::new(RecorderConfig {
        server_id: "mecmcp-test".to_string(),
        run_id: "run-001".to_string(),
        records_per_segment,
    })
}

fn recorder() -> EvidenceRecorder {
    recorder_of(4)
}

/// The four points are the change-set lifecycle. A record missing from any one
/// of them leaves a chain that verifies while describing less than happened.
#[test]
fn the_four_lifecycle_points_each_append_one_record() {
    // Wide enough that the segment stays open; the rolling behaviour is its
    // own test.
    let recorder = recorder_of(8);

    recorder.proposal("req-1", "cs-1", "vsrx-ci", "agent:test", "sha256:diff");
    recorder.approval("req-1", "cs-1", "user:alice", "approved");
    recorder.apply_intent("req-1", "cs-1", "vsrx-ci", "agent:test");
    recorder.result_receipt("req-1", "cs-1", "vsrx-ci", true, "");

    let closed = recorder.close_current().unwrap();
    let kinds: Vec<&str> = closed
        .records()
        .iter()
        .map(|record| match record {
            EvidenceRecord::Proposal(_) => "proposal",
            EvidenceRecord::Approval(_) => "approval",
            EvidenceRecord::ApplyIntent(_) => "apply_intent",
            EvidenceRecord::ResultReceipt(_) => "result_receipt",
        })
        .collect();

    assert_eq!(
        kinds,
        vec!["proposal", "approval", "apply_intent", "result_receipt"],
        "the lifecycle order is the evidence"
    );
}

/// Each record links to the one before. A break here is the failure the whole
/// mechanism exists to make detectable.
#[test]
fn records_are_chained_within_a_segment() {
    let recorder = recorder();
    recorder.proposal("req-1", "cs-1", "vsrx-ci", "agent:test", "sha256:diff");
    recorder.approval("req-1", "cs-1", "user:alice", "approved");

    let closed = recorder.close_current().unwrap();

    let hashes: Vec<String> = closed
        .records()
        .iter()
        .map(|record| match record {
            EvidenceRecord::Proposal(r) => r.prev_hash.clone(),
            EvidenceRecord::Approval(r) => r.prev_hash.clone(),
            EvidenceRecord::ApplyIntent(r) => r.prev_hash.clone(),
            EvidenceRecord::ResultReceipt(r) => r.prev_hash.clone(),
        })
        .collect();
    assert_eq!(hashes.len(), 2);
    assert!(
        !hashes[1].is_empty(),
        "the second record must link to the first"
    );
    assert_ne!(hashes[0], hashes[1], "each link is distinct");
}

/// Segments must roll, or one run accumulates an unbounded segment that is
/// never delivered and never verifiable until shutdown.
#[test]
fn a_full_segment_rolls_and_the_sequence_advances() {
    let recorder = recorder(); // records_per_segment: 4
    for n in 0..4 {
        recorder.proposal(&format!("req-{n}"), "cs-1", "vsrx-ci", "agent:test", "sha");
    }

    let rolled = recorder.take_closed();

    assert_eq!(rolled.len(), 1, "a full segment closes itself");
    assert_eq!(rolled[0].segment_seq, 0);
    assert_eq!(rolled[0].records().len(), 4);

    // The next record starts segment 1, linked to segment 0's head.
    recorder.proposal("req-4", "cs-1", "vsrx-ci", "agent:test", "sha");
    let next = recorder.close_current().unwrap();
    assert_eq!(next.segment_seq, 1, "the sequence advances");
    assert_eq!(
        next.prev_hash, rolled[0].head_hash,
        "segment 1 links to segment 0's head, or the chain forks at the boundary"
    );
}

/// Closing an empty segment yields nothing rather than an empty segment: a
/// zero-record segment consumes a sequence number and tells a verifier nothing.
#[test]
fn closing_an_empty_segment_produces_nothing() {
    let recorder = recorder();

    assert!(recorder.close_current().is_none());
}
