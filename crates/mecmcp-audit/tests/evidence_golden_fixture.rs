#![allow(clippy::unwrap_used)]
//! Golden fixture conformance test for evidence records.
//!
//! This test captures the expected serialization and hash-chain behavior
//! for a complete evidence lifecycle: proposal → approval → apply_intent → result_receipt.

use mecmcp_audit::{
    ApplyIntentRecord, ApprovalRecord, ChainSegment, EvidenceRecord, GENESIS_PREV_HASH,
    ProposalRecord, ResultReceipt, SegmentArchive, append, close,
};

#[test]
fn golden_fixture_full_segment_roundtrip() {
    // Create a full evidence chain for a single configuration change
    let mut seg = ChainSegment::new(
        "run_20260809_143210".to_string(),
        "rustsdcmcp-606".to_string(),
        0,
        GENESIS_PREV_HASH.to_string(),
    );

    // 1. Proposal: agent proposes a NAT rule change
    let proposal = ProposalRecord {
        request_id: "req_abc123".to_string(),
        changeset_id: "cs_xyz789".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:fedcba9876543210abcdef0123456789".to_string(),
        timestamp: "2026-08-09T14:32:10.500Z".to_string(),
        run_id: String::new(), // Will be injected by append()
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        metadata: Some(serde_json::json!({
            "commit_message": "Fix NAT rule source address",
            "change_summary": "Updated policy-nat-1"
        })),
    };

    let hash1 = append(&mut seg, EvidenceRecord::Proposal(proposal)).unwrap();
    assert!(hash1.starts_with("sha256:"));
    assert_eq!(hash1.len(), 71); // "sha256:" + 64 hex chars

    // 2. Approval: human approves the change
    let approval = ApprovalRecord {
        request_id: "req_abc123".to_string(),
        changeset_id: "cs_xyz789".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:fedcba9876543210abcdef0123456789".to_string(),
        timestamp: "2026-08-09T14:33:15.200Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        approver: "alice@mechub.org".to_string(),
        decision: "approved".to_string(),
        metadata: None,
    };

    let hash2 = append(&mut seg, EvidenceRecord::Approval(approval)).unwrap();
    assert!(hash2.starts_with("sha256:"));
    assert_ne!(hash1, hash2, "each record must have a unique hash");

    // 3. Apply intent: system begins executing
    let apply_intent = ApplyIntentRecord {
        request_id: "req_abc123".to_string(),
        changeset_id: "cs_xyz789".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:fedcba9876543210abcdef0123456789".to_string(),
        timestamp: "2026-08-09T14:34:20.100Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        metadata: None,
    };

    let hash3 = append(&mut seg, EvidenceRecord::ApplyIntent(apply_intent)).unwrap();
    assert!(hash3.starts_with("sha256:"));
    assert_ne!(hash2, hash3);

    // 4. Result receipt: execution succeeded
    let result = ResultReceipt {
        request_id: "req_abc123".to_string(),
        changeset_id: "cs_xyz789".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:fedcba9876543210abcdef0123456789".to_string(),
        timestamp: "2026-08-09T14:35:25.300Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        outcome: "success".to_string(),
        error: None,
        metadata: None,
    };

    let hash4 = append(&mut seg, EvidenceRecord::ResultReceipt(result)).unwrap();
    assert!(hash4.starts_with("sha256:"));
    assert_ne!(hash3, hash4);

    // Close the segment and verify head hash
    let closed = close(seg).unwrap();
    assert_eq!(closed.head_hash, hash4, "head hash must match last record");
    assert_eq!(closed.records().len(), 4);
    assert_eq!(closed.segment_seq, 0);

    // Serialize to JSON (for golden fixture)
    let json = serde_json::to_string_pretty(&closed).unwrap();

    // Deserialize and verify roundtrip
    let deserialized: mecmcp_audit::ClosedSegment = serde_json::from_str(&json).unwrap();
    assert_eq!(closed, deserialized);

    // Verify chain integrity: recompute from records
    // Note: We need to clear envelope fields before re-appending since they're already set
    let mut verify_seg = ChainSegment::new(
        closed.run_id.clone(),
        closed.server_id.clone(),
        closed.segment_seq,
        closed.prev_hash.clone(),
    );
    for record in closed.records() {
        let mut cleared_record = record.clone();
        // Clear envelope fields so append() can validate and inject them
        match &mut cleared_record {
            EvidenceRecord::Proposal(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
            EvidenceRecord::Approval(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
            EvidenceRecord::ApplyIntent(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
            EvidenceRecord::ResultReceipt(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
        }
        append(&mut verify_seg, cleared_record).unwrap();
    }
    let verify_closed = close(verify_seg).unwrap();
    assert_eq!(
        closed.head_hash, verify_closed.head_hash,
        "recomputed hash must match stored hash"
    );

    // Archive the segment and verify monotonicity
    let mut archive = SegmentArchive::new();
    archive.archive(closed.clone()).unwrap();
    assert_eq!(archive.len(), 1);

    // Demonstrate the golden properties:
    // 1. Each record has a unique hash
    // 2. The chain links correctly (each prev_hash matches)
    // 3. Tampering detection works (covered in unit tests)
    // 4. Serialization is stable and canonical
    println!("Golden fixture JSON:\n{}", json);
}

#[test]
fn golden_fixture_segment_continuation() {
    // Demonstrate segment rollover within a single run
    let mut archive = SegmentArchive::new();

    // First segment
    let mut seg1 = ChainSegment::new(
        "run_20260809_143210".to_string(),
        "rustsdcmcp-606".to_string(),
        0,
        GENESIS_PREV_HASH.to_string(),
    );

    let proposal = ProposalRecord {
        request_id: "req_001".to_string(),
        changeset_id: "cs_001".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        timestamp: "2026-08-09T14:32:10.500Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        metadata: None,
    };

    append(&mut seg1, EvidenceRecord::Proposal(proposal)).unwrap();
    let closed1 = close(seg1).unwrap();
    archive.archive(closed1.clone()).unwrap();

    // Second segment continues the chain
    let mut seg2 = ChainSegment::new(
        "run_20260809_143210".to_string(),
        "rustsdcmcp-606".to_string(),
        1,
        closed1.head_hash.clone(), // Link to previous segment
    );

    let approval = ApprovalRecord {
        request_id: "req_001".to_string(),
        changeset_id: "cs_001".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        timestamp: "2026-08-09T14:33:15.200Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        approver: "alice@mechub.org".to_string(),
        decision: "approved".to_string(),
        metadata: None,
    };

    append(&mut seg2, EvidenceRecord::Approval(approval)).unwrap();
    let closed2 = close(seg2).unwrap();
    archive.archive(closed2.clone()).unwrap();

    // Verify the chain links across segments
    assert_eq!(archive.len(), 2);
    assert_eq!(
        closed2.prev_hash, closed1.head_hash,
        "segment 2 must link to segment 1's head"
    );
    assert_eq!(archive.segments()[0].segment_seq, 0);
    assert_eq!(archive.segments()[1].segment_seq, 1);
}
