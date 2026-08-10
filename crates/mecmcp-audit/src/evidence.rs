//! Evidence records and hash-chained segments for configuration change audit.
//!
//! Implements the ssdf.audit evidence contract v1.0: proposal, approval, apply
//! intent, and result receipt records linked into per-run tamper-evident chains.

use crate::canonical::{self, CanonicalError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// Re-export GENESIS_PREV_HASH for convenience
pub use crate::canonical::GENESIS_PREV_HASH;

/// Configuration change proposed by an agent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRecord {
    /// Unique change request identifier.
    pub request_id: String,
    /// Configuration changeset identifier.
    pub changeset_id: String,
    /// Target device identifier.
    pub device_id: String,
    /// Originating agent/user identity.
    pub principal: String,
    /// SHA-256 hash of the configuration diff.
    pub diff_hash: String,
    /// Evidence event timestamp (UTC, RFC3339).
    pub timestamp: String,
    /// Audit run identifier (for deduplication).
    pub run_id: String,
    /// Originating audit server identifier.
    pub server_id: String,
    /// Sequence number within this run (0-based).
    pub segment_seq: u64,
    /// Previous record hash (empty for first record).
    pub prev_hash: String,
    /// Optional commit message or change summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Human approval of a proposed change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// Unique change request identifier.
    pub request_id: String,
    /// Configuration changeset identifier.
    pub changeset_id: String,
    /// Target device identifier.
    pub device_id: String,
    /// Originating agent/user identity.
    pub principal: String,
    /// SHA-256 hash of the configuration diff.
    pub diff_hash: String,
    /// Evidence event timestamp (UTC, RFC3339).
    pub timestamp: String,
    /// Audit run identifier (for deduplication).
    pub run_id: String,
    /// Originating audit server identifier.
    pub server_id: String,
    /// Sequence number within this run (0-based).
    pub segment_seq: u64,
    /// Previous record hash (empty for first record).
    pub prev_hash: String,
    /// Approving user identity.
    pub approver: String,
    /// Approval outcome: "approved" or "rejected".
    pub decision: String,
    /// Optional commit message or change summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// System begins executing the approved change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyIntentRecord {
    /// Unique change request identifier.
    pub request_id: String,
    /// Configuration changeset identifier.
    pub changeset_id: String,
    /// Target device identifier.
    pub device_id: String,
    /// Originating agent/user identity.
    pub principal: String,
    /// SHA-256 hash of the configuration diff.
    pub diff_hash: String,
    /// Evidence event timestamp (UTC, RFC3339).
    pub timestamp: String,
    /// Audit run identifier (for deduplication).
    pub run_id: String,
    /// Originating audit server identifier.
    pub server_id: String,
    /// Sequence number within this run (0-based).
    pub segment_seq: u64,
    /// Previous record hash (empty for first record).
    pub prev_hash: String,
    /// Optional commit message or change summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Execution result returned from the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultReceipt {
    /// Unique change request identifier.
    pub request_id: String,
    /// Configuration changeset identifier.
    pub changeset_id: String,
    /// Target device identifier.
    pub device_id: String,
    /// Originating agent/user identity.
    pub principal: String,
    /// SHA-256 hash of the configuration diff.
    pub diff_hash: String,
    /// Evidence event timestamp (UTC, RFC3339).
    pub timestamp: String,
    /// Audit run identifier (for deduplication).
    pub run_id: String,
    /// Originating audit server identifier.
    pub server_id: String,
    /// Sequence number within this run (0-based).
    pub segment_seq: u64,
    /// Previous record hash (empty for first record).
    pub prev_hash: String,
    /// Execution outcome: "success" or "failure".
    pub outcome: String,
    /// Error detail (execution failures only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Optional commit message or change summary.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Evidence record kinds (time-of-knowledge split).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EvidenceRecord {
    /// Configuration change proposed by an agent.
    #[serde(rename = "evidence:proposal")]
    Proposal(ProposalRecord),
    /// Human approval of a proposed change.
    #[serde(rename = "evidence:approval")]
    Approval(ApprovalRecord),
    /// System begins executing the approved change.
    #[serde(rename = "evidence:apply_intent")]
    ApplyIntent(ApplyIntentRecord),
    /// Execution result returned from the device.
    #[serde(rename = "evidence:result_receipt")]
    ResultReceipt(ResultReceipt),
}

/// A tamper-evident segment of evidence records within a single run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainSegment {
    /// Audit run identifier (for deduplication).
    pub run_id: String,
    /// Originating audit server identifier.
    pub server_id: String,
    /// Sequence number within this run (0-based).
    pub segment_seq: u64,
    /// Previous segment hash (for cross-segment linking).
    pub prev_hash: String,
    /// Evidence records in this segment.
    records: Vec<EvidenceRecord>,
    /// Hash of the last appended record (for linking the next append).
    #[serde(skip)]
    last_hash: Option<String>,
}

/// A finalized chain segment with computed head hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosedSegment {
    /// Audit run identifier (for deduplication).
    pub run_id: String,
    /// Originating audit server identifier.
    pub server_id: String,
    /// Sequence number within this run (0-based).
    pub segment_seq: u64,
    /// Previous segment hash (for cross-segment linking).
    pub prev_hash: String,
    /// Evidence records in this segment.
    records: Vec<EvidenceRecord>,
    /// Hash of the final record in this segment (segment head).
    pub head_hash: String,
}

/// Segment archive: stores finalized segments.
#[derive(Debug, Clone, Default)]
pub struct SegmentArchive {
    segments: Vec<ClosedSegment>,
}

impl SegmentArchive {
    /// Create a new empty archive.
    pub fn new() -> Self {
        Self::default()
    }

    /// Archive a closed segment.
    ///
    /// Enforces run_id monotonicity: a new run_id must be >= the last archived run_id.
    pub fn archive(&mut self, segment: ClosedSegment) -> Result<(), EvidenceError> {
        if let Some(last) = self.segments.last()
            && segment.run_id < last.run_id
        {
            return Err(EvidenceError::RunIdNotMonotonic {
                current_run_id: last.run_id.clone(),
                new_run_id: segment.run_id.clone(),
            });
        }
        self.segments.push(segment);
        Ok(())
    }

    /// Get all archived segments.
    pub fn segments(&self) -> &[ClosedSegment] {
        &self.segments
    }

    /// Get the number of archived segments.
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// Check if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

/// Errors that can occur when working with evidence records.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceError {
    /// Canonical JSON error.
    #[error("canonical JSON error: {0}")]
    Canonical(#[from] CanonicalError),
    /// Run ID monotonicity violation.
    #[error("run_id must be monotonically increasing: got {new_run_id} after {current_run_id}")]
    RunIdNotMonotonic {
        /// The current run_id.
        current_run_id: String,
        /// The new run_id that was attempted.
        new_run_id: String,
    },
    /// Envelope field mismatch between record and segment.
    #[error(
        "envelope field {field} mismatch: record has {record_value}, segment requires {segment_value}"
    )]
    EnvelopeMismatch {
        /// The name of the mismatched field.
        field: String,
        /// The value in the record.
        record_value: String,
        /// The value required by the segment.
        segment_value: String,
    },
}

/// Compute the hash of an evidence record.
fn compute_record_hash(record: &EvidenceRecord, prev_hash: &str) -> Result<String, EvidenceError> {
    // Build envelope: record + prev_hash for linking
    let mut envelope = serde_json::to_value(record).expect("EvidenceRecord must serialize");
    if let serde_json::Value::Object(ref mut map) = envelope {
        map.insert(
            "prev_hash".to_string(),
            serde_json::Value::String(prev_hash.to_string()),
        );
    }
    Ok(canonical::digest_of(&envelope)?)
}

impl ChainSegment {
    /// Create a new chain segment starting from a previous hash.
    pub fn new(run_id: String, server_id: String, segment_seq: u64, prev_hash: String) -> Self {
        Self {
            run_id,
            server_id,
            segment_seq,
            prev_hash,
            records: Vec::new(),
            last_hash: None,
        }
    }

    /// Get the evidence records in this segment.
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }
}

impl ClosedSegment {
    /// Get the evidence records in this segment.
    pub fn records(&self) -> &[EvidenceRecord] {
        &self.records
    }
}

/// Append an evidence record to a chain segment, linking it to the previous record.
///
/// Envelope fields (`run_id`, `server_id`, `segment_seq`, `prev_hash`) are injected
/// from the segment. If a record arrives with non-empty envelope fields, they must
/// match the segment's values or an error is returned. Empty fields (the normal
/// construction path) are accepted and populated.
///
/// `prev_hash` is always library-owned: any non-empty incoming `prev_hash` is treated
/// as a mismatch and rejected, as only the segment knows the correct link.
///
/// Returns the hash of the newly appended record.
pub fn append(seg: &mut ChainSegment, mut record: EvidenceRecord) -> Result<String, EvidenceError> {
    let prev = seg.last_hash.as_ref().unwrap_or(&seg.prev_hash);

    // Helper to validate and inject envelope fields
    let validate_and_inject = |run_id: &mut String,
                               server_id: &mut String,
                               segment_seq: &mut u64,
                               prev_hash: &mut String|
     -> Result<(), EvidenceError> {
        // Check run_id
        if !run_id.is_empty() && run_id != &seg.run_id {
            return Err(EvidenceError::EnvelopeMismatch {
                field: "run_id".to_string(),
                record_value: run_id.clone(),
                segment_value: seg.run_id.clone(),
            });
        }
        // Check server_id
        if !server_id.is_empty() && server_id != &seg.server_id {
            return Err(EvidenceError::EnvelopeMismatch {
                field: "server_id".to_string(),
                record_value: server_id.clone(),
                segment_value: seg.server_id.clone(),
            });
        }
        // Check segment_seq
        if *segment_seq != 0 && *segment_seq != seg.segment_seq {
            return Err(EvidenceError::EnvelopeMismatch {
                field: "segment_seq".to_string(),
                record_value: segment_seq.to_string(),
                segment_value: seg.segment_seq.to_string(),
            });
        }
        // prev_hash is always library-owned: any non-empty value is a mismatch
        if !prev_hash.is_empty() {
            return Err(EvidenceError::EnvelopeMismatch {
                field: "prev_hash".to_string(),
                record_value: prev_hash.clone(),
                segment_value: prev.clone(),
            });
        }

        // Inject correct values
        *run_id = seg.run_id.clone();
        *server_id = seg.server_id.clone();
        *segment_seq = seg.segment_seq;
        *prev_hash = prev.clone();
        Ok(())
    };

    // Validate and inject envelope fields per record type
    match &mut record {
        EvidenceRecord::Proposal(r) => {
            validate_and_inject(
                &mut r.run_id,
                &mut r.server_id,
                &mut r.segment_seq,
                &mut r.prev_hash,
            )?;
        }
        EvidenceRecord::Approval(r) => {
            validate_and_inject(
                &mut r.run_id,
                &mut r.server_id,
                &mut r.segment_seq,
                &mut r.prev_hash,
            )?;
        }
        EvidenceRecord::ApplyIntent(r) => {
            validate_and_inject(
                &mut r.run_id,
                &mut r.server_id,
                &mut r.segment_seq,
                &mut r.prev_hash,
            )?;
        }
        EvidenceRecord::ResultReceipt(r) => {
            validate_and_inject(
                &mut r.run_id,
                &mut r.server_id,
                &mut r.segment_seq,
                &mut r.prev_hash,
            )?;
        }
    }

    let hash = compute_record_hash(&record, prev)?;
    seg.records.push(record);
    seg.last_hash = Some(hash.clone());
    Ok(hash)
}

/// Close a chain segment, finalizing its head hash.
pub fn close(seg: ChainSegment) -> Result<ClosedSegment, EvidenceError> {
    let head_hash = seg.last_hash.unwrap_or(seg.prev_hash.clone());

    Ok(ClosedSegment {
        run_id: seg.run_id,
        server_id: seg.server_id,
        segment_seq: seg.segment_seq,
        prev_hash: seg.prev_hash,
        records: seg.records,
        head_hash,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn proposal_fixture() -> ProposalRecord {
        ProposalRecord {
            request_id: "req_abc123".to_string(),
            changeset_id: "cs_xyz789".to_string(),
            device_id: "vsrx-prod".to_string(),
            principal: "agent:mechub-config-agent".to_string(),
            diff_hash: "sha256:fedcba9876543210".to_string(),
            timestamp: "2026-08-09T14:32:10.500Z".to_string(),
            run_id: String::new(), // Will be injected by append()
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            metadata: None,
        }
    }

    fn approval_fixture() -> ApprovalRecord {
        ApprovalRecord {
            request_id: "req_abc123".to_string(),
            changeset_id: "cs_xyz789".to_string(),
            device_id: "vsrx-prod".to_string(),
            principal: "agent:mechub-config-agent".to_string(),
            diff_hash: "sha256:fedcba9876543210".to_string(),
            timestamp: "2026-08-09T14:33:10.500Z".to_string(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            approver: "alice@mechub.org".to_string(),
            decision: "approved".to_string(),
            metadata: None,
        }
    }

    fn apply_intent_fixture() -> ApplyIntentRecord {
        ApplyIntentRecord {
            request_id: "req_abc123".to_string(),
            changeset_id: "cs_xyz789".to_string(),
            device_id: "vsrx-prod".to_string(),
            principal: "agent:mechub-config-agent".to_string(),
            diff_hash: "sha256:fedcba9876543210".to_string(),
            timestamp: "2026-08-09T14:34:10.500Z".to_string(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            metadata: None,
        }
    }

    fn result_receipt_fixture() -> ResultReceipt {
        ResultReceipt {
            request_id: "req_abc123".to_string(),
            changeset_id: "cs_xyz789".to_string(),
            device_id: "vsrx-prod".to_string(),
            principal: "agent:mechub-config-agent".to_string(),
            diff_hash: "sha256:fedcba9876543210".to_string(),
            timestamp: "2026-08-09T14:35:10.500Z".to_string(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            outcome: "success".to_string(),
            error: None,
            metadata: None,
        }
    }

    #[test]
    fn proposal_record_serde_roundtrip() {
        let record = proposal_fixture();
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: ProposalRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn approval_record_serde_roundtrip() {
        let record = approval_fixture();
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: ApprovalRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn apply_intent_record_serde_roundtrip() {
        let record = apply_intent_fixture();
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: ApplyIntentRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn result_receipt_serde_roundtrip() {
        let record = result_receipt_fixture();
        let json = serde_json::to_string(&record).unwrap();
        let deserialized: ResultReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(record, deserialized);
    }

    #[test]
    fn evidence_record_enum_serde_roundtrip() {
        let records = vec![
            EvidenceRecord::Proposal(proposal_fixture()),
            EvidenceRecord::Approval(approval_fixture()),
            EvidenceRecord::ApplyIntent(apply_intent_fixture()),
            EvidenceRecord::ResultReceipt(result_receipt_fixture()),
        ];

        for record in records {
            let json = serde_json::to_string(&record).unwrap();
            let deserialized: EvidenceRecord = serde_json::from_str(&json).unwrap();
            assert_eq!(record, deserialized);
        }
    }

    #[test]
    fn append_links_prev_hash() {
        let mut seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        let hash1 = append(&mut seg, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        assert!(hash1.starts_with("sha256:"));
        assert_eq!(seg.records().len(), 1);

        let hash2 = append(&mut seg, EvidenceRecord::Approval(approval_fixture())).unwrap();
        assert!(hash2.starts_with("sha256:"));
        assert_ne!(hash1, hash2);
        assert_eq!(seg.records().len(), 2);
    }

    #[test]
    fn close_computes_stable_head() {
        let mut seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        append(&mut seg, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        append(&mut seg, EvidenceRecord::Approval(approval_fixture())).unwrap();

        let closed = close(seg.clone()).unwrap();
        assert!(closed.head_hash.starts_with("sha256:"));
        assert_eq!(closed.records().len(), 2);

        // Closing the same segment again should produce the same head hash
        let closed2 = close(seg).unwrap();
        assert_eq!(closed.head_hash, closed2.head_hash);
    }

    #[test]
    fn empty_segment_close_links_to_prev_hash() {
        let seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        let closed = close(seg).unwrap();
        assert_eq!(closed.head_hash, GENESIS_PREV_HASH);
    }

    #[test]
    fn tamper_test_bit_flip_fails_verification() {
        let mut seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        append(&mut seg, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        let closed = close(seg).unwrap();

        // Serialize the closed segment
        let json_bytes = serde_json::to_vec(&closed).unwrap();

        // Flip a bit in the request_id field (find "req_abc123" and change it)
        let json_str = String::from_utf8(json_bytes).unwrap();
        let tampered_str = json_str.replace("req_abc123", "req_TAMPER");
        let tampered_bytes = tampered_str.as_bytes();

        // Deserialize the tampered segment
        let tampered: ClosedSegment = serde_json::from_slice(tampered_bytes).unwrap();

        // Recompute the head hash from the tampered records
        // Clear envelope fields before re-appending (they'll be injected by append)
        let mut recompute_seg = ChainSegment::new(
            tampered.run_id.clone(),
            tampered.server_id.clone(),
            tampered.segment_seq,
            tampered.prev_hash.clone(),
        );
        for record in tampered.records() {
            let mut cleared_record = record.clone();
            // Clear envelope fields so append() can inject them
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
            append(&mut recompute_seg, cleared_record).unwrap();
        }
        let recomputed = close(recompute_seg).unwrap();

        // The stored head_hash (from before tampering) should NOT match the
        // recomputed hash (from the tampered records)
        assert_ne!(
            tampered.head_hash, recomputed.head_hash,
            "tampered record must fail verification: stored hash should not match recomputed hash"
        );
    }

    #[test]
    fn different_records_produce_different_hashes() {
        let mut seg1 = ChainSegment::new(
            "run_1".to_string(),
            "server_1".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        let mut seg2 = ChainSegment::new(
            "run_2".to_string(),
            "server_2".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        append(&mut seg1, EvidenceRecord::Proposal(proposal_fixture())).unwrap();

        let mut different_proposal = proposal_fixture();
        different_proposal.request_id = "req_DIFFERENT".to_string();
        append(&mut seg2, EvidenceRecord::Proposal(different_proposal)).unwrap();

        let closed1 = close(seg1).unwrap();
        let closed2 = close(seg2).unwrap();

        assert_ne!(closed1.head_hash, closed2.head_hash);
    }

    #[test]
    fn segment_rollover_archives_without_deleting() {
        let mut archive = SegmentArchive::new();
        assert_eq!(archive.len(), 0);

        // Create and close first segment
        let mut seg1 = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(&mut seg1, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        let closed1 = close(seg1).unwrap();

        // Archive it
        archive.archive(closed1.clone()).unwrap();
        assert_eq!(archive.len(), 1);

        // Create and close second segment (continuing the chain)
        let mut seg2 = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            1,
            closed1.head_hash.clone(),
        );
        append(&mut seg2, EvidenceRecord::Approval(approval_fixture())).unwrap();
        let closed2 = close(seg2).unwrap();

        // Archive it
        archive.archive(closed2).unwrap();
        assert_eq!(archive.len(), 2);

        // First segment is still present
        assert_eq!(archive.segments()[0].segment_seq, 0);
        assert_eq!(archive.segments()[1].segment_seq, 1);
    }

    #[test]
    fn run_id_monotonicity_guard_prevents_backwards_time() {
        let mut archive = SegmentArchive::new();

        // Archive a segment from run_2
        let mut seg2 = ChainSegment::new(
            "run_20260809_143300".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(&mut seg2, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        let closed2 = close(seg2).unwrap();
        archive.archive(closed2).unwrap();

        // Try to archive a segment from run_1 (earlier timestamp)
        let mut seg1 = ChainSegment::new(
            "run_20260809_143200".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(&mut seg1, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        let closed1 = close(seg1).unwrap();

        let result = archive.archive(closed1);
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EvidenceError::RunIdNotMonotonic { .. })
        ));
    }

    #[test]
    fn run_id_monotonicity_allows_equal_run_ids() {
        let mut archive = SegmentArchive::new();

        // Archive first segment from a run
        let mut seg1 = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );
        append(&mut seg1, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        let closed1 = close(seg1).unwrap();
        archive.archive(closed1.clone()).unwrap();

        // Archive second segment from the same run (continuation)
        let mut seg2 = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            1,
            closed1.head_hash.clone(),
        );
        append(&mut seg2, EvidenceRecord::Approval(approval_fixture())).unwrap();
        let closed2 = close(seg2).unwrap();

        assert!(archive.archive(closed2).is_ok());
        assert_eq!(archive.len(), 2);
    }

    #[test]
    fn contract_fields_present_in_serialized_records() {
        // C1: Verify per-record JSON contains exactly the contract's required fields
        let mut seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        append(&mut seg, EvidenceRecord::Proposal(proposal_fixture())).unwrap();
        let closed = close(seg).unwrap();

        // Serialize the first record
        let record_json = serde_json::to_value(closed.records().first().unwrap()).unwrap();
        let obj = record_json.as_object().unwrap();

        // Verify all contract-required fields are present
        assert!(obj.contains_key("request_id"), "missing request_id");
        assert!(obj.contains_key("changeset_id"), "missing changeset_id");
        assert!(obj.contains_key("device_id"), "missing device_id");
        assert!(obj.contains_key("diff_hash"), "missing diff_hash");
        assert!(obj.contains_key("run_id"), "missing run_id");
        assert!(obj.contains_key("server_id"), "missing server_id");
        assert!(obj.contains_key("segment_seq"), "missing segment_seq");
        assert!(obj.contains_key("prev_hash"), "missing prev_hash");

        // Verify values match what was injected
        assert_eq!(obj["run_id"], "run_20260809_143210");
        assert_eq!(obj["server_id"], "rustsdcmcp-606");
        assert_eq!(obj["segment_seq"], 0);
        assert_eq!(obj["prev_hash"], GENESIS_PREV_HASH);
    }

    #[test]
    fn prepopulated_matching_envelope_fields_accepted() {
        let mut seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        // Pre-populate with matching values
        let mut proposal = proposal_fixture();
        proposal.run_id = "run_20260809_143210".to_string();
        proposal.server_id = "rustsdcmcp-606".to_string();
        proposal.segment_seq = 0;
        // prev_hash left empty (library-owned)

        let result = append(&mut seg, EvidenceRecord::Proposal(proposal));
        assert!(
            result.is_ok(),
            "matching envelope fields should be accepted"
        );
    }

    #[test]
    fn mismatched_run_id_rejected() {
        let mut seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        // Pre-populate with mismatched run_id
        let mut proposal = proposal_fixture();
        proposal.run_id = "run_DIFFERENT".to_string();

        let result = append(&mut seg, EvidenceRecord::Proposal(proposal));
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EvidenceError::EnvelopeMismatch {
                field,
                record_value,
                segment_value
            }) if field == "run_id" && record_value == "run_DIFFERENT" && segment_value == "run_20260809_143210"
        ));
    }

    #[test]
    fn nonempty_prev_hash_rejected() {
        let mut seg = ChainSegment::new(
            "run_20260809_143210".to_string(),
            "rustsdcmcp-606".to_string(),
            0,
            GENESIS_PREV_HASH.to_string(),
        );

        // Pre-populate with non-empty prev_hash
        let mut proposal = proposal_fixture();
        proposal.prev_hash = "sha256:bogus".to_string();

        let result = append(&mut seg, EvidenceRecord::Proposal(proposal));
        assert!(result.is_err());
        assert!(matches!(
            result,
            Err(EvidenceError::EnvelopeMismatch { field, .. }) if field == "prev_hash"
        ));
    }
}
