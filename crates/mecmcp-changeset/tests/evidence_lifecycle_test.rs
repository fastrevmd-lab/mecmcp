//! A change moving through the coordinator must leave an evidence trail.
//!
//! The recorder and the sink both existed before this; nothing connected them
//! to a real change, so `ssdf.audit` held zero `evidence` rows and would have
//! kept holding zero however the sink was configured (mecmcp#292).

#![allow(clippy::unwrap_used)]

use mecmcp_audit::evidence::EvidenceRecord;
use mecmcp_audit::recorder::{EvidenceRecorder, RecorderConfig};
use mecmcp_changeset::{ChangesetCoordinator, OperationLimits};
use std::sync::Arc;
use std::time::Duration;

fn coordinator_with_evidence() -> (ChangesetCoordinator, Arc<EvidenceRecorder>) {
    let recorder = Arc::new(EvidenceRecorder::new(RecorderConfig {
        server_id: "mecmcp-test".to_string(),
        run_id: "run-001".to_string(),
        resume_from: None,
        records_per_segment: 64,
    }));
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap()
    .with_evidence(Arc::clone(&recorder));
    (coordinator, recorder)
}

fn fingerprint() -> String {
    format!("sha256:{}", "a".repeat(64))
}

/// Creating a change set is the proposal.
#[tokio::test]
async fn creating_a_change_set_records_a_proposal() {
    let (coordinator, recorder) = coordinator_with_evidence();

    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
        )
        .await
        .unwrap();

    let closed = recorder.close_current().expect("a proposal was recorded");
    let EvidenceRecord::Proposal(proposal) = &closed.records()[0] else {
        panic!("expected a proposal");
    };
    assert_eq!(proposal.changeset_id, output.change_set_id);
    assert_eq!(proposal.device_id, "vsrx-ci");
    assert_eq!(proposal.principal, "agent:planner");
    assert_eq!(
        proposal.diff_hash, output.digest,
        "the proposal must bind the plan it proposed"
    );
}

/// Approving records the decision and the approver — the second person, which
/// is the whole point of two-person control.
#[tokio::test]
async fn approving_records_the_approver_and_the_decision() {
    let (coordinator, recorder) = coordinator_with_evidence();
    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
        )
        .await
        .unwrap();

    coordinator
        .approve_change_set(
            output.change_set_id.clone(),
            "vsrx-ci".to_string(),
            "user:alice".to_string(),
            output.digest.clone(),
        )
        .await
        .unwrap();

    let closed = recorder.close_current().unwrap();
    let EvidenceRecord::Approval(approval) = &closed.records()[1] else {
        panic!("expected an approval");
    };
    assert_eq!(approval.approver, "user:alice");
    assert_eq!(approval.decision, "approved");
    assert_eq!(
        approval.device_id, "vsrx-ci",
        "the approval must name the device it approved, carried from the proposal"
    );
    assert_eq!(approval.diff_hash, output.digest);
}

/// A coordinator without a recorder must behave exactly as before: evidence is
/// a deployment choice, not a requirement.
#[tokio::test]
async fn a_coordinator_without_evidence_still_works() {
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .unwrap();

    let output = coordinator
        .create_change_set(
            "vsrx-ci".to_string(),
            vec![serde_json::json!({"op": "set"})],
            "agent:planner".to_string(),
            fingerprint(),
            "sig".to_string(),
        )
        .await;

    assert!(output.is_ok(), "evidence must be optional");
}
