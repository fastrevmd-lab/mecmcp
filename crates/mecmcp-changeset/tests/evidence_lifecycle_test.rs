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

/// A commit whose intent record cannot be persisted must not reach the device.
///
/// This is the fail-closed half of #292's "a sink that loses records is worse
/// than no sink, because the gap is invisible". `apply_intent` is written
/// *before* the device is touched precisely so a crash mid-commit still shows
/// the attempt; if that write cannot be made durable and the commit proceeds
/// anyway, the result is the one state the chain exists to rule out — a device
/// changed with no evidence that anyone tried.
mod refused_spool {
    use super::*;
    use async_trait::async_trait;
    use mecmcp_audit::Attribution;
    use mecmcp_audit::recorder::SpoolError;
    use mecmcp_changeset::{
        CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
    };
    use serde::{Deserialize, Serialize};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio_util::sync::CancellationToken;

    const POLICY: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const ENDPOINT: &str = "https://device.example.com";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Action {
        name: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Staged;

    #[derive(Debug, thiserror::Error)]
    #[error("device error")]
    struct DeviceError;

    /// Counts commits so the test can assert none was sent.
    #[derive(Default)]
    struct CountingTransaction {
        commits: AtomicUsize,
    }

    #[async_trait]
    impl DeviceTransaction for CountingTransaction {
        type Action = Action;
        type Staged = Staged;
        type Diff = String;
        type Validation = String;
        type Error = DeviceError;

        async fn fingerprint(&self) -> Result<String, Self::Error> {
            Ok(format!("sha256:{}", "1".repeat(64)))
        }

        async fn stage(&self, _actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
            Ok(Staged)
        }

        async fn diff(&self, _staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
            Ok(String::new())
        }

        async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
            Ok(String::new())
        }

        async fn commit(
            &self,
            _staged: &Self::Staged,
            _attribution: &Attribution,
            _options: &CommitOptions,
        ) -> Result<CommitOutcome, Self::Error> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: None,
            })
        }

        async fn confirm_commit(
            &self,
            _operation_id: &str,
            _attribution: &Attribution,
        ) -> Result<CommitOutcome, Self::Error> {
            Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: None,
            })
        }

        async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
            Ok(RollbackOutcome {
                succeeded: true,
                details: None,
            })
        }
    }

    #[tokio::test]
    async fn a_commit_is_refused_when_its_intent_cannot_be_persisted() {
        let recorder = Arc::new(
            EvidenceRecorder::new(RecorderConfig {
                server_id: "mecmcp-test".to_string(),
                run_id: "run-001".to_string(),
                resume_from: None,
                records_per_segment: 64,
            })
            .with_spool(|_| Err(SpoolError::new("outbox unwritable"))),
        );
        let coordinator = ChangesetCoordinator::load(
            None,
            OperationLimits::default(),
            Duration::from_secs(900),
            false,
        )
        .unwrap()
        .with_evidence(Arc::clone(&recorder));

        let transaction = CountingTransaction::default();
        let device_fingerprint = transaction.fingerprint().await.unwrap();
        let cancellation = CancellationToken::new();
        let staged = coordinator
            .stage_operation(
                "device-a",
                "owner-a",
                &device_fingerprint,
                ENDPOINT,
                &transaction,
                &[Action {
                    name: "one".to_owned(),
                }],
                "set",
                None,
                POLICY,
                None,
                &cancellation,
            )
            .await
            .unwrap();

        coordinator
            .validate_operation(
                &staged.operation_id,
                "device-a",
                "owner-a",
                &staged.after_fingerprint,
                &transaction,
                &staged.staged,
                &cancellation,
            )
            .await
            .unwrap();

        let error = coordinator
            .commit_operation(
                &staged.operation_id,
                "device-a",
                "owner-a",
                &staged.after_fingerprint,
                POLICY,
                &transaction,
                &staged.staged,
                &Attribution::stdio(),
                &CommitOptions::default(),
                &cancellation,
            )
            .await
            .expect_err("a commit with no durable intent record must be refused");

        assert_eq!(
            transaction.commits.load(Ordering::SeqCst),
            0,
            "no commit RPC may be sent when the intent record was not persisted: {error:?}"
        );
    }
}
