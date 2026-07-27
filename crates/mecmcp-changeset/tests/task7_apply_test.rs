//! Tests for Task 7: Change-set apply operation.

#![allow(clippy::unwrap_used)]

use async_trait::async_trait;
use mecmcp_audit::{ActorType, AgentIdentity, Attribution, Principal, Tier};
use mecmcp_changeset::{
    ApplyOutput, ChangeSetState, ChangesetCoordinator, CommitOptions, CommitOutcome,
    DeviceTransaction, OperationLimits, RollbackOutcome, RollbackRef,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

// ============================================================================
// Mock transaction for apply tests
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MockActionType {
    Set,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MockAction {
    action: MockActionType,
    path: String,
    value: Option<String>,
}

#[derive(Debug)]
#[allow(dead_code)]
struct MockStaged {
    actions: Vec<MockAction>,
    before_fp: String,
    after_fp: String,
}

#[derive(Debug, Clone, Serialize)]
struct MockDiff {
    changes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct MockValidation {
    succeeded: bool,
}

#[derive(Debug, Clone)]
struct MockDeviceState {
    config: Vec<(String, String)>,
    fail_on_action_index: Option<usize>,
    revert_fails: bool,
}

impl Default for MockDeviceState {
    fn default() -> Self {
        Self {
            config: vec![("/base".into(), "initial".into())],
            fail_on_action_index: None,
            revert_fails: false,
        }
    }
}

struct MockTransaction {
    state: Arc<Mutex<MockDeviceState>>,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockDeviceState::default())),
        }
    }

    fn with_state(state: Arc<Mutex<MockDeviceState>>) -> Self {
        Self { state }
    }

    fn set_fail_on_action(&self, index: usize) {
        let mut state = self.state.lock().unwrap();
        state.fail_on_action_index = Some(index);
    }

    /// Make a candidate revert report failure, so the caller has to cope with a
    /// device that may still be holding partially staged changes.
    fn set_revert_fails(&self, fails: bool) {
        let mut state = self.state.lock().unwrap();
        state.revert_fails = fails;
    }
}

#[derive(Debug, thiserror::Error)]
enum MockError {
    #[error("action {0} failed")]
    ActionFailed(usize),
    #[error("confirmed commit not supported")]
    ConfirmedCommitUnsupported,
}

#[async_trait]
impl DeviceTransaction for MockTransaction {
    type Action = MockAction;
    type Staged = MockStaged;
    type Diff = MockDiff;
    type Validation = MockValidation;
    type Error = MockError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        let state = self.state.lock().unwrap();
        let concatenated: String = state
            .config
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(";");
        let hash = sha2::Sha256::digest(concatenated.as_bytes());
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let before_fp = self.fingerprint().await?;

        // Apply actions with potential failure inside a scope
        {
            let mut state = self.state.lock().unwrap();

            for (idx, action) in actions.iter().enumerate() {
                if state.fail_on_action_index == Some(idx) {
                    // Fail before applying this action
                    return Err(MockError::ActionFailed(idx));
                }

                match action.action {
                    MockActionType::Set => {
                        if let Some(ref value) = action.value {
                            // Update or insert
                            if let Some(existing) =
                                state.config.iter_mut().find(|(k, _)| k == &action.path)
                            {
                                existing.1 = value.clone();
                            } else {
                                state.config.push((action.path.clone(), value.clone()));
                            }
                        }
                    }
                    MockActionType::Delete => {
                        state.config.retain(|(k, _)| k != &action.path);
                    }
                }
            }
        } // Mutex guard dropped here

        let after_fp = self.fingerprint().await?;

        Ok(MockStaged {
            actions: actions.to_vec(),
            before_fp,
            after_fp,
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        let changes = staged
            .actions
            .iter()
            .map(|a| format!("{:?} {}", a.action, a.path))
            .collect();
        Ok(MockDiff { changes })
    }

    async fn validate(&self, _staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        Ok(MockValidation { succeeded: true })
    }

    async fn commit(
        &self,
        _staged: &Self::Staged,
        _attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        if options.confirm_timeout.is_some() {
            return Err(MockError::ConfirmedCommitUnsupported);
        }

        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: Some("commit-123".into()),
            details: Some("commit completed".into()),
        })
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(MockError::ConfirmedCommitUnsupported)
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::CandidateRevert => {
                let mut state = self.state.lock().unwrap();
                if state.revert_fails {
                    return Ok(RollbackOutcome {
                        succeeded: false,
                        details: Some("candidate revert rejected by device".into()),
                    });
                }
                // Reset to initial state
                state.config = vec![("/base".into(), "initial".into())];
                Ok(RollbackOutcome {
                    succeeded: true,
                    details: Some("reverted candidate".into()),
                })
            }
            _ => Ok(RollbackOutcome {
                succeeded: false,
                details: Some("rollback type not supported in mock".into()),
            }),
        }
    }
}

fn test_attribution(principal: &str) -> Attribution {
    Attribution {
        principal: Principal::Token(principal.into()),
        actor_type: ActorType::Agent,
        agent: Some(AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-test".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: Some("fastrevmd@gmail.com".into()),
        change_ref: Some("CHG0012345".into()),
        request_id: Uuid::new_v4(),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[tokio::test]
async fn apply_approved_change_set_succeeds() {
    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let device = "test-device".to_string();
    let owner = "alice";
    let approver = "bob";

    // Capture initial fingerprint
    let initial_fp = transaction.fingerprint().await.unwrap();

    // Create change set
    let actions = vec![
        MockAction {
            action: MockActionType::Set,
            path: "/config/test1".into(),
            value: Some("value1".into()),
        },
        MockAction {
            action: MockActionType::Set,
            path: "/config/test2".into(),
            value: Some("value2".into()),
        },
    ];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    // Approve change set
    let approve_output = coordinator
        .approve_change_set(
            change_set_id.clone(),
            device.clone(),
            approver.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

    assert_eq!(approve_output.state, ChangeSetState::Approved);
    assert_eq!(approve_output.approver, Some(approver.to_string()));

    // Apply change set
    let apply_output: ApplyOutput<MockStaged> = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    // Verify operation ID is set
    assert!(!apply_output.operation_id.is_empty());
    assert_ne!(
        apply_output.before_fingerprint,
        apply_output.after_fingerprint
    );

    // Verify change set state is Applied
    let status = coordinator
        .change_set_status(change_set_id.clone(), device.clone())
        .await
        .unwrap();
    assert_eq!(status.state, ChangeSetState::Applied);

    // Verify operation_id is recorded on the change set
    let change_set_record = coordinator
        .change_set(&change_set_id, &device)
        .await
        .unwrap();
    assert_eq!(
        change_set_record.operation_id,
        Some(apply_output.operation_id.clone())
    );
}

#[tokio::test]
async fn apply_same_change_set_twice_fails() {
    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let device = "test-device".to_string();
    let owner = "alice";
    let approver = "bob";

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/config/test".into(),
        value: Some("value".into()),
    }];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    coordinator
        .approve_change_set(
            change_set_id.clone(),
            device.clone(),
            approver.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

    // First apply succeeds
    coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    // Second apply fails (change set is already Applied)
    let result = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires approval")
    );
}

#[tokio::test]
async fn partial_failure_auto_reverts_and_marks_failed() {
    let state = Arc::new(Mutex::new(MockDeviceState::default()));
    let transaction = MockTransaction::with_state(state.clone());
    let coordinator = ChangesetCoordinator::default();
    let device = "test-device".to_string();
    let owner = "alice";
    let approver = "bob";

    let initial_fp = transaction.fingerprint().await.unwrap();

    // Create a 3-action change set
    let actions = vec![
        MockAction {
            action: MockActionType::Set,
            path: "/config/test1".into(),
            value: Some("value1".into()),
        },
        MockAction {
            action: MockActionType::Set,
            path: "/config/test2".into(),
            value: Some("value2".into()),
        },
        MockAction {
            action: MockActionType::Set,
            path: "/config/test3".into(),
            value: Some("value3".into()),
        },
    ];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    coordinator
        .approve_change_set(
            change_set_id.clone(),
            device.clone(),
            approver.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

    // Configure the mock to fail on the second action (index 1)
    transaction.set_fail_on_action(1);

    // Apply the change set
    let result = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await;

    // Verify the apply failed
    assert!(result.is_err());
    let message = result.unwrap_err().to_string();
    assert!(message.contains("staging failed"), "got: {message}");
    assert!(
        message.contains("reverted"),
        "the error must say the candidate was reverted, got: {message}"
    );

    // Verify the change set is marked as Failed
    let status = coordinator
        .change_set_status(change_set_id.clone(), device.clone())
        .await
        .unwrap();
    assert_eq!(status.state, ChangeSetState::Failed);

    // Verify it is NOT marked as Applied
    assert_ne!(status.state, ChangeSetState::Applied);

    // The mock failed on action index 1, which means action 0 was already
    // written into the candidate. This is the part that matters: the device
    // must not be left holding those partial changes, or the next commit on
    // this device would carry them along silently.
    let config = state.lock().unwrap().config.clone();
    assert_eq!(
        config,
        vec![("/base".to_string(), "initial".to_string())],
        "the partially staged candidate must have been reverted, found: {config:?}"
    );
    assert!(
        !config.iter().any(|(path, _)| path == "/config/test1"),
        "action 0 was staged before the failure and must not survive it"
    );
}

#[tokio::test]
async fn partial_failure_whose_revert_also_fails_says_so() {
    let state = Arc::new(Mutex::new(MockDeviceState::default()));
    let transaction = MockTransaction::with_state(state.clone());
    let coordinator = ChangesetCoordinator::default();
    let device = "test-device".to_string();
    let owner = "alice";
    let approver = "bob";

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![
        MockAction {
            action: MockActionType::Set,
            path: "/config/test1".into(),
            value: Some("value1".into()),
        },
        MockAction {
            action: MockActionType::Set,
            path: "/config/test2".into(),
            value: Some("value2".into()),
        },
    ];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    coordinator
        .approve_change_set(
            create_output.change_set_id.clone(),
            device.clone(),
            approver.to_string(),
            create_output.digest.clone(),
        )
        .await
        .unwrap();

    transaction.set_fail_on_action(1);
    transaction.set_revert_fails(true);

    let result = coordinator
        .apply_change_set(
            create_output.change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            create_output.digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await;

    // When the revert cannot be completed the device may still hold a partial
    // candidate. An operator reading this error has to be told that, rather
    // than seeing a tidy "staging failed" and assuming the device is clean.
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("may still hold partial changes"),
        "a failed revert must be surfaced, got: {message}"
    );

    let status = coordinator
        .change_set_status(create_output.change_set_id, device)
        .await
        .unwrap();
    assert_eq!(status.state, ChangeSetState::Failed);
}

#[tokio::test]
async fn apply_with_mismatched_digest_fails() {
    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let device = "test-device".to_string();
    let owner = "alice";
    let approver = "bob";

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/config/test".into(),
        value: Some("value".into()),
    }];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    coordinator
        .approve_change_set(
            change_set_id.clone(),
            device.clone(),
            approver.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

    // Apply with wrong digest
    let wrong_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let result = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            wrong_digest.to_string(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("does not match"));
}

#[tokio::test]
async fn apply_with_mismatched_fingerprint_fails() {
    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let device = "test-device".to_string();
    let owner = "alice";
    let approver = "bob";

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/config/test".into(),
        value: Some("value".into()),
    }];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    coordinator
        .approve_change_set(
            change_set_id.clone(),
            device.clone(),
            approver.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

    // Mutate device state to change fingerprint
    {
        let mut state = transaction.state.lock().unwrap();
        state.config.push(("/drift".into(), "unexpected".into()));
    }

    // Apply with the original fingerprint (which is now stale)
    let result = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await;

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("fingerprint changed") || err_msg.contains("expected"));
}

#[tokio::test]
async fn apply_unapproved_change_set_fails() {
    let coordinator = ChangesetCoordinator::default();
    let transaction = MockTransaction::new();
    let device = "test-device".to_string();
    let owner = "alice";

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/config/test".into(),
        value: Some("value".into()),
    }];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    // Try to apply without approval
    let result = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await;

    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires approval")
    );
}

#[tokio::test]
async fn apply_lab_mode_waived_approval_succeeds() {
    // Create coordinator with lab mode enabled
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(900),
        true, // lab_mode = true
    )
    .unwrap();

    let transaction = MockTransaction::new();
    let device = "test-device".to_string();
    let owner = "alice";

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/config/test".into(),
        value: Some("value".into()),
    }];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    // Waive approval in lab mode
    let waive_output = coordinator
        .waive_approval(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

    assert_eq!(waive_output.state, ChangeSetState::Approved);
    assert!(waive_output.approver.is_none()); // No approver for waived approval

    // Apply the waived change set (must succeed)
    let apply_output: ApplyOutput<MockStaged> = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await
        .unwrap();

    assert!(!apply_output.operation_id.is_empty());

    // Verify the change set is Applied
    let status = coordinator
        .change_set_status(change_set_id.clone(), device.clone())
        .await
        .unwrap();
    assert_eq!(status.state, ChangeSetState::Applied);
}

#[tokio::test]
async fn apply_after_approval_expired_fails() {
    // Create coordinator with very short TTL
    let coordinator = ChangesetCoordinator::load(
        None,
        OperationLimits::default(),
        Duration::from_secs(1), // 1 second approval window
        false,
    )
    .unwrap();

    let transaction = MockTransaction::new();
    let device = "test-device".to_string();
    let owner = "alice";
    let approver = "bob";

    let initial_fp = transaction.fingerprint().await.unwrap();

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/config/test".into(),
        value: Some("value".into()),
    }];

    let create_output = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.to_string(),
            initial_fp.clone(),
            "policy-sig".to_string(),
        )
        .await
        .unwrap();

    let change_set_id = create_output.change_set_id;
    let digest = create_output.digest;

    coordinator
        .approve_change_set(
            change_set_id.clone(),
            device.clone(),
            approver.to_string(),
            digest.clone(),
        )
        .await
        .unwrap();

    // Wait to ensure expiration (1.5 seconds > 1 second TTL)
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Try to apply after expiration
    let result = coordinator
        .apply_change_set(
            change_set_id.clone(),
            device.clone(),
            owner.to_string(),
            digest.clone(),
            initial_fp.clone(),
            &transaction,
            &test_attribution(owner),
            &CancellationToken::new(),
        )
        .await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("expired"));
}
