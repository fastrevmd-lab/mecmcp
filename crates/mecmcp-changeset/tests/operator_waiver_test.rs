//! Operator waivers (mecmcp#275): the kind, expiry and ticket are bound into
//! the digest, so a record cannot be relabelled or its time box extended.

// `WaiverKind` and `WaiverRecord` are re-exported at the crate root (lib.rs:32);
// the digest functions are NOT — they live behind `pub mod digest`. Importing
// them from the root does not compile.
use async_trait::async_trait;
use mecmcp_audit::{ActorType, AgentIdentity, Attribution, Principal};
use mecmcp_changeset::digest::{
    change_set_digest, compute_approval_digest, compute_waiver_digest, compute_waiver_digest_v3,
};
use mecmcp_changeset::persistence::{read_state, write_state};
use mecmcp_changeset::{
    ApprovalRecord, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, ChangesetState,
    CommitOptions, CommitOutcome, DeviceTransaction, OperationLimits, RollbackOutcome, RollbackRef,
    WaiverKind, WaiverRecord, validate_state,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

fn waiver(kind: WaiverKind, expires: Option<u64>, ticket: Option<&str>) -> WaiverRecord {
    WaiverRecord {
        kind,
        reason: "authorised exception".to_owned(),
        expires_at_unix: expires,
        ticket: ticket.map(str::to_owned),
    }
}

const ID: &str = "cs-1";
const PLAN: &str = "sha256:plan";
const OWNER: &str = "operator";
const AT: u64 = 1_000;

/// Every bound field must change the digest. This is the whole point: without
/// it the distinction is advisory and a record can be edited after the fact.
#[test]
fn each_bound_field_changes_the_digest() {
    let base = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, None),
    );

    let other_kind = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::OperatorFile, None, None),
    );
    assert_ne!(
        base, other_kind,
        "kind is not bound: a waiver could be relabelled"
    );

    let with_expiry = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, Some(9_999), None),
    );
    assert_ne!(
        base, with_expiry,
        "expires_at is not bound: a time box could be extended"
    );

    let with_ticket = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, Some("CHG-1")),
    );
    assert_ne!(
        base, with_ticket,
        "ticket is not bound: an audit pointer could be rewritten"
    );

    let other_channel = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::OperatorTool, None, None),
    );
    assert_ne!(
        other_kind, other_channel,
        "the two operator channels must not collide"
    );
}

/// A value containing the old separator must not be able to impersonate a
/// different field arrangement. The legacy encoding joined fields with `|`;
/// this one serializes a tuple, so lengths are encoded.
#[test]
fn separator_bearing_values_cannot_shift_field_boundaries() {
    let a = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &WaiverRecord {
            kind: WaiverKind::OperatorFile,
            reason: "a|b".to_owned(),
            expires_at_unix: None,
            ticket: Some("c".to_owned()),
        },
    );
    let b = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &WaiverRecord {
            kind: WaiverKind::OperatorFile,
            reason: "a".to_owned(),
            expires_at_unix: None,
            ticket: Some("b|c".to_owned()),
        },
    );
    assert_ne!(a, b, "a `|` in a value shifted a field boundary");
}

/// A waiver digest must never equal an approval digest. The legacy waiver
/// digest achieved this with a literal marker; v3 uses a domain prefix.
#[test]
fn a_waiver_digest_is_never_an_approval_digest() {
    let waived = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, None),
    );
    let approved = compute_approval_digest(ID, PLAN, OWNER, "someone-else", AT);
    assert_ne!(waived, approved);

    let legacy = compute_waiver_digest(ID, PLAN, OWNER, AT);
    assert_ne!(waived, legacy, "v3 must not reproduce the legacy digest");
}

/// v1 and v2 files must keep loading. On the evidence of a 2026-08-14 fleet
/// survey no waiver record exists anywhere, so this path is unreachable today —
/// but that is a statement about five hosts on one afternoon, not a property of
/// the format.
#[test]
fn legacy_schema_versions_still_validate() {
    for (fixture, version) in [
        (include_str!("fixtures/waiver-v1.json"), 1_u32),
        (include_str!("fixtures/waiver-v2.json"), 2_u32),
    ] {
        let parsed: serde_json::Value = serde_json::from_str(fixture).expect("fixture parses");
        let state: ChangesetState =
            serde_json::from_value(parsed["state"].clone()).expect("fixture state decodes");
        validate_state(&state, version)
            .unwrap_or_else(|error| panic!("version {version} must still validate: {error:?}"));
    }
}

/// A waiver with non-LabMode kind, expiry, or ticket triggers v3 write and v3
/// verification. The v3 digest binds those fields; a forged legacy digest must
/// fail.
#[test]
fn v3_waiver_round_trip_and_version_dependence() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");

    let change_set_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let owner = "operator";
    let device = "firewall-1";
    let fingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let actions = vec![serde_json::json!({"set": "foo"})];
    let approved_at = 1_723_000_000_u64;

    // Compute the change-set digest
    let plan_digest =
        change_set_digest(owner, device, fingerprint, &actions).expect("compute digest");

    // Build a waiver with all v3-triggering fields: non-LabMode kind, expiry, ticket
    let waiver_record = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "documented exception".to_owned(),
        expires_at_unix: Some(1_723_999_999),
        ticket: Some("CHG-12345".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        change_set_id,
        &plan_digest,
        owner,
        approved_at,
        &waiver_record,
    );

    let change_set = ChangeSetRecord {
        id: change_set_id.to_owned(),
        owner: owner.to_owned(),
        device: device.to_owned(),
        expected_candidate_fingerprint: fingerprint.to_owned(),
        actions,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        approver: None,
        approval: Some(ApprovalRecord {
            approver: None,
            approved_at_unix: approved_at,
            digest: waiver_digest.clone(),
            waived: Some(waiver_record.clone()),
        }),
        expires_at_unix: approved_at + 900,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
    };

    let mut state = ChangesetState {
        operations: BTreeMap::new(),
        change_sets: BTreeMap::new(),
    };
    state
        .change_sets
        .insert(change_set_id.to_owned(), change_set);

    // Write the state
    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write state with v3 waiver");

    // Assert the written file has version 3
    let raw_json = std::fs::read_to_string(&state_path).expect("read written state");
    let parsed: serde_json::Value = serde_json::from_str(&raw_json).expect("parse written state");
    assert_eq!(
        parsed["version"], 3,
        "a waiver with non-LabMode kind, expiry, and ticket must trigger version 3"
    );

    // Verify it reads back successfully
    let loaded_state =
        read_state(&state_path, 8 * 1024 * 1024).expect("v3 waiver record must load");
    assert_eq!(
        loaded_state.change_sets.len(),
        1,
        "change set must survive round trip"
    );

    // CRITICAL: prove version-dependence. A legacy digest must NOT satisfy a v3 record.
    let legacy_digest = compute_waiver_digest(change_set_id, &plan_digest, owner, approved_at);
    let mut tampered_state = loaded_state;
    tampered_state
        .change_sets
        .get_mut(change_set_id)
        .expect("change set present")
        .approval
        .as_mut()
        .expect("approval present")
        .digest = legacy_digest;

    let result = validate_state(&tampered_state, 3);
    assert!(
        result.is_err(),
        "a legacy digest must NOT verify a v3 record — the version determines the rule"
    );
    let error_message = result.expect_err("already checked is_err").to_string();
    assert!(
        error_message.contains("approval digest mismatch"),
        "expected digest mismatch, got: {error_message}"
    );
}

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
struct MockStaged {
    actions: Vec<MockAction>,
    #[allow(dead_code)]
    before_fp: String,
    #[allow(dead_code)]
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
    config: std::collections::HashMap<String, String>,
}

impl Default for MockDeviceState {
    fn default() -> Self {
        let mut config = std::collections::HashMap::new();
        config.insert("/initial".to_string(), "value".to_string());
        Self { config }
    }
}

#[derive(Clone)]
struct MockTransaction {
    state: Arc<Mutex<MockDeviceState>>,
}

impl MockTransaction {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(MockDeviceState::default())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum MockError {
    #[error("mock error: {0}")]
    Generic(String),
}

#[async_trait]
impl DeviceTransaction for MockTransaction {
    type Action = MockAction;
    type Staged = MockStaged;
    type Diff = MockDiff;
    type Validation = MockValidation;
    type Error = MockError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        let state = self.state.lock().expect("lock");
        let mut keys: Vec<_> = state.config.keys().cloned().collect();
        keys.sort();
        let concatenated = keys.join(":");
        let hash = sha2::Sha256::digest(concatenated.as_bytes());
        Ok(format!("sha256:{}", hex::encode(hash)))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        let before_fp = self.fingerprint().await?;

        {
            let mut state = self.state.lock().expect("lock");
            for action in actions {
                match action.action {
                    MockActionType::Set => {
                        if let Some(ref value) = action.value {
                            state.config.insert(action.path.clone(), value.clone());
                        }
                    }
                    MockActionType::Delete => {
                        state.config.remove(&action.path);
                    }
                }
            }
        }

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
        _options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        Ok(CommitOutcome::Reconciled {
            succeeded: true,
            job_id: Some("mock-commit".to_string()),
            details: None,
        })
    }

    async fn rollback(&self, _to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        Ok(RollbackOutcome {
            succeeded: true,
            details: None,
        })
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        _attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        Err(MockError::Generic(
            "confirmed commit not supported in mock".to_string(),
        ))
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
            provider_tier: mecmcp_audit::Tier::Public,
            skills_used: vec![],
        }),
        on_behalf_of: Some("fastrevmd@gmail.com".into()),
        change_ref: Some("CHG0012345".into()),
        request_id: Uuid::new_v4(),
        token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
    }
}

/// Test harness providing a change set in Planned state with all necessary context.
struct PlannedChangeSetHarness {
    #[allow(dead_code)]
    coordinator: ChangesetCoordinator,
    change_set_id: String,
    device: String,
    owner: String,
    digest: String,
    transaction: MockTransaction,
    _temp_dir: tempfile::TempDir,
}

async fn planned_change_set_harness() -> PlannedChangeSetHarness {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("coordinator");

    let device = "test-device".to_string();
    let owner = "alice".to_string();

    // Use transaction to get the actual fingerprint
    let transaction = MockTransaction::new();
    let fingerprint = transaction.fingerprint().await.expect("fingerprint");

    let actions = vec![MockAction {
        action: MockActionType::Set,
        path: "/test/path".to_string(),
        value: Some("test-value".to_string()),
    }];

    let created = coordinator
        .create_change_set(
            device.clone(),
            actions,
            owner.clone(),
            fingerprint.clone(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    PlannedChangeSetHarness {
        coordinator,
        change_set_id: created.change_set_id,
        device,
        owner,
        digest: created.digest,
        transaction,
        _temp_dir: temp_dir,
    }
}

/// A waiver whose expiry has passed must not authorize an apply.
///
/// Sabotage-verify this one: remove the expiry check in `apply.rs` and confirm
/// this test fails. A time box that does not block anything is decoration.
#[tokio::test]
async fn an_expired_waiver_does_not_authorize_apply() {
    let harness = planned_change_set_harness().await;

    // Manually create an expired waiver and transition to Approved
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let expired_at = now - 3600; // 1 hour ago

    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test expired waiver".to_owned(),
        expires_at_unix: Some(expired_at),
        ticket: Some("TEST-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Directly manipulate the state to set the expired waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");

    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");

    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        waived: Some(waiver),
    });

    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator to pick up the modified state
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("reload coordinator");

    // Attempt apply with the expired waiver
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");
    let error = coordinator
        .apply_change_set(
            harness.change_set_id.clone(),
            harness.device.clone(),
            "https://test-device.example.com".to_string(),
            harness.owner.clone(),
            harness.digest.clone(),
            fingerprint,
            &harness.transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &CancellationToken::new(),
        )
        .await
        .expect_err("an expired waiver must not authorize apply");

    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired"),
        "the refusal must name expiry, not report a generic missing approval — \
         an operator sent looking for the wrong problem loses the time the \
         message was supposed to save: {message}"
    );
}

/// The pre-guard waiver expiry check must fail fast without waiting for the
/// device guard. Isolate it by pre-holding the guard: a dead check would block.
#[tokio::test]
async fn pre_guard_waiver_expiry_check_fails_without_blocking() {
    let harness = planned_change_set_harness().await;

    // Create an expired waiver
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let expired_at = now - 3600; // 1 hour ago

    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test pre-guard expired waiver".to_owned(),
        expires_at_unix: Some(expired_at),
        ticket: Some("PRE-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Set up the expired waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");
    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        waived: Some(waiver),
    });
    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("reload coordinator");

    // Pre-hold the device guard
    let cancellation = CancellationToken::new();
    let _guard = coordinator
        .device_guard(&harness.device, &cancellation)
        .await
        .expect("acquire device guard");

    // Attempt apply with a 2-second timeout. If the pre-guard check is working,
    // it returns the expiry error immediately without waiting for the guard.
    // If the check is dead, apply blocks waiting for the held guard and times out.
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");
    let apply_result = tokio::time::timeout(
        Duration::from_secs(2),
        coordinator.apply_change_set(
            harness.change_set_id.clone(),
            harness.device.clone(),
            "https://test-device.example.com".to_string(),
            harness.owner.clone(),
            harness.digest.clone(),
            fingerprint,
            &harness.transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &cancellation,
        ),
    )
    .await
    .expect("pre-guard check must return immediately, not block on the held guard");

    let error = apply_result.expect_err("expired waiver must not authorize apply");
    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired"),
        "pre-guard check must detect the expired waiver: {message}"
    );
}

/// The post-guard waiver expiry check must detect a TOCTOU attack: a waiver
/// rewritten to an expired value while apply is blocked on the device guard.
#[tokio::test]
async fn post_guard_waiver_expiry_check_detects_toctou_rewrite() {
    let harness = planned_change_set_harness().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let future_expiry = now + 3600; // 1 hour from now

    // Start with a valid future expiry so the pre-guard check passes
    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test post-guard TOCTOU".to_owned(),
        expires_at_unix: Some(future_expiry),
        ticket: Some("POST-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Set up the change set with a future-expiring waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");
    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        waived: Some(waiver.clone()),
    });
    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator and wrap in Arc for sharing between tasks
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = Arc::new(
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
            .expect("reload coordinator"),
    );

    // Pre-hold the device guard so apply will block
    let cancellation = CancellationToken::new();
    let guard = coordinator
        .device_guard(&harness.device, &cancellation)
        .await
        .expect("acquire device guard");

    // Spawn apply_change_set in the background; it will block on the held guard
    let coordinator_clone = Arc::clone(&coordinator);
    let change_set_id_clone = harness.change_set_id.clone();
    let device_clone = harness.device.clone();
    let owner_clone = harness.owner.clone();
    let digest_clone = harness.digest.clone();
    let transaction_clone = harness.transaction.clone();
    let cancellation_clone = cancellation.clone();
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");

    let apply_handle = tokio::spawn(async move {
        coordinator_clone
            .apply_change_set(
                change_set_id_clone,
                device_clone,
                "https://test-device.example.com".to_string(),
                owner_clone,
                digest_clone,
                fingerprint,
                &transaction_clone,
                "set",
                None,
                None,
                &test_attribution("alice"),
                &cancellation_clone,
            )
            .await
    });

    // Give the scheduler chances to run the background apply task so it passes
    // the pre-guard check and blocks on the held guard. Unlike sleep, yield_now
    // is not wall-clock based and won't flake on loaded CI machines.
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }

    // While apply is blocked, rewrite the waiver to have a PAST expiry
    let past_expiry = now - 3600; // 1 hour ago
    let expired_waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test post-guard TOCTOU".to_owned(),
        expires_at_unix: Some(past_expiry),
        ticket: Some("POST-123".to_owned()),
    };

    // Recompute the digest with the expired waiver
    let expired_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &expired_waiver,
    );

    // Update the coordinator's in-memory state with the expired waiver
    let mut updated_change_set = coordinator
        .change_set(&harness.change_set_id, &harness.device)
        .await
        .expect("retrieve change set");
    updated_change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: expired_digest,
        waived: Some(expired_waiver),
    });
    coordinator
        .update_change_set(updated_change_set)
        .await
        .expect("update change set with expired waiver");

    // Release the guard so apply can proceed
    drop(guard);

    // Wait for apply to complete; it should fail with the post-guard expiry error
    let result = apply_handle
        .await
        .expect("apply task must complete without panic");

    let error = result.expect_err("post-guard check must detect the expired waiver");
    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired"),
        "post-guard check must detect the TOCTOU rewrite: {message}"
    );
}

/// Waiver expiry boundary: a waiver whose `expires_at_unix` equals the current
/// time is treated as expired (consistent with change-set expiry everywhere else).
#[tokio::test]
async fn waiver_at_exact_expiry_instant_is_expired() {
    let harness = planned_change_set_harness().await;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();

    // Waiver expires at exactly now (not in the past, not in the future)
    let waiver = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "test boundary: expires at exactly now".to_owned(),
        expires_at_unix: Some(now),
        ticket: Some("BOUNDARY-123".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        &harness.change_set_id,
        &harness.digest,
        &harness.owner,
        now,
        &waiver,
    );

    // Set up the change set with the waiver
    let state_path = harness._temp_dir.path().join("state.json");
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let change_set = state
        .change_sets
        .get_mut(&harness.change_set_id)
        .expect("change set exists");
    change_set.state = ChangeSetState::Approved;
    change_set.approval = Some(ApprovalRecord {
        approver: None,
        approved_at_unix: now,
        digest: waiver_digest,
        waived: Some(waiver),
    });
    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write state");

    // Reload coordinator
    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);
    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, true)
        .expect("reload coordinator");

    let cancellation = CancellationToken::new();
    let fingerprint = harness
        .transaction
        .fingerprint()
        .await
        .expect("fingerprint");

    // Apply must fail because the waiver's expiry is at exactly now, which is
    // treated as expired (consistent with `now >= expires_at` everywhere else).
    let error = coordinator
        .apply_change_set(
            harness.change_set_id,
            harness.device,
            "https://test-device.example.com".to_string(),
            harness.owner,
            harness.digest,
            fingerprint,
            &harness.transaction,
            "set",
            None,
            None,
            &test_attribution("alice"),
            &cancellation,
        )
        .await
        .expect_err("waiver with expires_at_unix == now must be treated as expired");

    let message = format!("{error:?}");
    assert!(
        message.contains("waiver expired"),
        "boundary check: expires_at_unix == now must be expired, got: {message}"
    );
}
