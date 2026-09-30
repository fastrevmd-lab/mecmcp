//! Tests for Task 6 — change-set approval gate.
//!
//! Covers:
//! 1. Create change set as alice
//! 2. Approve as alice must fail
//! 3. Approve as bob must succeed
//! 4. Second approval must fail
//! 5. Expired change sets transition to Expired on status poll
//!
//! Plus Issue #50 (approval digest tamper-evidence) and #54 (lab mode)

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ApprovalRecord, ChangeSetState, ChangesetCoordinator, OperationLimits,
    persistence::{read_state, write_state_for_test},
};
use std::path::PathBuf;
use std::time::Duration;

/// Action type for test change sets.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

/// Sets up a temporary coordinator with a clean state file.
fn setup_coordinator() -> (tempfile::TempDir, ChangesetCoordinator) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    (dir, coordinator)
}

/// Generates a test fingerprint.
fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

#[tokio::test]
async fn test_create_then_approve_as_owner_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    assert_eq!(created.state, ChangeSetState::Planned);
    assert!(created.approver.is_none());

    // Attempt to approve as alice (the owner)
    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(
        err.message()
            .contains("owner cannot approve their own plan")
    );
}

#[tokio::test]
async fn test_create_then_approve_as_distinct_principal_succeeds() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    assert_eq!(created.state, ChangeSetState::Planned);

    // Approve as bob
    let approved = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);
    assert_eq!(approved.approver, Some("bob".to_string()));
    assert_eq!(approved.owner, "alice");
}

/// House rule: a human approves. An agent acting as the second principal must
/// not be able to move a change set to `Approved`, even though it is a distinct
/// principal from the owner.
#[tokio::test]
async fn test_approve_by_agent_actor_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Agent,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "approver_actor_type");
    assert!(err.message().contains("must be a human principal"));

    // Denied, so the change set is still Planned and a genuine human approval
    // can still land.
    let status = coordinator
        .change_set_status(created.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status");
    assert_eq!(status.state, ChangeSetState::Planned);
}

/// The stdio path and any unattributed caller carry `ActorType::Unknown`, not
/// `Human` — the same denial applies, so a caller context that never
/// established who is acting cannot approve either.
#[tokio::test]
async fn test_approve_by_unknown_actor_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Unknown,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "approver_actor_type");
}

/// The self-approval check must still win when both denials apply: a
/// non-human owner attempting to approve their own plan gets the
/// self-approval message, not the actor-type one, so an operator reading the
/// error is told the more specific and more actionable fact.
#[tokio::test]
async fn test_owner_approving_own_plan_as_agent_gets_self_approval_error() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "alice".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Agent,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(
        err.message()
            .contains("owner cannot approve their own plan")
    );
}

#[tokio::test]
async fn test_second_approval_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    // First approval as bob
    let approved = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);

    // Second approval as charlie must fail
    let result = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "charlie".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "change_set_id");
    assert!(err.message().contains("not awaiting approval"));
}

#[tokio::test]
async fn test_expired_change_set_transitions_on_status_poll() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };

    // Use a 1-second approval TTL so it expires immediately
    let approval_ttl = Duration::from_secs(1);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    assert_eq!(created.state, ChangeSetState::Planned);

    // Wait for expiry
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Poll status
    let status = coordinator
        .change_set_status(created.change_set_id.clone(), "device-a".to_string())
        .await
        .expect("status");

    assert_eq!(status.state, ChangeSetState::Expired);
}

// Issue #50 tests: approval digest tamper-evidence

/// Helper to stage the production fixture as a private temp file.
fn staged_production_fixture() -> (tempfile::TempDir, PathBuf) {
    let src: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "compat",
        "mutation-state-608.json",
    ]
    .iter()
    .collect();
    let dir = tempfile::tempdir().expect("tempdir");
    let dst = dir.path().join("mutation-state.json");
    std::fs::copy(&src, &dst).expect("copy fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o600))
            .expect("chmod fixture copy");
    }
    (dir, dst)
}

#[tokio::test]
async fn test_production_fixture_loads_without_approval_digest() {
    // The production fixture has no approval digest (legacy records).
    // validate_state must accept it because `approval` is Option<ApprovalRecord>.
    let (_dir, path) = staged_production_fixture();

    let state = read_state(&path, 8 * 1024 * 1024).expect("load production fixture");

    assert_eq!(state.change_sets.len(), 6);

    // All six change sets have an approver but no approval digest
    for (id, record) in &state.change_sets {
        assert!(
            record.approver.is_some(),
            "change set {id} has an approver (legacy field)"
        );
        assert!(
            record.approval.is_none(),
            "change set {id} has no approval digest (legacy record)"
        );
    }
}

#[tokio::test]
async fn test_approval_digest_tamper_detection_swap_approver() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    // Approve as bob
    let approved = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);
    assert_eq!(approved.approver, Some("bob".to_string()));

    // Read the state file
    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");

    // Tamper: swap approver to alice (masking a self-approval)
    let record = state.change_sets.get_mut(&created.change_set_id).unwrap();
    if let Some(approval) = &mut record.approval {
        approval.approver = Some("alice".to_string()); // tamper
    }

    // Write the tampered state back
    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write tampered state");

    // Attempt to reload — must be refused. The self-approval invariant now
    // rejects this shape outright, before the digest is even recomputed: a
    // record with owner == approver is illegal regardless of whether its
    // digest happens to verify.
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("same principal as owner and approver"),
        "Expected a self-approval rejection, got: {error_message}"
    );
}

/// Swapping the approver alone (as above) is caught by the stale digest, which
/// happens to still name "bob". A tampering party who also re-signs the
/// digest for the new (owner, owner) pair produces a record that is
/// internally self-consistent — the digest genuinely verifies what it claims
/// — and previously reached `apply` unchallenged. `read_state` must refuse it
/// on the self-approval invariant, not on digest mismatch, because there is
/// none.
#[tokio::test]
async fn test_self_consistent_forged_self_approval_digest_is_still_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    let approved = coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await
        .expect("approve");

    let mut state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let record = state.change_sets.get_mut(&created.change_set_id).unwrap();
    if let Some(approval) = &mut record.approval {
        // Re-sign the digest for a self-approval so it is internally
        // consistent — this is exactly what `compute_approval_digest_v5`
        // being a public function lets any caller do.
        approval.approver = Some("alice".to_string());
        approval.digest = mecmcp_changeset::digest::compute_approval_digest_v5(
            &created.change_set_id,
            &record.digest,
            record.preview.as_ref().map(|p| p.digest.as_str()),
            "alice",
            "alice",
            approval.approved_at_unix,
        );
    }
    assert_eq!(approved.approver, Some("bob".to_string()));

    write_state_for_test(&state_path, &state, 8 * 1024 * 1024).expect("write forged state");

    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(
        result.is_err(),
        "a self-consistent self-approval digest must still be rejected"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("same principal as owner and approver"),
        "Expected a self-approval rejection, got: {error_message}"
    );
}

/// `approve_change_set` refuses self-approval, but it is not the only public
/// way to move a change set to `Approved`: `update_change_set_from` writes
/// any record a caller hands it, gated only by `check_change_set_write`. A
/// caller that builds an "approved" record directly — never going through
/// `approve_change_set` at all — must be refused there too, or the owner
/// check is a property of one call path rather than of the change-set type.
#[tokio::test]
async fn test_self_approval_via_direct_update_is_denied() {
    let (_dir, coordinator) = setup_coordinator();

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    let mut record = coordinator
        .change_set(&created.change_set_id, "device-a")
        .await
        .expect("read change set");
    assert_eq!(record.state, ChangeSetState::Planned);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    record.state = ChangeSetState::Approved;
    record.approver = Some("alice".to_string());
    record.approval = Some(ApprovalRecord {
        approver: Some("alice".to_string()),
        approved_at_unix: now,
        digest: mecmcp_changeset::digest::compute_approval_digest_v5(
            &created.change_set_id,
            &record.digest,
            record.preview.as_ref().map(|p| p.digest.as_str()),
            "alice",
            "alice",
            now,
        ),
        digest_version: 5,
        waived: None,
    });

    let result = coordinator
        .update_change_set_from(ChangeSetState::Planned, record)
        .await;
    assert!(
        result.is_err(),
        "a self-approved record must not be writable by bypassing approve_change_set"
    );
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("cannot approve their own plan"),
        "Expected a self-approval rejection, got: {error_message}"
    );

    // And the change set is still exactly where it was left: Planned.
    let record = coordinator
        .change_set(&created.change_set_id, "device-a")
        .await
        .expect("read change set");
    assert_eq!(record.state, ChangeSetState::Planned);
}

#[tokio::test]
async fn test_new_approval_has_approval_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    let actions = vec![TestAction {
        action: "set".to_string(),
        target: "/test/path".to_string(),
    }];

    // Create as alice
    let created = coordinator
        .create_change_set(
            "device-a".to_string(),
            actions,
            "alice".to_string(),
            test_fingerprint(),
            "policy-sig".to_string(),
        )
        .await
        .expect("create");

    // Approve as bob
    coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await
        .expect("approve");

    // Read the state file and verify approval digest exists
    let state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let record = state.change_sets.get(&created.change_set_id).unwrap();

    assert!(record.approval.is_some(), "approval record must be present");
    let approval = record.approval.as_ref().unwrap();
    assert_eq!(approval.approver, Some("bob".to_string()));
    assert!(approval.digest.starts_with("sha256:"));
    assert_eq!(approval.digest.len(), "sha256:".len() + 64);
}
