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
    ChangeSetState, ChangesetCoordinator, OperationLimits,
    persistence::{read_state, write_state},
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
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl).expect("coordinator");

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
        )
        .await
        .expect("approve");

    assert_eq!(approved.state, ChangeSetState::Approved);
    assert_eq!(approved.approver, Some("bob".to_string()));
    assert_eq!(approved.owner, "alice");
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
    };

    // Use a 1-second approval TTL so it expires immediately
    let approval_ttl = Duration::from_secs(1);

    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl).expect("coordinator");

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
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl).expect("coordinator");

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
        approval.approver = "alice".to_string(); // tamper
    }

    // Write the tampered state back
    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write tampered state");

    // Attempt to reload — must fail with approval digest mismatch
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("approval digest mismatch"),
        "Expected approval digest mismatch, got: {error_message}"
    );
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
    };
    let approval_ttl = Duration::from_secs(15 * 60);

    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl).expect("coordinator");

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
        )
        .await
        .expect("approve");

    // Read the state file and verify approval digest exists
    let state = read_state(&state_path, 8 * 1024 * 1024).expect("read state");
    let record = state.change_sets.get(&created.change_set_id).unwrap();

    assert!(record.approval.is_some(), "approval record must be present");
    let approval = record.approval.as_ref().unwrap();
    assert_eq!(approval.approver, "bob");
    assert!(approval.digest.starts_with("sha256:"));
    assert_eq!(approval.digest.len(), "sha256:".len() + 64);
}
