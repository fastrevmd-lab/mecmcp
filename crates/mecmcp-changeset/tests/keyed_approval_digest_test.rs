//! MEC-457: the approval digest is keyed (HMAC) rather than a plain hash, so it
//! cannot be forged by anyone who can merely read or edit the state file —
//! only by someone who holds the deployment's key.
//!
//! Covers:
//! 1. Approving through a coordinator configured with a key produces a v6,
//!    HMAC-keyed digest — not the unkeyed v5 one.
//! 2. Reloading that state file with the correct key succeeds.
//! 3. Reloading it with no key, or the wrong key, is rejected: a v6 digest is
//!    unverifiable without the key that produced it.
//! 4. Editing the approval's plaintext fields (e.g. re-pointing `approver`)
//!    without also holding the key is detected as tampering on reload, exactly
//!    like the existing v4/v5 tamper-evidence tests.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetState, ChangesetCoordinator, OperationLimits,
    persistence::{read_state_with_key, write_state_for_test},
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct TestAction {
    action: String,
    target: String,
}

fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn limits() -> OperationLimits {
    OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    }
}

async fn setup_keyed_coordinator(
    key: Arc<[u8]>,
) -> (tempfile::TempDir, PathBuf, ChangesetCoordinator) {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");

    let coordinator = ChangesetCoordinator::load_with_key(
        Some(&state_path),
        limits(),
        Duration::from_secs(15 * 60),
        false,
        Some(Arc::clone(&key)),
    )
    .expect("coordinator")
    .with_approval_digest_key(key);

    (dir, state_path, coordinator)
}

async fn create_and_approve(
    coordinator: &ChangesetCoordinator,
) -> mecmcp_changeset::ChangeSetOutput {
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

    coordinator
        .approve_change_set(
            created.change_set_id.clone(),
            "device-a".to_string(),
            "bob".to_string(),
            created.digest.clone(),
            mecmcp_audit::ActorType::Human,
        )
        .await
        .expect("approve")
}

/// Approving through a keyed coordinator produces a v6 digest, not v5.
#[tokio::test]
async fn approving_with_a_key_produces_a_v6_digest() {
    let (_dir, state_path, coordinator) =
        setup_keyed_coordinator(Arc::from(b"the-deployment-key".as_slice())).await;

    let approved = create_and_approve(&coordinator).await;
    assert_eq!(approved.state, ChangeSetState::Approved);

    let state = read_state_with_key(
        &state_path,
        limits().max_state_bytes,
        Some(b"the-deployment-key"),
    )
    .expect("read with the correct key");
    let record = state
        .change_sets
        .get(&approved.change_set_id)
        .expect("change set");
    let approval = record.approval.as_ref().expect("approval");
    assert_eq!(
        approval.digest_version, 6,
        "a configured key must produce a v6 (keyed) digest"
    );
}

/// A coordinator with no key configured keeps signing the unkeyed v5 digest —
/// this is an additive capability, not a breaking change for deployments that
/// have not provisioned a key yet.
#[tokio::test]
async fn approving_without_a_key_still_produces_a_v5_digest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_path = dir.path().join("state.json");
    let coordinator =
        ChangesetCoordinator::load(Some(&state_path), limits(), Duration::from_secs(900), false)
            .expect("coordinator");

    let approved = create_and_approve(&coordinator).await;

    let state = mecmcp_changeset::persistence::read_state(&state_path, limits().max_state_bytes)
        .expect("read with no key");
    let approval = state.change_sets[&approved.change_set_id]
        .approval
        .as_ref()
        .expect("approval");
    assert_eq!(approval.digest_version, 5);
}

/// The whole point: a v6-signed state file cannot be loaded without the key
/// that signed it, even though every plaintext field is exactly as written.
#[tokio::test]
async fn reloading_a_v6_file_without_the_key_is_rejected() {
    let (_dir, state_path, coordinator) =
        setup_keyed_coordinator(Arc::from(b"the-real-key".as_slice())).await;
    create_and_approve(&coordinator).await;
    drop(coordinator);

    let no_key = read_state_with_key(&state_path, limits().max_state_bytes, None);
    assert!(
        no_key.is_err(),
        "a v6 digest must not be accepted without a key at all"
    );
    assert!(
        no_key
            .unwrap_err()
            .to_string()
            .contains("no approval digest key was supplied")
    );

    let wrong_key = read_state_with_key(
        &state_path,
        limits().max_state_bytes,
        Some(b"a-guessed-key"),
    );
    assert!(
        wrong_key.is_err(),
        "a v6 digest must not verify under the wrong key"
    );
    assert!(
        wrong_key
            .unwrap_err()
            .to_string()
            .contains("approval digest mismatch")
    );

    // `ChangesetCoordinator::load` goes through the same path and must refuse
    // the same way -- an operator who forgets to configure the key at startup
    // gets a load failure, not a coordinator that silently trusts an
    // unverifiable file.
    let reload =
        ChangesetCoordinator::load(Some(&state_path), limits(), Duration::from_secs(900), false);
    assert!(reload.is_err(), "load without the key must fail closed");
}

/// Reloading with the correct key succeeds and the approval is intact.
#[tokio::test]
async fn reloading_a_v6_file_with_the_correct_key_succeeds() {
    let key: Arc<[u8]> = Arc::from(b"the-real-key".as_slice());
    let (_dir, state_path, coordinator) = setup_keyed_coordinator(Arc::clone(&key)).await;
    let approved = create_and_approve(&coordinator).await;
    drop(coordinator);

    let reloaded = ChangesetCoordinator::load_with_key(
        Some(&state_path),
        limits(),
        Duration::from_secs(900),
        false,
        Some(key),
    )
    .expect("load with the correct key must succeed");

    let status = reloaded
        .change_set_status(approved.change_set_id, "device-a".to_string())
        .await
        .expect("status");
    assert_eq!(status.state, ChangeSetState::Approved);
}

/// Tamper-evidence: editing the approver in a v6-signed record — without
/// holding the key — must be caught on reload, exactly as it is for v4/v5.
#[tokio::test]
async fn a_tampered_approver_is_rejected_even_with_the_correct_key() {
    let key: Arc<[u8]> = Arc::from(b"the-real-key".as_slice());
    let (_dir, state_path, coordinator) = setup_keyed_coordinator(Arc::clone(&key)).await;
    let approved = create_and_approve(&coordinator).await;
    drop(coordinator);

    let mut state =
        read_state_with_key(&state_path, limits().max_state_bytes, Some(&key)).expect("read");
    {
        let record = state
            .change_sets
            .get_mut(&approved.change_set_id)
            .expect("change set");
        let approval = record.approval.as_mut().expect("approval");
        approval.approver = Some("eve".to_string());
    }
    write_state_for_test(&state_path, &state, limits().max_state_bytes).expect("write tampered");

    let result = read_state_with_key(&state_path, limits().max_state_bytes, Some(&key));
    assert!(result.is_err(), "a tampered approver must be rejected");
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("approval digest mismatch")
    );
}
