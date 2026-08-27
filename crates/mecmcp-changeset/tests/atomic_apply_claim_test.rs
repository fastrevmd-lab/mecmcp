//! One approval must buy exactly one execution.
//!
//! Reading `Approved` and then writing `Applying` is two operations with the
//! lock released between them, so two applies could both read `Approved`, both
//! pass the check, and both run. For a destroy that is nearly harmless — the
//! second one fails against a guest that is already gone. For an operation that
//! executes an arbitrary command inside a guest it is not, and that is the
//! operation this primitive was added for.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ApplyHandle, ChangeSetRecord, ChangeSetState, ChangesetCoordinator, OperationLimits,
    change_set_digest,
};
use std::sync::Arc;
use std::time::Duration;

fn approved(id: &str) -> ChangeSetRecord {
    // A real digest, not a placeholder: the state file is digest-bound and
    // reload refuses a record whose digest does not match its own contents, so
    // a synthetic one never survives the restart these tests are about.
    let owner = "planner";
    let device = "vsrx-ci";
    let fingerprint = format!("sha256:{}", "b".repeat(64));
    let actions = vec![serde_json::json!({"op": "guest_exec"})];
    let digest = change_set_digest(owner, device, &fingerprint, &actions).unwrap();
    ChangeSetRecord {
        id: id.to_owned(),
        device: device.to_owned(),
        owner: owner.to_owned(),
        digest,
        expected_candidate_fingerprint: fingerprint,
        actions,
        state: ChangeSetState::Approved,
        expires_at_unix: u64::MAX,
        operation_id: None,
        approver: Some("approver".to_owned()),
        approval: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: None,
        apply_without_handle: false,
    }
}

async fn coordinator(dir: &std::path::Path) -> Arc<ChangesetCoordinator> {
    Arc::new(
        ChangesetCoordinator::load(
            Some(&dir.join("state.json")),
            OperationLimits::default(),
            Duration::from_secs(3600),
            true,
        )
        .unwrap(),
    )
}

/// The claim is the whole point: exactly one caller may leave `Approved`.
///
/// A multi-threaded runtime and a barrier, both load-bearing. On the default
/// current-thread runtime the spawned tasks never interleave — each runs to
/// completion before the next is polled — so every task observes the state the
/// previous one left and the test passes whether or not the claim is atomic.
/// It has to be able to fail: with the lock released between the check and the
/// write, several tasks read `Approved` together and several claims win.
///
/// Repeated, because a race that can be lost is not one that is lost on every
/// run.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn only_one_concurrent_claim_can_win() {
    const CLAIMANTS: usize = 16;
    const ROUNDS: usize = 40;

    for round in 0..ROUNDS {
        let dir = tempfile::tempdir().unwrap();
        let coord = coordinator(dir.path()).await;
        let id = "a".repeat(64);
        coord.insert_change_set(approved(&id)).await.unwrap();

        // Every claimant waits here, so they hit the claim together rather
        // than in the order they were spawned.
        let gate = Arc::new(tokio::sync::Barrier::new(CLAIMANTS));
        let mut tasks = Vec::new();
        for _ in 0..CLAIMANTS {
            let coord = Arc::clone(&coord);
            let gate = Arc::clone(&gate);
            let id = id.clone();
            tasks.push(tokio::spawn(async move {
                gate.wait().await;
                coord
                    .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
                    .await
                    .is_ok()
            }));
        }

        let mut winners = 0;
        for task in tasks {
            if task.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(
            winners, 1,
            "round {round}: exactly one apply may claim an approval; {winners} \
             claims means the same approved command would have run {winners} times"
        );
        let record = coord.change_set(&id, "vsrx-ci").await.unwrap();
        assert_eq!(record.state, ChangeSetState::Applying);
    }
}

/// A loser must be able to tell "someone beat me" from "this expired".
#[tokio::test]
async fn a_losing_claim_is_told_which_state_it_lost_to() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    coord
        .insert_change_set(approved(&"b".repeat(64)))
        .await
        .unwrap();

    coord
        .claim_change_set_for_apply(&"b".repeat(64), "vsrx-ci", ApplyHandle::Expected)
        .await
        .expect("the first claim wins");

    let error = coord
        .claim_change_set_for_apply(&"b".repeat(64), "vsrx-ci", ApplyHandle::Expected)
        .await
        .expect_err("the second claim must be refused");
    let message = error.to_string();
    assert!(
        message.contains("Applying"),
        "the refusal must name the state it lost to, got: {message}"
    );
}

/// The device check is not bypassed by the claim path.
#[tokio::test]
async fn a_claim_for_another_device_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    coord
        .insert_change_set(approved(&"c".repeat(64)))
        .await
        .unwrap();

    assert!(
        coord
            .claim_change_set_for_apply(&"c".repeat(64), "some-other-guest", ApplyHandle::Expected)
            .await
            .is_err(),
        "a change set must not be claimable through another device's name"
    );
    let record = coord.change_set(&"c".repeat(64), "vsrx-ci").await.unwrap();
    assert_eq!(
        record.state,
        ChangeSetState::Approved,
        "a refused claim must not move the record"
    );
}

/// A handleless apply that dies mid-flight stays `Applying`, not `Failed`.
///
/// `Failed` asserts an outcome nobody observed. When the operation produces no
/// vendor handle, nothing but the device knows whether it ran, so the honest
/// state is the one that says "go and look" — and it also keeps the approval
/// spent, which is what stops a second execution.
#[tokio::test]
async fn a_handleless_apply_survives_a_restart_as_applying() {
    let dir = tempfile::tempdir().unwrap();
    {
        let coord = coordinator(dir.path()).await;
        coord
            .insert_change_set(approved(&"d".repeat(64)))
            .await
            .unwrap();
        coord
            .claim_change_set_for_apply(&"d".repeat(64), "vsrx-ci", ApplyHandle::None)
            .await
            .unwrap();
        // The process dies here: no handle was ever written, because this
        // operation never produces one.
    }

    let reloaded = coordinator(dir.path()).await;
    let record = reloaded
        .change_set(&"d".repeat(64), "vsrx-ci")
        .await
        .unwrap();
    assert_eq!(
        record.state,
        ChangeSetState::Applying,
        "a handleless apply must not be settled as Failed: the command may have \
         run, and only the device knows"
    );
    assert!(record.apply_without_handle);
}

/// The existing rule still holds for applies that *should* have had a handle.
#[tokio::test]
async fn a_handle_expecting_apply_without_one_is_still_failed() {
    let dir = tempfile::tempdir().unwrap();
    {
        let coord = coordinator(dir.path()).await;
        coord
            .insert_change_set(approved(&"e".repeat(64)))
            .await
            .unwrap();
        coord
            .claim_change_set_for_apply(&"e".repeat(64), "vsrx-ci", ApplyHandle::Expected)
            .await
            .unwrap();
        // Died before the vendor accepted the operation, so nothing started.
    }

    let reloaded = coordinator(dir.path()).await;
    let record = reloaded
        .change_set(&"e".repeat(64), "vsrx-ci")
        .await
        .unwrap();
    assert_eq!(
        record.state,
        ChangeSetState::Failed,
        "an apply that was going to record a handle and did not never started"
    );
}

/// The claim must be the *only* way into `Applying`, or it is advisory.
///
/// The first version of this change added a safe path and left the unsafe one
/// open: `update_change_set` still replaced the record unconditionally, so the
/// original read-`Approved`/write-`Applying` sequence still worked and still
/// raced. Caught by the review gate.
#[tokio::test]
async fn update_change_set_cannot_perform_the_apply_transition() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "f".repeat(64);
    coord.insert_change_set(approved(&id)).await.unwrap();

    let mut sneaky = coord.change_set(&id, "vsrx-ci").await.unwrap();
    sneaky.state = ChangeSetState::Applying;
    let error = coord
        .update_change_set(sneaky)
        .await
        .expect_err("Approved -> Applying must not be writable directly");
    assert!(
        error.to_string().contains("claim_change_set_for_apply"),
        "the refusal should name the method that owns this transition, got: {error}"
    );

    let record = coord.change_set(&id, "vsrx-ci").await.unwrap();
    assert_eq!(record.state, ChangeSetState::Approved);
}

/// A handleless in-flight apply must not be re-approved.
///
/// Whether the command ran is unknown, so re-opening it hands out a second
/// execution of something that may already have happened — the exact outcome
/// preserving `Applying` across a restart exists to prevent.
#[tokio::test]
async fn a_handleless_applying_record_cannot_be_returned_to_approved() {
    let dir = tempfile::tempdir().unwrap();
    let coord = coordinator(dir.path()).await;
    let id = "9".repeat(64);
    coord.insert_change_set(approved(&id)).await.unwrap();
    coord
        .claim_change_set_for_apply(&id, "vsrx-ci", ApplyHandle::None)
        .await
        .unwrap();

    let mut reopened = coord.change_set(&id, "vsrx-ci").await.unwrap();
    reopened.state = ChangeSetState::Approved;
    let error = coord
        .update_change_set(reopened)
        .await
        .expect_err("a handleless apply must not be re-approved");
    assert!(
        error.to_string().contains("second execution"),
        "the refusal should say why, got: {error}"
    );
    assert_eq!(
        coord.change_set(&id, "vsrx-ci").await.unwrap().state,
        ChangeSetState::Applying
    );
}
