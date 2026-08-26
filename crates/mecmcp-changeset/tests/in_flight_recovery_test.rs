//! A change set whose apply was in flight at a crash must survive the reload.
//!
//! `load_with_recovery` settles non-terminal state at startup. For a change set
//! carrying a vendor task handle that is the wrong thing to do twice over: it
//! asserts an outcome nobody observed, and it hides the record from the caller
//! that would have gone and asked.

use mecmcp_changeset::{
    ChangeSetRecord, ChangeSetState, ChangesetCoordinator, ChangesetState, OperationLimits,
    change_set_digest,
    persistence::{read_state, write_state},
};
use std::time::Duration;

const ID: &str = "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44";
const UPID: &str = "UPID:pve2:0000A1B2:00C3D4E5:66BC1234:vzdestroy:617:root@pam:";

fn applying_record(task_id: Option<&str>) -> ChangeSetRecord {
    let owner = "owner-a".to_owned();
    let device = "pve3".to_owned();
    let fingerprint = format!("sha256:{}", "f".repeat(64));
    let actions = vec![serde_json::json!({"op": "destroy", "vmid": 617})];
    // Computed, not fabricated: the state file validates this digest on load,
    // and a hand-written one would fail for the wrong reason.
    let digest = change_set_digest(&owner, &device, &fingerprint, &actions).expect("digest");

    ChangeSetRecord {
        id: ID.to_owned(),
        owner,
        device,
        expected_candidate_fingerprint: fingerprint,
        actions,
        digest,
        state: ChangeSetState::Applying,
        approver: Some("approver-b".to_owned()),
        approval: None,
        expires_at_unix: u64::MAX,
        operation_id: None,
        policy_signature: String::new(),
        targets: Vec::new(),
        preview: None,
        task_id: task_id.map(ToOwned::to_owned),
    }
}

fn write_applying(path: &std::path::Path, task_id: Option<&str>) {
    let mut state = ChangesetState::default();
    state
        .change_sets
        .insert(ID.to_owned(), applying_record(task_id));
    write_state(path, &state, OperationLimits::default().max_state_bytes).expect("write");
}

/// The case the field exists for. A handle means the vendor operation is still
/// running, or has finished and holds its own answer — either way the record
/// must stay `Applying` so the caller can re-probe it.
#[tokio::test]
async fn an_apply_with_a_task_handle_survives_the_reload() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");
    write_applying(&path, Some(UPID));

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("load");

    let records = coordinator.change_sets().await;
    let record = records.first().expect("one change set");

    assert_eq!(
        record.state,
        ChangeSetState::Applying,
        "a task-backed apply was settled at load, so nothing will ever re-probe it"
    );
    assert_eq!(
        record.task_id.as_deref(),
        Some(UPID),
        "the handle must survive alongside the state"
    );

    // The file must agree with memory, or a later load disagrees with this one.
    let on_disk = read_state(&path, OperationLimits::default().max_state_bytes).expect("read");
    assert_eq!(
        on_disk.change_sets[ID].state,
        ChangeSetState::Applying,
        "the file must match what the API reports"
    );
}

/// Without a handle there is genuinely nothing to ask, so the existing
/// behaviour stands. This pins that the fix is scoped and did not turn every
/// crashed apply into a permanent `Applying` record.
#[tokio::test]
async fn an_apply_without_a_handle_is_still_settled() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("state.json");
    write_applying(&path, None);

    let coordinator = ChangesetCoordinator::load(
        Some(&path),
        OperationLimits::default(),
        Duration::from_secs(900),
        false,
    )
    .expect("load");

    let records = coordinator.change_sets().await;
    assert_eq!(
        records.first().expect("one change set").state,
        ChangeSetState::Failed,
        "a handleless apply has nothing to re-probe and must still be settled"
    );
}
