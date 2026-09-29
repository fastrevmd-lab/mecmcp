//! MEC-540: two real OS processes racing a read-modify-write against the same
//! changeset state file must not corrupt the file or silently lose one
//! process's update.
//!
//! `resolve_persisted_operation` is documented to run "while the server is
//! stopped" — that convention was never enforced. Before `StateFileLock`,
//! two concurrent invocations each read the file, mutated their own
//! in-memory copy, and wrote back; whichever wrote last won outright,
//! silently reverting the other's resolution even though both processes
//! reported success.
//!
//! This spawns two genuine child processes (not threads: the guarantee
//! being tested is `flock`'s cross-process semantics, which two threads in
//! one address space cannot exercise) that each resolve a different
//! operation in the same state file at the same time, then asserts the
//! final file on disk reflects both resolutions.
//!
//! The child re-executes this same test binary filtered to this one test;
//! an environment variable distinguishes the "I am a worker" role from the
//! top-level orchestrating run.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    lifecycle::LifecycleState,
    persistence::{ChangesetState, read_state, write_state_for_test},
    records::OperationRecord,
    recovery::{RecoveryDisposition, resolve_persisted_operation},
    types::OperationLimits,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

/// Set on the child process to name the operation it must resolve; its
/// presence, not its value, is what selects the worker code path.
const WORKER_OPERATION_ID_ENV: &str = "MECMCP_STATE_LOCK_TEST_WORKER_OPERATION_ID";
const WORKER_STATE_PATH_ENV: &str = "MECMCP_STATE_LOCK_TEST_WORKER_STATE_PATH";

fn operation_id(byte: u8) -> String {
    format!("{byte:02x}{}", "0".repeat(62))
}

fn make_operation_record(id: &str, device: &str) -> OperationRecord {
    OperationRecord {
        id: id.to_string(),
        owner: "test_owner".to_string(),
        device: device.to_string(),
        endpoint: "https://device.example.com".to_string(),
        action: serde_json::json!({"action": "set"}),
        xpath: None,
        actions: vec![serde_json::json!({"action": "set"})],
        change_set_id: None,
        current: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        state: LifecycleState::Indeterminate,
        job_id: None,
        details: None,
        config_lock_held: true,
        policy_signature: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        attribution: None,
        rollback_deadline_unix: None,
        config_authority: None,
    }
}

#[test]
fn two_processes_resolving_different_operations_do_not_corrupt_or_lose_writes() {
    // Worker path: re-invoked as a child process, resolve one operation and
    // exit. `return`s into the ordinary libtest pass/fail machinery, so a
    // failed resolution fails the child's exit status, which the parent
    // below checks.
    if let Ok(operation_id) = std::env::var(WORKER_OPERATION_ID_ENV) {
        let state_path = PathBuf::from(
            std::env::var(WORKER_STATE_PATH_ENV).expect("worker must receive a state path"),
        );
        let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");
        resolve_persisted_operation(
            &state_path,
            &operation_id,
            RecoveryDisposition::Committed,
            &confirmation,
            OperationLimits::default(),
        )
        .expect("worker's resolve_persisted_operation should succeed");
        return;
    }

    // Orchestrator path.
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");

    let op_a = operation_id(0xa1);
    let op_b = operation_id(0xb2);

    let mut operations = BTreeMap::new();
    operations.insert(op_a.clone(), make_operation_record(&op_a, "device-a"));
    operations.insert(op_b.clone(), make_operation_record(&op_b, "device-b"));
    let seed_state = ChangesetState {
        operations,
        change_sets: BTreeMap::new(),
    };
    write_state_for_test(
        &state_path,
        &seed_state,
        OperationLimits::default().max_state_bytes,
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let exe = std::env::current_exe().expect("test binary path");
    let test_name = "two_processes_resolving_different_operations_do_not_corrupt_or_lose_writes";

    let children: Vec<_> = [&op_a, &op_b]
        .into_iter()
        .map(|operation_id| {
            Command::new(&exe)
                .arg("--exact")
                .arg(test_name)
                .env(WORKER_OPERATION_ID_ENV, operation_id)
                .env(WORKER_STATE_PATH_ENV, &state_path)
                .spawn()
                .expect("spawning worker process")
        })
        .collect();

    for mut child in children {
        let status = child.wait().expect("waiting for worker process");
        assert!(
            status.success(),
            "worker process exited with failure: {status:?}"
        );
    }

    // Both resolutions must be present. Before the state file lock, the
    // process that wrote last would silently overwrite the other's change
    // with its own stale (pre-resolution) read of the other operation —
    // this is the lost update the lock exists to prevent.
    let limits = OperationLimits::default();
    let final_state = read_state(&state_path, limits.max_state_bytes)
        .expect("final state file must still be valid JSON, not corrupted");

    for operation_id in [&op_a, &op_b] {
        let record = final_state.operations.get(operation_id).unwrap_or_else(|| {
            panic!(
                "operation {operation_id} is missing from the final state entirely \
                 (the file was overwritten, losing this record)"
            )
        });
        assert_eq!(
            record.state,
            LifecycleState::Committed,
            "operation {operation_id} was not resolved: a concurrent process's write clobbered it"
        );
    }
}
