//! MEC-540 review, finding 2: offline `resolve_persisted_operation` runs
//! against a state file, not against a live server's in-memory copy. If a
//! server is currently loaded on that same path, whatever this repair writes
//! is silently reverted by the server's own next persist -- the operator is
//! told the reconciliation succeeded, and it does not stick.
//!
//! `resolve_persisted_operation` must refuse outright, and touch nothing,
//! whenever a `ChangesetCoordinator` already has the state file loaded.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangesetCoordinator, OperationLimits,
    lifecycle::LifecycleState,
    persistence::ChangesetState,
    persistence::write_state_for_test,
    records::OperationRecord,
    recovery::{RecoveryDisposition, resolve_persisted_operation},
};
use std::collections::BTreeMap;

fn make_operation_record(id: &str) -> OperationRecord {
    OperationRecord {
        id: id.to_string(),
        owner: "test_owner".to_string(),
        device: "test_device".to_string(),
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
fn resolution_is_refused_and_the_file_is_untouched_while_a_server_holds_it() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");

    let operation_id = format!("{:0>64}", "a1");
    let mut operations = BTreeMap::new();
    operations.insert(operation_id.clone(), make_operation_record(&operation_id));
    let seed_state = ChangesetState {
        operations,
        change_sets: BTreeMap::new(),
    };
    let limits = OperationLimits::default();
    write_state_for_test(&state_path, &seed_state, limits.max_state_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let before = std::fs::read(&state_path).unwrap();

    // Simulates a running server: a live coordinator loaded on this path
    // holds the owner lock for as long as it exists.
    let _server = ChangesetCoordinator::load(
        Some(&state_path),
        limits,
        std::time::Duration::from_secs(900),
        false,
    )
    .expect("server loads cleanly");

    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");
    let result = resolve_persisted_operation(
        &state_path,
        &operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        limits,
    );

    let error = result.expect_err("resolution must be refused while a server holds the file");
    assert!(
        error.message().contains("running server"),
        "the refusal must name the reason, got: {error}"
    );

    let after = std::fs::read(&state_path).unwrap();
    assert_eq!(
        before, after,
        "a refused resolution must not touch the file at all"
    );
}

#[test]
fn resolution_succeeds_once_the_server_is_gone() {
    let dir = tempfile::tempdir().unwrap();
    let state_path = dir.path().join("state.json");

    let operation_id = format!("{:0>64}", "b2");
    let mut operations = BTreeMap::new();
    operations.insert(operation_id.clone(), make_operation_record(&operation_id));
    let seed_state = ChangesetState {
        operations,
        change_sets: BTreeMap::new(),
    };
    let limits = OperationLimits::default();
    write_state_for_test(&state_path, &seed_state, limits.max_state_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let server = ChangesetCoordinator::load(
        Some(&state_path),
        limits,
        std::time::Duration::from_secs(900),
        false,
    )
    .expect("server loads cleanly");
    drop(server);

    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");
    resolve_persisted_operation(
        &state_path,
        &operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        limits,
    )
    .expect("resolution must succeed once no server holds the file");
}
