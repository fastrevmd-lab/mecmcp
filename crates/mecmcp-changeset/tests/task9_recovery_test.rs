//! Task 9 recovery tests.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    lifecycle::LifecycleState,
    persistence::{ChangesetState, read_state, write_state},
    records::OperationRecord,
    recovery::{RecoveryDisposition, resolve_persisted_operation},
    types::OperationLimits,
};
use std::{collections::BTreeMap, path::PathBuf};

fn make_operation_record(id: &str, state: LifecycleState) -> OperationRecord {
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
        state,
        job_id: None,
        details: None,
        config_lock_held: true,
        policy_signature: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
    }
}

fn setup_state_file(operation_id: &str, state: LifecycleState) -> (tempfile::TempDir, PathBuf) {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    let operation = make_operation_record(operation_id, state);
    let mut operations = BTreeMap::new();
    operations.insert(operation_id.to_string(), operation);

    let changeset_state = ChangesetState {
        operations,
        change_sets: BTreeMap::new(),
    };

    let limits = OperationLimits::default();
    write_state(&state_path, &changeset_state, limits.max_state_bytes).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod state file");
    }

    (temp_dir, state_path)
}

#[test]
fn test_resolve_with_wrong_confirmation_string() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000001";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Indeterminate);

    // Try to resolve with a wrong confirmation string
    let result = resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Committed,
        "not enough",
        OperationLimits::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "confirmation");
    assert!(err.message().contains("exact"));
}

#[test]
fn test_resolve_with_mismatched_disposition() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000002";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Indeterminate);

    // Build a confirmation for COMMITTED but pass DISCARDED disposition
    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");

    let result = resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Discarded,
        &confirmation,
        OperationLimits::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "confirmation");
    assert!(err.message().contains("exact"));
}

#[test]
fn test_resolve_as_committed() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000003";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Indeterminate);

    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");

    let output = resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    )
    .unwrap();

    assert_eq!(output.operation_id, operation_id);
    assert_eq!(output.state, "committed");
    assert_eq!(output.device, "test_device");
    assert!(output.details.is_some());
    assert!(output.details.unwrap().contains("COMMITTED"));

    // Reload and verify state was persisted
    let limits = OperationLimits::default();
    let state = read_state(&state_path, limits.max_state_bytes).unwrap();
    let record = state.operations.get(operation_id).unwrap();
    assert_eq!(record.state, LifecycleState::Committed);
    assert!(!record.config_lock_held);
}

#[test]
fn test_resolve_as_discarded() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000004";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Indeterminate);

    let confirmation = format!("RESOLVED {operation_id} AS DISCARDED");

    let output = resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Discarded,
        &confirmation,
        OperationLimits::default(),
    )
    .unwrap();

    assert_eq!(output.operation_id, operation_id);
    assert_eq!(output.state, "discarded");
    assert_eq!(output.device, "test_device");
    assert!(output.details.is_some());
    assert!(output.details.unwrap().contains("DISCARDED"));

    // Reload and verify state was persisted
    let limits = OperationLimits::default();
    let state = read_state(&state_path, limits.max_state_bytes).unwrap();
    let record = state.operations.get(operation_id).unwrap();
    assert_eq!(record.state, LifecycleState::Discarded);
    assert!(!record.config_lock_held);
}

#[test]
fn test_resolve_already_resolved_operation() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000005";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Indeterminate);

    // First resolution succeeds
    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");
    resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    )
    .unwrap();

    // Second resolution fails because operation is no longer Indeterminate
    let result = resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "operation_id");
    assert!(err.message().contains("indeterminate"));
}

#[test]
fn test_resolve_with_relative_path() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000006";
    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");

    let result = resolve_persisted_operation(
        std::path::Path::new("relative/path.json"),
        operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "path");
    assert!(err.message().contains("absolute"));
}

#[test]
fn test_resolve_unknown_operation_id() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000007";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Indeterminate);

    let unknown_id = "b000000000000000000000000000000000000000000000000000000000000099";
    let confirmation = format!("RESOLVED {unknown_id} AS COMMITTED");

    let result = resolve_persisted_operation(
        &state_path,
        unknown_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "operation_id");
    assert!(err.message().contains("unknown"));
}

#[test]
fn test_resolve_invalid_operation_id_format() {
    let (_temp_dir, state_path) = setup_state_file(
        "a000000000000000000000000000000000000000000000000000000000000008",
        LifecycleState::Indeterminate,
    );

    let invalid_id = "not-a-valid-operation-id";
    let confirmation = format!("RESOLVED {invalid_id} AS COMMITTED");

    let result = resolve_persisted_operation(
        &state_path,
        invalid_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "operation_id");
    assert!(err.message().contains("64 hexadecimal"));
}

#[test]
fn test_resolve_non_indeterminate_operation() {
    let operation_id = "a000000000000000000000000000000000000000000000000000000000000009";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Staged);

    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");

    let result = resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    );

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.field(), "operation_id");
    assert!(err.message().contains("indeterminate"));
}

#[test]
fn test_resolve_uses_the_caller_supplied_state_size_limit() {
    let operation_id = "a00000000000000000000000000000000000000000000000000000000000000a";
    let (_temp_dir, state_path) = setup_state_file(operation_id, LifecycleState::Indeterminate);

    let confirmation = format!("RESOLVED {operation_id} AS COMMITTED");

    // A limit far below the real file size must be honoured rather than
    // silently replaced by the default. This is what lets an operator whose
    // deployment raised max_state_bytes repair a state file the default
    // would refuse to open.
    let tiny = OperationLimits {
        max_state_bytes: 16,
        ..OperationLimits::default()
    };

    let result = resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        tiny,
    );

    assert!(
        result.is_err(),
        "a 16-byte cap must reject a larger state file"
    );

    // And the generous limit still succeeds on the same file, so the failure
    // above is the cap talking and not some unrelated breakage.
    resolve_persisted_operation(
        &state_path,
        operation_id,
        RecoveryDisposition::Committed,
        &confirmation,
        OperationLimits::default(),
    )
    .unwrap();
}
