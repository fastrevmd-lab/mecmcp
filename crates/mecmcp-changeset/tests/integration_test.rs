//! Integration tests for changeset persistence and lifecycle.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    digest::{validate_digest, validate_fingerprint},
    lifecycle::{ChangeSetState, LifecycleState},
    persistence::{read_state, validate_state, write_state},
};
use std::path::PathBuf;

#[test]
fn test_lifecycle_state_serialization() {
    // Test all lifecycle states round-trip through serde
    let states = [
        LifecycleState::Staging,
        LifecycleState::Staged,
        LifecycleState::Validating,
        LifecycleState::Validated,
        LifecycleState::Committing,
        LifecycleState::Committed,
        LifecycleState::Discarded,
        LifecycleState::Failed,
        LifecycleState::Indeterminate,
    ];

    for state in states {
        let serialized = serde_json::to_string(&state).unwrap();
        let deserialized: LifecycleState = serde_json::from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);
        assert_eq!(serialized, format!("\"{}\"", state.as_str()));
    }
}

#[test]
fn test_lifecycle_state_terminal() {
    assert!(LifecycleState::Committed.terminal());
    assert!(LifecycleState::Discarded.terminal());
    assert!(!LifecycleState::Staging.terminal());
    assert!(!LifecycleState::Staged.terminal());
    assert!(!LifecycleState::Validating.terminal());
    assert!(!LifecycleState::Validated.terminal());
    assert!(!LifecycleState::Committing.terminal());
    assert!(!LifecycleState::Failed.terminal());
    assert!(!LifecycleState::Indeterminate.terminal());
}

#[test]
fn test_changeset_state_serialization() {
    // Test all changeset states round-trip through serde
    let states = [
        ChangeSetState::Planned,
        ChangeSetState::Approved,
        ChangeSetState::Applying,
        ChangeSetState::Applied,
        ChangeSetState::Expired,
        ChangeSetState::Failed,
    ];

    for state in states {
        let serialized = serde_json::to_string(&state).unwrap();
        let deserialized: ChangeSetState = serde_json::from_str(&serialized).unwrap();
        assert_eq!(state, deserialized);
        assert_eq!(serialized, format!("\"{}\"", state.as_str()));
    }
}

#[test]
fn test_version_rejection() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Write a state file with version 2
    let invalid_version = serde_json::json!({
        "version": 2,
        "state": {
            "operations": {},
            "change_sets": {}
        }
    });
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&invalid_version).unwrap(),
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Attempt to read it
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("unsupported changeset state version 2"),
        "Expected version error, got: {error_message}"
    );
}

#[test]
fn test_bare_operations_rejected() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Write a bare operations object without version wrapper
    let bare_format = serde_json::json!({
        "operations": {},
        "change_sets": {}
    });
    std::fs::write(
        &state_path,
        serde_json::to_vec_pretty(&bare_format).unwrap(),
    )
    .unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // Attempt to read it - should fail because version field is missing
    let result = read_state(&state_path, 8 * 1024 * 1024);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("invalid changeset state JSON"),
        "Expected JSON parse error, got: {error_message}"
    );
}

#[test]
fn test_digest_validation_rejects_uppercase() {
    let uppercase_digest =
        "sha256:ABCD1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB";
    let result = validate_digest(uppercase_digest, "test_field");
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected lowercase hex error, got: {error_message}"
    );
}

#[test]
fn test_digest_validation_rejects_short() {
    let short_digest = "sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890a"; // 63 chars
    let result = validate_digest(short_digest, "test_field");
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected format error, got: {error_message}"
    );
}

#[test]
fn test_digest_validation_rejects_sha512_prefix() {
    let sha512_digest = "sha512:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
    let result = validate_digest(sha512_digest, "test_field");
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected sha256 prefix error, got: {error_message}"
    );
}

#[test]
fn test_fingerprint_validation_rejects_uppercase() {
    let uppercase_fp = "sha256:ABCD1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890AB";
    let result = validate_fingerprint(uppercase_fp);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected lowercase hex error, got: {error_message}"
    );
}

#[test]
fn test_fingerprint_validation_rejects_short() {
    let short_fp = "sha256:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890a"; // 63 chars
    let result = validate_fingerprint(short_fp);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected format error, got: {error_message}"
    );
}

#[test]
fn test_fingerprint_validation_rejects_sha512_prefix() {
    let sha512_fp = "sha512:abcd1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";
    let result = validate_fingerprint(sha512_fp);
    assert!(result.is_err());
    let error_message = result.unwrap_err().to_string();
    assert!(
        error_message.contains("sha256:<64 lowercase hex>"),
        "Expected sha256 prefix error, got: {error_message}"
    );
}

#[test]
fn test_production_fixture_round_trip() {
    // This is THE critical test: the production file from LXC 608 must round-trip
    let fixture_path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "compat",
        "mutation-state-608.json",
    ]
    .iter()
    .collect();

    // Read the production fixture
    let state = read_state(&fixture_path, 8 * 1024 * 1024)
        .expect("production fixture must parse without error");

    // Verify exactly 6 operations and 6 change sets survive
    assert_eq!(
        state.operations.len(),
        6,
        "expected 6 operations from production fixture"
    );
    assert_eq!(
        state.change_sets.len(),
        6,
        "expected 6 change sets from production fixture"
    );

    // Verify all change sets have owner != approver, non-empty digest and fingerprint
    for (id, change_set) in &state.change_sets {
        assert!(
            change_set.approver.is_some(),
            "change set {id} must have an approver"
        );
        let approver = change_set.approver.as_ref().unwrap();
        assert_ne!(
            &change_set.owner, approver,
            "change set {id} owner and approver must be distinct"
        );
        assert!(
            !change_set.digest.is_empty(),
            "change set {id} must have a non-empty digest"
        );
        assert!(
            !change_set.expected_candidate_fingerprint.is_empty(),
            "change set {id} must have a non-empty fingerprint"
        );

        // Verify the digest is valid format
        validate_digest(&change_set.digest, "digest").expect("change set digest must be valid");

        // Note: We do NOT recompute the digest here because the actions are stored as
        // serde_json::Value, but the original digest was computed from vendor-specific
        // action types (PAN-OS ChangeSetAction). The serialization might differ due to
        // field ordering. Digest recomputation will be in Task 4 when we have the
        // full coordinator with vendor-specific action types.
    }

    // Read the original file as JSON for semantic comparison
    let original_bytes = std::fs::read(&fixture_path).unwrap();
    let original_value: serde_json::Value = serde_json::from_slice(&original_bytes).unwrap();

    // Re-serialize the parsed state
    let reserialized = serde_json::to_vec_pretty(&serde_json::json!({
        "version": 1,
        "state": state
    }))
    .unwrap();
    let reserialized_value: serde_json::Value = serde_json::from_slice(&reserialized).unwrap();

    // Compare as parsed JSON values (key order doesn't matter)
    assert_eq!(
        original_value, reserialized_value,
        "round-trip must produce semantically equal JSON"
    );
}

#[test]
fn test_state_validation() {
    let fixture_path: PathBuf = [
        env!("CARGO_MANIFEST_DIR"),
        "tests",
        "compat",
        "mutation-state-608.json",
    ]
    .iter()
    .collect();

    let state = read_state(&fixture_path, 8 * 1024 * 1024).unwrap();

    // validate_state should pass for the production fixture
    validate_state(&state).expect("production fixture must pass validation");
}

#[test]
fn test_round_trip_write_read() {
    let temp_dir = tempfile::tempdir().unwrap();
    let state_path = temp_dir.path().join("state.json");

    // Create a minimal valid state
    let state = mecmcp_changeset::ChangesetState {
        operations: Default::default(),
        change_sets: Default::default(),
    };

    // Write it
    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write must succeed");

    // Read it back
    let loaded = read_state(&state_path, 8 * 1024 * 1024).expect("read must succeed");

    // Verify it matches
    assert_eq!(state.operations.len(), loaded.operations.len());
    assert_eq!(state.change_sets.len(), loaded.change_sets.len());
}
