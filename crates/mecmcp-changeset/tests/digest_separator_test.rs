//! Digest separator validation (interim mitigation for #283).
//!
//! `compute_approval_digest` and `compute_waiver_digest` join fields with a literal
//! `|` separator. If a principal identifier (owner or approver) contains `|`, two
//! different pairings hash identically:
//!
//! ```text
//! owner="a|b", approver="c"   ->  id|plan|a|b|c|timestamp
//! owner="a",   approver="b|c" ->  id|plan|a|b|c|timestamp
//! ```
//!
//! This is the opposite of tamper-evidence. The full fix (#283) is a versioned
//! tuple encoding; this test covers the interim mitigation that rejects `|` in
//! principals at both creation and load.

#![allow(clippy::unwrap_used)]

use mecmcp_changeset::{
    ChangeSetState, ChangesetCoordinator, ChangesetState as StateFile, OperationLimits,
    digest::{compute_approval_digest, validate_principal_for_digest},
    persistence::{read_state, write_state},
    records::{ApprovalRecord, ChangeSetRecord},
};
use serde_json::json;
use std::{collections::BTreeMap, time::Duration};
use tempfile::TempDir;

const LIMIT: u64 = 1024 * 1024;

/// Test action type.
#[derive(Debug, Clone, serde::Serialize)]
struct TestAction {
    action: String,
}

/// Documents the collision: two distinct pairings produce the same digest under
/// the current `|`-joined encoding. This test must continue to pass — it is a
/// statement about the encoding, not a bug to fix here. The full fix is #283.
#[test]
fn collision_exists_with_separator_in_principals() {
    let digest_a = compute_approval_digest("id", "plan", "a|b", "c", 1234567890);
    let digest_b = compute_approval_digest("id", "plan", "a", "b|c", 1234567890);
    assert_eq!(
        digest_a, digest_b,
        "the collision proves why the guard is needed"
    );
}

/// The validator rejects `|` in a principal identifier.
#[test]
fn validator_rejects_separator() {
    let result = validate_principal_for_digest("test_field", "foo|bar");
    assert!(result.is_err(), "value containing '|' must be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("test_field"),
        "error must name the field: {err}"
    );
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
    assert!(
        err.contains("ambiguous"),
        "error must explain the consequence: {err}"
    );
}

/// The validator accepts a clean principal.
#[test]
fn validator_accepts_clean_principal() {
    assert!(
        validate_principal_for_digest("owner", "demo-agent").is_ok(),
        "clean owner must pass"
    );
    assert!(
        validate_principal_for_digest("approver", "demo-approver").is_ok(),
        "clean approver must pass"
    );
    assert!(
        validate_principal_for_digest("owner", "mechubbench").is_ok(),
        "another clean owner must pass"
    );
    assert!(
        validate_principal_for_digest("approver", "claude-reviewer").is_ok(),
        "another clean approver must pass"
    );
}

fn test_fingerprint() -> String {
    "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string()
}

fn setup_coordinator() -> (TempDir, ChangesetCoordinator) {
    let dir = TempDir::new().unwrap();
    let state_path = dir.path().join("state.json");

    let limits = OperationLimits {
        max_operations: 1024,
        max_change_sets: 1024,
        max_actions_per_set: 64,
        max_state_bytes: 8 * 1024 * 1024,
        max_change_set_bytes: 256 * 1024,
        ..OperationLimits::default()
    };
    let approval_ttl = Duration::from_secs(3600);

    let coord = ChangesetCoordinator::load(Some(&state_path), limits, approval_ttl, false)
        .expect("coordinator");

    (dir, coord)
}

/// Creating an approval with `|` in the approver is refused.
#[tokio::test]
async fn approval_creation_rejects_separator_in_approver() {
    let (_dir, coord) = setup_coordinator();

    let actions = vec![TestAction {
        action: "test".into(),
    }];

    let plan_result = coord
        .create_change_set(
            "device1".into(),
            actions,
            "clean-owner".into(),
            test_fingerprint(),
            "policy-sig".into(),
        )
        .await;
    assert!(plan_result.is_ok(), "plan with clean owner must succeed");
    let created = plan_result.unwrap();

    let approve_result = coord
        .approve_change_set(
            created.change_set_id.clone(),
            "device1".into(),
            "bad|approver".into(),
            created.digest.clone(),
        )
        .await;
    assert!(
        approve_result.is_err(),
        "approval with separator in approver must be rejected"
    );
    let err = approve_result.unwrap_err().to_string();
    assert!(err.contains("approver"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Creating an approval with `|` in the owner (inherited from the change set) is refused.
#[tokio::test]
async fn approval_creation_rejects_separator_in_owner() {
    let (_dir, coord) = setup_coordinator();

    let actions = vec![TestAction {
        action: "test".into(),
    }];

    let plan_result = coord
        .create_change_set(
            "device1".into(),
            actions,
            "bad|owner".into(),
            test_fingerprint(),
            "policy-sig".into(),
        )
        .await;
    assert!(plan_result.is_ok(), "plan can be created");
    let created = plan_result.unwrap();

    let approve_result = coord
        .approve_change_set(
            created.change_set_id.clone(),
            "device1".into(),
            "clean-approver".into(),
            created.digest.clone(),
        )
        .await;
    assert!(
        approve_result.is_err(),
        "approval must be rejected when owner has separator"
    );
    let err = approve_result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a state file with `|` in the approver is refused.
#[test]
fn load_rejects_separator_in_approver() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000001".to_string();
    let fingerprint = test_fingerprint();
    let actions = vec![json!({"action": "test"})];
    let plan_digest = mecmcp_changeset::digest::change_set_digest(
        "clean-owner",
        "device1",
        &fingerprint,
        &actions,
    )
    .unwrap();

    // Hand-craft a state file with a bad approver.
    let mut record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: "clean-owner".into(),
        device: "device1".into(),
        expected_candidate_fingerprint: fingerprint,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        expires_at_unix: 9999999999_u64,
        actions,
        approver: Some("bad|approver".into()),
        approval: None,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
    };
    let digest = compute_approval_digest(
        &change_set_id,
        &plan_digest,
        &record.owner,
        "bad|approver",
        1234567890,
    );
    record.approval = Some(ApprovalRecord {
        approver: Some("bad|approver".into()),
        approved_at_unix: 1234567890,
        digest,
        waived: None,
    });

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id, record);
    let state = StateFile {
        operations: BTreeMap::new(),
        change_sets,
    };
    write_state(&path, &state, LIMIT).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading state with separator in approver must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("approver"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a state file with `|` in the owner is refused.
#[test]
fn load_rejects_separator_in_owner() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000002".to_string();
    let fingerprint = test_fingerprint();
    let actions = vec![json!({"action": "test"})];
    let plan_digest =
        mecmcp_changeset::digest::change_set_digest("bad|owner", "device1", &fingerprint, &actions)
            .unwrap();

    // Hand-craft a state file with a bad owner.
    let mut record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: "bad|owner".into(),
        device: "device1".into(),
        expected_candidate_fingerprint: fingerprint,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        expires_at_unix: 9999999999_u64,
        actions,
        approver: Some("clean-approver".into()),
        approval: None,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
    };
    let digest = compute_approval_digest(
        &change_set_id,
        &plan_digest,
        &record.owner,
        "clean-approver",
        1234567890,
    );
    record.approval = Some(ApprovalRecord {
        approver: Some("clean-approver".into()),
        approved_at_unix: 1234567890,
        digest,
        waived: None,
    });

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id, record);
    let state = StateFile {
        operations: BTreeMap::new(),
        change_sets,
    };
    write_state(&path, &state, LIMIT).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading state with separator in owner must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a v2 legacy waiver with `|` in the owner (with waived field) is refused.
///
/// Covers `persistence.rs:305` — the version < 3 path with a `waived` field present.
/// The fixture digest is valid for the piped owner, computed independently:
/// `printf '%s' '...|test|owner|...' | sha256sum`
#[test]
fn load_rejects_separator_in_owner_for_legacy_waiver_with_waived() {
    let fixture = include_str!("fixtures/waiver-v2-piped-owner.json");
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, fixture).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading v2 waiver with separator in owner must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// Loading a v2 legacy waiver with `|` in the owner (without waived field) is refused.
///
/// Covers `persistence.rs:316` — the `else` branch when `approval.waived` is absent.
/// The fixture digest is valid for the piped owner, computed independently:
/// `printf '%s' '...|bad|owner|...' | sha256sum`
#[test]
fn load_rejects_separator_in_owner_for_legacy_waiver_without_waived() {
    let fixture = include_str!("fixtures/waiver-v2-piped-owner-no-waived.json");
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");
    std::fs::write(&path, fixture).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_err(),
        "loading v2 waiver (no waived field) with separator in owner must be rejected"
    );
    let err = result.unwrap_err().to_string();
    assert!(err.contains("owner"), "error must name the field: {err}");
    assert!(
        err.contains("'|'"),
        "error must mention the separator: {err}"
    );
}

/// A normal approval with clean values loads successfully.
#[test]
fn load_accepts_clean_approval() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("state.json");

    let change_set_id =
        "0000000000000000000000000000000000000000000000000000000000000004".to_string();
    let fingerprint = test_fingerprint();
    let actions = vec![json!({"action": "test"})];
    let plan_digest = mecmcp_changeset::digest::change_set_digest(
        "demo-agent",
        "device1",
        &fingerprint,
        &actions,
    )
    .unwrap();

    let mut record = ChangeSetRecord {
        id: change_set_id.clone(),
        owner: "demo-agent".into(),
        device: "device1".into(),
        expected_candidate_fingerprint: fingerprint,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        expires_at_unix: 9999999999_u64,
        actions,
        approver: Some("demo-approver".into()),
        approval: None,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
    };
    let digest = compute_approval_digest(
        &change_set_id,
        &plan_digest,
        &record.owner,
        "demo-approver",
        1234567890,
    );
    record.approval = Some(ApprovalRecord {
        approver: Some("demo-approver".into()),
        approved_at_unix: 1234567890,
        digest,
        waived: None,
    });

    let mut change_sets = BTreeMap::new();
    change_sets.insert(change_set_id, record);
    let state = StateFile {
        operations: BTreeMap::new(),
        change_sets,
    };
    write_state(&path, &state, LIMIT).unwrap();

    let result = read_state(&path, LIMIT);
    assert!(
        result.is_ok(),
        "clean approval must load: {:?}",
        result.unwrap_err()
    );
}

/// Validates all 10 real approval records from the live fleet (verified 2026-08-15).
#[test]
fn real_fleet_approvals_are_clean() {
    // LXC 950: 3 records (demo-agent/demo-approver)
    assert!(validate_principal_for_digest("owner", "demo-agent").is_ok());
    assert!(validate_principal_for_digest("approver", "demo-approver").is_ok());

    // LXC 960: 7 records
    // - 4 mechubbench/demo-approver
    assert!(validate_principal_for_digest("owner", "mechubbench").is_ok());
    assert!(validate_principal_for_digest("approver", "demo-approver").is_ok());

    // - 3 claude-writer/claude-reviewer
    assert!(validate_principal_for_digest("owner", "claude-writer").is_ok());
    assert!(validate_principal_for_digest("approver", "claude-reviewer").is_ok());
}
