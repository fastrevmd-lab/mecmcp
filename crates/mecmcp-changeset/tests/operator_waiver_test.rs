//! Operator waivers (mecmcp#275): the kind, expiry and ticket are bound into
//! the digest, so a record cannot be relabelled or its time box extended.

// `WaiverKind` and `WaiverRecord` are re-exported at the crate root (lib.rs:32);
// the digest functions are NOT — they live behind `pub mod digest`. Importing
// them from the root does not compile.
use mecmcp_changeset::digest::{
    change_set_digest, compute_approval_digest, compute_waiver_digest, compute_waiver_digest_v3,
};
use mecmcp_changeset::persistence::{read_state, write_state};
use mecmcp_changeset::{
    ApprovalRecord, ChangeSetRecord, ChangeSetState, ChangesetState, WaiverKind, WaiverRecord,
    validate_state,
};
use std::collections::BTreeMap;

fn waiver(kind: WaiverKind, expires: Option<u64>, ticket: Option<&str>) -> WaiverRecord {
    WaiverRecord {
        kind,
        reason: "authorised exception".to_owned(),
        expires_at_unix: expires,
        ticket: ticket.map(str::to_owned),
    }
}

const ID: &str = "cs-1";
const PLAN: &str = "sha256:plan";
const OWNER: &str = "operator";
const AT: u64 = 1_000;

/// Every bound field must change the digest. This is the whole point: without
/// it the distinction is advisory and a record can be edited after the fact.
#[test]
fn each_bound_field_changes_the_digest() {
    let base = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, None),
    );

    let other_kind = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::OperatorFile, None, None),
    );
    assert_ne!(
        base, other_kind,
        "kind is not bound: a waiver could be relabelled"
    );

    let with_expiry = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, Some(9_999), None),
    );
    assert_ne!(
        base, with_expiry,
        "expires_at is not bound: a time box could be extended"
    );

    let with_ticket = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, Some("CHG-1")),
    );
    assert_ne!(
        base, with_ticket,
        "ticket is not bound: an audit pointer could be rewritten"
    );

    let other_channel = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::OperatorTool, None, None),
    );
    assert_ne!(
        other_kind, other_channel,
        "the two operator channels must not collide"
    );
}

/// A value containing the old separator must not be able to impersonate a
/// different field arrangement. The legacy encoding joined fields with `|`;
/// this one serializes a tuple, so lengths are encoded.
#[test]
fn separator_bearing_values_cannot_shift_field_boundaries() {
    let a = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &WaiverRecord {
            kind: WaiverKind::OperatorFile,
            reason: "a|b".to_owned(),
            expires_at_unix: None,
            ticket: Some("c".to_owned()),
        },
    );
    let b = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &WaiverRecord {
            kind: WaiverKind::OperatorFile,
            reason: "a".to_owned(),
            expires_at_unix: None,
            ticket: Some("b|c".to_owned()),
        },
    );
    assert_ne!(a, b, "a `|` in a value shifted a field boundary");
}

/// A waiver digest must never equal an approval digest. The legacy waiver
/// digest achieved this with a literal marker; v3 uses a domain prefix.
#[test]
fn a_waiver_digest_is_never_an_approval_digest() {
    let waived = compute_waiver_digest_v3(
        ID,
        PLAN,
        OWNER,
        AT,
        &waiver(WaiverKind::LabMode, None, None),
    );
    let approved = compute_approval_digest(ID, PLAN, OWNER, "someone-else", AT);
    assert_ne!(waived, approved);

    let legacy = compute_waiver_digest(ID, PLAN, OWNER, AT);
    assert_ne!(waived, legacy, "v3 must not reproduce the legacy digest");
}

/// v1 and v2 files must keep loading. On the evidence of a 2026-08-14 fleet
/// survey no waiver record exists anywhere, so this path is unreachable today —
/// but that is a statement about five hosts on one afternoon, not a property of
/// the format.
#[test]
fn legacy_schema_versions_still_validate() {
    for (fixture, version) in [
        (include_str!("fixtures/waiver-v1.json"), 1_u32),
        (include_str!("fixtures/waiver-v2.json"), 2_u32),
    ] {
        let parsed: serde_json::Value = serde_json::from_str(fixture).expect("fixture parses");
        let state: ChangesetState =
            serde_json::from_value(parsed["state"].clone()).expect("fixture state decodes");
        validate_state(&state, version)
            .unwrap_or_else(|error| panic!("version {version} must still validate: {error:?}"));
    }
}

/// A waiver with non-LabMode kind, expiry, or ticket triggers v3 write and v3
/// verification. The v3 digest binds those fields; a forged legacy digest must
/// fail.
#[test]
fn v3_waiver_round_trip_and_version_dependence() {
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let state_path = temp_dir.path().join("state.json");

    let change_set_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let owner = "operator";
    let device = "firewall-1";
    let fingerprint = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    let actions = vec![serde_json::json!({"set": "foo"})];
    let approved_at = 1_723_000_000_u64;

    // Compute the change-set digest
    let plan_digest =
        change_set_digest(owner, device, fingerprint, &actions).expect("compute digest");

    // Build a waiver with all v3-triggering fields: non-LabMode kind, expiry, ticket
    let waiver_record = WaiverRecord {
        kind: WaiverKind::OperatorFile,
        reason: "documented exception".to_owned(),
        expires_at_unix: Some(1_723_999_999),
        ticket: Some("CHG-12345".to_owned()),
    };

    let waiver_digest = compute_waiver_digest_v3(
        change_set_id,
        &plan_digest,
        owner,
        approved_at,
        &waiver_record,
    );

    let change_set = ChangeSetRecord {
        id: change_set_id.to_owned(),
        owner: owner.to_owned(),
        device: device.to_owned(),
        expected_candidate_fingerprint: fingerprint.to_owned(),
        actions,
        digest: plan_digest.clone(),
        state: ChangeSetState::Approved,
        approver: None,
        approval: Some(ApprovalRecord {
            approver: None,
            approved_at_unix: approved_at,
            digest: waiver_digest.clone(),
            waived: Some(waiver_record.clone()),
        }),
        expires_at_unix: approved_at + 900,
        operation_id: None,
        policy_signature: String::new(),
        targets: vec![],
        preview: None,
    };

    let mut state = ChangesetState {
        operations: BTreeMap::new(),
        change_sets: BTreeMap::new(),
    };
    state
        .change_sets
        .insert(change_set_id.to_owned(), change_set);

    // Write the state
    write_state(&state_path, &state, 8 * 1024 * 1024).expect("write state with v3 waiver");

    // Assert the written file has version 3
    let raw_json = std::fs::read_to_string(&state_path).expect("read written state");
    let parsed: serde_json::Value = serde_json::from_str(&raw_json).expect("parse written state");
    assert_eq!(
        parsed["version"], 3,
        "a waiver with non-LabMode kind, expiry, and ticket must trigger version 3"
    );

    // Verify it reads back successfully
    let loaded_state =
        read_state(&state_path, 8 * 1024 * 1024).expect("v3 waiver record must load");
    assert_eq!(
        loaded_state.change_sets.len(),
        1,
        "change set must survive round trip"
    );

    // CRITICAL: prove version-dependence. A legacy digest must NOT satisfy a v3 record.
    let legacy_digest = compute_waiver_digest(change_set_id, &plan_digest, owner, approved_at);
    let mut tampered_state = loaded_state;
    tampered_state
        .change_sets
        .get_mut(change_set_id)
        .expect("change set present")
        .approval
        .as_mut()
        .expect("approval present")
        .digest = legacy_digest;

    let result = validate_state(&tampered_state, 3);
    assert!(
        result.is_err(),
        "a legacy digest must NOT verify a v3 record — the version determines the rule"
    );
    let error_message = result.expect_err("already checked is_err").to_string();
    assert!(
        error_message.contains("approval digest mismatch"),
        "expected digest mismatch, got: {error_message}"
    );
}
