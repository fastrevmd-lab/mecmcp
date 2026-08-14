//! Operator waivers (mecmcp#275): the kind, expiry and ticket are bound into
//! the digest, so a record cannot be relabelled or its time box extended.

// `WaiverKind` and `WaiverRecord` are re-exported at the crate root (lib.rs:32);
// the digest functions are NOT — they live behind `pub mod digest`. Importing
// them from the root does not compile.
use mecmcp_changeset::digest::{
    compute_approval_digest, compute_waiver_digest, compute_waiver_digest_v3,
};
use mecmcp_changeset::{ChangesetState, WaiverKind, WaiverRecord, validate_state};

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
