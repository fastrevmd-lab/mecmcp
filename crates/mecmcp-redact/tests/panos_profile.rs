//! The PAN-OS profile — representative PAN-OS XML API responses proving two
//! things at once, the way MEC-711's Mist fixtures (`json.rs`'s `mec_711_*`
//! tests) do for Mist:
//!
//! 1. Real PAN-OS secret shapes (an admin password hash, a keygen API key, an
//!    IKE pre-shared key, an SNMP community string) are redacted.
//! 2. Legitimate PAN-OS operational/config fields that merely contain the
//!    words "session" or "community" — `show session info` diagnostics, a BGP
//!    route community — are not.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{
    Profile, redact_json_str, redact_json_value_with_profile, redact_xml_str,
    redact_xml_str_with_profile,
};

/// A representative PAN-OS profile. [`Profile::key_exemptions`] carries the
/// operational/routing-policy field names, and
/// [`Profile::with_bgp_route_communities`] opts into the BGP route-community
/// exemption — both scoped to PAN-OS tool-output callers only, rather than
/// loosening the denylist for every vendor server that links this crate.
const PANOS_PROFILE: Profile = Profile::new(
    &[],
    &[
        "sessions",
        "sessionsactive",
        "maxsessions",
        "sessiontimeout",
        "idletimeouttcpsession",
        "communitylist",
        "matchcommunity",
        "addcommunity",
        "removecommunity",
    ],
)
.with_bgp_route_communities();

#[test]
fn panos_profile_key_exemptions_do_not_collide_with_the_denylist() {
    assert_eq!(PANOS_PROFILE.check_exemptions(), Ok(()));
}

#[test]
fn panos_admin_phash_is_redacted_but_permissions_survive() {
    let xml = r#"<response status="success"><result><system><entry name="admin"><phash>$1$fakesaltQQ$fakehashvaluepanos1</phash><permissions>superuser</permissions></entry></system></result></response>"#;
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("fakehashvaluepanos1"), "got: {got}");
    assert!(got.contains("superuser"), "got: {got}");
}

#[test]
fn panos_keygen_response_key_is_redacted() {
    let xml = r#"<response status="success"><result><key>LUFRPT1QQpanoskeygenfakeAPIkeyvalue-AQ==</key></result></response>"#; // gitleaks:allow -- fabricated PAN-OS keygen response shape, not a real key
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("QQpanoskeygenfakeAPIkeyvalue"), "got: {got}");
}

#[test]
fn panos_ike_pre_shared_key_is_redacted() {
    let xml = r#"<entry name="gw1"><authentication><pre-shared-key><key>QQpanosPSKfakevalue</key></pre-shared-key></authentication></entry>"#;
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("QQpanosPSKfakevalue"), "got: {got}");
}

#[test]
fn panos_snmp_community_string_is_redacted() {
    let xml = r#"<snmp-setting><access-setting><version><v2c><community>QQpanosSnmpCommunityFake</community></v2c></version></access-setting></snmp-setting>"#;
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("QQpanosSnmpCommunityFake"), "got: {got}");
}

/// `show session info`-shaped operational output, structured as JSON (the
/// shape a rustpanosmcp typed-read tool would return).
///
/// The exemption that lets these fields survive is not a global denylist
/// carve-out — it only applies through the PAN-OS [`Profile`], so this goes
/// through [`redact_json_value_with_profile`] rather than the generic
/// [`redact_json_str`]. The generic scan (exercised by
/// `denylist::tests::mec_537_session_and_community_match_as_substrings`)
/// still redacts these same field names for every caller that has not
/// declared this exemption.
#[test]
fn panos_show_session_info_fields_survive() {
    let mut v = serde_json::json!({
        "sessions": {
            "num-active": 523,
            "num-max": 262144,
            "num-tcp": 45,
            "tcp-timeout": 3600,
            "idle-timeout-tcp-session": 3600,
        }
    });
    mecmcp_redact::redact_json_value_with_profile(&mut v, &PANOS_PROFILE);
    assert_eq!(v["sessions"]["num-active"], 523);
    assert_eq!(v["sessions"]["num-max"], 262144);
    assert_eq!(v["sessions"]["tcp-timeout"], 3600);
    assert_eq!(v["sessions"]["idle-timeout-tcp-session"], 3600);
}

/// Without the PAN-OS profile, the same field names are not exempted — the
/// generic scan is the default for every other vendor.
#[test]
fn panos_show_session_info_fields_are_redacted_without_the_profile() {
    let v = serde_json::json!({"sessions": {"num-active": 523}});
    let got = redact_json_str(&v.to_string()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&got).unwrap();
    assert_eq!(parsed["sessions"]["num-active"], "[REDACTED]");
}

/// A BGP export policy's route community (`65000:100`, a routing tag, not a
/// secret) survives redaction once a caller opts into the PAN-OS profile's
/// BGP route-community exemption. Without the profile
/// (`bgp_community_without_the_profile_is_still_redacted_in_json`/`_xml`
/// below), the same shape is redacted.
#[test]
fn panos_bgp_route_community_survives_in_json() {
    let mut v = serde_json::json!({
        "bgp": {
            "policy": {
                "export": {
                    "rules": {
                        "entry": {
                            "action": {
                                "add": {
                                    "community": {
                                        "member": ["65000:100"]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
    redact_json_value_with_profile(&mut v, &PANOS_PROFILE);
    let got = v.to_string();
    assert!(got.contains("65000:100"), "got: {got}");
}

#[test]
fn panos_bgp_route_community_survives_in_xml() {
    let xml = r#"<bgp><policy><export><rules><entry name="r1"><action><add><community><member>65000:100</member></community></add></action></entry></rules></export></policy></bgp>"#;
    let got = redact_xml_str_with_profile(xml, &PANOS_PROFILE).unwrap();
    assert!(got.contains("65000:100"), "got: {got}");
}

/// Without a profile opting into the BGP route-community exemption, the same
/// shapes that survive above are redacted like any other `community` field —
/// proving the exemption is opt-in, not a change to the generic scan every
/// vendor server gets by linking this crate.
#[test]
fn bgp_community_without_the_profile_is_still_redacted_in_json() {
    let v = serde_json::json!({"bgp": {"community": {"member": ["65000:100"]}}});
    let got = redact_json_str(&v.to_string()).unwrap();
    assert!(!got.contains("65000:100"), "got: {got}");
}

#[test]
fn bgp_community_without_the_profile_is_still_redacted_in_xml() {
    let xml = r#"<bgp><community><member>65000:100</member></community></bgp>"#;
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("65000:100"), "got: {got}");
}

/// The BGP community exemption checks object keys as well as values before
/// treating a value as BGP-shaped.
#[test]
fn mec_1342_f2_bgp_community_object_with_non_member_key_is_still_redacted() {
    let mut v = serde_json::json!({
        "bgp": {
            "community": {
                "QQkeyleak3": "1:2"
            }
        }
    });
    redact_json_value_with_profile(&mut v, &PANOS_PROFILE);
    let got = v.to_string();
    assert!(
        !got.contains("\"1:2\""),
        "value must be redacted, got: {got}"
    );
}

/// Sanity check that the BGP exception is scoped to a `bgp` ancestor: the
/// same shape outside any BGP context (an SNMP community nested one level,
/// Junos-style) must still be redacted.
#[test]
fn panos_snmp_community_without_bgp_ancestor_is_still_redacted_when_nested() {
    let xml = r#"<snmp><community><name>QQpanosSnmpNestedFake</name></community></snmp>"#;
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("QQpanosSnmpNestedFake"), "got: {got}");
}

/// A `session` field that directly holds a token/cookie value, rather than
/// acting as a diagnostic container, must still be redacted.
///
/// The fixture value is deliberately neutral (no other denylisted substring
/// in it, no crypt-hash/PAN-`-AQ==`/`ENC`/PEM shape) so this proves the
/// `session` *key* itself still drives the redaction, not some unrelated
/// value-shape rule coincidentally catching it too.
#[test]
fn panos_session_token_leaf_is_still_redacted() {
    let v = serde_json::json!({"session": "QQpanosSessionLeafValue001"});
    let got = redact_json_str(&v.to_string()).unwrap();
    assert!(!got.contains("QQpanosSessionLeafValue001"), "got: {got}");
}

/// Compound SNMP-community field spellings — not just the bare `community`
/// string — must still be redacted. Mist's `snmp_config` schema
/// (`v2c_config[].community_name`) is this shape.
#[test]
fn mec_537_f1_compound_community_field_spellings_are_redacted() {
    for (field, secret) in [
        ("community_name", "QQcommunityName1"),
        ("ro_community", "QQroCommunity2"),
        ("rw-community", "QQrwCommunity3"),
        ("snmp_community", "QQsnmpCommunity4"),
    ] {
        let v = serde_json::json!({ field: secret });
        let got = redact_json_str(&v.to_string()).unwrap();
        assert!(!got.contains(secret), "field '{field}' leaked: {got}");
    }
}

/// Compound session-secret field spellings must still be redacted.
#[test]
fn mec_537_f2_compound_session_field_spellings_are_redacted() {
    for (field, secret) in [
        ("auth_session", "QQauthSession1"),
        ("session_ticket", "QQsessionTicket2"),
        ("session_value", "QQsessionValue3"),
    ] {
        let v = serde_json::json!({ field: secret });
        let got = redact_json_str(&v.to_string()).unwrap();
        assert!(!got.contains(secret), "field '{field}' leaked: {got}");
    }
}

/// A secret nested under a bare `session` container (not the PAN-OS
/// diagnostic shape) must still be redacted — `session` containers get no
/// blanket pass just because they can also hold non-secret diagnostics.
#[test]
fn mec_537_f3_secret_nested_under_session_container_is_redacted() {
    let v = serde_json::json!({"session": {"id": "QQsessionNestedId1"}});
    let got = redact_json_str(&v.to_string()).unwrap();
    assert!(!got.contains("QQsessionNestedId1"), "got: {got}");
}

/// The `bgp`-ancestor exemption must not fire just because some key named
/// `bgp` sits above a `community` field — the value must also look like BGP
/// community-tag syntax. A vendor's own user-chosen map key (here, a profile
/// literally named `bgp`) wrapping an SNMP community string is not BGP
/// routing data. Exercised through the PAN-OS profile so the guard is
/// actually in play.
#[test]
fn mec_537_f4_bgp_ancestor_without_community_shaped_value_is_still_redacted_in_json() {
    let mut v = serde_json::json!({
        "profiles": {"bgp": {"community": "QQprofileBgpCommunity1"}}
    });
    redact_json_value_with_profile(&mut v, &PANOS_PROFILE);
    let got = v.to_string();
    assert!(!got.contains("QQprofileBgpCommunity1"), "got: {got}");

    let mut v = serde_json::json!({
        "bgp": {"snmp": {"community": "QQbgpSnmpCommunity2"}}
    });
    redact_json_value_with_profile(&mut v, &PANOS_PROFILE);
    let got = v.to_string();
    assert!(!got.contains("QQbgpSnmpCommunity2"), "got: {got}");
}

/// XML counterpart of the above: a `community` nested arbitrarily deep under
/// a `bgp` element, holding a non-community-shaped value, must still be
/// redacted.
#[test]
fn mec_537_f4_bgp_ancestor_without_community_shaped_value_is_still_redacted_in_xml() {
    let xml = r#"<bgp><x><community><name>QQbgpXNestedCommunity3</name></community></x></bgp>"#;
    let got = redact_xml_str_with_profile(xml, &PANOS_PROFILE).unwrap();
    assert!(!got.contains("QQbgpXNestedCommunity3"), "got: {got}");
}

/// XML twin of
/// `mec_1342_f2_bgp_community_object_with_non_member_key_is_still_redacted` —
/// a `community` element's only child other than `member`/`members` is not
/// the known BGP shape and must still be redacted, even with a genuine `bgp`
/// ancestor and a community-tag-shaped value.
#[test]
fn mec_1370_f1_bgp_community_child_other_than_member_is_still_redacted_in_xml() {
    let xml = r#"<bgp><community><anything>1234:5678</anything></community></bgp>"#;
    let got = redact_xml_str_with_profile(xml, &PANOS_PROFILE).unwrap();
    assert!(!got.contains("1234:5678"), "got: {got}");
}

/// A `bgp` element *nested inside* `community` (rather than an ancestor of
/// it) must not trigger the exemption — only a `bgp` scope strictly above
/// the `community` element counts, matching JSON's
/// `looks_like_bgp_community_value` scope exactly, so the two parsers agree
/// on the same logical document.
#[test]
fn mec_1370_f1_bgp_nested_below_community_does_not_exempt_xml() {
    let xml = r#"<snmp><community><bgp>1234:5678</bgp></community></snmp>"#;
    let got = redact_xml_str_with_profile(xml, &PANOS_PROFILE).unwrap();
    assert!(!got.contains("1234:5678"), "got: {got}");
}

/// JSON counterpart of the above: a `bgp` key nested inside `community`
/// (rather than an ancestor of it) must not trigger the exemption either.
#[test]
fn mec_1370_f1_bgp_nested_below_community_does_not_exempt_json() {
    let mut v = serde_json::json!({"snmp": {"community": {"bgp": "1234:5678"}}});
    redact_json_value_with_profile(&mut v, &PANOS_PROFILE);
    let got = v.to_string();
    assert!(!got.contains("1234:5678"), "got: {got}");
}

/// JSON's `looks_like_bgp_community_value` and XML's
/// `is_bgp_route_community_ancestor` both cap the `member`/`members` shape
/// at exactly one level — an extra level of nesting is not the known BGP
/// shape and must still be redacted in both formats, keeping them in
/// agreement.
#[test]
fn bgp_community_member_nested_two_levels_deep_is_still_redacted_in_json() {
    let mut v = serde_json::json!({"bgp": {"community": {"member": {"member": ["1:2"]}}}});
    redact_json_value_with_profile(&mut v, &PANOS_PROFILE);
    let got = v.to_string();
    assert!(!got.contains("\"1:2\""), "got: {got}");
}

#[test]
fn bgp_community_member_nested_two_levels_deep_is_still_redacted_in_xml() {
    let xml = r#"<bgp><community><member><member>1:2</member></member></community></bgp>"#;
    let got = redact_xml_str_with_profile(xml, &PANOS_PROFILE).unwrap();
    assert!(!got.contains("1:2"), "got: {got}");
}
