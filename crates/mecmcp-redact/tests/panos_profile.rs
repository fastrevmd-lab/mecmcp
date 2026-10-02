//! MEC-537: the PAN-OS profile — representative PAN-OS XML API responses
//! proving two things at once, the way MEC-711's Mist fixtures
//! (`json.rs`'s `mec_711_*` tests) do for Mist:
//!
//! 1. Real PAN-OS secret shapes (an admin password hash, a keygen API key, an
//!    IKE pre-shared key, an SNMP community string) are redacted.
//! 2. Legitimate PAN-OS operational/config fields that merely contain the
//!    words "session" or "community" — `show session info` diagnostics, a BGP
//!    route community — are not, which `main` got wrong before this change
//!    (mecmcp#418).

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{redact_json_str, redact_xml_str};

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

/// mecmcp#418: `show session info`-shaped operational output, structured as
/// JSON (the shape a rustpanosmcp typed-read tool would return), used to be
/// blanked wholesale because "sessions"/"session" tripped the old
/// `session`-as-substring denylist entry.
#[test]
fn panos_show_session_info_fields_survive() {
    let v = serde_json::json!({
        "sessions": {
            "num-active": 523,
            "num-max": 262144,
            "num-tcp": 45,
            "tcp-timeout": 3600,
            "idle-timeout-tcp-session": 3600,
        }
    });
    let input = v.to_string();
    let got = redact_json_str(&input).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&got).unwrap();
    assert_eq!(parsed["sessions"]["num-active"], 523);
    assert_eq!(parsed["sessions"]["num-max"], 262144);
    assert_eq!(parsed["sessions"]["tcp-timeout"], 3600);
    assert_eq!(parsed["sessions"]["idle-timeout-tcp-session"], 3600);
}

/// mecmcp#418: a BGP export policy's route community (`65000:100`, a routing
/// tag, not a secret) used to be blanked by the same `community` field name
/// an SNMP community string uses.
#[test]
fn panos_bgp_route_community_survives_in_json() {
    let v = serde_json::json!({
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
    let input = v.to_string();
    let got = redact_json_str(&input).unwrap();
    assert!(got.contains("65000:100"), "got: {got}");
}

#[test]
fn panos_bgp_route_community_survives_in_xml() {
    let xml = r#"<bgp><policy><export><rules><entry name="r1"><action><add><community><member>65000:100</member></community></add></action></entry></rules></export></policy></bgp>"#;
    let got = redact_xml_str(xml).unwrap();
    assert!(got.contains("65000:100"), "got: {got}");
}

/// MEC-1342 review (F2): the BGP community exemption now checks object
/// keys as well as values before treating a value as BGP-shaped.
#[test]
fn mec_1342_f2_bgp_community_object_with_non_member_key_is_still_redacted() {
    let v = serde_json::json!({
        "bgp": {
            "community": {
                "QQkeyleak3": "1:2"
            }
        }
    });
    let input = v.to_string();
    let got = redact_json_str(&input).unwrap();
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
/// value-shape rule coincidentally catching it too (MEC-537 review, F5).
#[test]
fn panos_session_token_leaf_is_still_redacted() {
    let v = serde_json::json!({"session": "QQpanosSessionLeafValue001"});
    let got = redact_json_str(&v.to_string()).unwrap();
    assert!(!got.contains("QQpanosSessionLeafValue001"), "got: {got}");
}

/// mecmcp#418/MEC-537 review (F1): compound SNMP-community field spellings
/// — not just the bare `community` string and the few exact spellings the
/// first pass covered — must still be redacted. Mist's `snmp_config`
/// schema (`v2c_config[].community_name`) is this shape.
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

/// mecmcp#418/MEC-537 review (F2): compound session-secret field spellings
/// must still be redacted.
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

/// mecmcp#418/MEC-537 review (F3): a secret nested under a bare `session`
/// container (not the PAN-OS diagnostic shape) must still be redacted —
/// `session` containers get no blanket pass just because they can also hold
/// non-secret diagnostics.
#[test]
fn mec_537_f3_secret_nested_under_session_container_is_redacted() {
    let v = serde_json::json!({"session": {"id": "QQsessionNestedId1"}});
    let got = redact_json_str(&v.to_string()).unwrap();
    assert!(!got.contains("QQsessionNestedId1"), "got: {got}");
}

/// mecmcp#418/MEC-537 review (F4): the `bgp`-ancestor exemption must not
/// fire just because some key named `bgp` sits above a `community` field —
/// the value must also look like BGP community-tag syntax. A vendor's own
/// user-chosen map key (here, a profile literally named `bgp`) wrapping an
/// SNMP community string is not BGP routing data.
#[test]
fn mec_537_f4_bgp_ancestor_without_community_shaped_value_is_still_redacted_in_json() {
    let v = serde_json::json!({
        "profiles": {"bgp": {"community": "QQprofileBgpCommunity1"}}
    });
    let got = redact_json_str(&v.to_string()).unwrap();
    assert!(!got.contains("QQprofileBgpCommunity1"), "got: {got}");

    let v = serde_json::json!({
        "bgp": {"snmp": {"community": "QQbgpSnmpCommunity2"}}
    });
    let got = redact_json_str(&v.to_string()).unwrap();
    assert!(!got.contains("QQbgpSnmpCommunity2"), "got: {got}");
}

/// XML counterpart of the above: a `community` nested arbitrarily deep under
/// a `bgp` element, holding a non-community-shaped value, must still be
/// redacted.
#[test]
fn mec_537_f4_bgp_ancestor_without_community_shaped_value_is_still_redacted_in_xml() {
    let xml = r#"<bgp><x><community><name>QQbgpXNestedCommunity3</name></community></x></bgp>"#;
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("QQbgpXNestedCommunity3"), "got: {got}");
}
