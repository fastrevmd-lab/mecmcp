//! MEC-1245: the Junos profile — proves this crate's existing
//! denylist-and-shape XML/text redaction (`redact_xml_str`/`redact_text`)
//! covers every case rustjunosmcp's hand-rolled, pre-dating
//! `rust-junosmcp-srx-core/src/workflows/support_bundle/redact.rs` engine
//! locked down for `collect_jtac_support_bundle`'s `redact=true` default:
//! every name in that module's `REDACT_ELEMENT_NAMES` list, the independent
//! Junos crypt-hash (`$N$...`) catch-all, and the `set`-statement-aware
//! plain-text log-line redaction for non-XML support-bundle artefacts
//! (`/var/log/*` files, `request support information` tech-support text).
//!
//! This is the parallel to MEC-711's Mist fixtures (`json.rs`'s `mec_711_*`
//! tests) and MEC-537's PAN-OS fixtures (`tests/panos_profile.rs`): once this
//! suite passes, rustjunosmcp's own module can become a thin call-through to
//! this crate the same way `rustpanosmcp`'s `redact_device_xml` already is,
//! with no loss of coverage.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::junos::{redact_log_text, redact_xml as junos_redact_xml};
use mecmcp_redact::redact_xml_str;

/// rustjunosmcp `REDACT_ELEMENT_NAMES`, reproduced here so this suite fails
/// loudly if that locked list and this crate's denylist ever drift apart
/// instead of silently losing coverage.
const JUNOS_REDACT_ELEMENT_NAMES: &[&str] = &[
    "pre-shared-key",
    "secret",
    "simple-password",
    "encrypted-password",
    "community",
    "hmac-key",
    "authentication-key",
    "authentication-password",
    "privacy-password",
    "key",
    "value",
];

#[test]
fn every_junos_locked_element_name_is_redacted_as_an_xml_leaf() {
    for name in JUNOS_REDACT_ELEMENT_NAMES {
        let xml = format!("<root><{name}>leak-{name}</{name}></root>");
        // `value` is the one name in this list the generic, vendor-agnostic
        // `redact_xml_str` does not cover on its own (see `junos.rs` module
        // docs: too generic a tag name to denylist crate-wide) — the
        // `junos`-profile entry point is required for that one.
        let got = junos_redact_xml(&xml).unwrap();
        assert!(
            !got.contains(&format!("leak-{name}")),
            "secret leaked for <{name}>: {got}"
        );
    }
}

#[test]
fn pre_shared_key_text_is_redacted_structure_preserved() {
    let xml = "<ike-policy><pre-shared-key>s3cr3t-psk</pre-shared-key></ike-policy>";
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("s3cr3t-psk"), "got: {got}");
    assert!(got.contains("pre-shared-key"), "got: {got}");
}

#[test]
fn namespace_prefixed_element_still_matches_local_name() {
    let xml = "<junos:secret xmlns:junos=\"http://x\">topsecret</junos:secret>";
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("topsecret"), "got: {got}");
}

#[test]
fn sibling_text_and_structure_survive_redaction() {
    let xml = "<users><user><name>bob</name><secret>pw123</secret></user></users>";
    let got = redact_xml_str(xml).unwrap();
    assert!(got.contains("bob"), "got: {got}");
    assert!(!got.contains("pw123"), "got: {got}");
    assert!(got.contains("<name>"), "got: {got}");
}

#[test]
fn unparseable_xml_is_refused_not_shipped_unredacted() {
    // rust-junosmcp's `try_redact_xml` returns `XmlRedaction::Unparseable`
    // here, and `redact_rpc_reply` refuses the artefact entirely rather than
    // shipping it (fail-closed). `redact_xml_str` must refuse the same way.
    let bad = "<unclosed><secret>oops";
    assert!(redact_xml_str(bad).is_err());
}

/// A live `get-configuration` reply with undeclared `junos:` attribute
/// prefixes on its root (rustjunosmcp #91) must still have every secret
/// scrubbed.
#[test]
fn live_get_configuration_reply_is_fully_scrubbed() {
    let xml = concat!(
        "<configuration xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\" ",
        "junos:changed-seconds=\"1700000000\">",
        "<system><root-authentication>",
        "<encrypted-password>$6$rootsaltA$rootHASHaaaaaaaaaa</encrypted-password>",
        "</root-authentication>",
        "<login><user><name>admin</name><authentication>",
        "<encrypted-password>$6$usersaltB$userHASHbbbbbbbbbb</encrypted-password>",
        "</authentication></user></login></system>",
        "<snmp><community><name>commLEAK</name></community></snmp>",
        "</configuration>",
    );
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("rootHASHaaaaaaaaaa"), "got: {got}");
    assert!(!got.contains("userHASHbbbbbbbbbb"), "got: {got}");
    assert!(!got.contains("commLEAK"), "got: {got}");
    assert!(got.contains("admin"), "got: {got}");
}

#[test]
fn snmpv3_usm_auth_and_priv_passwords_are_redacted() {
    let xml = concat!(
        "<snmp><v3><usm><local-engine><user>",
        "<name>oncall</name>",
        "<authentication-md5><authentication-password>$9$authLEAK</authentication-password></authentication-md5>", // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        "<privacy-des><privacy-password>$9$privLEAK</privacy-password></privacy-des>", // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
        "</user></local-engine></usm></v3></snmp>",
    );
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("authLEAK"), "got: {got}");
    assert!(!got.contains("privLEAK"), "got: {got}");
    assert!(got.contains("oncall"), "got: {got}");
}

#[test]
fn routing_protocol_authentication_key_is_redacted() {
    let xml = "<protocols><bgp><group><name>ext</name><authentication-key>$9$bgpKeyLEAK</authentication-key></group></bgp></protocols>"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("bgpKeyLEAK"), "got: {got}");
}

#[test]
fn md5_authentication_key_element_is_redacted() {
    let xml = "<protocols><ospf><area><interface><authentication><md5><name>1</name><key>$9$ospfMd5LEAK</key></md5></authentication></interface></area></ospf></protocols>"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("ospfMd5LEAK"), "got: {got}");
}

#[test]
fn ntp_authentication_key_value_is_redacted() {
    let xml = "<system><ntp><authentication-key><key>1</key><type>md5</type><value>$9$ntpValueLEAK</value></authentication-key></ntp></system>"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("ntpValueLEAK"), "got: {got}");
}

/// MEC-1245: Junos routing-options HMAC authentication key — the one gap
/// this crate's denylist did not already cover (`hmac-key` fix alongside
/// this test).
#[test]
fn routing_options_hmac_key_is_redacted() {
    let xml = "<routing-options><authentication-key-chains><key-chain><name>chain1</name><key><name>1</name><hmac-key><md5>$9$hmacKeyLEAK</md5></hmac-key></key></key-chain></authentication-key-chains></routing-options>"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("hmacKeyLEAK"), "got: {got}");
}

#[test]
fn junos_crypt_hash_catch_all_applies_under_an_unlisted_element_name() {
    let xml = "<config><password-hash>$6$saltXYZ$hashLEAKvalue</password-hash></config>";
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("$6$saltXYZ$hashLEAKvalue"), "got: {got}");
}

#[test]
fn junos_sha1_crypt_hash_catch_all_is_redacted() {
    let xml = "<config><password-hash>$sha1$leakedSHA1hash</password-hash></config>";
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("leakedSHA1hash"), "got: {got}");
}

#[test]
fn dollar_digit_prose_is_not_mistaken_for_a_crypt_hash() {
    let xml = "<config><promo>$5 off your order</promo></config>";
    let got = redact_xml_str(xml).unwrap();
    assert!(got.contains("$5 off your order"), "got: {got}");
}

// ── Non-XML support-bundle artefacts: `/var/log/*` files and
// `request support information` tech-support text, redacted via the junos
// profile's `redact_log_text` (rustjunosmcp's own `redact_log_text`
// equivalent — always succeeds, never refuses). ──────────────────────────

#[test]
fn log_line_qualified_quoted_pre_shared_key_is_redacted() {
    let line = r#"set security ike policy p pre-shared-key ascii-text "$9$abcDEF123""#; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_log_text(line);
    assert!(!got.contains("$9$abcDEF123"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    assert!(got.contains("pre-shared-key"), "got: {got}");
    assert!(got.contains("ascii-text"), "got: {got}");
}

#[test]
fn log_line_bare_value_on_set_statement_is_redacted() {
    let got = redact_log_text("set snmp community privateRO");
    assert!(!got.contains("privateRO"), "got: {got}");
}

#[test]
fn log_line_semicolon_terminated_community_is_redacted() {
    let got = redact_log_text("    community s3cr3tCommunity;");
    assert!(!got.contains("s3cr3tCommunity"), "got: {got}");
    assert!(got.trim_end().ends_with(';'), "got: {got}");
}

#[test]
fn log_line_bare_junos_hash_is_redacted() {
    let got = redact_log_text("encrypted-password $6$saltsalt$hashhashhash");
    assert!(!got.contains("$6$saltsalt$hashhashhash"), "got: {got}");
}

#[test]
fn log_line_hmac_key_equals_form_is_redacted() {
    let got = redact_log_text("hmac-key=deadbeefcafe1234");
    assert!(!got.contains("deadbeefcafe1234"), "got: {got}");
    assert!(got.contains("hmac-key="), "got: {got}");
}

#[test]
fn log_line_prose_mention_of_a_denylisted_word_is_untouched() {
    // `redact_text` (the generic, vendor-agnostic pass) intentionally
    // over-redacts prose like this — see `text.rs`'s accepted-cost doc
    // comment. A support bundle's `/var/log/*` files are full of prose, so
    // the junos profile's `redact_log_text` is conservative instead: it
    // requires a config-syntax signal, not just the bare word.
    let line = "Note: the secret to success is consistent testing.";
    assert_eq!(redact_log_text(line), line);
}

#[test]
fn log_line_substring_of_a_denylisted_word_is_untouched() {
    let line = "The secretary updated the community-board listing today";
    assert_eq!(redact_log_text(line), line);
}

#[test]
fn log_text_preserves_newline_structure_across_lines() {
    let input = "ts=1 user=admin action=login\nset security ike policy p pre-shared-key ascii-text \"$9$leakme\"\nts=2 user=admin action=logout\n"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_log_text(input);
    assert!(!got.contains("$9$leakme"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    assert!(got.contains("action=login"), "got: {got}");
    assert!(got.contains("action=logout"), "got: {got}");
    assert_eq!(got.lines().count(), 3, "got: {got}");
}

/// rustjunosmcp #89: `request support information` output is plain
/// tech-support text, never XML. The dispatcher must not let a text payload
/// slip through unredacted just because it is not XML.
#[test]
fn tech_support_output_text_is_redacted_not_shipped_raw() {
    let tech_support = "Hostname: srx1\nset security ike policy p1 pre-shared-key ascii-text \"$9$leakedPSK\";\nset snmp community privateRO;\n"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_log_text(tech_support);
    assert!(!got.contains("leakedPSK"), "got: {got}");
    assert!(!got.contains("privateRO"), "got: {got}");
}

/// rustjunosmcp #92: a `set` config statement echoed mid-line (e.g. a
/// `UI_CMDLINE_READ_LINE` syslog entry) must still trip the set-context rule.
#[test]
fn midline_set_statement_in_a_cmdline_echo_is_redacted() {
    let line = "Jun  5 12:00:00 host mgd[123]: UI_CMDLINE_READ_LINE: User 'admin', \
                command 'load-configuration rpc rpc ... set snmp community SMOKE89LEAK \
                authorization read-only'";
    let got = redact_log_text(line);
    assert!(!got.contains("SMOKE89LEAK"), "got: {got}");
}

/// rustjunosmcp F1: legacy curly-brace SNMP config syntax.
#[test]
fn curly_brace_config_block_value_is_redacted() {
    let got = redact_log_text("    community s3cr3tCommunity {\n");
    assert!(!got.contains("s3cr3tCommunity"), "got: {got}");
    assert!(got.trim_end().ends_with('{'), "got: {got}");
}

/// rustjunosmcp F2: an RPC reply with CLI-syntax text under an element name
/// not on the locked list (no `<output>` wrapper) must still have the
/// embedded secret scrubbed — this crate's `xml::redact` runs the text-path
/// scan over every text node, not only ones under a denylisted ancestor, so
/// one `redact_xml_str` call already covers what rustjunosmcp needed two
/// passes (`try_redact_xml` + `redact_log_text`) for.
#[test]
fn cli_text_embedded_in_xml_without_an_output_wrapper_is_scrubbed() {
    let xml = "<rpc-reply>set snmp community leakedXML;\n</rpc-reply>";
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("leakedXML"), "got: {got}");
}

/// A `configuration-text` blob (the `generic` support-bundle path's
/// `request support information` payload, embedded in an RPC reply) must
/// have its embedded secrets scrubbed while unrelated lines survive.
#[test]
fn configuration_text_blob_is_scrubbed_for_embedded_secrets() {
    let xml = "<rpc-reply><configuration-text>set interfaces ge-0/0/0 unit 0\nset security ike policy p1 pre-shared-key ascii-text \"$9$fakehashvalue\"; ## SECRET-DATA\n</configuration-text></rpc-reply>"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real key
    let got = redact_xml_str(xml).unwrap();
    assert!(!got.contains("fakehashvalue"), "got: {got}");
    assert!(got.contains("set interfaces ge-0/0/0 unit 0"), "got: {got}");
}
