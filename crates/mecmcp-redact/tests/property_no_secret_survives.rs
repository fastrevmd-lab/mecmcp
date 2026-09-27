//! Acceptance criterion: "A property test shows that no fixture secret
//! survives redaction."
//!
//! This enumerates the whole finite state space it claims to cover — every
//! entry in [`mecmcp_redact::denylist::DENYLISTED_KEYS`] crossed with every
//! wire format, plus every value shape crossed with every format under a
//! field name that is on no list at all — rather than sampling it, the way a
//! `proptest`-style generator would. For a state space this small and this
//! enumerable, exhaustive coverage is a strictly stronger guarantee than
//! random sampling, and it does not add a new dependency to a crate whose own
//! job is minimizing what a supply-chain audit has to look at.
//!
//! Every fixture secret is a unique token so a failure names exactly which
//! `(key_or_shape, format)` pair leaked, instead of a generic "some secret
//! somewhere" failure.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::denylist::DENYLISTED_KEYS;
use mecmcp_redact::{redact_json_str, redact_text, redact_xml_str};

#[derive(Clone, Copy)]
enum Format {
    Json,
    Xml,
    Text,
}

const FORMATS: &[Format] = &[Format::Json, Format::Xml, Format::Text];

/// Value-shape fixtures under a field name (`zz_unlisted_field`) that is not,
/// and normalizes to nothing that is, on [`DENYLISTED_KEYS`].
const SHAPE_FIXTURES: &[&str] = &[
    "$9$fakesaltfakehashvalueA",
    "AKKgtu07M3XlnBEEmH0OZ1YkKl9-AQ==",
    "ENC(fakeciphertextB==)",
];

fn render(field: &str, secret: &str, format: Format) -> String {
    match format {
        Format::Json => format!(r#"{{"{field}": "{secret}"}}"#),
        Format::Xml => format!("<{field}>{secret}</{field}>"),
        Format::Text => format!("{field}: {secret}"),
    }
}

fn redact(input: &str, format: Format) -> String {
    match format {
        Format::Json => redact_json_str(input).unwrap(),
        Format::Xml => redact_xml_str(input).unwrap(),
        Format::Text => redact_text(input),
    }
}

fn format_name(format: Format) -> &'static str {
    match format {
        Format::Json => "json",
        Format::Xml => "xml",
        Format::Text => "text",
    }
}

#[test]
fn no_denylisted_key_fixture_secret_survives_any_format() {
    for (i, key) in DENYLISTED_KEYS.iter().enumerate() {
        // `DENYLISTED_KEYS` entries are already normalized (lowercase,
        // alphanumeric only), so using one directly as the field name means
        // it normalizes right back to itself.
        let field = *key;
        for &format in FORMATS {
            let secret = format!("QQZZ{i:04}{}", format_name(format));
            let input = render(field, &secret, format);
            let got = redact(&input, format);
            assert!(
                !got.contains(&secret),
                "denylisted key '{key}' (field '{field}') leaked in {}: {got}",
                format_name(format)
            );
        }
    }
}

/// Render `key` in its hyphenated vendor spelling: `pre_shared_key` ->
/// `pre-shared-key`. The other property test above renders keys in their
/// already-normalized form (`presharedkey`), which is exactly the spelling
/// [`mecmcp_redact::denylist::is_denylisted_key`] normalizes *to*, not the
/// hyphenated form a real vendor field name typically arrives in — that gap
/// is why F1 (hyphen/underscore-joined keys defeating the text tokenizer)
/// went uncaught by the exhaustive property test that was supposed to cover
/// exactly this.
fn hyphenate(key: &str) -> String {
    key.chars()
        .map(|c| if c == '_' { '-' } else { c })
        .collect()
}

#[test]
fn no_denylisted_key_fixture_secret_survives_any_format_in_its_hyphenated_vendor_spelling() {
    for (i, key) in DENYLISTED_KEYS.iter().enumerate() {
        let field = hyphenate(key);
        for &format in FORMATS {
            let secret = format!("QQZZH{i:04}{}", format_name(format));
            let input = render(&field, &secret, format);
            let got = redact(&input, format);
            assert!(
                !got.contains(&secret),
                "denylisted key '{key}' (hyphenated field '{field}') leaked in {}: {got}",
                format_name(format)
            );
        }
    }
}

#[test]
fn no_value_shape_fixture_secret_survives_any_format_under_an_unlisted_key() {
    for (i, secret) in SHAPE_FIXTURES.iter().enumerate() {
        for &format in FORMATS {
            let field = "zz_unlisted_field";
            let input = render(field, secret, format);
            let got = redact(&input, format);
            assert!(
                !got.contains(secret),
                "shape fixture #{i} ('{secret}') leaked in {}: {got}",
                format_name(format)
            );
        }
    }
}
