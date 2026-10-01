//! Junos profile (MEC-1245): two pieces of redaction coverage rustjunosmcp's
//! `collect_jtac_support_bundle` (`redact=true`, the default) needs that this
//! crate's vendor-agnostic [`crate::xml`]/[`crate::text`] passes do not
//! provide on their own.
//!
//! - [`redact_xml`] — the generic XML pass (denylisted element/attribute
//!   names plus the [`crate::shape`] value-shape catch-all) already covers
//!   every name on rustjunosmcp's locked `REDACT_ELEMENT_NAMES` list except
//!   one: a bare `<value>` element (the NTP `authentication-key` secret,
//!   `<key><name>1</name><type>md5</type><value>$9$...</value></key>`).
//!   `value` is deliberately not on [`crate::denylist`] — as a substring or
//!   exact match it is far too generic a tag name to redact unconditionally
//!   across every vendor this crate serves — but within Junos's own closed
//!   NETCONF element vocabulary, treating it as unconditionally
//!   secret-bearing is the same judgement call rustjunosmcp already made and
//!   has shipped on for years. [`redact_xml`] is the generic pass plus that
//!   one Junos-specific addition, not a second XML scanner (parser
//!   differentials are exactly the risk a second hand-rolled XML walk would
//!   invite).
//! - [`redact_log_text`] — a conservative, `set`-statement-aware line
//!   redactor for the non-XML support-bundle artefacts (`/var/log/*` files,
//!   `request support information` tech-support output). This is *not* a
//!   thin wrapper over [`crate::text::redact`]: that pass is substring-keyed
//!   and intentionally over-redacts (documented, accepted cost for the
//!   generic multi-vendor case) — it matches `secret` inside `secretary` and
//!   flags a bare prose mention of a denylisted word with no config-syntax
//!   signal at all. A support bundle's `/var/log/*` files are full of prose
//!   (syslog messages, command echoes), so that cost is not acceptable here.
//!   This pass instead whole-word-matches a closed, Junos-specific key list
//!   and only redacts the following value when a config-syntax signal is
//!   present: quotes, a `=`, a trailing `;`/`{`, a Junos crypt hash, or a
//!   preceding `set` statement (including one echoed mid-line in a
//!   `UI_CMDLINE_READ_LINE` syslog entry).
//!
//! Ported from `rust-junosmcp-srx-core/src/workflows/support_bundle/redact.rs`
//! (Phase 3 design doc § "Redact rules"; `docs/superpowers/plans/`
//! `2026-07-13-audit-field-redaction.md`), which becomes a thin call-through
//! to this module.

#![deny(clippy::indexing_slicing, clippy::string_slice)]

use crate::RedactError;
use crate::policy::{RedactionPolicy, active};
use crate::shape::looks_like_secret_value;
use crate::xml;

/// Junos element names whose value is always a secret, independent of its
/// `crate::denylist`-covered ancestor and of whether the text itself looks
/// like a crypt hash — see the module docs for why only `value` needs to be
/// named here (`key` is already denylisted under exact match).
fn is_extra_secret_element(local_name: &str) -> bool {
    local_name == "value"
}

/// Redact a Junos NETCONF/XML support-bundle artefact.
///
/// Identical to [`crate::redact_xml_str`] except that a bare `<value>`
/// element is always treated as secret-bearing (see the module docs).
///
/// # Errors
/// Returns [`RedactError::InvalidXml`] when `input` does not parse as
/// well-formed XML — callers on a fail-closed path (anything shipped in a
/// JTAC support bundle) must refuse the artefact rather than fall back to
/// the unredacted input.
pub fn redact_xml(input: &str) -> Result<String, RedactError> {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        xml::validate(input)?;
        return Ok(input.to_string());
    }
    xml::redact_with(input, &is_extra_secret_element)
}

/// Redact a Junos non-XML support-bundle artefact (`/var/log/*` files,
/// `request support information` tech-support text). Always succeeds — there
/// is no parse step to fail on free-form text.
#[must_use]
pub fn redact_log_text(input: &str) -> String {
    if matches!(active(), RedactionPolicy::DisabledByOperator { .. }) {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    // `split_inclusive` keeps the line terminator attached, preserving the
    // exact newline structure (including any final newline) on rejoin.
    for line in input.split_inclusive('\n') {
        out.push_str(&redact_log_line(line));
    }
    out
}

/// Route a captured support-bundle artefact through the appropriate pass.
/// Well-formed XML is run through [`redact_xml`] and then *always* through
/// [`redact_log_text`] as well — a CLI-syntax secret can end up sitting in
/// plain text under an element name not on the XML pass's locked list (e.g.
/// directly under `<rpc-reply>` when the expected wrapper element is
/// absent), so the line-oriented pass is the floor every artefact goes
/// through regardless of its outer shape. Content that only looks like XML
/// but that the redactor could not actually walk falls back to the
/// line-oriented pass alone rather than shipping unredacted.
#[must_use]
pub fn redact_log_artefact(input: &str) -> String {
    match redact_xml(input) {
        Ok(redacted) => redact_log_text(&redacted),
        Err(_) => redact_log_text(input),
    }
}

/// Element/key names whose value in Junos CLI/log syntax is a secret. Whole-
/// word matched (see [`is_word_char`]) against a closed, Junos-specific
/// vocabulary — unlike [`crate::denylist::is_denylisted_key`]'s deliberate
/// substring matching, which would turn `secret` into a false-positive match
/// inside `secretary`.
const REDACT_LOG_KEYS: &[&str] = &[
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

/// Characters that form part of a Junos identifier token. Used for whole-word
/// matching of key names (so `community` does not match inside
/// `community-name` and `secret` does not match inside `secretary`).
#[allow(clippy::indexing_slicing)] // called with bounds-checked byte offsets
fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Redact a single log line (which may include a trailing `\n`).
fn redact_log_line(line: &str) -> String {
    // `set:` is the Junos audit marker (`UI_CFG_AUDIT_SET`); when present the
    // whole line is config context. Otherwise set-context is decided per-key
    // by `set_statement_precedes`, which also catches a `set` statement
    // echoed mid-line (e.g. a `UI_CMDLINE_READ_LINE` syslog entry).
    let audit_context = line.contains("set:");

    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut idx = 0;
    while idx < bytes.len() {
        // SOUND: `idx > 0` guard ensures `idx - 1` is valid.
        #[allow(clippy::indexing_slicing)]
        let at_boundary = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut matched = false;
        if at_boundary {
            for key in REDACT_LOG_KEYS {
                let klen = key.len();
                let end = idx + klen;
                // SOUND: `idx` is always a char boundary, `klen` is the byte
                // length of an ASCII key, so `end` is also a char boundary.
                // The `end <= bytes.len()` guard prevents out-of-bounds.
                #[allow(clippy::indexing_slicing)]
                if end <= bytes.len()
                    && &bytes[idx..end] == key.as_bytes()
                    && (end == bytes.len() || !is_word_char(bytes[end]))
                {
                    let set_context = audit_context || set_statement_precedes(line, idx);
                    if let Some((value_start, value_end)) = redactable_value(line, end, set_context)
                    {
                        // SOUND: `idx` is a char boundary, `value_start` comes
                        // from `value_token`, which guarantees char
                        // boundaries (scans for ASCII delimiters or
                        // `line.len()`).
                        #[allow(clippy::string_slice)]
                        out.push_str(&line[idx..value_start]);
                        out.push_str("[REDACTED]");
                        idx = value_end;
                        matched = true;
                    }
                    break;
                }
            }
        }
        if !matched {
            // Push the current char (respecting UTF-8 boundaries).
            // SOUND: `idx` is always a char boundary (loop invariant).
            #[allow(clippy::string_slice)]
            let ch = line[idx..]
                .chars()
                .next()
                .expect("chars().next() cannot fail: loop invariant idx < line.len()");
            out.push(ch);
            idx += ch.len_utf8();
        }
    }
    out
}

/// English determiners/possessives that, when sitting between a `set` token
/// and a sensitive key, indicate prose ("we set the secret aside") rather
/// than a Junos `set` config statement. Used to suppress false positives.
const SET_CONTEXT_STOPWORDS: &[&str] = &[
    "the", "a", "an", "this", "that", "these", "those", "my", "your", "our", "his", "her", "its",
    "their",
];

/// True when `token` looks like a Junos config path element: non-empty and
/// made up solely of identifier characters (alphanumerics plus `-_/.:`).
/// Tokens with spaces, quotes, or punctuation are not config identifiers.
fn is_config_identifier(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'/'
                || byte == b'.'
                || byte == b':'
        })
}

/// Decide whether a Junos `set` config statement precedes the key at byte
/// offset `key_start` on this line. Returns true when a whole-word `set`
/// token appears earlier on the line and every whitespace-separated token
/// between that `set` and the key is a config identifier (not a stopword).
/// This catches both a line that starts with `set ...` and a `set ...`
/// statement echoed mid-line (e.g. a `UI_CMDLINE_READ_LINE` syslog:
/// `... load-configuration set snmp community VALUE ...`), while leaving
/// prose like "we set the secret aside" untouched because the intervening
/// "the" is a stopword.
fn set_statement_precedes(line: &str, key_start: usize) -> bool {
    // SOUND: `key_start` is `idx` from the caller, which is always a char
    // boundary.
    #[allow(clippy::string_slice)]
    let prefix = &line[..key_start];
    let tokens: Vec<&str> = prefix.split_whitespace().collect();
    let Some(set_idx) = tokens.iter().rposition(|&token| token == "set") else {
        return false;
    };
    // SOUND: `set_idx` comes from `rposition`, so it is a valid index.
    #[allow(clippy::indexing_slicing)]
    tokens[set_idx + 1..]
        .iter()
        .all(|&token| is_config_identifier(token) && !SET_CONTEXT_STOPWORDS.contains(&token))
}

/// Format qualifiers that may sit between a sensitive key and its value in
/// Junos config/log syntax (e.g. `pre-shared-key ascii-text "$9$..."`). When
/// present they are preserved and the *following* token is redacted.
const VALUE_QUALIFIERS: &[&str] = &["ascii-text", "hexadecimal", "plain-text", "encrypted"];

/// XML entity form of a double quote (`&quot;`). CLI text redacted after
/// [`redact_xml`]'s element pass (see [`redact_log_artefact`]) may still have
/// its literal `"` characters XML-escaped; [`value_token`] and
/// [`redactable_value`] must recognise this form too, or a quoted value with
/// an internal space is only partially matched up to the first space —
/// leaking the remainder.
const QUOT_ENTITY: &[u8] = b"&quot;";

/// True when `bytes[pos..]` starts with `needle`, without slicing (this
/// module denies `clippy::indexing_slicing`/`clippy::string_slice`).
fn bytes_start_with(bytes: &[u8], pos: usize, needle: &[u8]) -> bool {
    needle
        .iter()
        .enumerate()
        .all(|(i, &b)| bytes.get(pos + i) == Some(&b))
}

/// Given the byte offset just past a matched key, decide whether the
/// following value should be redacted and return its `[start, end)` byte
/// range (the slice to replace with the marker, excluding any trailing `;`).
/// Returns `None` when there is no config signal, leaving prose mentions
/// untouched.
fn redactable_value(line: &str, after_key: usize, set_context: bool) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let pos = after_key;

    // Equals form: optional spaces, `=`, optional spaces, then the value.
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    let mut scan = pos;
    #[allow(clippy::indexing_slicing)]
    while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
        scan += 1;
    }
    #[allow(clippy::indexing_slicing)]
    if scan < bytes.len() && bytes[scan] == b'=' {
        scan += 1;
        #[allow(clippy::indexing_slicing)]
        while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
            scan += 1;
        }
        return value_token(line, scan);
    }

    // Space form: require at least one space after the key.
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    if pos >= bytes.len() || (bytes[pos] != b' ' && bytes[pos] != b'\t') {
        return None;
    }
    let mut pos = pos;
    #[allow(clippy::indexing_slicing)]
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }

    // Optional format qualifier (e.g. `ascii-text`): preserved, value
    // follows.
    let mut qualifier_present = false;
    let (tok_start, tok_end) = token_bounds(line, pos);
    // SOUND: `token_bounds` guarantees char boundaries (scans for ASCII
    // delimiters or line.len()).
    #[allow(clippy::string_slice)]
    if VALUE_QUALIFIERS.contains(&&line[tok_start..tok_end]) {
        qualifier_present = true;
        pos = tok_end;
        // SOUND: bounds-checked against bytes.len().
        #[allow(clippy::indexing_slicing)]
        while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
    }

    let (value_start, value_end) = value_token(line, pos)?;
    // SOUND: bounds checks prevent out-of-bounds indexing.
    #[allow(clippy::indexing_slicing)]
    let quoted = bytes[value_start] == b'"'
        || bytes[value_start] == b'\''
        || bytes_start_with(bytes, value_start, QUOT_ENTITY);
    #[allow(clippy::indexing_slicing)]
    let terminated = value_end < bytes.len() && bytes[value_end] == b';';
    // A `{` (optionally preceded by whitespace) opens a config block — treat
    // it as a terminator like `;` (legacy curly-brace SNMP syntax, e.g.
    // `community NAME {`).
    let mut block_scan = value_end;
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while block_scan < bytes.len() && (bytes[block_scan] == b' ' || bytes[block_scan] == b'\t') {
        block_scan += 1;
    }
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    let opens_block = block_scan < bytes.len() && bytes[block_scan] == b'{';
    // SOUND: `value_token` guarantees char boundaries (scans for ASCII
    // delimiters or line.len()).
    #[allow(clippy::string_slice)]
    let hash = looks_like_secret_value(&line[value_start..value_end]);

    if quoted || qualifier_present || terminated || opens_block || hash || set_context {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// Locate the value token starting at `pos`, returning its `[start, end)`
/// byte range. A quoted token — delimited by `"`, `'`, or the XML entity
/// `&quot;` — spans to its matching closing quote; a bare token runs until
/// whitespace or a `;` terminator. Returns `None` at end-of-line.
fn value_token(line: &str, pos: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    if pos >= bytes.len() {
        return None;
    }
    // SOUND: bounds-checked above.
    #[allow(clippy::indexing_slicing)]
    let first = bytes[pos];
    if first == b'"' || first == b'\'' {
        let mut end = pos + 1;
        // SOUND: bounds-checked against bytes.len().
        #[allow(clippy::indexing_slicing)]
        while end < bytes.len() && bytes[end] != first {
            end += 1;
        }
        // SOUND: bounds-checked.
        #[allow(clippy::indexing_slicing)]
        if end < bytes.len() {
            end += 1; // include the closing quote
        }
        // `end` is always a char boundary: either `bytes.len()` or one byte
        // past an ASCII quote (`"` or `'`), both of which are char
        // boundaries.
        return Some((pos, end));
    }
    if bytes_start_with(bytes, pos, QUOT_ENTITY) {
        let mut end = pos + QUOT_ENTITY.len();
        while end < bytes.len() && !bytes_start_with(bytes, end, QUOT_ENTITY) {
            end += 1;
        }
        if end < bytes.len() {
            end += QUOT_ENTITY.len(); // include the closing entity
        }
        // `end` only ever lands where the ASCII byte sequence `&quot;`
        // starts or matches `bytes.len()`, both of which are char
        // boundaries — the scan advances one byte at a time but a partial
        // match can never stop mid-multi-byte-char, since `&` (0x26) never
        // occurs as a UTF-8 continuation byte (0x80-0xBF).
        return Some((pos, end));
    }
    let (start, end) = token_bounds(line, pos);
    if start == end {
        None
    } else {
        Some((start, end))
    }
}

/// Bare-token bounds starting at `pos`: a run until whitespace, `;`, or EOL.
fn token_bounds(line: &str, pos: usize) -> (usize, usize) {
    let bytes = line.as_bytes();
    let mut end = pos;
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while end < bytes.len()
        && bytes[end] != b' '
        && bytes[end] != b'\t'
        && bytes[end] != b'\n'
        && bytes[end] != b'\r'
        && bytes[end] != b';'
    {
        end += 1;
    }
    // `end` is always a char boundary: either `bytes.len()` or pointing to an
    // ASCII delimiter (space, tab, newline, carriage return, or semicolon).
    (pos, end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    #[test]
    fn bare_value_element_is_redacted_even_without_a_denylisted_ancestor() {
        let xml = "<root><value>leak-value</value></root>";
        let got = redact_xml(xml).unwrap();
        assert!(!got.contains("leak-value"), "got: {got}");
    }

    #[test]
    fn unrelated_elements_are_untouched() {
        let xml = "<host><name>r1.example.net</name></host>";
        let got = redact_xml(xml).unwrap();
        assert_eq!(got, xml);
    }

    #[test]
    fn malformed_xml_is_refused_not_shipped_unredacted() {
        assert!(redact_xml("<unclosed><secret>oops").is_err());
    }

    #[test]
    fn prose_mention_of_a_denylisted_word_is_untouched() {
        let line = "Note: the secret to success is consistent testing.";
        assert_eq!(redact_log_text(line), line);
    }

    #[test]
    fn substring_of_a_denylisted_word_is_untouched() {
        let line = "The secretary updated the community-board listing today";
        assert_eq!(redact_log_text(line), line);
    }

    #[test]
    fn qualified_quoted_pre_shared_key_is_redacted() {
        let line = r#"set security ike policy p pre-shared-key ascii-text "$9$abcDEF123""#; // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        let got = redact_log_text(line);
        assert!(!got.contains("$9$abcDEF123"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        assert!(got.contains("pre-shared-key"), "got: {got}");
        assert!(got.contains("ascii-text"), "got: {got}");
    }

    #[test]
    fn bare_value_on_set_statement_is_redacted() {
        let got = redact_log_text("set snmp community privateRO");
        assert!(!got.contains("privateRO"), "got: {got}");
    }

    #[test]
    fn semicolon_terminated_community_is_redacted() {
        let got = redact_log_text("    community s3cr3tCommunity;");
        assert!(!got.contains("s3cr3tCommunity"), "got: {got}");
        assert!(got.trim_end().ends_with(';'), "got: {got}");
    }

    #[test]
    fn bare_junos_hash_is_redacted() {
        let got = redact_log_text("encrypted-password $6$saltsalt$hashhashhash");
        assert!(!got.contains("$6$saltsalt$hashhashhash"), "got: {got}");
    }

    #[test]
    fn hmac_key_equals_form_is_redacted() {
        let got = redact_log_text("hmac-key=deadbeefcafe1234");
        assert!(!got.contains("deadbeefcafe1234"), "got: {got}");
        assert!(got.contains("hmac-key="), "got: {got}");
    }

    #[test]
    fn newline_structure_is_preserved_across_lines() {
        let input = "ts=1 user=admin action=login\nset security ike policy p pre-shared-key ascii-text \"$9$leakme\"\nts=2 user=admin action=logout\n"; // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        let got = redact_log_text(input);
        assert!(!got.contains("$9$leakme"), "got: {got}"); // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        assert!(got.contains("action=login"), "got: {got}");
        assert!(got.contains("action=logout"), "got: {got}");
        assert_eq!(got.lines().count(), 3, "got: {got}");
    }

    #[test]
    fn tech_support_output_text_is_redacted() {
        let tech_support = "Hostname: srx1\nset security ike policy p1 pre-shared-key ascii-text \"$9$leakedPSK\";\nset snmp community privateRO;\n"; // gitleaks:allow -- fabricated Junos $9$ PSK fixture, not a real key
        let got = redact_log_text(tech_support);
        assert!(!got.contains("leakedPSK"), "got: {got}");
        assert!(!got.contains("privateRO"), "got: {got}");
    }

    #[test]
    fn midline_set_statement_in_a_cmdline_echo_is_redacted() {
        let line = "Jun  5 12:00:00 host mgd[123]: UI_CMDLINE_READ_LINE: User 'admin', \
                    command 'load-configuration rpc rpc ... set snmp community SMOKE89LEAK \
                    authorization read-only'";
        let got = redact_log_text(line);
        assert!(!got.contains("SMOKE89LEAK"), "got: {got}");
    }

    #[test]
    fn curly_brace_config_block_value_is_redacted() {
        let got = redact_log_text("    community s3cr3tCommunity {\n");
        assert!(!got.contains("s3cr3tCommunity"), "got: {got}");
        assert!(got.trim_end().ends_with('{'), "got: {got}");
    }

    #[test]
    fn cli_text_embedded_in_xml_without_an_output_wrapper_is_scrubbed() {
        let xml = "<rpc-reply>set snmp community leakedXML;\n</rpc-reply>";
        let got = redact_log_artefact(xml);
        assert!(!got.contains("leakedXML"), "got: {got}");
    }

    #[test]
    fn unparseable_xml_still_goes_through_the_log_text_floor() {
        let bad = "<unclosed>set snmp community leakedBad;";
        let got = redact_log_artefact(bad);
        assert!(!got.contains("leakedBad"), "got: {got}");
    }
}
