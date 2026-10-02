//! Junos-specific line-oriented redaction (MEC-1245).
//!
//! Ported from `rustjunosmcp`'s `rust-junosmcp-srx-core` support-bundle
//! redactor, which predates this crate. It is kept as a **separate entry
//! point from [`crate::text::redact`]**, not folded into it, because the two
//! have a deliberately different false-positive posture:
//!
//! - [`crate::text::redact`] is intentionally aggressive: once a denylisted
//!   key token is found anywhere on a line, by design it redacts to the end
//!   of the line with no further signal required — over-redaction in the
//!   safe direction, accepted as the cost of a generic best-effort scan.
//! - [`redact_junos_log_text`] is intentionally conservative: it only
//!   redacts a key's value when a Junos config-syntax signal is present (a
//!   `=`, surrounding quotes, a format qualifier like `ascii-text`, a
//!   trailing `;`/`{`, a bare value that looks like a crypt hash, or a
//!   `set ...` statement — including one echoed mid-line in a
//!   `UI_CMDLINE_READ_LINE` syslog). A bare prose mention of `secret` or
//!   `community` with no such signal is left untouched.
//!
//! This distinction matters for a JTAC support bundle: it bundles real
//! device log files (`/var/log/*`) that get read by a support engineer, not
//! just scanned by a model. Collapsing every line that happens to mention
//! "secret" or "password" in prose to a single marker — `text::redact`'s
//! accepted tradeoff elsewhere — would make those logs meaningfully less
//! useful for diagnosis. `redact_junos_log_text` keeps the narrower,
//! previously-shipped behavior instead.
//!
//! The redaction marker is `<REDACTED>`, not this crate's usual
//! `[REDACTED]` (see [`crate::json::PLACEHOLDER`] / `crate::xml::PLACEHOLDER`),
//! to keep `collect_jtac_support_bundle`'s shipped output byte-for-byte
//! unchanged for callers that already parse or diff it.

#![deny(clippy::indexing_slicing, clippy::string_slice)]

/// Key names whose value is redacted in Junos config/log syntax. Matching is
/// whole-word (see [`is_word_char`]), not substring — this list is
/// deliberately independent of [`crate::denylist::DENYLISTED_KEYS`]'s
/// substring matching, which would be too permissive for the
/// signal-gated redaction this module does.
pub const JUNOS_LOG_REDACT_KEYS: &[&str] = &[
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

/// Replacement string used in redacted text. See the module docs for why
/// this differs from this crate's usual `[REDACTED]` marker.
pub const REDACTED_MARKER: &str = "<REDACTED>";

/// Redact secrets embedded in plain-text log lines (Junos `/var/log/*`
/// artefacts, `request support information` output). For each name in
/// [`JUNOS_LOG_REDACT_KEYS`] appearing as a whole word, the value that
/// follows is replaced with [`REDACTED_MARKER`] when a config-syntax signal
/// is present (an `=`, surrounding quotes, a format qualifier, a trailing
/// `;`, a Junos crypt-hash value, or a `set ...` config line). Bare prose
/// mentions of a key name with no such signal are left untouched to avoid
/// false positives.
#[must_use]
pub fn redact_junos_log_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    // `split_inclusive` keeps the line terminator attached, preserving the
    // exact newline structure (including any final newline) on rejoin.
    for line in input.split_inclusive('\n') {
        out.push_str(&redact_junos_log_line(line));
    }
    out
}

/// Characters that form part of a Junos identifier token. Used for whole-word
/// matching of key names (so `community` does not match inside `community-name`
/// and `secret` does not match inside `secretary`).
#[allow(clippy::indexing_slicing)] // called with bounds-checked byte offsets
fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// Format qualifiers that may sit between a sensitive key and its value in
/// Junos config/log syntax (e.g. `pre-shared-key ascii-text "$9$..."`). When
/// present they are preserved and the *following* token is redacted.
const VALUE_QUALIFIERS: &[&str] = &["ascii-text", "hexadecimal", "plain-text", "encrypted"];

/// A bare value is treated as a secret with no further context when it is a
/// Junos crypt hash: a `$`, one or more digits (crypt id `$1$`, `$5$`, `$6$`,
/// `$8$`, `$9$`, ...) or the literal `sha1`, then a closing `$`. Such tokens
/// never occur in ordinary prose. Requiring the closing `$` (rather than just
/// `$` + one digit) avoids false positives like `$5 off` and covers the
/// `$sha1$...` form, which has no leading digit.
fn is_junos_hash(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.first() != Some(&b'$') {
        return false;
    }
    if token.starts_with("$sha1$") {
        return true;
    }
    let mut i = 1;
    let mut digits = 0usize;
    while let Some(&b) = bytes.get(i) {
        if !b.is_ascii_digit() {
            break;
        }
        digits += 1;
        i += 1;
    }
    digits > 0 && bytes.get(i) == Some(&b'$')
}

/// Redact a single log line (which may include a trailing `\n`).
fn redact_junos_log_line(line: &str) -> String {
    // `set:` is the Junos audit marker (`UI_CFG_AUDIT_SET`); when present the
    // whole line is config context. Otherwise set-context is decided per-key by
    // [`set_statement_precedes`], which also catches a `set` statement echoed
    // mid-line (e.g. a `UI_CMDLINE_READ_LINE` syslog).
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
            for key in JUNOS_LOG_REDACT_KEYS {
                let klen = key.len();
                let end = idx + klen;
                // SOUND: `idx` is always a char boundary (advances by ch.len_utf8()),
                // `klen` is the byte length of an ASCII key, so `end` is also a char
                // boundary. The `end <= bytes.len()` guard prevents out-of-bounds.
                #[allow(clippy::indexing_slicing)]
                if end <= bytes.len()
                    && &bytes[idx..end] == key.as_bytes()
                    && (end == bytes.len() || !is_word_char(bytes[end]))
                {
                    let set_context = audit_context || set_statement_precedes(line, idx);
                    if let Some((value_start, value_end)) = redactable_value(line, end, set_context)
                    {
                        // SOUND: `idx` is a char boundary, `value_start` comes from
                        // `value_token` which guarantees char boundaries (scans for
                        // ASCII delimiters or line.len()).
                        #[allow(clippy::string_slice)]
                        out.push_str(&line[idx..value_start]);
                        out.push_str(REDACTED_MARKER);
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

/// English determiners/possessives that, when sitting between a `set` token and
/// a sensitive key, indicate prose ("we set the secret aside") rather than a
/// Junos `set` config statement. Used to suppress false positives.
const SET_CONTEXT_STOPWORDS: &[&str] = &[
    "the", "a", "an", "this", "that", "these", "those", "my", "your", "our", "his", "her", "its",
    "their",
];

/// True when `token` looks like a Junos config path element: non-empty and made
/// up solely of identifier characters (alphanumerics plus `-_/.:`). Tokens with
/// spaces, quotes, or punctuation are not config identifiers.
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

/// Decide whether a Junos `set` config statement precedes the key at byte offset
/// `key_start` on this line. Returns true when a whole-word `set` token appears
/// earlier on the line and every whitespace-separated token between that `set`
/// and the key is a config identifier (not a stopword). This catches both a
/// line that starts with `set ...` and a `set ...` statement echoed mid-line
/// (e.g. a `UI_CMDLINE_READ_LINE` syslog: `... load-configuration set snmp
/// community VALUE ...`), while leaving prose like "we set the secret aside"
/// untouched because the intervening "the" is a stopword.
fn set_statement_precedes(line: &str, key_start: usize) -> bool {
    // SOUND: `key_start` is `idx` from the caller, which is always a char boundary.
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

/// Given the byte offset just past a matched key, decide whether the following
/// value should be redacted and return its `[start, end)` byte range (the slice
/// to replace with the marker, excluding any trailing `;`). Returns `None` when
/// there is no config signal, leaving prose mentions untouched.
fn redactable_value(line: &str, after_key: usize, set_context: bool) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut pos = after_key;

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
    #[allow(clippy::indexing_slicing)]
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }

    // Optional format qualifier (e.g. `ascii-text`): preserved, value follows.
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
    let hash = is_junos_hash(&line[value_start..value_end]);

    if quoted || qualifier_present || terminated || opens_block || hash || set_context {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// XML entity form of a double quote (`&quot;`). CLI text redacted after an
/// XML element pass may still have its literal `"` characters XML-escaped;
/// [`value_token`] and [`redactable_value`] must recognise this form too, or
/// a quoted value with an internal space is only partially matched up to the
/// first space — leaking the remainder.
const QUOT_ENTITY: &[u8] = b"&quot;";

/// True when `bytes[pos..]` starts with `needle`, without slicing (this
/// module denies `clippy::indexing_slicing`/`clippy::string_slice`).
fn bytes_start_with(bytes: &[u8], pos: usize, needle: &[u8]) -> bool {
    needle
        .iter()
        .enumerate()
        .all(|(i, &b)| bytes.get(pos + i) == Some(&b))
}

/// Locate the value token starting at `pos`, returning its `[start, end)` byte
/// range. A quoted token — delimited by `"`, `'`, or the XML entity `&quot;`
/// — spans to its matching closing quote; a bare token runs until whitespace
/// or a `;` terminator. Returns `None` at end-of-line.
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
        // past an ASCII quote (`"` or `'`), both of which are char boundaries.
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
        // `end` only ever lands where the ASCII byte sequence `&quot;` starts
        // or matches `bytes.len()`, both of which are char boundaries — the
        // scan advances one byte at a time but a partial match can never
        // stop mid-multi-byte-char, since `&` (0x26) never occurs as a UTF-8
        // continuation byte (0x80-0xBF).
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
mod tests {
    use super::*;

    #[test]
    fn redacts_qualified_quoted_pre_shared_key() {
        let line = "set security ike policy p pre-shared-key ascii-text \"$9$abcDEF123\""; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real secret
        let out = redact_junos_log_text(line);
        assert!(!out.contains("$9$abcDEF123"), "secret leaked: {out}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real secret
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
        assert!(out.contains("pre-shared-key"), "key dropped: {out}");
        assert!(out.contains("ascii-text"), "qualifier dropped: {out}");
    }

    #[test]
    fn redacts_quoted_secret() {
        let line = "secret \"$9$topSEKRET\""; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real secret
        let out = redact_junos_log_text(line);
        assert!(!out.contains("$9$topSEKRET"), "secret leaked: {out}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real secret
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
    }

    #[test]
    fn redacts_equals_form() {
        let line = "hmac-key=deadbeefcafe1234";
        let out = redact_junos_log_text(line);
        assert!(!out.contains("deadbeefcafe1234"), "secret leaked: {out}");
        assert!(out.contains("hmac-key="), "lhs dropped: {out}");
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
    }

    #[test]
    fn redacts_semicolon_terminated_community() {
        let line = "    community s3cr3tCommunity;";
        let out = redact_junos_log_text(line);
        assert!(!out.contains("s3cr3tCommunity"), "secret leaked: {out}");
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
        assert!(out.trim_end().ends_with(';'), "terminator dropped: {out}");
    }

    #[test]
    fn redacts_bare_junos_hash() {
        let line = "encrypted-password $6$saltsalt$hashhashhash";
        let out = redact_junos_log_text(line);
        assert!(
            !out.contains("$6$saltsalt$hashhashhash"),
            "secret leaked: {out}"
        );
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
    }

    #[test]
    fn redacts_bare_value_on_set_line() {
        let line = "set snmp community privateRO";
        let out = redact_junos_log_text(line);
        assert!(!out.contains("privateRO"), "secret leaked: {out}");
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
    }

    #[test]
    fn redacts_every_known_key() {
        for name in JUNOS_LOG_REDACT_KEYS {
            let line = format!("set foo {name} \"leak-{name}\"");
            let out = redact_junos_log_text(&line);
            assert!(
                !out.contains(&format!("leak-{name}")),
                "secret leaked for {name}: {out}"
            );
            assert!(
                out.contains("<REDACTED>"),
                "marker missing for {name}: {out}"
            );
        }
    }

    #[test]
    fn leaves_prose_mention_untouched() {
        let line = "Note: the secret to success is consistent testing.";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "prose mention was redacted: {out}");
    }

    #[test]
    fn leaves_substring_key_untouched() {
        let line = "The secretary updated the community-board listing today";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "substring match redacted: {out}");
    }

    #[test]
    fn preserves_structure_across_lines() {
        let input = "ts=1 user=admin action=login\nset security ike policy p pre-shared-key ascii-text \"$9$leakme\"\nts=2 user=admin action=logout\n"; // gitleaks:allow -- fabricated Junos $9$ fixture, not a real secret
        let out = redact_junos_log_text(input);
        assert!(!out.contains("$9$leakme"), "secret leaked: {out}"); // gitleaks:allow -- fabricated Junos $9$ fixture, not a real secret
        assert!(out.contains("action=login"), "first line lost: {out}");
        assert!(out.contains("action=logout"), "last line lost: {out}");
        assert_eq!(out.lines().count(), 3, "line count changed: {out}");
        assert!(out.ends_with('\n'), "trailing newline lost: {out}");
    }

    #[test]
    fn redacts_midline_set_in_cmdline_echo() {
        let line = "Jun  5 12:00:00 host mgd[123]: UI_CMDLINE_READ_LINE: User 'admin', \
                    command 'load-configuration rpc rpc ... set snmp community SMOKE89LEAK \
                    authorization read-only'";
        let out = redact_junos_log_text(line);
        assert!(!out.contains("SMOKE89LEAK"), "secret leaked: {out}");
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
        assert!(out.contains("community"), "key dropped: {out}");
    }

    #[test]
    fn leaves_prose_set_the_secret_untouched() {
        let line = "Earlier we set the secret aside for review.";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "prose set-the-secret was redacted: {out}");
    }

    #[test]
    fn near_miss_pre_shared_key_with_multibyte_char() {
        let line = " pre-shared-keé";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn near_miss_secret_with_multibyte_char() {
        let line = " secreé";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn near_miss_simple_password_with_multibyte_char() {
        let line = " simple-passworé";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn near_miss_encrypted_password_with_multibyte_char() {
        let line = " encrypted-passworé";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn near_miss_community_with_multibyte_char() {
        let line = " communité";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn near_miss_hmac_key_with_multibyte_char() {
        let line = " hmac-keé";
        let out = redact_junos_log_text(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn redacts_real_key_with_non_ascii_value() {
        let line = "set snmp community \"välue123\"";
        let out = redact_junos_log_text(line);
        assert!(!out.contains("välue123"), "secret leaked: {out}");
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
        assert!(out.contains("community"), "key dropped: {out}");
    }

    #[test]
    fn redacts_community_in_curly_brace_block() {
        let line = "    community s3cr3tCommunity {\n";
        let out = redact_junos_log_text(line);
        assert!(!out.contains("s3cr3tCommunity"), "secret leaked: {out}");
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
        assert!(out.trim_end().ends_with('{'), "brace dropped: {out}");
    }

    #[test]
    fn is_junos_hash_matches_sha1_prefix() {
        assert!(is_junos_hash(
            "$sha1$abcdef0123456789abcdef0123456789abcdef01"
        ));
    }

    #[test]
    fn is_junos_hash_rejects_dollar_digit_without_closing_dollar() {
        assert!(!is_junos_hash("$5 off"));
    }

    #[test]
    fn is_junos_hash_still_matches_crypt_hash() {
        assert!(is_junos_hash("$6$saltsalt$hashhashhash"));
    }

    #[test]
    fn redacts_value_quoted_with_xml_entity_quot_containing_internal_space() {
        let line =
            "set security ike policy p1 pre-shared-key ascii-text &quot;correct horse&quot;;";
        let out = redact_junos_log_text(line);
        assert!(!out.contains("correct horse"), "secret leaked: {out}");
        assert!(out.contains("<REDACTED>"), "marker missing: {out}");
        assert!(out.contains("pre-shared-key"), "key dropped: {out}");
    }
}
