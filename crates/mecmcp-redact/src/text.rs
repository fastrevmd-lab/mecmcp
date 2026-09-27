//! Line-oriented redaction for unstructured text: flat vendor config dumps,
//! CLI output, and free-form log-ish blobs that are not valid XML or JSON.
//!
//! This is best-effort by construction — there is no grammar for "vendor CLI
//! output" to parse against. It runs a denylisted-key scan and the
//! [`crate::shape`] catch-all per line, plus a dedicated PEM-block and
//! `## SECRET-DATA` handler, and always **replaces** rather than "cleans" a
//! value: on ambiguity about where a value ends, it takes the larger span.

use crate::denylist::is_denylisted_key;
use crate::shape::{is_pem_begin, is_pem_end, looks_like_secret_value};

const PLACEHOLDER: &str = "[REDACTED]";

/// Redact a block of unstructured text.
#[must_use]
pub fn redact(input: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut in_pem = false;
    for line in input.split('\n') {
        let trimmed = line.trim().trim_end_matches('\r');
        if in_pem {
            if is_pem_end(trimmed) {
                in_pem = false;
                out.push(line.to_string());
            }
            // Body lines of an open PEM block are dropped; the single
            // placeholder was already pushed when the block opened.
            continue;
        }
        if is_pem_begin(trimmed) {
            in_pem = true;
            out.push(line.to_string());
            out.push(PLACEHOLDER.to_string());
            continue;
        }
        out.push(redact_line(line));
    }
    out.join("\n")
}

fn redact_line(line: &str) -> String {
    if let Some(idx) = line.find("## SECRET-DATA") {
        let (prefix, suffix) = line.split_at(idx);
        return format!("{}{}", redact_value_span(prefix, true), suffix);
    }
    // Keep `-`/`_` attached to the token: they're intra-key separators
    // (`private_key`, `pre-shared-key`) that `is_denylisted_key` normalizes
    // away itself. Splitting on them here would break a compound key into
    // pieces that individually match nothing on the denylist.
    let has_denylisted_key = line
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .any(is_denylisted_key);
    if has_denylisted_key {
        return redact_value_span(line, true);
    }
    redact_value_span(line, false)
}

/// Redact the "value" part of a line.
///
/// `force`: a denylisted key (or a `## SECRET-DATA` marker) was found on this
/// line, so *something* on it is redacted even if no shape matches — a known
/// secret field with a value shape nobody anticipated must still not survive.
/// When `force` is false, only text matching a known value shape is touched.
fn redact_value_span(line: &str, force: bool) -> String {
    // Quoted values first: `key "value"` / `key: 'value'` / inline JSON-ish
    // text. Every quoted span is a value-shape or force candidate.
    if let Some(redacted) = redact_quoted_spans(line, force) {
        return redacted;
    }
    // When forced, redact the value token that follows the specific
    // denylisted key token, not the last `=`/`:`/whitespace on the line — a
    // line can carry several `k=v` pairs (`user=admin password=X src=...`)
    // or bare trailing tokens (`community X authorization read-only`) where
    // the denylisted key is nowhere near the end.
    if force && let Some(redacted) = redact_after_denylisted_key(line) {
        return redacted;
    }
    if let Some(eq) = line.rfind('=') {
        let (head, tail) = line.split_at(eq + 1);
        if force || looks_like_secret_value(tail.trim()) {
            return format!("{head}{PLACEHOLDER}");
        }
    }
    if let Some(colon) = line.find(':') {
        let (head, tail) = line.split_at(colon + 1);
        if force || looks_like_secret_value(tail.trim()) {
            return format!("{head}{PLACEHOLDER}");
        }
    }
    // No `=`/`:` — bare `key value` (Junos `set` style). Redact the last
    // whitespace-delimited token when forced, or when it alone looks secret.
    if let Some(last_space) = line.rfind(char::is_whitespace) {
        let (head, tail) = line.split_at(last_space + 1);
        let tail_trimmed = tail.trim_end_matches(';');
        let trailing = &tail[tail_trimmed.len()..];
        if !tail_trimmed.is_empty() && (force || looks_like_secret_value(tail_trimmed)) {
            return format!("{head}{PLACEHOLDER}{trailing}");
        }
    } else if force || looks_like_secret_value(line) {
        return PLACEHOLDER.to_string();
    }
    line.to_string()
}

/// Byte ranges of every maximal run of non-whitespace characters in `line`,
/// in order.
fn whitespace_token_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in line.char_indices() {
        if c.is_whitespace() {
            if let Some(s) = start.take() {
                spans.push((s, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        spans.push((s, line.len()));
    }
    spans
}

/// Replace `line[value_start..value_end]` with [`PLACEHOLDER`], but keep any
/// trailing structural punctuation (`;`, `,`, `{`, `}`) that is attached
/// directly to the value with no separating whitespace — a Junos statement
/// terminator or hierarchy brace is not part of the secret.
fn splice_placeholder(line: &str, value_start: usize, value_end: usize) -> String {
    let value = &line[value_start..value_end];
    let core_len = value.trim_end_matches([';', ',', '{', '}']).len();
    let punct_start = value_start + core_len;
    format!(
        "{}{PLACEHOLDER}{}",
        &line[..value_start],
        &line[punct_start..]
    )
}

/// Find a denylisted key token on `line` and redact the value that follows
/// it, for `key=value`, `key: value` / `key:value`, and bare `key value`
/// forms. Quoted values (`key "value"`) are handled earlier by
/// [`redact_quoted_spans`] and never reach here. Returns `None` when no
/// denylisted key token is found this way, so the caller can fall back to a
/// whole-line heuristic.
fn redact_after_denylisted_key(line: &str) -> Option<String> {
    let tokens = whitespace_token_spans(line);
    for (i, &(s, e)) in tokens.iter().enumerate() {
        let text = &line[s..e];
        for sep in ['=', ':'] {
            let Some(rel) = text.find(sep) else {
                continue;
            };
            let key_part = &text[..rel];
            if !is_denylisted_key(key_part) {
                continue;
            }
            let value_start = s + rel + 1;
            if value_start < e {
                return Some(splice_placeholder(line, value_start, e));
            }
            // `key=`/`key:` with nothing else in this token: the value is
            // the next whitespace token, if there is one.
            if let Some(&(vs, ve)) = tokens.get(i + 1) {
                return Some(splice_placeholder(line, vs, ve));
            }
        }
        // Bare key token, no `=`/`:` attached to it.
        let bare_key = text.trim_end_matches([':', ';']);
        if !bare_key.is_empty()
            && is_denylisted_key(bare_key)
            && let Some(&(vs, ve)) = tokens.get(i + 1)
        {
            let next_token = &line[vs..ve];
            // Some vendors put a type keyword directly after the key,
            // before the actual secret (Junos `pre-shared-key ascii-text
            // "..."`). A type keyword never carries entropy — no digit —
            // so when the immediate next token looks like one and a
            // further token follows, that further token is the value.
            if !next_token.chars().any(|c| c.is_ascii_digit())
                && let Some(&(vs2, ve2)) = tokens.get(i + 2)
            {
                return Some(splice_placeholder(line, vs2, ve2));
            }
            return Some(splice_placeholder(line, vs, ve));
        }
    }
    None
}

/// Replace the content of every `"..."` or `'...'` span in `line`. Returns
/// `None` when there are no quoted spans, or when `force` is false and none
/// of them looks like a secret value (so the caller falls through to the
/// `=`/`:`/bare-token rules instead).
fn redact_quoted_spans(line: &str, force: bool) -> Option<String> {
    // Single left-to-right scan: whichever quote character (`"` or `'`)
    // opens first is the one that closes the span, and the scan resumes
    // after that close. Scanning each quote character independently and
    // merging the results (the previous approach) can produce overlapping
    // spans whenever the two quote kinds nest — e.g. `"a'b"` opens a `"`
    // span at 0..end and a `'` span starting *inside* it — and slicing
    // `line[cursor..=start]` against an out-of-order later span panics.
    let mut spans = Vec::new();
    let mut idx = 0;
    while let Some(rel) = line[idx..].find(['"', '\'']) {
        let start = idx + rel;
        let quote = line[start..].chars().next().expect("find matched a char");
        if let Some(end_rel) = line[start + quote.len_utf8()..].find(quote) {
            let end = start + quote.len_utf8() + end_rel;
            spans.push((start, end));
            idx = end + quote.len_utf8();
        } else {
            // Unterminated quote: nothing further to pair it with.
            break;
        }
    }
    if spans.is_empty() {
        return None;
    }
    let any_match = force
        || spans
            .iter()
            .any(|&(start, end)| looks_like_secret_value(&line[start + 1..end]));
    if !any_match {
        return None;
    }
    let mut result = String::with_capacity(line.len());
    let mut cursor = 0;
    for (start, end) in spans {
        result.push_str(&line[cursor..=start]);
        result.push_str(PLACEHOLDER);
        cursor = end;
    }
    result.push_str(&line[cursor..]);
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylisted_key_with_quoted_value_is_redacted() {
        let line = r#"set system root-authentication encrypted-password "$9$topsecrethash";"#;
        let got = redact(line);
        assert!(!got.contains("topsecrethash"), "got: {got}");
        assert!(got.contains(PLACEHOLDER));
    }

    #[test]
    fn denylisted_key_colon_form_is_redacted() {
        let got = redact("password: hunter2-fake");
        assert!(!got.contains("hunter2-fake"), "got: {got}");
    }

    #[test]
    fn denylisted_key_equals_form_is_redacted() {
        let got = redact("PSK=FAKEPRESHAREDKEY123");
        assert!(!got.contains("FAKEPRESHAREDKEY123"), "got: {got}");
    }

    #[test]
    fn denylisted_key_bare_token_form_is_redacted() {
        let got = redact("set snmp community FAKEcommunityABC");
        assert!(!got.contains("FAKEcommunityABC"), "got: {got}");
    }

    #[test]
    fn secret_data_marker_redacts_only_the_value_before_it() {
        let line = r#"pre-shared-key ascii-text "$9$fakehashvalue"; ## SECRET-DATA"#;
        let got = redact(line);
        assert!(!got.contains("fakehashvalue"), "got: {got}");
        assert!(got.contains("## SECRET-DATA"), "marker must survive: {got}");
    }

    #[test]
    fn value_shape_catch_all_without_denylisted_key() {
        // `totally_new_vendor_field` is not on the denylist; the crypt-hash
        // shape must still catch it.
        let got = redact(r#"totally_new_vendor_field: "$6$fakesaltfakehash""#);
        assert!(!got.contains("fakesaltfakehash"), "got: {got}");
    }

    #[test]
    fn pem_block_body_is_removed_but_headers_survive() {
        let pem = "intro line\n-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEBASE64==\nMoreFakeBase64==\n-----END RSA PRIVATE KEY-----\ntrailer line"; // gitleaks:allow -- fabricated base64 body ("FAKE"), not a real key
        let got = redact(pem);
        assert!(got.contains("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(got.contains("-----END RSA PRIVATE KEY-----"));
        assert!(!got.contains("MIIFAKEBASE64=="));
        assert!(!got.contains("MoreFakeBase64=="));
        assert!(got.contains("intro line"));
        assert!(got.contains("trailer line"));
    }

    #[test]
    fn unrelated_lines_pass_through_unchanged() {
        let text = "hostname: r1.example.net\ndescription: uplink to core";
        assert_eq!(redact(text), text);
    }

    // --- F1: hyphen/underscore-joined denylist terms must still match. ---

    #[test]
    fn f1_hyphenated_key_bare_form_is_redacted() {
        let got = redact("set security ike policy p1 pre-shared-key ascii-text QQvalue1");
        assert!(!got.contains("QQvalue1"), "got: {got}");
    }

    #[test]
    fn f1_underscore_key_equals_form_is_redacted() {
        let got = redact("api_key=QQvalue2");
        assert!(!got.contains("QQvalue2"), "got: {got}");
    }

    #[test]
    fn f1_hyphenated_key_colon_form_is_redacted() {
        let got = redact("private-key: QQvalue3");
        assert!(!got.contains("QQvalue3"), "got: {got}");
    }

    #[test]
    fn f1_hyphenated_key_bare_form_with_trailing_semicolon_is_redacted() {
        let got = redact("authentication-key QQvalue4;");
        assert!(!got.contains("QQvalue4"), "got: {got}");
        assert!(got.ends_with(';'), "terminator must survive: {got}");
    }

    // --- F2: redact the value that follows the key, not the last span. ---

    #[test]
    fn f2a_equals_form_redacts_the_matching_keys_value_not_the_last_one() {
        let got = redact("login ok user=admin password=QQvalue8 src=192.0.2.1");
        assert!(!got.contains("QQvalue8"), "got: {got}");
        assert!(
            got.contains("user=admin"),
            "unrelated field must survive: {got}"
        );
        assert!(
            got.contains("src=192.0.2.1"),
            "unrelated field must survive: {got}"
        );
    }

    #[test]
    fn f2b_bare_form_redacts_the_token_after_the_key_not_the_last_token() {
        let got = redact("set snmp community QQvalue6 authorization read-only");
        assert!(!got.contains("QQvalue6"), "got: {got}");
        assert!(
            got.contains("read-only"),
            "trailing unrelated tokens must survive: {got}"
        );
    }

    #[test]
    fn f2b_junos_hierarchical_form_redacts_the_value_not_the_brace() {
        let got = redact("community QQvalue5 {");
        assert!(!got.contains("QQvalue5"), "got: {got}");
        assert!(got.trim_end().ends_with('{'), "brace must survive: {got}");
    }

    // --- F6: overlapping/nested quote spans must not panic. ---

    #[test]
    fn f6_nested_mixed_quotes_do_not_panic() {
        let got = redact(r#"set password "a'b" 'x'"#);
        assert!(got.contains(PLACEHOLDER));
    }

    #[test]
    fn f6_quote_mix_fuzz_style_no_panic_over_many_shapes() {
        let bodies = [
            "", "a", "ab", "a'b", "a\"b", "'", "\"", "''", "\"\"", "'\"'\"",
        ];
        let wrappers: &[fn(&str) -> String] = &[
            |b: &str| format!(r#"set password "{b}""#),
            |b: &str| format!("set password '{b}'"),
            |b: &str| format!(r#"set password "{b}" 'x'"#),
            |b: &str| format!(r#"set password '{b}' "x""#),
            |b: &str| format!(r#"a "{b}" b '{b}' c"#),
        ];
        for wrapper in wrappers {
            for body in bodies {
                // Must not panic for any combination; the exact placeholder
                // count is not asserted since some bodies leave a quote
                // unterminated (deliberately, to exercise that path too).
                let _ = redact(&wrapper(body));
            }
        }
    }
}
