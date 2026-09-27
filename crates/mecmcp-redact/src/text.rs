//! Line-oriented redaction for unstructured text: flat vendor config dumps,
//! CLI output, and free-form log-ish blobs that are not valid XML or JSON.
//!
//! This is best-effort by construction — there is no grammar for "vendor CLI
//! output" to parse against. It runs a denylisted-key scan and the
//! [`crate::shape`] catch-all per line, plus a dedicated PEM-block and
//! `## SECRET-DATA` handler, and always **replaces** rather than "cleans" a
//! value: on ambiguity about where a value ends, it takes the larger span.

use crate::denylist::is_denylisted_key;
use crate::shape::{is_pem_begin, is_pem_end, line_has_secret_data_marker, looks_like_secret_value};

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
    let has_denylisted_key = line
        .split(|c: char| !c.is_ascii_alphanumeric())
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

/// Replace the content of every `"..."` or `'...'` span in `line`. Returns
/// `None` when there are no quoted spans, or when `force` is false and none
/// of them looks like a secret value (so the caller falls through to the
/// `=`/`:`/bare-token rules instead).
fn redact_quoted_spans(line: &str, force: bool) -> Option<String> {
    let mut spans = Vec::new();
    for quote in ['"', '\''] {
        let mut search_from = 0;
        while let Some(start) = line[search_from..].find(quote) {
            let start = search_from + start;
            if let Some(end_rel) = line[start + 1..].find(quote) {
                let end = start + 1 + end_rel;
                spans.push((start, end));
                search_from = end + 1;
            } else {
                break;
            }
        }
    }
    if spans.is_empty() {
        return None;
    }
    spans.sort_unstable_by_key(|&(start, _)| start);
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
        let pem = "intro line\n-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEBASE64==\nMoreFakeBase64==\n-----END RSA PRIVATE KEY-----\ntrailer line";
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
}
