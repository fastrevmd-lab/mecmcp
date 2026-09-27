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
    // When forced, take the union of every span any pass would redact on its
    // own: the denylisted-key matches, every quoted span that itself looks
    // like a secret value, and every whitespace token that looks like one —
    // a line can carry a keyed value (`password=X`) *and* an unrelated
    // shape-matching value the key scan never touches (`secret X $9$hash`,
    // `password=X hash "$9$hash"`). Splicing once over the union (rather than
    // returning as soon as the key scan finds something) is what keeps the
    // quoted-span and shape passes from being silently skipped whenever a key
    // happens to match earlier on the same line.
    if force {
        let mut spans = denylisted_key_spans(line);
        for &(start, end) in &quoted_content_spans(line) {
            if looks_like_secret_value(&line[start..end]) {
                spans.push((start, end));
            }
        }
        for &(start, end) in &whitespace_token_spans(line) {
            if looks_like_secret_value(&line[start..end]) {
                spans.push((start, end));
            }
        }
        if !spans.is_empty() {
            return splice_spans(line, spans);
        }
        // Nothing keyed or shape-matched: fall through to the unconditional
        // `=`/`:`/last-token redaction below so a forced line still never
        // passes through untouched (a `## SECRET-DATA` marker with no
        // recognizable value shape on its line, say).
    } else if let Some(redacted) = redact_quoted_spans(line, false) {
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

/// Vendor "value type" keywords that some CLIs put directly after a
/// denylisted key and before the actual secret (Junos
/// `pre-shared-key ascii-text "..."`, `encrypted-password "$9$..."`). Every
/// one of these is a closed, known vocabulary — unlike "the next token has no
/// digit in it", which also matches an ordinary digit-free SNMP community
/// string or weak PSK (N1) and would skip straight past the real secret.
/// Matching is case-insensitive; nothing here is normalized/hyphen-agnostic
/// on purpose, since these are compared as literal tokens, not denylist keys.
const VALUE_TYPE_KEYWORDS: &[&str] = &[
    "ascii-text",
    "hexadecimal",
    "encrypted-password",
    "plain-text-password",
    "simple-password",
    "authentication-key",
    "md5",
    "sha1",
    "sha256",
];

fn is_value_type_keyword(token: &str) -> bool {
    VALUE_TYPE_KEYWORDS
        .iter()
        .any(|kw| kw.eq_ignore_ascii_case(token))
}

/// A bare `=`, `:`, or `=>` occupying its own whitespace-delimited token —
/// `password = X` / `password => X` — rather than attached to the key
/// (`password=X`, handled by the `key=value` scan instead). Every one of
/// these is a separator, never the value itself (R1): treating it as an
/// unrecognized "value" left the real value one token further along exposed.
fn is_lone_separator(token: &str) -> bool {
    matches!(token, "=" | ":" | "=>")
}

/// A one- or two-digit Cisco-style type code (`password 7 X`, `secret 5 X`).
fn is_short_digit_code(token: &str) -> bool {
    (1..=2).contains(&token.len()) && !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit())
}

/// Vendor `ENC`-prefixed ciphertext marker used as its own token (FortiOS
/// `set psksecret ENC <blob>`), case-insensitive.
fn is_enc_token(token: &str) -> bool {
    token.eq_ignore_ascii_case("ENC")
}

/// Characters that can join otherwise-independent `key=value` pairs into one
/// whitespace-delimited token: a query string (`url=...?user=x&password=y`),
/// a `;`-joined attribute list, or inline JSON (`{"password":"x"}`). Splitting
/// on these before running the `=`/`:` key scan (R3) is what lets a key
/// buried inside such a token be found at all — the whole-token scan below
/// only ever inspected the *first* `=`/`:` in the token.
const SUBTOKEN_SPLIT_CHARS: [char; 6] = ['&', ';', ',', '?', '{', '}'];

/// Byte ranges of the non-empty pieces of `line[start..end]` after splitting
/// on [`SUBTOKEN_SPLIT_CHARS`]. Returns a single span equal to the input when
/// none of those characters are present.
fn subtoken_spans(line: &str, start: usize, end: usize) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut piece_start = start;
    for (i, c) in line[start..end].char_indices() {
        if SUBTOKEN_SPLIT_CHARS.contains(&c) {
            let abs = start + i;
            if piece_start < abs {
                spans.push((piece_start, abs));
            }
            piece_start = abs + c.len_utf8();
        }
    }
    if piece_start < end {
        spans.push((piece_start, end));
    }
    spans
}

/// `quoted_value_end(line, start).unwrap_or(fallback_end)`, but never
/// shorter than `token_end` — a quoted value that closes before its
/// enclosing whitespace token ends (`password="ab"QQtail`) must still have
/// the rest of that token swept (R4): a value cannot leak just because a
/// quote happened to close early inside the same token.
fn value_end_at_least(line: &str, start: usize, token_end: usize) -> usize {
    quoted_value_end(line, start).map_or(token_end, |end| end.max(token_end))
}

/// If `line[start..]` begins with a quote character, return the byte offset
/// just past its matching closing quote elsewhere on `line`. A quoted value
/// may contain whitespace (`description "core value"`), so its span cannot
/// be assumed to end at the next whitespace-delimited token boundary the
/// caller computed with [`whitespace_token_spans`].
fn quoted_value_end(line: &str, start: usize) -> Option<usize> {
    let quote = line[start..].chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let after = start + quote.len_utf8();
    let end_rel = line[after..].find(quote)?;
    Some(after + end_rel + quote.len_utf8())
}

/// Replace every `line[start..end]` in `spans` with [`PLACEHOLDER`], keeping
/// any trailing structural punctuation (`;`, `,`, `{`, `}`) attached directly
/// to a span with no separating whitespace — a Junos statement terminator or
/// hierarchy brace is not part of the secret.
///
/// Overlapping spans are tolerated: sorting by `(start, Reverse(end))` before
/// the sweep means that when two spans start at the same offset the longer
/// one is kept and the shorter one is dropped as already covered, and any
/// span that starts inside a span already emitted is dropped the same way.
fn splice_spans(line: &str, mut spans: Vec<(usize, usize)>) -> String {
    spans.sort_by_key(|&(start, end)| (start, std::cmp::Reverse(end)));
    let mut result = String::with_capacity(line.len());
    let mut cursor = 0;
    for (start, end) in spans {
        if start < cursor {
            // Overlapping with an already-spliced span (e.g. a type-keyword
            // skip and the bare-key match both landing on the same value) —
            // already covered.
            continue;
        }
        let value = &line[start..end];
        let core_len = value.trim_end_matches([';', ',', '{', '}']).len();
        let punct_start = start + core_len;
        result.push_str(&line[cursor..start]);
        result.push_str(PLACEHOLDER);
        result.push_str(&line[punct_start..end]);
        cursor = end;
    }
    result.push_str(&line[cursor..]);
    result
}

/// Find every denylisted key token on `line` and return the span of the
/// value that follows each one, for `key=value`, `key: value` / `key:value`,
/// and bare `key value` forms — a line can carry more than one `k=v` pair
/// (`psk=X password=Y`), and every one must be redacted, not just the first.
/// Each whitespace token is additionally split on [`SUBTOKEN_SPLIT_CHARS`]
/// before the `=`/`:` scan (R3), so a key buried inside a compound token
/// (`url=...&password=X`, `{"password":"X"}`) is still found, not just a key
/// that is the entire token. Quoted values (`key "value"`) are recognized via
/// [`quoted_value_end`] so a value containing whitespace is not truncated at
/// the first space, and never end before their enclosing token does (R4).
/// Returns an empty `Vec` when no denylisted key token is found this way.
fn denylisted_key_spans(line: &str) -> Vec<(usize, usize)> {
    let tokens = whitespace_token_spans(line);
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (i, &(s, e)) in tokens.iter().enumerate() {
        let mut matched_sep = false;
        for (ss, se) in subtoken_spans(line, s, e) {
            let text = &line[ss..se];
            for sep in ['=', ':'] {
                let Some(rel) = text.find(sep) else {
                    continue;
                };
                let key_part = &text[..rel];
                if !is_denylisted_key(key_part) {
                    continue;
                }
                matched_sep = true;
                let value_start = ss + rel + 1;
                if value_start < se {
                    spans.push((value_start, value_end_at_least(line, value_start, se)));
                } else if let Some(&(vs, ve)) = tokens.get(i + 1) {
                    // `key=`/`key:` with nothing else in this (sub)token: the
                    // value is the next whitespace token, if there is one.
                    spans.push((vs, value_end_at_least(line, vs, ve)));
                }
                break;
            }
        }
        if matched_sep {
            continue;
        }
        // Bare key token, no `=`/`:` attached to it.
        let bare_key = line[s..e].trim_end_matches([':', ';']);
        if !bare_key.is_empty()
            && is_denylisted_key(bare_key)
            && let Some(&(vs, ve)) = tokens.get(i + 1)
        {
            let next_token = &line[vs..ve];
            let is_keyword = is_value_type_keyword(next_token);
            // R1: anything that is not a real value-type keyword — a bare
            // separator (`password = X`), a Cisco-style digit type code
            // (`password 7 X`), or FortiOS's `ENC` marker (`psksecret ENC
            // X`) — is itself not the value, so token i+2 must be swept too,
            // not treated as an unrelated trailing token. The type keyword
            // itself is kept visible (it is a closed, known vocabulary, not
            // a secret); everything else is redacted along with the value,
            // which is the safe direction to over-redact in.
            let skip_over = is_keyword
                || is_lone_separator(next_token)
                || is_enc_token(next_token)
                || is_short_digit_code(next_token);
            if skip_over {
                if !is_keyword {
                    spans.push((vs, value_end_at_least(line, vs, ve)));
                }
                if let Some(&(vs2, ve2)) = tokens.get(i + 2) {
                    spans.push((vs2, value_end_at_least(line, vs2, ve2)));
                }
            } else {
                spans.push((vs, value_end_at_least(line, vs, ve)));
            }
        }
    }
    spans
}

/// Byte ranges of the *content* of every `"..."` / `'...'` span in `line`
/// (excluding the quote characters themselves), left to right. Whichever
/// quote character (`"` or `'`) opens first is the one that closes the span,
/// and the scan resumes after that close: scanning each quote kind
/// independently and merging the results can produce overlapping spans
/// whenever the two kinds nest (`"a'b"`).
fn quoted_content_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut idx = 0;
    while let Some(rel) = line[idx..].find(['"', '\'']) {
        let start = idx + rel;
        let quote = line[start..].chars().next().expect("find matched a char");
        if let Some(end_rel) = line[start + quote.len_utf8()..].find(quote) {
            let end = start + quote.len_utf8() + end_rel;
            spans.push((start + quote.len_utf8(), end));
            idx = end + quote.len_utf8();
        } else {
            // Unterminated quote: nothing further to pair it with.
            break;
        }
    }
    spans
}

/// Replace the content of every `"..."` or `'...'` span in `line`. Returns
/// `None` when there are no quoted spans, or when `force` is false and none
/// of them looks like a secret value (so the caller falls through to the
/// `=`/`:`/bare-token rules instead).
fn redact_quoted_spans(line: &str, force: bool) -> Option<String> {
    let spans = quoted_content_spans(line);
    if spans.is_empty() {
        return None;
    }
    let any_match = force
        || spans
            .iter()
            .any(|&(start, end)| looks_like_secret_value(&line[start..end]));
    if !any_match {
        return None;
    }
    Some(splice_spans(line, spans))
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
        // `authorization` is itself a denylisted key (F7, the HTTP
        // `Authorization` header) that happens to collide with Junos's SNMP
        // `authorization read-only|read-write` clause keyword here — after
        // N3 (every denylisted key on a line is redacted, not just the
        // first), its value is swept too. That is the safe direction to be
        // wrong in, and is why this no longer asserts "read-only" survives.
        let got = redact("set snmp community QQvalue6 authorization read-only");
        assert!(!got.contains("QQvalue6"), "got: {got}");
    }

    #[test]
    fn f2b_junos_hierarchical_form_redacts_the_value_not_the_brace() {
        let got = redact("community QQvalue5 {");
        assert!(!got.contains("QQvalue5"), "got: {got}");
        assert!(got.trim_end().ends_with('{'), "brace must survive: {got}");
    }

    // --- N1: a digit-free value must not be mistaken for a "type keyword"
    // and skipped in favor of redacting a later, unrelated token instead. ---

    #[test]
    fn n1_digit_free_community_value_is_redacted_directly_not_skipped() {
        let got = redact("set snmp community mycommunity authorization read-only");
        assert!(!got.contains("mycommunity"), "got: {got}");
    }

    #[test]
    fn n1_digit_free_hierarchical_value_is_redacted_not_the_brace() {
        let got = redact("community public {");
        assert!(!got.contains("public"), "got: {got}");
        assert!(got.trim_end().ends_with('{'), "brace must survive: {got}");
    }

    #[test]
    fn n1_real_type_keyword_still_skips_to_the_value_after_it() {
        let got = redact("set security ike policy p1 pre-shared-key ascii-text QQvalue1");
        assert!(!got.contains("QQvalue1"), "got: {got}");
        assert!(
            got.contains("ascii-text"),
            "the type keyword itself is not a secret: {got}"
        );
    }

    // --- N2: a quoted span elsewhere on a forced line must not
    // short-circuit redaction of the actual denylisted key's value. ---

    #[test]
    fn n2_unrelated_quoted_field_does_not_short_circuit_the_keyed_value() {
        let got = redact(r#"set snmp description "core" community QQvalue7"#);
        assert!(!got.contains("QQvalue7"), "got: {got}");
        assert!(
            got.contains("\"core\""),
            "unrelated quoted field must survive untouched: {got}"
        );
    }

    // --- N3: every denylisted key on a line must be redacted, not just the
    // first one found. ---

    #[test]
    fn n3_multiple_keyed_values_on_one_line_are_all_redacted() {
        let got = redact("psk=QQaaa1 password=QQbbb2");
        assert!(!got.contains("QQaaa1"), "got: {got}");
        assert!(!got.contains("QQbbb2"), "got: {got}");
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

    // --- R1 (mecmcp#386 re-review, regression from the N1 fix): a separator
    // or unlisted type token after a bare key must not be mistaken for the
    // value, leaving the real value one token further along exposed. ---

    #[test]
    fn r1_spaced_equals_separator_does_not_leak_the_value() {
        let got = redact("password = QQplainA");
        assert!(!got.contains("QQplainA"), "got: {got}");
    }

    #[test]
    fn r1_spaced_colon_separator_does_not_leak_the_value() {
        let got = redact("password : QQplainB");
        assert!(!got.contains("QQplainB"), "got: {got}");
    }

    #[test]
    fn r1_fortios_enc_marker_does_not_leak_the_value() {
        let got = redact("set psksecret ENC QQfortiValueA");
        assert!(!got.contains("QQfortiValueA"), "got: {got}");
    }

    #[test]
    fn r1_cisco_type_seven_code_does_not_leak_the_value() {
        let got = redact("username admin password 7 QQtypeSeven");
        assert!(!got.contains("QQtypeSeven"), "got: {got}");
    }

    #[test]
    fn r1_cisco_type_five_code_does_not_leak_the_value() {
        let got = redact("enable secret 5 QQx");
        assert!(!got.contains("QQx"), "got: {got}");
    }

    #[test]
    fn r1_spaced_separator_leak_also_reaches_xml_text_nodes_via_n5() {
        let xml = "<m>psk=QQa1 password = QQsp2</m>";
        let got = crate::xml::redact(xml).expect("valid xml");
        assert!(!got.contains("QQa1"), "got: {got}");
        assert!(!got.contains("QQsp2"), "got: {got}");
    }

    // --- R2 (mecmcp#386 re-review, regression from the N2 fix): once a
    // denylisted key match succeeds on a line, the quoted-span and
    // value-shape catch-all passes must still run over the rest of it. ---

    #[test]
    fn r2_bare_key_match_does_not_suppress_the_shape_pass_on_the_same_line() {
        let got = redact("secret QQnormal $9$abcdefghijklmnop");
        assert!(!got.contains("QQnormal"), "got: {got}");
        assert!(!got.contains("$9$abcdefghijklmnop"), "got: {got}");
    }

    #[test]
    fn r2_keyed_match_does_not_suppress_a_later_quoted_shape_match() {
        let got = redact(r#"password=QQx1 hash "$9$abcdefghijklmnopqrst""#);
        assert!(!got.contains("QQx1"), "got: {got}");
        assert!(!got.contains("$9$abcdefghijklmnopqrst"), "got: {got}");
    }

    #[test]
    fn r2_keyed_match_does_not_suppress_a_json_password_field_on_the_same_line() {
        let got = redact(r#"psk=QQa1 {"user":"bob","password":"QQjson2"}"#);
        assert!(!got.contains("QQa1"), "got: {got}");
        assert!(!got.contains("QQjson2"), "got: {got}");
    }

    // --- R3 (mecmcp#386 re-review, left over from N3): a key buried inside a
    // compound whitespace token (query string, `;`-joined pairs, inline
    // JSON) must be found too, not just a key that is the entire token. ---

    #[test]
    fn r3_key_inside_a_query_string_token_is_redacted() {
        let got = redact("psk=QQa1 url=https://h/?user=bob&password=QQurl2");
        assert!(!got.contains("QQa1"), "got: {got}");
        assert!(!got.contains("QQurl2"), "got: {got}");
    }

    #[test]
    fn r3_key_inside_a_semicolon_joined_token_is_redacted() {
        let got = redact("user=bob;password=QQsemi2 psk=QQa1");
        assert!(!got.contains("QQsemi2"), "got: {got}");
        assert!(!got.contains("QQa1"), "got: {got}");
    }

    // --- R4 (mecmcp#386 re-review): a quoted value that closes before its
    // token ends must not leave the tail behind. ---

    #[test]
    fn r4_trailing_text_after_an_early_closing_quote_is_redacted() {
        let got = redact(r#"password="ab"QQtail3"#);
        assert!(!got.contains("QQtail3"), "got: {got}");
    }
}
