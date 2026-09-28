//! Line-oriented redaction for unstructured text: flat vendor config dumps,
//! CLI output, and free-form log-ish blobs that are not valid XML or JSON.
//!
//! This is best-effort by construction — there is no grammar for "vendor CLI
//! output" to parse against. It runs a denylisted-key scan and the
//! [`crate::shape`] catch-all per line, plus a dedicated PEM-block and
//! `## SECRET-DATA` handler, and always **replaces** rather than "cleans" a
//! value: on ambiguity about where a value ends, it takes the larger span.
//!
//! X1 (mecmcp#386 re-review): the value locator does not try to guess how
//! many wrapper tokens (separators, type codes, `ENC` markers, ...) sit
//! between a denylisted key and its value. Once the key is found, everything
//! from the first non-punctuation token onward is redacted to the end of the
//! line — real vendor syntax puts an unbounded number of such tokens in
//! between, and guessing a fixed lookahead only ever produces another
//! counterexample. Over-redacting the rest of the line is the accepted cost.

use crate::denylist::is_denylisted_key;
use crate::shape::{is_pem_begin, is_pem_end, looks_like_secret_value};

const PLACEHOLDER: &str = "[REDACTED]";

/// Redact a block of unstructured text.
#[must_use]
pub fn redact(input: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut in_pem = false;
    // X1/Y1: block-scalar carry state — once a denylisted key's own line has
    // no complete inline value (a `key: |`/`key: >` marker, or nothing at
    // all after the colon), every following line indented more deeply than
    // the key line is its value, however many lines it spans and whatever
    // shape it takes (a scalar, a nested map, a sequence), and none of them
    // are visited by the per-line key/shape scan.
    let mut block_scalar_indent: Option<usize> = None;
    for line in input.split('\n') {
        let trimmed = line.trim().trim_end_matches('\r');

        if let Some(indent) = block_scalar_indent {
            let is_blank = trimmed.is_empty();
            if !is_blank && indent_len(line) <= indent {
                block_scalar_indent = None;
            } else if is_blank {
                // Blank lines inside a block scalar are part of its value in
                // YAML but never carry secret bytes themselves; pass through.
                out.push(line.to_string());
                continue;
            } else {
                let prefix = &line[..indent_len(line)];
                out.push(format!("{prefix}{PLACEHOLDER}"));
                continue;
            }
        }

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
        if let Some(colon) = trimmed.find(':') {
            let key_part = trimmed[..colon].trim();
            let tail = strip_yaml_comment(&trimmed[colon + 1..]).trim();
            // Y1: the same end-of-statement rule as X1, applied to a YAML
            // key rather than an inline value — for a denylisted key, the
            // "statement" is everything indented under it, whether that's a
            // block scalar (`key: |`), a nested map (`key:` with fields on
            // following lines), or a sequence (`key:` with `- item` lines).
            // An empty tail after stripping a trailing `# comment` covers
            // all three: block scalars are also caught explicitly so a
            // trailing chomp/indent modifier (`|2-`) is recognized even
            // though it isn't empty.
            if is_denylisted_key(key_part) && (tail.is_empty() || is_yaml_block_scalar_marker(tail))
            {
                out.push(redact_line(line));
                block_scalar_indent = Some(indent_len(line));
                continue;
            }
        }
        out.push(redact_line(line));
    }
    out.join("\n")
}

/// Byte length of the leading run of spaces/tabs on `line`.
fn indent_len(line: &str) -> usize {
    line.len() - line.trim_start_matches([' ', '\t']).len()
}

/// Strip a trailing YAML comment (` #...` to end of string) from `tail`, if
/// present. Requires the leading whitespace so a `#` inside an actual value
/// (a URL fragment, say) is not mistaken for a comment marker.
fn strip_yaml_comment(tail: &str) -> &str {
    match tail.find(" #") {
        Some(idx) => &tail[..idx],
        None => tail,
    }
}

/// Whether `tail` (the text after a `key:`) is a YAML block-scalar
/// indicator: `|` or `>`, optionally followed by a chomping modifier (`+`,
/// `-`) or an explicit indentation-indicator digit (`|2`, `>-1`, ...). When
/// it is, the value is not on this line at all — it is every following line
/// indented more deeply than the key.
fn is_yaml_block_scalar_marker(tail: &str) -> bool {
    let trimmed = tail.trim();
    let mut chars = trimmed.chars();
    match chars.next() {
        Some('|' | '>') => {}
        _ => return false,
    }
    chars.all(|c| c == '+' || c == '-' || c.is_ascii_digit())
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
    // own: the denylisted-key matches (each running to the end of the line,
    // per X1), every quoted span that itself looks like a secret value, and
    // every whitespace token that looks like one — a line can carry a keyed
    // value (`password=X`) *and* an unrelated shape-matching value the key
    // scan never touches (`secret X $9$hash`, `password=X hash "$9$hash"`).
    // Splicing once over the union (rather than returning as soon as the key
    // scan finds something) is what keeps the quoted-span and shape passes
    // from being silently skipped whenever a key happens to match earlier on
    // the same line.
    if force {
        let key_spans = denylisted_key_spans(line);
        // S2: when no denylisted key was found on a forced line (a `##
        // SECRET-DATA` marker with an unrecognized field name, say), every
        // quoted span must still be redacted regardless of shape — the old
        // unconditional quoted-span fallback this replaced is exactly the
        // backstop `## SECRET-DATA` exists for, and it must not fail open.
        let no_keyed_value = key_spans.is_empty();
        let mut spans = key_spans;
        spans.extend(shape_matching_spans(line));
        if no_keyed_value {
            spans.extend(quoted_content_spans(line));
        }
        if !spans.is_empty() {
            return splice_spans(line, spans);
        }
        // Nothing keyed, quoted, or shape-matched: fall through to the
        // unconditional `=`/`:`/last-token redaction below so a forced line
        // still never passes through untouched.
    } else {
        // S3: a shape-matching quoted span must not suppress the same shape
        // check over the rest of the line (`foo "$9$aaa" bar $9$bbb` must
        // redact both hashes, not just the quoted one).
        let spans = shape_matching_spans(line);
        if !spans.is_empty() {
            return splice_spans(line, spans);
        }
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
/// one of these is a closed, known vocabulary, so it is safe to keep visible
/// rather than folding it into the redacted span like everything else X1
/// sweeps to the end of the line.
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

/// Byte offset where a value begins, searching forward from whitespace-token
/// index `from` for the first token that contains at least one alphanumeric
/// character — i.e. is not pure separator/structural punctuation (`=`, `:`,
/// `{`, `&`, a bare quote pair, a Cisco-style `->`/`:=` arrow, ...). Bare
/// punctuation never carries the secret itself (X1, subsuming the old R1/S4
/// separator check); skipping it is what keeps `password = X`,
/// `password { X }`, and `password: & X` from mistaking the separator for
/// the value.
///
/// When that token is a known [`VALUE_TYPE_KEYWORDS`] entry, the keyword
/// itself is not the secret either (N1) — it is kept visible by continuing
/// the search past it, one keyword at a time, rather than being folded into
/// the redacted span like an unrecognized wrapper token is.
///
/// Once this offset is found, the caller redacts everything from it to the
/// end of the line (X1): unlike the value-type keywords, there is no closed
/// vocabulary of "things vendors put between a key and its value" to skip
/// past one token at a time, so the only fail-closed choice is to stop
/// trying to guess where the value ends.
fn first_value_start(line: &str, tokens: &[(usize, usize)], from: usize) -> Option<usize> {
    let j = (from..tokens.len()).find(|&j| {
        let (s, e) = tokens[j];
        line[s..e].chars().any(|c| c.is_ascii_alphanumeric())
    })?;
    let (s, e) = tokens[j];
    if is_value_type_keyword(&line[s..e]) {
        first_value_start(line, tokens, j + 1)
    } else {
        Some(s)
    }
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
            // Overlapping with an already-spliced span (e.g. two denylisted
            // keys on the same line, each redacting to the end of it) —
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

/// Find every denylisted key token on `line` and return the span from the
/// start of its value to the **end of the line** (X1) — for `key=value`,
/// `key: value` / `key:value`, and bare `key value` forms. A line can carry
/// more than one `k=v` pair (`psk=X password=Y`), and every one must be
/// found, not just the first; each redacts to the end of the line
/// regardless, so overlap between them is harmless and expected.
///
/// Each whitespace token is additionally split on [`SUBTOKEN_SPLIT_CHARS`]
/// before the `=`/`:` scan (R3), so a key buried inside a compound token
/// (`url=...&password=X`, `{"password":"X"}`) is still found, not just a key
/// that is the entire token. Returns an empty `Vec` when no denylisted key
/// token is found this way.
fn denylisted_key_spans(line: &str) -> Vec<(usize, usize)> {
    let tokens = whitespace_token_spans(line);
    let mut spans: Vec<(usize, usize)> = Vec::new();
    for (i, &(s, e)) in tokens.iter().enumerate() {
        let mut matched_sep = false;
        for (ss, se) in subtoken_spans(line, s, e) {
            let text = &line[ss..se];
            let mut matched_this_subtoken = false;
            for sep in ['=', ':'] {
                let Some(rel) = text.find(sep) else {
                    continue;
                };
                let key_part = &text[..rel];
                if !is_denylisted_key(key_part) {
                    continue;
                }
                matched_sep = true;
                matched_this_subtoken = true;
                let value_start = ss + rel + 1;
                let has_value_here = line[value_start..e]
                    .chars()
                    .any(|c| !SUBTOKEN_SPLIT_CHARS.contains(&c));
                if has_value_here {
                    // `key=value...`: everything from the first byte of the
                    // value to the end of the line is redacted (X1), not
                    // just this whitespace token — `password=X more words`
                    // is a real multi-word secret shape, not `X` followed by
                    // unrelated content.
                    spans.push((value_start, line.len()));
                } else if let Some(vstart) = first_value_start(line, &tokens, i + 1) {
                    // `key=`/`key:` with nothing but structural punctuation
                    // after it in this token (`password=`, `password={`):
                    // the value starts at the next non-punctuation token, if
                    // there is one, and runs to the end of the line.
                    spans.push((vstart, line.len()));
                }
                break;
            }
            if matched_this_subtoken {
                // The value span above already extends to the end of the
                // line, so later sub-tokens of the same token have nothing
                // left to contribute.
                break;
            }
        }
        if matched_sep {
            continue;
        }
        // Bare key token, no `=`/`:` attached to it. The key itself only
        // ever contains `[A-Za-z0-9_-]` (X1's own compound-key convention);
        // cutting there — rather than matching the whole token, as before —
        // is what keeps a non-`=`/`:` separator glued directly onto the key
        // (`password->X`, `password|X`, `password#X`, `password/X`) from
        // being swallowed into the "key" and pushing the value search past
        // it to the *next* token, silently skipping the attached value (Y2).
        let key_end = s + line[s..e]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .unwrap_or(e - s);
        let bare_key = &line[s..key_end];
        if !bare_key.is_empty() && is_denylisted_key(bare_key) {
            if line[key_end..e].chars().any(|c| c.is_ascii_alphanumeric()) {
                // The rest of this token past the key already has value
                // content attached (`->X`, `|X`) — redact from there.
                spans.push((key_end, line.len()));
            } else if let Some(vstart) = first_value_start(line, &tokens, i + 1) {
                // Nothing but separator/structural punctuation left in this
                // token (`password:`, `password;`) — the value is the next
                // token, as before.
                spans.push((vstart, line.len()));
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

/// Byte range of the password in a `scheme://user:PASS@host` URL userinfo
/// component (X3). Credentials embedded in a URL's userinfo are not covered
/// by any keyed or crypt-hash shape check, and a recognized key elsewhere on
/// the same line (`psk=A url=https://admin:X@h/`) must not suppress this
/// pass — it is folded into [`shape_matching_spans`], which always runs.
fn userinfo_password_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut cursor = 0;
    while let Some(rel) = line[cursor..].find("://") {
        let authority_start = cursor + rel + 3;
        if authority_start > line.len() {
            break;
        }
        let rest = &line[authority_start..];
        let authority_len = rest
            .find(|c: char| c == '/' || c.is_whitespace())
            .unwrap_or(rest.len());
        let authority = &rest[..authority_len];
        // `rfind`, not `find`: a userinfo password can itself contain a
        // literal `@` (`admin:p@word@host`) — curl and git both split
        // userinfo from host on the *last* `@` in the authority, not the
        // first (Y4).
        if let Some(at_rel) = authority.rfind('@') {
            let userinfo = &authority[..at_rel];
            if let Some(colon_rel) = userinfo.find(':') {
                let pass_start = authority_start + colon_rel + 1;
                let pass_end = authority_start + at_rel;
                if pass_start < pass_end {
                    spans.push((pass_start, pass_end));
                }
            }
        }
        cursor = (authority_start + authority_len.max(1)).min(line.len());
    }
    spans
}

/// SNMPv3 `snmp-server user <name> <group> v3 auth <alg> X priv <alg>
/// [bits] Y` (X2): the authentication and privacy keys are not carried by
/// any denylisted key token — `auth`/`priv` are too generic to denylist
/// outright without matching unrelated words — so they are only treated as
/// secret-bearing when they follow a `snmp-server user` clause on the same
/// line, and each redacts to the end of the line like any other X1 match.
fn snmpv3_auth_priv_spans(line: &str) -> Vec<(usize, usize)> {
    let tokens = whitespace_token_spans(line);
    // Tokenized, case-insensitive, whitespace-width-independent match for
    // adjacent `snmp-server`/`user` tokens (Y3) — the old exact substring
    // check (`line.contains("snmp-server user")`) missed any other casing
    // and any run of whitespace longer than a single space.
    let Some(user_idx) = tokens.windows(2).position(|pair| {
        let (s0, e0) = pair[0];
        let (s1, e1) = pair[1];
        line[s0..e0].eq_ignore_ascii_case("snmp-server")
            && line[s1..e1].eq_ignore_ascii_case("user")
    }) else {
        return Vec::new();
    };
    let mut spans = Vec::new();
    for (i, &(s, e)) in tokens.iter().enumerate().skip(user_idx + 2) {
        let text = &line[s..e];
        if (text.eq_ignore_ascii_case("auth") || text.eq_ignore_ascii_case("priv"))
            && let Some(vstart) = first_value_start(line, &tokens, i + 1)
        {
            spans.push((vstart, line.len()));
        }
    }
    spans
}

/// Union of every quoted span and every whitespace token on `line` that
/// itself looks like a secret value (S3), plus the URL-userinfo (X3) and
/// SNMPv3 auth/priv (X2) passes: all run independently rather than the
/// first match short-circuiting the rest, since a line can carry more than
/// one shape-matching value and only some of them are quoted or keyed
/// (`foo "$9$aaa" bar $9$bbb`).
fn shape_matching_spans(line: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
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
    spans.extend(userinfo_password_spans(line));
    spans.extend(snmpv3_auth_priv_spans(line));
    spans
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
    fn f2a_equals_form_redacts_the_matching_keys_value_to_end_of_line() {
        // X1: once the value is located, everything to the end of the line
        // is redacted with it — `src=192.0.2.1` no longer survives here,
        // which is the accepted over-redaction cost the re-review calls out
        // (`community X authorization read-only` -> `community
        // [REDACTED]`). Only the *preceding* field is unaffected.
        let got = redact("login ok user=admin password=QQvalue8 src=192.0.2.1");
        assert!(!got.contains("QQvalue8"), "got: {got}");
        assert!(
            got.contains("user=admin"),
            "field before the key is untouched: {got}"
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
            "unrelated quoted field before the key must survive untouched: {got}"
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

    // --- S1 (mecmcp#386 re-review, regression from the R3 fix): the
    // sub-token split must not truncate a keyed value at the first
    // `& ; , ? { }` — a generated PSK/password routinely contains one. ---

    #[test]
    fn s1_comma_inside_a_keyed_value_does_not_truncate_it() {
        let got = redact("password=QQp1,QQp2");
        assert!(!got.contains("QQp1"), "got: {got}");
        assert!(!got.contains("QQp2"), "got: {got}");
    }

    #[test]
    fn s1_semicolon_inside_a_keyed_value_does_not_truncate_it() {
        let got = redact("password=QQs1;QQs2");
        assert!(!got.contains("QQs1"), "got: {got}");
        assert!(!got.contains("QQs2"), "got: {got}");
    }

    #[test]
    fn s1_ampersand_inside_a_keyed_value_does_not_truncate_it() {
        let got = redact("password=QQa1&QQa2");
        assert!(!got.contains("QQa1"), "got: {got}");
        assert!(!got.contains("QQa2"), "got: {got}");
    }

    #[test]
    fn s1_question_mark_inside_a_keyed_value_does_not_truncate_it() {
        let got = redact("psk=QQq1?QQq2");
        assert!(!got.contains("QQq1"), "got: {got}");
        assert!(!got.contains("QQq2"), "got: {got}");
    }

    #[test]
    fn s1_brace_inside_a_keyed_value_does_not_truncate_it() {
        let got = redact("password=QQb1}QQb2");
        assert!(!got.contains("QQb1"), "got: {got}");
        assert!(!got.contains("QQb2"), "got: {got}");
    }

    #[test]
    fn s1_comma_inside_a_json_string_leaf_does_not_truncate_it() {
        let got = crate::redact_json_str(r#"{"note":"password=QQz1,QQz2"}"#).expect("valid json");
        assert!(!got.contains("QQz1"), "got: {got}");
        assert!(!got.contains("QQz2"), "got: {got}");
    }

    // --- S2 (mecmcp#386 re-review, regression from the R2 refactor): a
    // forced line with no keyed value and no shape match must still
    // force-redact every quoted span — `## SECRET-DATA` is Junos's own
    // backstop for secrets under keys we don't list and must not fail open.

    #[test]
    fn s2_forced_quoted_span_with_no_shape_match_is_still_redacted() {
        let got = redact(r#"foo "QQf1 two" bar ## SECRET-DATA"#);
        assert!(!got.contains("QQf1"), "got: {got}");
    }

    #[test]
    fn s2_forced_quoted_span_before_a_semicolon_is_still_redacted() {
        let got = redact(r#"foo "QQf2"; ## SECRET-DATA"#);
        assert!(!got.contains("QQf2"), "got: {got}");
    }

    #[test]
    fn s2_forced_quoted_span_under_an_unlisted_key_is_still_redacted() {
        let got = redact(r#"hmac-key "QQg6 x"; ## SECRET-DATA"#);
        assert!(!got.contains("QQg6"), "got: {got}");
    }

    // --- S3 (pre-existing, same class as R2 on the non-forced path): a
    // shape-matching quoted span must not suppress the shape pass over the
    // rest of the line. ---

    #[test]
    fn s3_shape_match_outside_quotes_is_redacted_even_after_a_quoted_shape_match() {
        let got = redact(r#"foo "$9$aaaaaaaaaaaaaaaa" bar $9$bbbbbbbbbbbbbbbb"#);
        assert!(!got.contains("aaaaaaaaaaaaaaaa"), "got: {got}");
        assert!(!got.contains("bbbbbbbbbbbbbbbb"), "got: {got}");
    }

    // --- S4 (optional): any token made only of separator characters is a
    // separator, not the value. ---

    #[test]
    fn s4_walrus_style_separator_does_not_leak_the_value() {
        let got = redact("password := QQw1");
        assert!(!got.contains("QQw1"), "got: {got}");
    }

    #[test]
    fn s4_arrow_separator_does_not_leak_the_value() {
        let got = redact("password -> QQw2");
        assert!(!got.contains("QQw2"), "got: {got}");
    }

    #[test]
    fn s4_double_equals_separator_does_not_leak_the_value() {
        let got = redact("password == QQw3");
        assert!(!got.contains("QQw3"), "got: {got}");
    }

    // --- T1 (mecmcp#386 re-review, regression from R3/S1): a keyed value
    // that *starts* with a SUBTOKEN_SPLIT_CHARS character (`password=&X`)
    // has an empty sub-token after the `=`, so `denylisted_key_spans`
    // mistook the value for absent and redacted the *next whitespace
    // token* instead, leaking the real secret in plain sight. ---

    #[test]
    fn t1_value_starting_with_ampersand_is_redacted() {
        // X1: the value now redacts to the end of the line, so the
        // unrelated trailing words this test used to assert survive
        // (`user`, `bob`) are swallowed too — the accepted over-redaction
        // cost, same as f2a.
        let got = redact("password=&QQm3 user bob");
        assert!(!got.contains("QQm3"), "got: {got}");
    }

    #[test]
    fn t1_value_starting_with_comma_does_not_leak_a_later_key() {
        let got = redact("password=,QQm1 psk=QQm2");
        assert!(!got.contains("QQm1"), "got: {got}");
        assert!(!got.contains("QQm2"), "got: {got}");
    }

    #[test]
    fn t1_value_starting_with_brace_is_redacted() {
        let got = redact("psk={QQm4} x");
        assert!(!got.contains("QQm4"), "got: {got}");
    }

    #[test]
    fn t1_value_starting_with_ampersand_inside_a_query_string_is_redacted() {
        let got = redact("a=1&password=&QQm5&b=2");
        assert!(!got.contains("QQm5"), "got: {got}");
    }

    #[test]
    fn u1_split_char_only_value_then_whitespace_does_not_leak_next_token() {
        for (input, secret) in [
            ("password={ QQu1 }", "QQu1"),
            ("password=& QQu2", "QQu2"),
            ("psk=; QQu3", "QQu3"),
            ("password=, QQu4", "QQu4"),
        ] {
            let got = redact(input);
            assert!(!got.contains(secret), "input: {input} got: {got}");
        }
    }

    #[test]
    fn v1_punctuation_only_token_between_key_and_value_does_not_leak() {
        for (input, secret) in [
            ("password { QQv1 }", "QQv1"),
            ("password: { QQv2 }", "QQv2"),
            ("password = { QQv3 }", "QQv3"),
            ("psk & QQv4", "QQv4"),
            ("secret ; QQv5", "QQv5"),
            ("password: & QQv6", "QQv6"),
            ("password=& ; QQv7", "QQv7"),
        ] {
            let got = redact(input);
            assert!(!got.contains(secret), "input: {input} got: {got}");
        }
    }

    // --- W1 (mecmcp#386 re-review, sibling gap to V1): the `key=`/`key:`
    // empty-value branch found its value token via a lookahead but, unlike
    // the bare-key branch, never checked whether that token was itself a
    // separator/digit-code/ENC-marker/type-keyword rather than the real
    // value — so `password= - QQw1` redacted the `-` and left the real
    // secret one token further along exposed. ---

    #[test]
    fn w1_separator_or_type_token_after_attached_equals_or_colon_does_not_leak() {
        for (input, secret) in [
            ("password= - QQw1", "QQw1"),
            ("password= 7 QQw2", "QQw2"),
            ("password: ENC QQw3", "QQw3"),
            ("psk: -> QQw4", "QQw4"),
            ("secret= 5 QQw5", "QQw5"),
            ("password: ascii-text QQw6", "QQw6"),
        ] {
            let got = redact(input);
            assert!(!got.contains(secret), "input: {input} got: {got}");
        }
    }

    #[test]
    fn w1_type_keyword_after_attached_colon_stays_visible() {
        let got = redact("password: ascii-text QQw7");
        assert!(!got.contains("QQw7"), "got: {got}");
        assert!(
            got.contains("ascii-text"),
            "the type keyword itself is not a secret: {got}"
        );
    }

    // --- X1 (mecmcp#386 re-review, structural fix): fail closed to the end
    // of the statement rather than looking ahead a fixed number of tokens.
    // Every input from the re-review's counterexample table, table-driven so
    // each one fails against d4ae4c4 and passes here. ---

    #[test]
    fn x1_multi_token_wrappers_between_key_and_value_do_not_leak() {
        for (input, secret) in [
            ("enable password level 15 Summer2024", "Summer2024"),
            (
                "ntp authentication-key 1 md5 104D000A0618 7",
                "104D000A0618",
            ),
            ("enable secret level 15 0 QQa2plain", "QQa2plain"),
            ("psksecret = ENC QQa7", "QQa7"),
            ("pre-shared-key = ascii-text QQa8", "QQa8"),
            ("password = 7 QQa5", "QQa5"),
            ("secret 5 = QQf7", "QQf7"),
            ("password == = QQd2", "QQd2"),
            ("password ( QQb1 )", "QQb1"),
            ("password [ QQb2 ]", "QQb2"),
            ("password=( QQb3 )", "QQb3"),
            ("password | QQb4", "QQb4"),
            ("password <- QQb5", "QQb5"),
            ("password: # QQb6", "QQb6"),
            ("password is QQb7", "QQb7"),
            ("psk \"\" QQc1", "QQc1"),
            ("password '' QQc2", "QQc2"),
            ("password=\"\" QQc3", "QQc3"),
            ("password = QQd1 horse battery", "QQd1"),
            ("wpa_passphrase=QQd2horse horse battery", "QQd2horse"),
        ] {
            let got = redact(input);
            assert!(!got.contains(secret), "input: {input} got: {got}");
        }
    }

    #[test]
    fn t1_x1_end_of_statement_redacts_every_word_of_a_multi_word_secret() {
        // MEC-385 T1: these two rows already passed against e29f2d5 on the
        // narrow `!got.contains(secret)` check above because the old code
        // redacted the first word of the value — the bug X1 fixes is that
        // `horse battery` survived past it. Assert every word is gone, so
        // this fails against d4ae4c4 (pre-X1) the way it should have.
        for (input, words) in [
            (
                "password = QQd1 horse battery",
                ["QQd1", "horse", "battery"],
            ),
            (
                "wpa_passphrase=QQd2horse horse battery",
                ["QQd2horse", "horse", "battery"],
            ),
        ] {
            let got = redact(input);
            for word in words {
                assert!(!got.contains(word), "input: {input} got: {got}");
            }
        }
    }

    #[test]
    fn x1_yaml_block_scalar_value_on_a_following_indented_line_is_redacted() {
        let got = redact("password: |\n  QQyaml1\nnext_field: ok");
        assert!(!got.contains("QQyaml1"), "got: {got}");
        assert!(got.contains("next_field: ok"), "got: {got}");
    }

    #[test]
    fn x1_yaml_block_scalar_folded_indicator_with_chomp_is_redacted() {
        let got = redact("secret: >-\n    QQyaml2\n    QQyaml3\nhost: r1");
        assert!(!got.contains("QQyaml2"), "got: {got}");
        assert!(!got.contains("QQyaml3"), "got: {got}");
        assert!(got.contains("host: r1"), "got: {got}");
    }

    #[test]
    fn x1_yaml_block_scalar_carry_ends_at_dedent() {
        let got = redact("password: |\n  QQyaml4\nsibling: visible");
        assert!(!got.contains("QQyaml4"), "got: {got}");
        assert!(got.contains("sibling: visible"), "got: {got}");
    }

    // --- X2 (mecmcp#386 re-review): denylist gaps for common IOS/SNMP
    // credential keys. ---

    #[test]
    fn x2_ios_key_chain_key_string_is_redacted() {
        let got = redact("key-string QQe1");
        assert!(!got.contains("QQe1"), "got: {got}");
    }

    #[test]
    fn x2_ospf_message_digest_key_is_redacted() {
        let got = redact("ip ospf message-digest-key 1 md5 QQe2");
        assert!(!got.contains("QQe2"), "got: {got}");
    }

    #[test]
    fn x2_snmpv3_auth_and_priv_keys_are_redacted() {
        let got = redact("snmp-server user u g v3 auth sha QQe3 priv aes 128 QQe4");
        assert!(!got.contains("QQe3"), "got: {got}");
        assert!(!got.contains("QQe4"), "got: {got}");
    }

    #[test]
    fn x2_auth_priv_keywords_off_an_snmp_user_line_are_not_specially_swept() {
        // Sanity check that the SNMPv3 special case is scoped to
        // `snmp-server user` lines and does not fire on unrelated uses of
        // the words "auth"/"priv".
        let got = redact("auth priv are just words here");
        assert_eq!(got, "auth priv are just words here");
    }

    // --- X3 (mecmcp#386 re-review): a recognized key on the line must not
    // suppress the URL-userinfo shape check for the rest of it. ---

    #[test]
    fn x3_url_userinfo_password_is_redacted_even_with_an_unrelated_keyed_value() {
        let got = redact("psk=QQf1 url=https://admin:QQf2@host/api");
        assert!(!got.contains("QQf1"), "got: {got}");
        assert!(!got.contains("QQf2"), "got: {got}");
    }

    #[test]
    fn x3_url_userinfo_password_is_redacted_with_no_denylisted_key_on_the_line() {
        let got = redact("output: https://admin:QQf3@host/api");
        assert!(!got.contains("QQf3"), "got: {got}");
        assert!(got.contains("admin"), "username is not the secret: {got}");
    }

    // --- Y1 (MEC-385, mecmcp#386 re-review): the X1 block-scalar carry must
    // also start when a denylisted key's line has *no* inline value at all,
    // not only on a bare `|`/`>` marker — the value is on a following,
    // more-indented line (or lines) either way. Each row fails against
    // e29f2d5. ---

    #[test]
    fn y1_yaml_next_line_values_are_redacted() {
        for (input, secret) in [
            ("secrets:\n  db_primary: hunter2", "hunter2"),
            ("  password:\n    QQy3", "QQy3"),
            ("snmp:\n  community:\n    - public2x", "public2x"),
            ("password: |  # comment\n  QQy1", "QQy1"),
        ] {
            let got = redact(input);
            assert!(!got.contains(secret), "input: {input:?} got: {got:?}");
        }
    }

    #[test]
    fn y1_non_denylisted_empty_key_does_not_start_a_block_scalar_carry() {
        // Sanity check: an empty-value key that is not denylisted must not
        // swallow the following line.
        let got = redact("host:\n  password: QQy5");
        assert!(!got.contains("QQy5"), "got: {got}");
        assert!(got.contains("host:"), "got: {got}");
    }

    // --- Y2 (MEC-385, mecmcp#386 re-review): a non-`=`/`:` separator
    // attached directly to a denylisted key, with no whitespace between
    // them, must not let the value hide in the same token as the key. Each
    // row fails against e29f2d5. ---

    #[test]
    fn y2_attached_non_standard_separator_does_not_leak_the_value() {
        for (input, secret) in [
            ("password->QQp1 trailing", "QQp1"),
            ("password|QQp2 y", "QQp2"),
            ("password#QQp3 y", "QQp3"),
            ("password/QQp4 y", "QQp4"),
        ] {
            let got = redact(input);
            assert!(!got.contains(secret), "input: {input} got: {got}");
        }
    }

    // --- Y3 (MEC-385, mecmcp#386 re-review): the SNMPv3 auth/priv sweep
    // must be tokenized, not an exact-substring match on `snmp-server
    // user`, so different casing or run of whitespace still trigger it. ---

    #[test]
    fn y3_snmpv3_sweep_is_case_and_whitespace_insensitive() {
        for input in [
            "SNMP-SERVER USER u g v3 auth sha QQe5",
            "snmp-server  user u g v3 auth sha QQe6",
        ] {
            let got = redact(input);
            assert!(
                !got.contains("QQe5") && !got.contains("QQe6"),
                "input: {input} got: {got}"
            );
        }
    }

    // --- Y4 (MEC-385, mecmcp#386 re-review): a URL userinfo password that
    // itself contains a literal `@` must be redacted in full, splitting the
    // authority on the *last* `@` like curl and git do. ---

    #[test]
    fn y4_userinfo_password_containing_at_sign_is_fully_redacted() {
        let got = redact("https://admin:p@QQu1@host/");
        assert!(!got.contains("p@QQu1"), "got: {got}");
        assert!(!got.contains("QQu1"), "got: {got}");
    }
}
