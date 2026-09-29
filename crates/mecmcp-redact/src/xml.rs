//! Denylist-and-shape redaction over XML: NETCONF `<rpc-reply>` bodies and
//! vendor REST responses that come back as XML rather than JSON.
//!
//! Hand-rolling an XML scanner for this is exactly the trap the
//! parser-differentials lens warns about — two ad hoc scanners disagreeing
//! about where a tag ends is how a secret slips through the gap. This uses
//! `quick-xml`, the same parser family already vetted for this ecosystem
//! (`rustpanosmcp` depends on it), and rejects rather than guesses on
//! malformed input: [`redact`] returns [`crate::RedactError::InvalidXml`]
//! instead of emitting a best-effort partial result.

use crate::RedactError;
use crate::denylist::is_denylisted_key;
use crate::shape::looks_like_secret_value;
use quick_xml::events::attributes::Attribute;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::name::QName;
use quick_xml::{Reader, Writer};
use std::borrow::Cow;
use std::io::Cursor;

const PLACEHOLDER: &[u8] = b"[REDACTED]";

/// Redact secret element text and attribute values out of an XML document.
///
/// # Errors
/// Returns [`RedactError::InvalidXml`] when `input` does not parse as XML —
/// this crate never falls back to returning the input unredacted just
/// because it could not be understood.
pub fn redact(input: &str) -> Result<String, RedactError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(false);
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    let mut tag_stack: Vec<Vec<u8>> = Vec::new();

    loop {
        let event = reader
            .read_event()
            .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
        match event {
            Event::Eof => {
                if let Some(unclosed) = tag_stack.last() {
                    return Err(RedactError::InvalidXml(format!(
                        "unclosed element <{}>",
                        String::from_utf8_lossy(unclosed)
                    )));
                }
                break;
            }
            Event::Start(e) => {
                tag_stack.push(local_name(e.name()).to_vec());
                let rewritten = redact_attributes(&e, &tag_stack)?;
                writer
                    .write_event(Event::Start(rewritten))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::Empty(e) => {
                // An empty element (`<community name="..."/>`) is its own
                // open-and-close in one event — it never reaches the
                // `Event::Start`/`Event::End` pair that pushes its name onto
                // `tag_stack`, so without pushing it here a denylisted
                // element name on the empty form fails to redact its own
                // attributes even though the non-empty `<community
                // name="..."></community>` form does (N4).
                tag_stack.push(local_name(e.name()));
                let rewritten = redact_attributes(&e, &tag_stack)?;
                tag_stack.pop();
                writer
                    .write_event(Event::Empty(rewritten))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::End(e) => {
                tag_stack.pop();
                writer
                    .write_event(Event::End(e))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::Text(e) => {
                let ancestor_is_secret = any_ancestor_denylisted(&tag_stack);
                let redacted = redact_text_bytes(&e, ancestor_is_secret)?;
                writer
                    .write_event(Event::Text(redacted))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::CData(e) => {
                let decoded = e.into_inner().into_owned();
                let ancestor_is_secret = any_ancestor_denylisted(&tag_stack);
                let out = if ancestor_is_secret || looks_like_secret_value(&decoded) {
                    quick_xml::events::BytesCData::new(
                        String::from_utf8_lossy(PLACEHOLDER).into_owned(),
                    )
                } else {
                    // Run the text-path scan over every CDATA body, not just
                    // ones that already look like a multi-line blob or PEM —
                    // a single-line `user login password=X ok` payload (a
                    // Mist event, syslog-as-JSON) needs the same `k=v` scan
                    // (N5). `text::redact`'s non-forced path only touches
                    // known value shapes, so this is a no-op on ordinary
                    // CDATA.
                    quick_xml::events::BytesCData::new(crate::text::redact(&decoded))
                };
                writer
                    .write_event(Event::CData(out))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::Comment(e) => {
                let redacted = redact_comment(&e);
                writer
                    .write_event(Event::Comment(BytesText::from_escaped(escape_text(
                        &redacted,
                    ))))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            other => {
                writer
                    .write_event(other)
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
        }
    }

    String::from_utf8(writer.into_inner().into_inner())
        .map_err(|e| RedactError::InvalidXml(e.to_string()))
}

fn local_name(name: QName<'_>) -> Vec<u8> {
    name.local_name().as_ref().as_bytes().to_vec()
}

/// Validate that `input` is well-formed XML — every element opened is closed
/// before EOF — without redacting or otherwise transforming it.
///
/// This is the same depth tracking [`redact`] does via `tag_stack`, factored
/// out so `redact_xml_str`'s disabled-policy passthrough (which must not
/// redact, but still must not become a way to skip the "this is valid XML"
/// check every other entry point enforces) can reuse it instead of running a
/// second, easily-drifting scan loop (N7).
///
/// # Errors
/// Returns [`RedactError::InvalidXml`] on a parse error or an element left
/// open at EOF.
pub(crate) fn validate(input: &str) -> Result<(), RedactError> {
    let mut reader = Reader::from_str(input);
    let mut depth: usize = 0;
    loop {
        match reader
            .read_event()
            .map_err(|e| RedactError::InvalidXml(e.to_string()))?
        {
            Event::Eof => {
                return if depth > 0 {
                    Err(RedactError::InvalidXml(
                        "unclosed element at end of input".to_string(),
                    ))
                } else {
                    Ok(())
                };
            }
            Event::Start(_) => depth += 1,
            Event::End(_) => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
}

/// Whether any element currently open (not just the immediate parent) is a
/// denylisted key — a Junos SNMP community landing in `<name>` under
/// `<community>`, or a PSK in `<ascii-text>` under `<pre-shared-key>`, both
/// have a *grandparent*, not a parent, that names the secret.
fn any_ancestor_denylisted(tag_stack: &[Vec<u8>]) -> bool {
    tag_stack
        .iter()
        .any(|name| is_denylisted_key(&String::from_utf8_lossy(name)))
}

fn redact_attributes<'a>(
    start: &BytesStart<'a>,
    tag_stack: &[Vec<u8>],
) -> Result<BytesStart<'a>, RedactError> {
    let ancestor_is_secret = any_ancestor_denylisted(tag_stack);
    let mut out = BytesStart::new(start.name().as_ref().to_owned());
    for attr in start.attributes() {
        let attr = attr.map_err(|e| RedactError::InvalidXml(e.to_string()))?;
        let key = String::from_utf8_lossy(local_name(attr.key).as_slice()).into_owned();
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| RedactError::InvalidXml(e.to_string()))?
            .into_owned();
        let redacted_value =
            if ancestor_is_secret || is_denylisted_key(&key) || looks_like_secret_value(&value) {
                String::from_utf8_lossy(PLACEHOLDER).into_owned()
            } else {
                value
            };
        // Built directly rather than via `(&str, &str).into()`, which since
        // quick-xml 0.42 also escapes `\r`/`\n`/`\t` — see [`escape_text`].
        out.push_attribute(Attribute {
            key: attr.key,
            value: Cow::Owned(escape_text(&redacted_value)),
        });
    }
    Ok(out)
}

fn redact_text_bytes<'a>(
    text: &BytesText<'a>,
    ancestor_is_secret: bool,
) -> Result<BytesText<'static>, RedactError> {
    // quick-xml 0.42 stores text as `str`: deref yields the raw, still-escaped
    // content (no EOL normalization), which is what 0.41's `decode()`
    // returned for a `Reader::from_str` source.
    let raw: &str = text;
    let decoded = quick_xml::escape::unescape(raw)
        .map_err(|e| RedactError::InvalidXml(e.to_string()))?
        .into_owned();
    if ancestor_is_secret || looks_like_secret_value(&decoded) {
        Ok(
            BytesText::from_escaped(escape_text(&String::from_utf8_lossy(PLACEHOLDER)))
                .into_owned(),
        )
    } else {
        // Same reasoning as the CDATA branch above (N5): scan every text
        // node's body, not only ones that already look like an embedded
        // blob.
        Ok(BytesText::from_escaped(escape_text(&crate::text::redact(&decoded))).into_owned())
    }
}

/// Escape `<`, `>`, `&`, `'` and `"` — exactly the set quick-xml 0.41's
/// `escape` (used by `BytesText::new` and `Attribute::from((&str, &str))`)
/// replaced.
///
/// quick-xml 0.42 widened that set to also turn `\r` into `&#13;` (text and
/// attributes) and `\n`/`\t` into `&#10;`/`&#9;` (attributes). Pinning the
/// old set keeps this crate's output byte-identical across the upgrade: a
/// CRLF text node passes through as CRLF rather than gaining `&#13;`, which
/// would change what a downstream parser reads. Only the escaping of
/// *output* is affected; what gets redacted is decided before this runs.
fn escape_text(raw: &str) -> String {
    if !raw.contains(['<', '>', '&', '\'', '"']) {
        return raw.to_owned();
    }
    let mut out = String::with_capacity(raw.len() + 8);
    for ch in raw.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            other => out.push(other),
        }
    }
    out
}

fn redact_comment(text: &str) -> String {
    if let Some(idx) = text.find("## SECRET-DATA") {
        let (prefix, suffix) = text.split_at(idx);
        if prefix.trim().is_empty() {
            return text.to_string();
        }
        return format!("{}{suffix}", String::from_utf8_lossy(PLACEHOLDER));
    }
    if looks_like_secret_value(text) {
        return String::from_utf8_lossy(PLACEHOLDER).into_owned();
    }
    text.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;

    #[test]
    fn denylisted_element_text_is_redacted() {
        let xml = r#"<config><pre-shared-key>FAKEpsk12345</pre-shared-key></config>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEpsk12345"), "got: {got}");
    }

    #[test]
    fn denylisted_attribute_value_is_redacted() {
        let xml = r#"<user password="FAKEhunter2"/>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEhunter2"), "got: {got}");
    }

    #[test]
    fn nested_element_under_repeated_sibling_tags_is_redacted() {
        let xml = r#"<peers><peer><name>p1</name><psk>FAKEpsk1</psk></peer><peer><name>p2</name><psk>FAKEpsk2</psk></peer></peers>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("FAKEpsk1"), "got: {got}");
        assert!(!got.contains("FAKEpsk2"), "got: {got}");
        assert!(got.contains("p1") && got.contains("p2"));
    }

    #[test]
    fn value_shape_catch_all_applies_to_unknown_element_names() {
        let xml = r#"<totally-new-vendor-field>$6$fakesaltfakehash</totally-new-vendor-field>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("fakesaltfakehash"), "got: {got}");
    }

    #[test]
    fn unrelated_elements_are_untouched() {
        let xml = r#"<host><name>r1.example.net</name><vlan>100</vlan></host>"#;
        let got = redact(xml).unwrap();
        assert_eq!(got, xml);
    }

    #[test]
    fn malformed_xml_is_rejected_not_passed_through() {
        let err = redact("<unclosed><tag>").unwrap_err();
        assert!(matches!(err, RedactError::InvalidXml(_)));
    }

    #[test]
    fn f4a_denylisted_grandparent_element_redacts_descendant_text() {
        let xml = r#"<snmp><community><name>QQcommunity1</name></community></snmp>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQcommunity1"), "got: {got}");
    }

    #[test]
    fn f4a_denylisted_grandparent_redacts_nested_ascii_text() {
        let xml = r#"<pre-shared-key><ascii-text>QQpsk1</ascii-text></pre-shared-key>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQpsk1"), "got: {got}");
    }

    #[test]
    fn f4b_configuration_text_blob_is_scrubbed_for_embedded_secrets() {
        let xml = r#"<rpc-reply><configuration-text>set interfaces ge-0/0/0 unit 0
set security ike policy p1 pre-shared-key ascii-text "$9$fakehashvalue"; ## SECRET-DATA
</configuration-text></rpc-reply>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("fakehashvalue"), "got: {got}");
        assert!(
            got.contains("set interfaces ge-0/0/0 unit 0"),
            "unrelated config lines must survive: {got}"
        );
    }

    #[test]
    fn f4b_command_output_blob_is_scrubbed() {
        let xml = r#"<output>root:$6$fakesaltfakehash:19000:0:99999:7:::
another line</output>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("fakesaltfakehash"), "got: {got}");
        assert!(got.contains("another line"), "got: {got}");
    }

    // --- N4: a denylisted element name on the self-closing `Empty` form
    // must redact its own attributes exactly like the `Start`/`End` form. ---

    #[test]
    fn n4_denylisted_empty_element_attribute_is_redacted() {
        let xml = r#"<snmp><community name="QQcomm1"/></snmp>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQcomm1"), "got: {got}");
    }

    #[test]
    fn n4_denylisted_empty_element_under_entry_is_redacted() {
        let xml = r#"<entry><password value="QQpw2"/></entry>"#;
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQpw2"), "got: {got}");
    }

    // --- N5: a single-line `k=v` secret inside an otherwise ordinary text
    // node must be caught by the text-path scan, not just multi-line blobs
    // or PEM/`SECRET-DATA` markers. ---

    #[test]
    fn n5_single_line_kv_secret_in_text_node_is_redacted() {
        // X1 (mecmcp#386 re-review): the value locator redacts to the end
        // of the text node once the key is found, so trailing text after
        // the secret (`ok`) is swept too — the accepted over-redaction
        // cost; only the text *before* the key is unaffected.
        let xml = "<message>user login password=QQvalue9 ok</message>";
        let got = redact(xml).unwrap();
        assert!(!got.contains("QQvalue9"), "got: {got}");
        assert!(got.contains("user login"), "got: {got}");
    }

    // --- quick-xml 0.42 widened its output escaping (`\r` in text,
    // `\r`/`\n`/`\t` in attributes). Output must stay byte-identical to the
    // 0.41-era behaviour pinned here. ---

    #[test]
    fn crlf_text_and_comment_pass_through_unescaped() {
        let xml = "<?xml version=\"1.0\"?>\r\n<!-- a < b\r\n --><a>line1\r\nline2</a>";
        let got = redact(xml).unwrap();
        assert_eq!(
            got,
            "<?xml version=\"1.0\"?>\r\n<!-- a &lt; b\r\n --><a>line1\r\nline2</a>"
        );
    }

    #[test]
    fn attribute_whitespace_char_refs_are_not_re_escaped() {
        let xml = r#"<a x="v&#10;w" y="t&#9;u" z="c&#13;d" q="&amp;&lt;&gt;&quot;&apos;"/>"#;
        let got = redact(xml).unwrap();
        assert_eq!(
            got,
            "<a x=\"v\nw\" y=\"t\tu\" z=\"c\rd\" q=\"&amp;&lt;&gt;&quot;&apos;\"/>"
        );
    }
}
