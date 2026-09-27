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

use crate::denylist::is_denylisted_key;
use crate::shape::looks_like_secret_value;
use crate::RedactError;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::name::QName;
use quick_xml::{Reader, Writer};
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
            Event::Eof => break,
            Event::Start(e) => {
                tag_stack.push(local_name(e.name()).to_vec());
                let rewritten = redact_attributes(&e)?;
                writer
                    .write_event(Event::Start(rewritten))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::Empty(e) => {
                let rewritten = redact_attributes(&e)?;
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
                let enclosing_key_is_secret = tag_stack
                    .last()
                    .map(|name| is_denylisted_key(&String::from_utf8_lossy(name)))
                    .unwrap_or(false);
                let redacted = redact_text_bytes(&e, enclosing_key_is_secret)?;
                writer
                    .write_event(Event::Text(redacted))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::CData(e) => {
                let text = e.into_inner();
                let decoded = String::from_utf8_lossy(&text).into_owned();
                let enclosing_key_is_secret = tag_stack
                    .last()
                    .map(|name| is_denylisted_key(&String::from_utf8_lossy(name)))
                    .unwrap_or(false);
                let out = if enclosing_key_is_secret || looks_like_secret_value(&decoded) {
                    quick_xml::events::BytesCData::new(
                        String::from_utf8_lossy(PLACEHOLDER).into_owned(),
                    )
                } else {
                    quick_xml::events::BytesCData::new(decoded)
                };
                writer
                    .write_event(Event::CData(out))
                    .map_err(|e| RedactError::InvalidXml(e.to_string()))?;
            }
            Event::Comment(e) => {
                let text = String::from_utf8_lossy(&e).into_owned();
                let redacted = redact_comment(&text);
                writer
                    .write_event(Event::Comment(BytesText::new(&redacted)))
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
    name.local_name().as_ref().to_vec()
}

fn redact_attributes<'a>(start: &BytesStart<'a>) -> Result<BytesStart<'a>, RedactError> {
    let mut out = BytesStart::new(String::from_utf8_lossy(start.name().as_ref()).into_owned());
    for attr in start.attributes() {
        let attr = attr.map_err(|e| RedactError::InvalidXml(e.to_string()))?;
        let key = String::from_utf8_lossy(local_name(attr.key).as_slice()).into_owned();
        let value = attr
            .unescape_value()
            .map_err(|e| RedactError::InvalidXml(e.to_string()))?
            .into_owned();
        let redacted_value = if is_denylisted_key(&key) || looks_like_secret_value(&value) {
            String::from_utf8_lossy(PLACEHOLDER).into_owned()
        } else {
            value
        };
        out.push_attribute((
            String::from_utf8_lossy(attr.key.as_ref()).as_ref(),
            redacted_value.as_str(),
        ));
    }
    Ok(out)
}

fn redact_text_bytes<'a>(
    text: &BytesText<'a>,
    enclosing_key_is_secret: bool,
) -> Result<BytesText<'static>, RedactError> {
    let decoded = text
        .unescape()
        .map_err(|e| RedactError::InvalidXml(e.to_string()))?
        .into_owned();
    if enclosing_key_is_secret || looks_like_secret_value(&decoded) {
        Ok(BytesText::new(&String::from_utf8_lossy(PLACEHOLDER).into_owned()).into_owned())
    } else {
        Ok(BytesText::new(&decoded).into_owned())
    }
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
}
