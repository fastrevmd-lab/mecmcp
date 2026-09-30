//! Project device XML into JSON.
//!
//! A NETCONF `rpc-reply` or a vendor REST response that comes back as XML
//! reaches a handler as text. Handed straight to [`crate::tool_result`] as a
//! string, it survives as one long escaped blob inside pretty-printed JSON —
//! a 512 KiB reply can spend over 100,000 model tokens re-quoting angle
//! brackets the model never needed to see literally. [`xml_to_json`] parses
//! that text once and returns the same information as a [`serde_json::Value`]
//! tree, so a handler can hand a model structured data instead of a string
//! that happens to contain markup.
//!
//! This is a **shape** transform, not a **trust** one: run
//! [`mecmcp_redact::redact_xml_str`] over the device text first if it might
//! carry a secret, same as any other device response. [`xml_to_json`] does not
//! redact, and it does not know a vendor's element names or schema — it turns
//! the same document into a different serialization of itself, nothing more.
//!
//! ## The mapping
//!
//! - An element with no attributes and no child elements becomes its text
//!   content: `<name>fw-01</name>` → `"fw-01"`; an empty or all-whitespace
//!   element becomes `null`.
//! - An element with attributes and/or child elements becomes an object.
//!   Attributes are keyed `@name`; non-whitespace text alongside attributes or
//!   children is kept as `#text`, since neither can otherwise sit next to a
//!   sibling field without one silently overwriting the other.
//! - Repeated child element names become a JSON array in document order;
//!   an element name seen exactly once stays a scalar. This is the one
//!   genuine ambiguity in XML→JSON: nothing in the document says whether a
//!   future reply would repeat that element, so a caller that always wants an
//!   array for a given field must ask for that field explicitly rather than
//!   read the shape of a single reply.
//! - Parsing fails closed: malformed XML (an unclosed element, an unresolved
//!   entity reference) returns [`XmlProjectionError`] rather than a
//!   best-effort partial tree, same rule [`mecmcp_redact::redact_xml_str`]
//!   follows and for the same reason — a parser guessing at broken input is
//!   how two parsers of the same bytes end up disagreeing.
//! - Nesting past [`XmlProjectionError::TooDeep`]'s limit is refused for a
//!   different reason: no real device schema nests that deep, and building —
//!   then dropping — a [`serde_json::Value`] tree that deep can overflow the
//!   native stack even though parsing itself cannot.

use quick_xml::Reader;
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::name::QName;
use serde_json::{Map, Value};

/// `xml_to_json` could not turn `input` into JSON.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlProjectionError {
    /// `input` is not well-formed XML, or contains an entity reference this
    /// crate does not resolve. Carries the parser's own message, which never
    /// contains bytes from `input` itself.
    #[error("input is not well-formed XML, refusing to guess: {0}")]
    InvalidXml(String),
    /// `input` contains no root element.
    #[error("input has no root element")]
    Empty,
    /// `input` nests elements deeper than the configured limit.
    ///
    /// The parser itself walks an explicit stack, not recursion, so parsing
    /// a deep document cannot overflow the native stack. Building and later
    /// dropping the resulting [`Value`] tree can: `serde_json::Value`'s
    /// `Drop` recurses one stack frame per nesting level, and a hostile or
    /// merely buggy device reply nested deep enough turns that into an
    /// abort. Refusing past a bound no real device schema approaches keeps
    /// this projection a parse error away from that, not a crash away.
    #[error("input nests elements past the {MAX_DEPTH}-level limit")]
    TooDeep,
}

/// The deepest element nesting [`xml_to_json`] will project. See
/// [`XmlProjectionError::TooDeep`] for why this exists.
const MAX_DEPTH: usize = 512;

/// One element's state while its children and text are still being
/// collected. Finalized into a [`Value`] when its closing tag (or its own
/// `Empty` form) is seen.
struct OpenElement {
    tag: String,
    attributes: Map<String, Value>,
    /// Children in document order, so repeated-name grouping below can tell
    /// "seen once" from "seen more than once" without a second pass.
    children: Vec<(String, Value)>,
    text: String,
}

impl OpenElement {
    fn new(tag: String, attributes: Map<String, Value>) -> Self {
        Self {
            tag,
            attributes,
            children: Vec::new(),
            text: String::new(),
        }
    }

    /// Turn this element into the [`Value`] it contributes to its parent,
    /// per the mapping documented on [`xml_to_json`].
    fn finish(self) -> Value {
        let text = self.text.trim();
        if self.attributes.is_empty() && self.children.is_empty() {
            return if text.is_empty() {
                Value::Null
            } else {
                Value::String(text.to_owned())
            };
        }

        let mut object = self.attributes;
        if !text.is_empty() {
            object.insert("#text".to_owned(), Value::String(text.to_owned()));
        }
        for (name, value) in group_by_name(self.children) {
            object.insert(name, value);
        }
        Value::Object(object)
    }
}

/// Collapse a document-ordered list of `(tag, value)` pairs into one entry
/// per distinct tag: a single occurrence stays a scalar, repeats become an
/// array in the order they appeared.
fn group_by_name(children: Vec<(String, Value)>) -> Vec<(String, Value)> {
    let mut grouped: Vec<(String, Vec<Value>)> = Vec::new();
    for (name, value) in children {
        match grouped.iter_mut().find(|(existing, _)| *existing == name) {
            Some((_, values)) => values.push(value),
            None => grouped.push((name, vec![value])),
        }
    }
    grouped
        .into_iter()
        .map(|(name, mut values)| {
            let value = if values.len() == 1 {
                values.remove(0)
            } else {
                Value::Array(values)
            };
            (name, value)
        })
        .collect()
}

/// Project a device XML document into a [`serde_json::Value`] tree.
///
/// See the module documentation for the mapping and for why this does not
/// also redact — call [`mecmcp_redact::redact_xml_str`] on `input` first if
/// the document might carry a secret.
///
/// # Errors
/// Returns [`XmlProjectionError::InvalidXml`] on malformed XML or an
/// unresolvable entity reference, and [`XmlProjectionError::Empty`] when
/// `input` has no root element. Never returns a partial tree on error.
///
/// # Examples
/// ```
/// use mecmcp_server::xml_to_json;
///
/// let value = xml_to_json(
///     r#"<interfaces><interface id="ge-0/0/0"><enabled>true</enabled></interface></interfaces>"#,
/// )
/// .unwrap();
/// assert_eq!(value["interface"]["@id"], "ge-0/0/0");
/// assert_eq!(value["interface"]["enabled"], "true");
/// ```
pub fn xml_to_json(input: &str) -> Result<Value, XmlProjectionError> {
    let mut reader = Reader::from_str(input);
    reader.config_mut().trim_text(false);
    // Explicit stack rather than recursive descent: a handler that hands this
    // a malicious or just very deeply nested device reply must not be able to
    // turn "parse this XML" into a native stack overflow (no panics in
    // library code applies to aborts too, not only `panic!`).
    let mut stack: Vec<OpenElement> = Vec::new();
    let mut root: Option<Value> = None;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| XmlProjectionError::InvalidXml(e.to_string()))?;
        match event {
            Event::Eof => {
                if let Some(unclosed) = stack.last() {
                    return Err(XmlProjectionError::InvalidXml(format!(
                        "unclosed element <{}>",
                        unclosed.tag
                    )));
                }
                return root.ok_or(XmlProjectionError::Empty);
            }
            Event::Start(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlProjectionError::TooDeep);
                }
                let tag = local_name(e.name());
                let attributes = read_attributes(&e)?;
                stack.push(OpenElement::new(tag, attributes));
            }
            Event::Empty(e) => {
                let tag = local_name(e.name());
                let attributes = read_attributes(&e)?;
                let value = OpenElement::new(tag.clone(), attributes).finish();
                attach(&mut stack, &mut root, tag, value)?;
            }
            Event::End(_) => {
                let element = stack
                    .pop()
                    .ok_or_else(|| XmlProjectionError::InvalidXml("unmatched close tag".into()))?;
                let tag = element.tag.clone();
                let value = element.finish();
                attach(&mut stack, &mut root, tag, value)?;
            }
            Event::Text(e) => {
                let raw: &str = &e;
                let decoded = quick_xml::escape::unescape(raw)
                    .map_err(|e| XmlProjectionError::InvalidXml(e.to_string()))?;
                push_text(&mut stack, &decoded);
            }
            Event::CData(e) => {
                push_text(&mut stack, &e.into_inner());
            }
            Event::GeneralRef(e) => {
                push_text(&mut stack, &resolve_general_ref(&e)?);
            }
            // Declarations, comments, processing instructions, DOCTYPE: none
            // carry data a JSON projection would keep.
            _ => {}
        }
    }
}

fn push_text(stack: &mut [OpenElement], text: &str) {
    if let Some(top) = stack.last_mut() {
        top.text.push_str(text);
    }
    // Text outside any open element (only whitespace can legally appear
    // there) carries nothing to project.
}

/// Attach a finished child's value either to the new top of `stack`, or, if
/// the stack is now empty, install it as the document root.
///
/// # Errors
/// Returns [`XmlProjectionError::InvalidXml`] if a second root element
/// appears after the first has already closed — multiple top-level elements
/// is not well-formed XML.
fn attach(
    stack: &mut [OpenElement],
    root: &mut Option<Value>,
    tag: String,
    value: Value,
) -> Result<(), XmlProjectionError> {
    match stack.last_mut() {
        Some(parent) => parent.children.push((tag, value)),
        None => {
            if root.is_some() {
                return Err(XmlProjectionError::InvalidXml(
                    "multiple root elements".into(),
                ));
            }
            *root = Some(value);
        }
    }
    Ok(())
}

fn local_name(name: QName<'_>) -> String {
    String::from_utf8_lossy(name.local_name().as_ref().as_bytes()).into_owned()
}

fn read_attributes(start: &BytesStart<'_>) -> Result<Map<String, Value>, XmlProjectionError> {
    let mut attributes = Map::new();
    for attr in start.attributes() {
        let attr = attr.map_err(|e| XmlProjectionError::InvalidXml(e.to_string()))?;
        let key = local_name(attr.key);
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| XmlProjectionError::InvalidXml(e.to_string()))?
            .into_owned();
        attributes.insert(format!("@{key}"), Value::String(value));
    }
    Ok(attributes)
}

/// Resolve a `GeneralRef` (`&#x..;`, `&amp;`, …) to the literal text it
/// represents. Fails closed on an entity this crate cannot resolve — an
/// unresolved custom entity is a document this projection refuses to guess
/// at, same as [`mecmcp_redact::xml`]'s reasoning for the same event.
fn resolve_general_ref(e: &BytesRef<'_>) -> Result<String, XmlProjectionError> {
    if let Some(ch) = e
        .resolve_char_ref()
        .map_err(|err| XmlProjectionError::InvalidXml(err.to_string()))?
    {
        return Ok(ch.to_string());
    }
    let name: &str = e;
    quick_xml::escape::resolve_predefined_entity(name)
        .map(str::to_string)
        .ok_or_else(|| {
            XmlProjectionError::InvalidXml(format!("unresolved entity reference &{name};"))
        })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_leaf_element_becomes_its_text() {
        let value = xml_to_json("<name>fw-01</name>").unwrap();
        assert_eq!(value, json!("fw-01"));
    }

    #[test]
    fn an_empty_element_becomes_null() {
        let value = xml_to_json("<name></name>").unwrap();
        assert_eq!(value, Value::Null);
        let value = xml_to_json("<name/>").unwrap();
        assert_eq!(value, Value::Null);
    }

    #[test]
    fn whitespace_only_text_is_treated_as_empty() {
        let value = xml_to_json("<name>\n  \t</name>").unwrap();
        assert_eq!(value, Value::Null);
    }

    #[test]
    fn attributes_become_at_prefixed_fields() {
        let value = xml_to_json(r#"<interface id="ge-0/0/0" up="true"/>"#).unwrap();
        assert_eq!(value["@id"], "ge-0/0/0");
        assert_eq!(value["@up"], "true");
    }

    #[test]
    fn a_single_child_element_stays_a_scalar_field() {
        let value = xml_to_json("<host><name>r1</name></host>").unwrap();
        assert_eq!(value, json!({"name": "r1"}));
    }

    #[test]
    fn repeated_child_elements_become_an_array_in_document_order() {
        let value = xml_to_json(
            "<interfaces><interface>ge-0/0/0</interface><interface>ge-0/0/1</interface></interfaces>",
        )
        .unwrap();
        assert_eq!(value, json!({"interface": ["ge-0/0/0", "ge-0/0/1"]}));
    }

    #[test]
    fn nested_structure_is_projected_recursively() {
        let value = xml_to_json(
            r#"<rpc-reply><interface id="ge-0/0/0"><enabled>true</enabled><unit><name>0</name></unit></interface></rpc-reply>"#,
        )
        .unwrap();
        assert_eq!(value["interface"]["@id"], "ge-0/0/0");
        assert_eq!(value["interface"]["enabled"], "true");
        assert_eq!(value["interface"]["unit"]["name"], "0");
    }

    #[test]
    fn mixed_content_keeps_text_under_a_hash_text_key() {
        let value = xml_to_json(r#"<note lang="en">hello <b>world</b></note>"#).unwrap();
        assert_eq!(value["@lang"], "en");
        assert_eq!(value["#text"], "hello");
        assert_eq!(value["b"], "world");
    }

    #[test]
    fn entity_and_character_references_decode_into_text() {
        let value = xml_to_json("<name>AT&amp;T &#x26; friends</name>").unwrap();
        assert_eq!(value, json!("AT&T & friends"));
    }

    #[test]
    fn cdata_is_kept_literally() {
        let value = xml_to_json("<script><![CDATA[if (a < b) {}]]></script>").unwrap();
        assert_eq!(value, json!("if (a < b) {}"));
    }

    #[test]
    fn comments_and_declarations_are_ignored() {
        let value =
            xml_to_json("<?xml version=\"1.0\"?>\n<!-- note --><config><item>1</item></config>")
                .unwrap();
        assert_eq!(value, json!({"item": "1"}));
    }

    #[test]
    fn malformed_xml_is_rejected_not_guessed_at() {
        let err = xml_to_json("<unclosed><tag>").unwrap_err();
        assert!(matches!(err, XmlProjectionError::InvalidXml(_)));
    }

    #[test]
    fn an_unresolved_custom_entity_is_rejected() {
        let err = xml_to_json("<name>&totally-custom;</name>").unwrap_err();
        assert!(matches!(err, XmlProjectionError::InvalidXml(_)));
    }

    #[test]
    fn empty_input_is_rejected_rather_than_returning_null() {
        let err = xml_to_json("   ").unwrap_err();
        assert_eq!(err, XmlProjectionError::Empty);
    }

    #[test]
    fn a_second_root_element_is_rejected() {
        let err = xml_to_json("<a/><b/>").unwrap_err();
        assert!(matches!(err, XmlProjectionError::InvalidXml(_)));
    }

    fn nested(depth: usize) -> String {
        let mut xml = String::new();
        for _ in 0..depth {
            xml.push_str("<a>");
        }
        xml.push_str("leaf");
        for _ in 0..depth {
            xml.push_str("</a>");
        }
        xml
    }

    /// A document nested right up to the limit parses fine and does not
    /// overflow the stack — neither the parser (an explicit `Vec`, not
    /// recursion) nor dropping the resulting `Value` tree afterward.
    #[test]
    fn nesting_up_to_the_limit_succeeds() {
        let value = xml_to_json(&nested(MAX_DEPTH)).unwrap();
        let mut cursor = &value;
        for _ in 0..MAX_DEPTH - 1 {
            cursor = &cursor["a"];
        }
        assert_eq!(*cursor, json!("leaf"));
    }

    /// One level past the limit is refused rather than accepted and later
    /// crashing the process when the resulting deep tree is dropped.
    #[test]
    fn nesting_past_the_limit_is_refused() {
        let err = xml_to_json(&nested(MAX_DEPTH + 1)).unwrap_err();
        assert_eq!(err, XmlProjectionError::TooDeep);
    }
}
