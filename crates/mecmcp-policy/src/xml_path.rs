//! Hierarchy-aware, fail-closed read policy evaluated on parsed XML.
//!
//! Evaluating a read policy per raw device path or raw command text has a
//! fail-open gap: a rule that denies one subtree says nothing about an
//! ancestor element, even though reading the ancestor returns the denied
//! subtree as part of its own content. [`element_paths`] turns an XML
//! document into every element path it contains — the ancestor chain of tag
//! names (plus attributes, folded in canonically so attribute order can't
//! change a path) down to that element — and [`blocked_read_paths`]
//! propagates a deny match up every ancestor of a blocked path, so a policy
//! that blocks a subtree also blocks reading any of its ancestors.
//!
//! [`canonical_command_path`] applies the same parse-first treatment to a
//! single XML command/op payload (for example a PAN-OS op-command document):
//! rule matching happens against the parsed element structure, never the raw
//! serialization, so reordered attributes or incidental whitespace can
//! neither evade nor spuriously trip a rule.

use std::collections::HashSet;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;

use crate::{CompiledRule, evaluate};

/// The deepest element nesting this module will walk. Mirrors
/// `mecmcp_server::xml_json`'s bound and exists for the same reason: parsing
/// itself walks an explicit stack and cannot overflow the native stack, but
/// no real vendor schema nests this deep, so a document that does is refused
/// rather than walked.
const MAX_DEPTH: usize = 512;

/// [`element_paths`] or [`canonical_command_path`] could not parse the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlPathError {
    /// The input is not well-formed XML. Fails closed rather than guess at a
    /// best-effort partial tree, the same rule
    /// `mecmcp_server::xml_to_json` follows and for the same reason: a
    /// parser that guesses at broken input is how two parsers of the same
    /// bytes end up disagreeing about what a read policy should block.
    #[error("input is not well-formed XML, refusing to guess: {0}")]
    InvalidXml(String),
    /// The input nests elements past [`MAX_DEPTH`].
    #[error("input nests elements past the {MAX_DEPTH}-level limit")]
    TooDeep,
}

/// One element's ancestor chain, root first, each segment a canonicalized
/// tag (see [`segment`]).
pub type ElementPath = Vec<String>;

/// Render a path as the `/`-joined string [`evaluate`]'s glob rules match
/// against.
#[must_use]
pub fn path_string(path: &[String]) -> String {
    path.join("/")
}

/// Canonicalize one element's tag and attributes into a single path segment
/// that does not depend on attribute order: a bare tag with no attributes,
/// or `tag[@a=1][@b=2]` with attributes sorted by name. Two elements that
/// differ only in attribute order or in how their source XML was formatted
/// produce the same segment.
fn segment(tag: &str, attrs: &mut [(String, String)]) -> String {
    if attrs.is_empty() {
        return tag.to_string();
    }
    attrs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = tag.to_string();
    for (key, value) in attrs.iter() {
        out.push_str("[@");
        out.push_str(key);
        out.push('=');
        out.push_str(value);
        out.push(']');
    }
    out
}

fn local_name(name: QName<'_>) -> String {
    String::from_utf8_lossy(name.local_name().as_ref().as_bytes()).into_owned()
}

fn read_attrs(start: &BytesStart<'_>) -> Result<Vec<(String, String)>, XmlPathError> {
    let mut attrs = Vec::new();
    for attr in start.attributes() {
        let attr = attr.map_err(|e| XmlPathError::InvalidXml(e.to_string()))?;
        let key = local_name(attr.key);
        let value = attr
            .normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| XmlPathError::InvalidXml(e.to_string()))?
            .into_owned();
        attrs.push((key, value));
    }
    Ok(attrs)
}

/// Parse `xml` and return the path of every element in the document, in
/// document order: an element nested three deep contributes one path of
/// length three, and its ancestors each already contributed their own
/// (shorter) path earlier in the list.
///
/// # Errors
///
/// Returns [`XmlPathError::InvalidXml`] on malformed XML (an unclosed
/// element, an unmatched closing tag, an unparsable attribute) and
/// [`XmlPathError::TooDeep`] past [`MAX_DEPTH`] levels of nesting. Never
/// returns a partial path list on error.
pub fn element_paths(xml: &str) -> Result<Vec<ElementPath>, XmlPathError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut paths = Vec::new();

    loop {
        let event = reader
            .read_event()
            .map_err(|e| XmlPathError::InvalidXml(e.to_string()))?;
        match event {
            Event::Eof => {
                if !stack.is_empty() {
                    return Err(XmlPathError::InvalidXml("unclosed element".to_string()));
                }
                return Ok(paths);
            }
            Event::Start(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlPathError::TooDeep);
                }
                let tag = local_name(e.name());
                let mut attrs = read_attrs(&e)?;
                stack.push(segment(&tag, &mut attrs));
                paths.push(stack.clone());
            }
            Event::Empty(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlPathError::TooDeep);
                }
                let tag = local_name(e.name());
                let mut attrs = read_attrs(&e)?;
                stack.push(segment(&tag, &mut attrs));
                paths.push(stack.clone());
                stack.pop();
            }
            Event::End(_) => {
                stack
                    .pop()
                    .ok_or_else(|| XmlPathError::InvalidXml("unmatched closing tag".to_string()))?;
            }
            _ => {}
        }
    }
}

/// Evaluate `rules` against every element path in `xml` and return the set
/// of `/`-joined paths a read policy must block.
///
/// **Fail-closed hierarchy propagation:** when a path matches a rule whose
/// action is `deny_action`, every ancestor prefix of that path is added to
/// the blocked set too — not just the matched path itself. A read request
/// for a blocked path's ancestor would return the blocked subtree's content
/// as part of its own, so the ancestor must be refused as well. This closes
/// the gap where a child's block did not propagate to its parent.
///
/// # Errors
///
/// Returns [`XmlPathError`] if `xml` cannot be parsed; see
/// [`element_paths`].
pub fn blocked_read_paths<A: Copy + PartialEq>(
    rules: &[&CompiledRule<A>],
    xml: &str,
    deny_action: A,
) -> Result<HashSet<String>, XmlPathError> {
    let paths = element_paths(xml)?;
    let mut blocked = HashSet::new();
    for path in &paths {
        let candidate = path_string(path);
        if let Some(rule) = evaluate(rules, &candidate)
            && rule.action == deny_action
        {
            for end in 1..=path.len() {
                blocked.insert(path_string(&path[..end]));
            }
        }
    }
    Ok(blocked)
}

/// True if `requested_path` is in the `blocked` set computed by
/// [`blocked_read_paths`] — either because it matched a deny rule directly,
/// or because one of its descendants did.
#[must_use]
pub fn is_read_blocked(blocked: &HashSet<String>, requested_path: &[String]) -> bool {
    blocked.contains(&path_string(requested_path))
}

/// Canonicalize a single XML command/op payload (for example a PAN-OS
/// op-command document like `<show><system><info/></show>`) into the
/// `/`-joined path of its deepest element, for matching against command
/// allow/deny rules.
///
/// Because this parses the document rather than matching its raw text,
/// reordered attributes and incidental whitespace between tags never change
/// the result: two XML documents that parse to the same element structure
/// canonicalize to the same path.
///
/// # Errors
///
/// Returns [`XmlPathError`] if `xml_command` cannot be parsed; see
/// [`element_paths`].
pub fn canonical_command_path(xml_command: &str) -> Result<String, XmlPathError> {
    let paths = element_paths(xml_command)?;
    Ok(paths
        .into_iter()
        .max_by_key(Vec::len)
        .map(|p| path_string(&p))
        .unwrap_or_default())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{RuleSource, compile_rules};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestAction {
        Deny,
    }

    fn test_error_builder(_: String, _: String, e: globset::Error) -> globset::Error {
        e
    }

    fn deny_rules(patterns: &[&str]) -> Vec<CompiledRule<TestAction>> {
        let rules: Vec<(TestAction, String)> = patterns
            .iter()
            .map(|p| (TestAction::Deny, p.to_string()))
            .collect();
        compile_rules(&rules, "test", RuleSource::Defaults, test_error_builder).unwrap()
    }

    #[test]
    fn element_paths_walks_nested_structure() {
        let xml = "<configuration><system><host-name>fw1</host-name></system></configuration>";
        let paths = element_paths(xml).unwrap();
        assert_eq!(
            paths,
            vec![
                vec!["configuration".to_string()],
                vec!["configuration".to_string(), "system".to_string()],
                vec![
                    "configuration".to_string(),
                    "system".to_string(),
                    "host-name".to_string()
                ],
            ]
        );
    }

    #[test]
    fn element_paths_rejects_malformed_xml() {
        assert!(element_paths("<unclosed>").is_err());
        assert!(element_paths("<a></b>").is_err());
    }

    #[test]
    fn blocked_subtree_also_blocks_its_ancestors() {
        let xml = r#"
            <configuration>
                <system>
                    <root-authentication>
                        <encrypted-password>REDACTED</encrypted-password>
                    </root-authentication>
                    <host-name>fw1</host-name>
                </system>
            </configuration>
        "#;
        let rules = deny_rules(&["configuration/system/root-authentication*"]);
        let rule_refs: Vec<_> = rules.iter().collect();
        let blocked = blocked_read_paths(&rule_refs, xml, TestAction::Deny).unwrap();

        // The blocked subtree itself, and everything under it.
        assert!(is_read_blocked(
            &blocked,
            &[
                "configuration".into(),
                "system".into(),
                "root-authentication".into()
            ]
        ));
        assert!(is_read_blocked(
            &blocked,
            &[
                "configuration".into(),
                "system".into(),
                "root-authentication".into(),
                "encrypted-password".into()
            ]
        ));

        // Every ancestor of the blocked subtree is blocked too — the
        // fail-open gap this closes.
        assert!(is_read_blocked(&blocked, &["configuration".into()]));
        assert!(is_read_blocked(
            &blocked,
            &["configuration".into(), "system".into()]
        ));

        // An unrelated sibling of the blocked subtree is not swept in.
        assert!(!is_read_blocked(
            &blocked,
            &["configuration".into(), "system".into(), "host-name".into()]
        ));
    }

    #[test]
    fn no_matching_rule_blocks_nothing() {
        let xml = "<configuration><system><host-name>fw1</host-name></system></configuration>";
        let rules = deny_rules(&["configuration/system/root-authentication*"]);
        let rule_refs: Vec<_> = rules.iter().collect();
        let blocked = blocked_read_paths(&rule_refs, xml, TestAction::Deny).unwrap();
        assert!(blocked.is_empty());
    }

    #[test]
    fn canonical_command_path_ignores_attribute_order_and_whitespace() {
        let compact = r#"<request><system><power-off slot="0" force="yes"/></system></request>"#;
        let reformatted = "
            <request>
                <system>
                    <power-off force=\"yes\"   slot=\"0\" />
                </system>
            </request>
        ";
        let a = canonical_command_path(compact).unwrap();
        let b = canonical_command_path(reformatted).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, "request/system/power-off[@force=yes][@slot=0]");
    }

    #[test]
    fn command_rule_matches_parsed_structure_regardless_of_formatting() {
        let rules = deny_rules(&["request/system/power-off*"]);
        let rule_refs: Vec<_> = rules.iter().collect();

        let compact = r#"<request><system><power-off slot="0" force="yes"/></system></request>"#;
        let reformatted = "
            <request>
                <system>
                    <power-off force=\"yes\"   slot=\"0\" />
                </system>
            </request>
        ";

        let path_a = canonical_command_path(compact).unwrap();
        let path_b = canonical_command_path(reformatted).unwrap();
        assert!(evaluate(&rule_refs, &path_a).is_some());
        assert!(evaluate(&rule_refs, &path_b).is_some());
    }
}
