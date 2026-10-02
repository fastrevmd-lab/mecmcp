//! Hierarchy-aware, fail-closed read policy evaluated on parsed XML.
//!
//! [`element_paths`] turns an XML document into every element path it
//! contains — the ancestor chain of bare tag names down to that element,
//! independent of attributes, attribute order, or incidental whitespace —
//! and [`blocked_read_paths`] propagates a deny match up every ancestor of a
//! blocked path, so a policy that blocks a subtree also blocks reading any
//! of its ancestors.
//!
//! [`canonical_command_path`] applies the same parse-first treatment to a
//! single XML command/op payload (for example a PAN-OS op-command document):
//! rule matching happens against the parsed element structure, never the raw
//! serialization. A payload that does not parse to one unambiguous command
//! chain is refused rather than guessed at.

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

/// The most elements a single document may contain. Bounds the total work
/// and memory this module spends on one input independent of nesting depth,
/// the same way `MAX_DEPTH` bounds it independent of document size.
const MAX_ELEMENTS: usize = 50_000;

/// [`element_paths`] or [`canonical_command_path`] could not parse the input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XmlPathError {
    /// The input is not well-formed XML, or has no root element. Fails
    /// closed rather than guess at a best-effort partial tree, the same
    /// rule `mecmcp_server::xml_to_json` follows and for the same reason: a
    /// parser that guesses at broken input is how two parsers of the same
    /// bytes end up disagreeing about what a read policy should block.
    #[error("input is not well-formed XML, refusing to guess: {0}")]
    InvalidXml(String),
    /// The input nests elements past `MAX_DEPTH`.
    #[error("input nests elements past the {MAX_DEPTH}-level limit")]
    TooDeep,
    /// The input contains more than `MAX_ELEMENTS` elements.
    #[error("input contains more than {MAX_ELEMENTS} elements")]
    TooLarge,
    /// A command payload parsed to more than one root element, or branched
    /// into more than one leaf, so there is no single unambiguous element
    /// chain to match a command rule against.
    #[error("command payload has more than one root or branches into more than one element chain")]
    AmbiguousCommand,
}

/// One element's ancestor chain, root first, each segment a bare local tag
/// name (no namespace prefix, no attributes).
pub type ElementPath = Vec<String>;

/// Render a path as the `/`-joined string [`evaluate`]'s glob rules match
/// against.
#[must_use]
pub fn path_string(path: &[String]) -> String {
    path.join("/")
}

fn local_name(name: QName<'_>) -> String {
    String::from_utf8_lossy(name.local_name().as_ref().as_bytes()).into_owned()
}

/// Validate (but discard) an element's attributes: malformed attributes
/// still fail the parse closed, but attribute content never becomes part of
/// a matched path, so a rule author never has to anticipate the exact
/// attributes a device happens to emit on a given element.
fn validate_attrs(start: &BytesStart<'_>) -> Result<(), XmlPathError> {
    for attr in start.attributes() {
        let attr = attr.map_err(|e| XmlPathError::InvalidXml(e.to_string()))?;
        attr.normalized_value(quick_xml::XmlVersion::Implicit1_0)
            .map_err(|e| XmlPathError::InvalidXml(e.to_string()))?;
    }
    Ok(())
}

/// Walk every element in `xml` in document order, calling `on_element` with
/// its current ancestor-chain path (root first, this element last). Streams
/// one stack through the whole document rather than materializing every
/// path up front, so the caller controls how much it retains.
///
/// # Errors
///
/// Returns [`XmlPathError::InvalidXml`] on malformed XML (an unclosed
/// element, an unmatched closing tag, an unparsable attribute, or a document
/// with no root element), [`XmlPathError::TooDeep`] past `MAX_DEPTH` levels
/// of nesting, and [`XmlPathError::TooLarge`] past `MAX_ELEMENTS` elements.
fn walk_elements<F: FnMut(&[String])>(xml: &str, mut on_element: F) -> Result<(), XmlPathError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<String> = Vec::new();
    let mut element_count: usize = 0;

    loop {
        let event = reader
            .read_event()
            .map_err(|e| XmlPathError::InvalidXml(e.to_string()))?;
        match event {
            Event::Eof => {
                if !stack.is_empty() {
                    return Err(XmlPathError::InvalidXml("unclosed element".to_string()));
                }
                if element_count == 0 {
                    return Err(XmlPathError::InvalidXml(
                        "document has no root element".to_string(),
                    ));
                }
                return Ok(());
            }
            Event::Start(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlPathError::TooDeep);
                }
                validate_attrs(&e)?;
                element_count += 1;
                if element_count > MAX_ELEMENTS {
                    return Err(XmlPathError::TooLarge);
                }
                stack.push(local_name(e.name()));
                on_element(&stack);
            }
            Event::Empty(e) => {
                if stack.len() >= MAX_DEPTH {
                    return Err(XmlPathError::TooDeep);
                }
                validate_attrs(&e)?;
                element_count += 1;
                if element_count > MAX_ELEMENTS {
                    return Err(XmlPathError::TooLarge);
                }
                stack.push(local_name(e.name()));
                on_element(&stack);
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

/// Parse `xml` and return the path of every element in the document, in
/// document order: an element nested three deep contributes one path of
/// length three, and its ancestors each already contributed their own
/// (shorter) path earlier in the list.
///
/// Materializes every path up front, so worst-case cost (a document at both
/// the `MAX_DEPTH` and `MAX_ELEMENTS` ceilings) is bounded but non-trivial:
/// up to `MAX_ELEMENTS * MAX_DEPTH` owned path segments. Callers that only
/// need to test paths against rules, not collect them all, should stream
/// through [`blocked_read_paths`] or a direct [`quick_xml`] walk instead.
///
/// # Errors
///
/// See the parse errors on this module's private walker. Never returns a partial path list on error.
pub fn element_paths(xml: &str) -> Result<Vec<ElementPath>, XmlPathError> {
    let mut paths = Vec::new();
    walk_elements(xml, |path| paths.push(path.to_vec()))?;
    Ok(paths)
}

/// Evaluate `rules` against every element path in `xml` and return the set
/// of `/`-joined paths a read policy must block.
///
/// **Fail-closed hierarchy propagation:** when a path matches a rule whose
/// action is `deny_action`, every ancestor prefix of that path is added to
/// the blocked set too — not just the matched path itself. A read request
/// for a blocked path's ancestor would return the blocked subtree's content
/// as part of its own, so the ancestor must be refused as well.
///
/// # Errors
///
/// Returns [`XmlPathError`] if `xml` cannot be parsed (malformed XML, too deep, or too many elements).
pub fn blocked_read_paths<A: Copy + PartialEq>(
    rules: &[&CompiledRule<A>],
    xml: &str,
    deny_action: A,
) -> Result<HashSet<String>, XmlPathError> {
    let mut blocked = HashSet::new();
    // Many documents repeat the same path back-to-back — a run of sibling
    // elements that share a tag name (as `blocked_read_paths_propagates_
    // ancestors_promptly_under_many_matches` exercises with 49,000 identical
    // `leaf-match` siblings) produces the exact same path string on every
    // call. Skipping a call whose path is bit-identical to the previous
    // one's avoids redoing the glob match and ancestor-prefix walk for every
    // repeat: since the path is unchanged, `evaluate` and the `blocked`
    // inserts it would perform are guaranteed to reach the same outcome the
    // first occurrence already reached.
    let mut last_path: Option<Vec<String>> = None;
    walk_elements(xml, |path| {
        if last_path.as_deref() == Some(path) {
            return;
        }
        last_path = Some(path.to_vec());

        let candidate = path_string(path);
        if let Some(rule) = evaluate(rules, &candidate)
            && rule.action == deny_action
        {
            // Build every ancestor prefix by slicing the already-joined
            // `candidate` string at each segment boundary (no repeated
            // joins), and walk from the longest prefix down to the
            // shortest. The moment a prefix is already in `blocked`, every
            // shorter prefix is too — a previous match already propagated
            // all the way to the root — so stop immediately.
            let mut end_offset = 0usize;
            let mut offsets = Vec::with_capacity(path.len());
            for (i, segment) in path.iter().enumerate() {
                if i > 0 {
                    end_offset += 1; // the '/' separator
                }
                end_offset += segment.len();
                offsets.push(end_offset);
            }
            for offset in offsets.into_iter().rev() {
                if !blocked.insert(candidate[..offset].to_string()) {
                    break;
                }
            }
        }
    })?;
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
/// `/`-joined path of its one unambiguous deepest element, for matching
/// against command allow/deny rules.
///
/// Because this parses the document rather than matching its raw text,
/// attributes, attribute order, and incidental whitespace between tags
/// never change the result.
///
/// # Errors
///
/// Returns [`XmlPathError`] if `xml_command` cannot be parsed (malformed
/// XML, too deep, or too many elements), and
/// [`XmlPathError::AmbiguousCommand`] if the
/// document does not parse to exactly one root with exactly one leaf —
/// for example more than one top-level element, or an element with more
/// than one element child anywhere in the chain. A command payload is
/// refused rather than matched against a guessed element when its shape
/// does not describe a single unambiguous command.
pub fn canonical_command_path(xml_command: &str) -> Result<String, XmlPathError> {
    // A single unambiguous command is a straight chain: one root, and every
    // element along the way has at most one element child. Rather than
    // materializing every path with `element_paths` and then scanning for
    // the one path nothing extends (which misses a branch whose branches
    // share a tag name, since two differently-shaped paths can stringify
    // the same way), walk the document once and track each open element's
    // child count directly. The moment any element would gain a second
    // element child, or a second root element appears, the payload is
    // ambiguous and there is no need to keep parsing.
    struct Frame {
        name: String,
        child_count: usize,
    }

    let mut reader = Reader::from_str(xml_command);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<Frame> = Vec::new();
    let mut root_seen = false;
    let mut element_count: usize = 0;
    let mut leaf_path: Option<Vec<String>> = None;

    // Record that an element is opening: enforce the depth and element-count
    // ceilings, and reject a second root or a second element child of the
    // current top-of-stack element.
    fn open(
        stack: &mut [Frame],
        root_seen: &mut bool,
        element_count: &mut usize,
    ) -> Result<(), XmlPathError> {
        if stack.len() >= MAX_DEPTH {
            return Err(XmlPathError::TooDeep);
        }
        match stack.last_mut() {
            Some(parent) => {
                parent.child_count += 1;
                if parent.child_count > 1 {
                    return Err(XmlPathError::AmbiguousCommand);
                }
            }
            None => {
                if *root_seen {
                    return Err(XmlPathError::AmbiguousCommand);
                }
                *root_seen = true;
            }
        }
        *element_count += 1;
        if *element_count > MAX_ELEMENTS {
            return Err(XmlPathError::TooLarge);
        }
        Ok(())
    }

    // Record that an element with `child_count` element children (0 means a
    // true leaf) closed. Since every parent is capped at one element child,
    // a single-chain document has exactly one closing element with zero
    // children: the chain's unambiguous deepest element.
    fn record_if_leaf(
        leaf_path: &mut Option<Vec<String>>,
        child_count: usize,
        ancestors: &[Frame],
        name: String,
    ) -> Result<(), XmlPathError> {
        if child_count != 0 {
            return Ok(());
        }
        if leaf_path.is_some() {
            return Err(XmlPathError::AmbiguousCommand);
        }
        let mut path: Vec<String> = ancestors.iter().map(|f| f.name.clone()).collect();
        path.push(name);
        *leaf_path = Some(path);
        Ok(())
    }

    loop {
        let event = reader
            .read_event()
            .map_err(|e| XmlPathError::InvalidXml(e.to_string()))?;
        match event {
            Event::Eof => {
                if !stack.is_empty() {
                    return Err(XmlPathError::InvalidXml("unclosed element".to_string()));
                }
                if !root_seen {
                    return Err(XmlPathError::InvalidXml(
                        "document has no root element".to_string(),
                    ));
                }
                return leaf_path
                    .map(|path| path_string(&path))
                    .ok_or(XmlPathError::AmbiguousCommand);
            }
            Event::Start(e) => {
                validate_attrs(&e)?;
                open(&mut stack, &mut root_seen, &mut element_count)?;
                stack.push(Frame {
                    name: local_name(e.name()),
                    child_count: 0,
                });
            }
            Event::Empty(e) => {
                validate_attrs(&e)?;
                open(&mut stack, &mut root_seen, &mut element_count)?;
                record_if_leaf(&mut leaf_path, 0, &stack, local_name(e.name()))?;
            }
            Event::End(_) => {
                let frame = stack
                    .pop()
                    .ok_or_else(|| XmlPathError::InvalidXml("unmatched closing tag".to_string()))?;
                record_if_leaf(&mut leaf_path, frame.child_count, &stack, frame.name)?;
            }
            _ => {}
        }
    }
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
    fn element_paths_ignores_attributes() {
        let xml = r#"<configuration xmlns:junos="urn:junos" junos:commit-seconds="1" junos:commit-user="x"><system inactive="yes"><root-authentication/></system></configuration>"#;
        let paths = element_paths(xml).unwrap();
        assert_eq!(
            paths,
            vec![
                vec!["configuration".to_string()],
                vec!["configuration".to_string(), "system".to_string()],
                vec![
                    "configuration".to_string(),
                    "system".to_string(),
                    "root-authentication".to_string()
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
    fn element_paths_rejects_empty_or_elementless_input() {
        assert_eq!(
            element_paths(""),
            Err(XmlPathError::InvalidXml(
                "document has no root element".to_string()
            ))
        );
        assert_eq!(
            element_paths("   "),
            Err(XmlPathError::InvalidXml(
                "document has no root element".to_string()
            ))
        );
        assert_eq!(
            element_paths("<!-- just a comment -->"),
            Err(XmlPathError::InvalidXml(
                "document has no root element".to_string()
            ))
        );
    }

    #[test]
    fn element_paths_rejects_documents_past_max_elements() {
        let mut xml = String::new();
        for _ in 0..=MAX_ELEMENTS {
            xml.push_str("<leaf/>");
        }
        let wrapped = format!("<root>{xml}</root>");
        assert_eq!(element_paths(&wrapped), Err(XmlPathError::TooLarge));
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
    fn blocked_subtree_matches_despite_ancestor_attributes() {
        // A Junos-shaped document carries namespace declarations and
        // commit-tracking attributes on ancestor elements; the deny rule
        // must still match the tag-only path.
        let xml = r#"
            <configuration xmlns:junos="urn:junos" junos:commit-seconds="1" junos:commit-user="root">
                <system junos:changed="yes">
                    <root-authentication>
                        <encrypted-password>REDACTED</encrypted-password>
                    </root-authentication>
                </system>
            </configuration>
        "#;
        let rules = deny_rules(&["configuration/system/root-authentication*"]);
        let rule_refs: Vec<_> = rules.iter().collect();
        let blocked = blocked_read_paths(&rule_refs, xml, TestAction::Deny).unwrap();

        assert!(is_read_blocked(
            &blocked,
            &[
                "configuration".into(),
                "system".into(),
                "root-authentication".into()
            ]
        ));
        assert!(is_read_blocked(&blocked, &["configuration".into()]));
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
        assert_eq!(a, "request/system/power-off");
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

    #[test]
    fn canonical_command_path_rejects_multiple_roots() {
        let xml = r#"<request><system><power-off/></system></request><request><system><reboot/></system></request>"#;
        assert_eq!(
            canonical_command_path(xml),
            Err(XmlPathError::AmbiguousCommand)
        );
    }

    #[test]
    fn canonical_command_path_rejects_branching_chains() {
        // Two children under the same element: no single unambiguous
        // deepest element to canonicalize to.
        let xml = r#"<request><system><power-off/><reboot/></system></request>"#;
        assert_eq!(
            canonical_command_path(xml),
            Err(XmlPathError::AmbiguousCommand)
        );
    }

    #[test]
    fn canonical_command_path_rejects_empty_or_elementless_input() {
        assert!(matches!(
            canonical_command_path(""),
            Err(XmlPathError::InvalidXml(_))
        ));
        assert!(matches!(
            canonical_command_path("power-off"),
            Err(XmlPathError::InvalidXml(_))
        ));
    }

    #[test]
    fn canonical_command_path_rejects_attribute_bearing_ancestor_evasion() {
        // An attribute on an ancestor must not change which element is
        // treated as the command's single leaf.
        let xml = r#"<request><system junk="a"><power-off/></system></request>"#;
        assert_eq!(
            canonical_command_path(xml).unwrap(),
            "request/system/power-off"
        );
    }

    #[test]
    fn canonical_command_path_rejects_same_tag_sibling_branch() {
        // Two `<system>` siblings under the same root: tag-only paths alias
        // them, so a naive "nothing extends this path" leaf scan sees only
        // one `request/system` path and picks the deepest descendant under
        // either branch as if it were the command's unambiguous leaf. The
        // payload is still a branch and must be refused.
        let xml = r#"<request><system><reboot/></system><system><reboot><in>5</in></reboot></system></request>"#;
        assert_eq!(
            canonical_command_path(xml),
            Err(XmlPathError::AmbiguousCommand)
        );
    }

    #[test]
    fn canonical_command_path_rejects_empty_sibling_next_to_populated_sibling() {
        // A self-closing `<system/>` next to a second, populated `<system>`:
        // the root still has two element children, so this is a branch even
        // though one branch contributes no deeper path of its own.
        let xml = r#"<request><system/><system><power-off/></system></request>"#;
        assert_eq!(
            canonical_command_path(xml),
            Err(XmlPathError::AmbiguousCommand)
        );
    }

    #[test]
    fn canonical_command_path_rejects_large_flat_branch_promptly() {
        // A command payload is model-authored, so a prompt-injected model
        // controls this input. A document that is cheap to reject must stay
        // cheap: ambiguity (the second element child of `request`) has to be
        // caught as soon as it appears, not after materializing every path
        // in the document and scanning it for leaves.
        let mut xml = String::from("<request>");
        for _ in 0..49_000 {
            xml.push_str("<leaf/>");
        }
        xml.push_str("</request>");

        let start = std::time::Instant::now();
        let result = canonical_command_path(&xml);
        let elapsed = start.elapsed();

        assert_eq!(result, Err(XmlPathError::AmbiguousCommand));
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "rejecting an ambiguous command took {elapsed:?}, expected it to short-circuit on the second child"
        );
    }

    #[test]
    fn blocked_read_paths_propagates_ancestors_promptly_under_many_matches() {
        // Mirrors the shape that made naive per-match ancestor propagation
        // cost O(n * depth^2): a deep chain ending in many matching
        // siblings, each of which would otherwise re-join and re-insert
        // every ancestor prefix from scratch.
        const CHAIN_DEPTH: usize = 490;
        let mut xml = String::new();
        for i in 0..CHAIN_DEPTH {
            xml.push_str(&format!("<n{i}>"));
        }
        for _ in 0..49_000 {
            xml.push_str("<leaf-match/>");
        }
        for i in (0..CHAIN_DEPTH).rev() {
            xml.push_str(&format!("</n{i}>"));
        }

        let rules = deny_rules(&["*leaf-match*"]);
        let rule_refs: Vec<_> = rules.iter().collect();

        let start = std::time::Instant::now();
        let blocked = blocked_read_paths(&rule_refs, &xml, TestAction::Deny).unwrap();
        let elapsed = start.elapsed();

        // The whole chain down to the matched leaves is blocked...
        assert!(is_read_blocked(&blocked, &["n0".to_string()]));
        // ...and the chain is shared by every match, so early-break on an
        // already-inserted prefix keeps this fast.
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "propagating ancestors for {} matches took {elapsed:?}, expected early-break on shared prefixes to keep this fast",
            49_000
        );
    }
}
