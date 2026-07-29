//! Tracing-capture helper for asserting on `audit`-target output in tests.
#![cfg(any(test, feature = "test-util"))]
#![allow(clippy::unwrap_used)]

use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

/// A cloneable in-memory writer collecting everything written to it.
#[derive(Clone, Default)]
pub struct CapturingWriter(pub Arc<Mutex<Vec<u8>>>);

impl Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturingWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Names from `registry` that produced no audit event when exercised.
///
/// Audit coverage is currently a property of whether whoever added a tool
/// remembered to open an [`AuditScope`](crate::AuditScope), and the failure is
/// silent in both directions: a new tool is simply absent from the trail, and
/// nothing in the log says so. A partial trail that presents as complete is
/// worse to reason about than no trail (mecmcp#32).
///
/// Nothing tied the tool registry to the audit output, so this ties them.
/// `exercise` is called once per tool name and should drive that tool's handler
/// path; any name whose run emits no `tool=<name>` audit field is returned.
///
/// Returning the gaps rather than panicking lets the caller name all of them in
/// one failure instead of one per run:
///
/// ```ignore
/// let missing = tools_without_audit_events(KNOWN_TOOLS, |tool| dispatch(tool));
/// assert!(missing.is_empty(), "tools with no audit event: {missing:?}");
/// ```
///
/// Each tool is captured independently, so one noisy tool cannot mask a silent
/// neighbour.
pub fn tools_without_audit_events<F>(registry: &[&str], mut exercise: F) -> Vec<String>
where
    F: FnMut(&str),
{
    registry
        .iter()
        .filter(|tool| {
            let captured = run_with_capture(|| exercise(tool));
            !emits_audit_for_tool(&captured, tool)
        })
        .map(|tool| (*tool).to_owned())
        .collect()
}

/// Whether `captured` contains an audit event for exactly this tool.
///
/// Matches the `tool=<name>` field with its terminator, so `get_config` is not
/// satisfied by an event for `get_config_diff`. A substring test would let a
/// tool with a longer name vouch for one that was never audited, which is the
/// exact failure this is meant to detect.
fn emits_audit_for_tool(captured: &str, tool: &str) -> bool {
    let needle = format!("tool={tool}");
    captured.match_indices(&needle).any(|(index, _)| {
        captured[index + needle.len()..]
            .chars()
            .next()
            .is_none_or(|next| !matches!(next, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-'))
    })
}

/// Run `f` with a temporary subscriber capturing INFO output; return the text.
pub fn run_with_capture<F: FnOnce()>(f: F) -> String {
    let cap = CapturingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(cap.clone())
        .with_ansi(false)
        .with_target(true)
        .with_max_level(tracing::Level::INFO)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = cap.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditScope;

    fn audit(tool: &'static str) {
        let mut scope = AuditScope::stdio(tool, "read", Vec::new());
        scope.succeed();
    }

    #[test]
    fn tools_that_audit_are_not_reported() {
        let missing = tools_without_audit_events(&["alpha", "beta"], |tool| match tool {
            "alpha" => audit("alpha"),
            "beta" => audit("beta"),
            other => panic!("unexpected tool {other}"),
        });

        assert!(missing.is_empty(), "expected no gaps, got {missing:?}");
    }

    /// The case the issue is about: a tool nobody remembered to audit.
    #[test]
    fn a_tool_with_no_audit_event_is_reported() {
        let missing = tools_without_audit_events(&["alpha", "forgotten"], |tool| {
            if tool == "alpha" {
                audit("alpha");
            }
            // "forgotten" does nothing, exactly like a handler that never opened
            // a scope.
        });

        assert_eq!(missing, vec!["forgotten".to_owned()]);
    }

    /// A tool must not be vouched for by a different tool that merely shares its
    /// prefix. Without the terminator check, `get_config` would look audited
    /// because `get_config_diff` emitted an event.
    #[test]
    fn a_prefix_of_another_tool_is_not_counted_as_audited() {
        let missing = tools_without_audit_events(&["get_config"], |_| audit("get_config_diff"));

        assert_eq!(
            missing,
            vec!["get_config".to_owned()],
            "a longer tool name must not satisfy a shorter one"
        );
    }

    /// Each tool is captured on its own, so a chatty tool cannot mask a silent
    /// one that ran earlier or later.
    #[test]
    fn each_tool_is_captured_independently() {
        let missing = tools_without_audit_events(&["silent", "chatty"], |tool| {
            if tool == "chatty" {
                audit("chatty");
                audit("silent"); // emitted during the wrong tool's run
            }
        });

        assert_eq!(
            missing,
            vec!["silent".to_owned()],
            "an event emitted while exercising another tool must not count"
        );
    }
}
