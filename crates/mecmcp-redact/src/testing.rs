//! Shared tool-output-redaction coverage helper.
//!
//! Every server that returns device data has, independently, hand-built the
//! same shape of test: a lookup table of tool names, a mock backend that
//! plants a distinct synthetic secret in each tool's response, and an
//! assertion that no tool's rendered output contains any planted secret —
//! not just the one its own fixture was built around, so a tool that leaks
//! the *wrong* secret is still caught. [`tools_leaking_secrets`] is that
//! assertion, generalized once, the same way
//! [`mecmcp_audit::testutil::tools_without_audit_events`] generalized the
//! equivalent audit-coverage check.
//!
//! This does not remove the need for a server's own mock backend and
//! per-tool fixture table — that part is irreducibly vendor-specific. What
//! it removes is every server re-deriving the leak-detection assertion
//! itself.
#![cfg(any(test, feature = "test-util"))]

/// Names from `registry` whose rendered output contains at least one of
/// `secrets`.
///
/// `exercise` is called once per tool name and must return that tool's
/// rendered output (typically `serde_json::to_string(&out)` or an error's
/// `to_string()`). Every one of `secrets` is checked against every tool's
/// output, not just whichever secret that tool's own fixture happens to
/// plant — a tool that echoes a *different* secret than the one its mock
/// response was built around is still caught.
///
/// Each tool is exercised independently and only its own output is
/// scanned, so a chatty tool's output cannot mask — or wrongly implicate —
/// a neighbour.
///
/// ```
/// use mecmcp_redact::testing::tools_leaking_secrets;
///
/// let secrets = ["FAKEsecret123"];
/// let leaking = tools_leaking_secrets(&["safe_tool", "leaky_tool"], &secrets, |tool| {
///     match tool {
///         "leaky_tool" => "response: FAKEsecret123".to_owned(),
///         _ => "response: ok".to_owned(),
///     }
/// });
/// assert_eq!(leaking, vec!["leaky_tool".to_owned()]);
/// ```
#[must_use]
pub fn tools_leaking_secrets<F>(registry: &[&str], secrets: &[&str], mut exercise: F) -> Vec<String>
where
    F: FnMut(&str) -> String,
{
    registry
        .iter()
        .filter_map(|tool| {
            let rendered = exercise(tool);
            secrets
                .iter()
                .any(|secret| rendered.contains(secret))
                .then(|| (*tool).to_owned())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_tool_is_not_reported() {
        let leaking = tools_leaking_secrets(&["clean"], &["FAKEsecret"], |_| "ok".to_owned());
        assert!(leaking.is_empty());
    }

    #[test]
    fn a_tool_leaking_its_own_fixture_secret_is_reported() {
        let leaking = tools_leaking_secrets(&["leaky"], &["FAKEsecret"], |_| {
            "value: FAKEsecret".to_owned()
        });
        assert_eq!(leaking, vec!["leaky".to_owned()]);
    }

    /// The case hand-rolled per-server tests exist to catch: a tool that
    /// leaks a *different* secret than the one its own case was written
    /// around. `exercise` here ignores which tool it was given and always
    /// returns the "wrong" secret.
    #[test]
    fn a_tool_leaking_a_different_registered_secret_is_still_reported() {
        let secrets = ["FAKEsecret_a", "FAKEsecret_b"];
        let leaking =
            tools_leaking_secrets(&["tool_a"], &secrets, |_| "value: FAKEsecret_b".to_owned());
        assert_eq!(leaking, vec!["tool_a".to_owned()]);
    }

    #[test]
    fn each_tool_is_scanned_independently() {
        let leaking = tools_leaking_secrets(&["clean", "leaky"], &["FAKEsecret"], |tool| {
            if tool == "leaky" {
                "value: FAKEsecret".to_owned()
            } else {
                "ok".to_owned()
            }
        });
        assert_eq!(leaking, vec!["leaky".to_owned()]);
    }

    #[test]
    fn empty_registry_reports_nothing() {
        let leaking = tools_leaking_secrets(&[], &["FAKEsecret"], |_| "ok".to_owned());
        assert!(leaking.is_empty());
    }
}
