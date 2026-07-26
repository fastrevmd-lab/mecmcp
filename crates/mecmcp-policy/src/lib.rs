//! Pure rule-evaluation logic for blocklist guardrails.
//!
//! Provides the rule engine primitives that power policy checks in both
//! Junos and PAN-OS MCP servers. The rule engine is generic over action types
//! and decoupled from any specific inventory format.

use globset::{Glob, GlobMatcher};

/// Origin of a rule, used for tiebreaking equal-specificity matches and for
/// the human-readable error message on denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuleSource {
    /// Rule from a global or shared defaults section.
    Defaults,
    /// Rule from a device-specific blocklist.
    Device,
}

impl RuleSource {
    /// Returns the static string representation of this source.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Defaults => "defaults",
            Self::Device => "device",
        }
    }
}

/// A glob rule with its compiled matcher and pre-computed specificity score.
///
/// Generic over the action type to support both Junos (Allow/Deny) and PAN-OS
/// action enums.
#[derive(Debug)]
pub struct CompiledRule<A> {
    /// The original glob pattern string.
    pub pattern: String,
    /// The action to take when this rule matches.
    pub action: A,
    /// Whether this rule came from defaults or a device-specific blocklist.
    pub source: RuleSource,
    /// Compiled glob matcher for efficient matching.
    pub matcher: GlobMatcher,
    /// Higher = more specific. Tuple is `(literal_chars, total_len)`.
    pub specificity: (usize, usize),
}

/// Count non-wildcard, non-character-class literal characters in a glob pattern.
/// `*`, `?`, and `[...]` ranges are wildcards; everything else (including
/// escaped characters) counts.
pub fn count_literal_chars(pattern: &str) -> usize {
    let mut count = 0usize;
    let mut in_class = false;
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if in_class {
            if c == ']' {
                in_class = false;
            }
            continue;
        }
        match c {
            '*' | '?' => continue,
            '[' => {
                in_class = true;
                continue;
            }
            '\\' => {
                if chars.next().is_some() {
                    count += 1;
                }
            }
            _ => count += 1,
        }
    }
    count
}

/// Compile a list of rules into `CompiledRule`s, attaching the given
/// `source` and a scope label used in compile-time error messages.
///
/// # Errors
///
/// Returns an error if any glob pattern fails to compile.
pub fn compile_rules<A, E>(
    rules: &[(A, String)],
    scope: &str,
    source: RuleSource,
    error_builder: impl Fn(String, String, globset::Error) -> E,
) -> Result<Vec<CompiledRule<A>>, E>
where
    A: Copy,
{
    rules
        .iter()
        .map(|(action, pattern)| {
            let glob = Glob::new(pattern)
                .map_err(|e| error_builder(scope.to_string(), pattern.clone(), e))?;
            let literal_chars = count_literal_chars(pattern);
            Ok(CompiledRule {
                pattern: pattern.clone(),
                action: *action,
                source,
                matcher: glob.compile_matcher(),
                specificity: (literal_chars, pattern.len()),
            })
        })
        .collect()
}

/// Outcome of a policy check.
#[derive(Debug)]
pub enum Decision<'a, A> {
    /// The input is allowed.
    Allow,
    /// The input is denied by the matched rule.
    Deny {
        /// The rule that triggered the denial.
        rule: &'a CompiledRule<A>,
        /// Whether the rule came from defaults or device config.
        source: RuleSource,
        /// Set only for config-domain checks; identifies the offending line
        /// (1-indexed, comment lines counted).
        line_number: Option<usize>,
    },
}

/// Trim and collapse runs of whitespace to a single space.
pub fn normalize_input(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_ws = false;
    for c in s.trim().chars() {
        if c.is_whitespace() {
            if !last_was_ws {
                out.push(' ');
                last_was_ws = true;
            }
        } else {
            out.push(c);
            last_was_ws = false;
        }
    }
    out
}

/// Pick the most-specific matching rule. Tiebreak: device > defaults.
pub fn evaluate<'r, A>(
    rules: &[&'r CompiledRule<A>],
    candidate: &str,
) -> Option<&'r CompiledRule<A>> {
    rules
        .iter()
        .filter(|r| r.matcher.is_match(candidate))
        .copied()
        .max_by(|a, b| {
            a.specificity
                .cmp(&b.specificity)
                .then_with(|| match (a.source, b.source) {
                    (RuleSource::Device, RuleSource::Defaults) => std::cmp::Ordering::Greater,
                    (RuleSource::Defaults, RuleSource::Device) => std::cmp::Ordering::Less,
                    _ => std::cmp::Ordering::Equal,
                })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TestAction {
        Allow,
        Deny,
    }

    #[derive(Debug)]
    struct TestError {
        scope: String,
        pattern: String,
    }

    fn test_error_builder(scope: String, pattern: String, _: globset::Error) -> TestError {
        TestError { scope, pattern }
    }

    #[test]
    fn count_literal_chars_basic() {
        assert_eq!(count_literal_chars("show version"), 12);
        assert_eq!(count_literal_chars("request system *"), 15);
        assert_eq!(count_literal_chars("*"), 0);
        assert_eq!(count_literal_chars("?"), 0);
    }

    #[test]
    fn count_literal_chars_character_classes() {
        assert_eq!(count_literal_chars("[abc]def"), 3);
        assert_eq!(count_literal_chars("pre[0-9]post"), 7);
    }

    #[test]
    fn count_literal_chars_escaped() {
        assert_eq!(count_literal_chars(r"foo\*bar"), 7);
    }

    #[test]
    fn normalize_input_trims_and_collapses() {
        assert_eq!(normalize_input("  foo   bar  "), "foo bar");
        assert_eq!(normalize_input("foo\t\tbar"), "foo bar");
        assert_eq!(normalize_input("  \n  foo  \n  bar  \n  "), "foo bar");
    }

    #[test]
    fn normalize_input_preserves_single_spaces() {
        assert_eq!(normalize_input("foo bar"), "foo bar");
    }

    #[test]
    fn compile_rules_success() {
        let rules = vec![
            (TestAction::Deny, "request system *".to_string()),
            (TestAction::Allow, "show *".to_string()),
        ];
        let compiled =
            compile_rules(&rules, "test", RuleSource::Defaults, test_error_builder).unwrap();
        assert_eq!(compiled.len(), 2);
        assert_eq!(compiled[0].pattern, "request system *");
        assert_eq!(compiled[0].specificity, (15, 16));
    }

    #[test]
    fn compile_rules_invalid_pattern() {
        let rules = vec![(TestAction::Deny, "[unclosed".to_string())];
        let result = compile_rules(&rules, "test", RuleSource::Defaults, test_error_builder);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.scope, "test");
        assert_eq!(err.pattern, "[unclosed");
    }

    #[test]
    fn evaluate_no_match_returns_none() {
        let rules = vec![(TestAction::Deny, "request system *".to_string())];
        let compiled =
            compile_rules(&rules, "test", RuleSource::Defaults, test_error_builder).unwrap();
        let rule_refs: Vec<_> = compiled.iter().collect();
        assert!(evaluate(&rule_refs, "show version").is_none());
    }

    #[test]
    fn evaluate_single_match_returns_rule() {
        let rules = vec![(TestAction::Deny, "request system *".to_string())];
        let compiled =
            compile_rules(&rules, "test", RuleSource::Defaults, test_error_builder).unwrap();
        let rule_refs: Vec<_> = compiled.iter().collect();
        let result = evaluate(&rule_refs, "request system reboot");
        assert!(result.is_some());
        assert_eq!(result.unwrap().pattern, "request system *");
    }

    #[test]
    fn evaluate_picks_most_specific() {
        let rules = vec![
            (TestAction::Deny, "request *".to_string()),
            (TestAction::Allow, "request system reboot".to_string()),
        ];
        let compiled =
            compile_rules(&rules, "test", RuleSource::Defaults, test_error_builder).unwrap();
        let rule_refs: Vec<_> = compiled.iter().collect();
        let result = evaluate(&rule_refs, "request system reboot");
        assert_eq!(result.unwrap().pattern, "request system reboot");
    }

    #[test]
    fn evaluate_device_wins_tiebreak() {
        let defaults = vec![(TestAction::Deny, "request system *".to_string())];
        let device = vec![(TestAction::Allow, "request system *".to_string())];
        let compiled_defaults =
            compile_rules(&defaults, "test", RuleSource::Defaults, test_error_builder).unwrap();
        let compiled_device =
            compile_rules(&device, "test", RuleSource::Device, test_error_builder).unwrap();
        let mut all_rules = Vec::new();
        all_rules.extend(compiled_defaults.iter());
        all_rules.extend(compiled_device.iter());
        let result = evaluate(&all_rules, "request system reboot");
        assert!(result.is_some());
        assert_eq!(result.unwrap().source, RuleSource::Device);
    }
}
