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

use std::collections::HashMap;

/// Pre-compiled rule collections for one subject domain (commands, config, or pfe_commands).
///
/// Generic over the action type to support both Junos (Allow/Deny) and PAN-OS action enums.
#[derive(Debug)]
pub struct DomainRules<A> {
    /// Rules that apply to all devices.
    pub defaults: Vec<CompiledRule<A>>,
    /// Per-device additions to defaults.
    pub device_specific: HashMap<String, Vec<CompiledRule<A>>>,
}

impl<A> Default for DomainRules<A> {
    fn default() -> Self {
        Self {
            defaults: Vec::new(),
            device_specific: HashMap::new(),
        }
    }
}

/// Compiled, per-device blocklist policy.
///
/// **Important:** This is a **fail-open, deny-pattern blocklist**. Any input that does
/// not match a deny rule is **allowed**. Callers expecting fail-closed behaviour (where
/// unmatched input is denied) must use a different authorisation model, such as an allowlist
/// or prefix validator. This engine is designed for operational blocklists where an operator
/// lists what must never run, and everything else is permitted.
///
/// The policy is built once at startup from pre-compiled rules and is cheap to clone via `Arc`.
/// Tool handlers consult it before any device interaction.
///
/// Generic over the action type `A` to support different action enums (e.g., Junos Allow/Deny,
/// PAN-OS equivalents). The action type must implement `Copy` and `PartialEq`.
#[derive(Debug)]
pub struct Policy<A> {
    /// Compiled rules for the "commands" domain.
    commands: DomainRules<A>,
    /// Compiled rules for the "config" domain.
    config: DomainRules<A>,
    /// Compiled rules for the "pfe_commands" domain.
    pfe_commands: DomainRules<A>,
}

impl<A> Policy<A>
where
    A: Copy + PartialEq,
{
    /// Build a policy from pre-compiled domain rule sets.
    ///
    /// This constructor accepts three `DomainRules` structs (one per subject domain:
    /// commands, config, pfe_commands), each containing default rules and per-device
    /// additions. The caller is responsible for compiling globs via `compile_rules()`
    /// before passing them in.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_policy::{Policy, DomainRules};
    ///
    /// let commands = DomainRules::default();
    /// let config = DomainRules::default();
    /// let pfe_commands = DomainRules::default();
    ///
    /// let policy: Policy<()> = Policy::new(commands, config, pfe_commands);
    /// ```
    pub fn new(
        commands: DomainRules<A>,
        config: DomainRules<A>,
        pfe_commands: DomainRules<A>,
    ) -> Self {
        Self {
            commands,
            config,
            pfe_commands,
        }
    }

    /// Effective command rules for a device = defaults ⊕ device-specific.
    pub fn command_rules_for(&self, device: &str) -> Vec<&CompiledRule<A>> {
        self.commands
            .defaults
            .iter()
            .chain(
                self.commands
                    .device_specific
                    .get(device)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Effective config rules for a device = defaults ⊕ device-specific.
    pub fn config_rules_for(&self, device: &str) -> Vec<&CompiledRule<A>> {
        self.config
            .defaults
            .iter()
            .chain(
                self.config
                    .device_specific
                    .get(device)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// True if the per-device effective config rule list is non-empty.
    pub fn has_config_rules_for(&self, device: &str) -> bool {
        !self.config.defaults.is_empty()
            || self
                .config
                .device_specific
                .get(device)
                .is_some_and(|v| !v.is_empty())
    }

    /// Effective PFE-command rules for a device = defaults ⊕ device-specific.
    pub fn pfe_command_rules_for(&self, device: &str) -> Vec<&CompiledRule<A>> {
        self.pfe_commands
            .defaults
            .iter()
            .chain(
                self.pfe_commands
                    .device_specific
                    .get(device)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Decide whether `command` is allowed on `device` in the commands domain.
    ///
    /// **Fail-open behaviour:** If no deny rule matches (or there are no rules), the
    /// command is **allowed**. This is a blocklist, not an allowlist.
    ///
    /// Whitespace is normalized before matching (trimmed and collapsed to single spaces).
    pub fn check_command<'a>(
        &'a self,
        device: &str,
        command: &str,
        deny_action: A,
    ) -> Decision<'a, A> {
        let normalized = normalize_input(command);
        let rules = self.command_rules_for(device);
        match evaluate(&rules, &normalized) {
            Some(rule) if rule.action == deny_action => Decision::Deny {
                rule,
                source: rule.source,
                line_number: None,
            },
            _ => Decision::Allow,
        }
    }

    /// Decide whether `pfe_command` is allowed on `device` in the pfe_commands domain.
    ///
    /// **Fail-open behaviour:** If no deny rule matches (or there are no rules), the
    /// command is **allowed**. This is a blocklist, not an allowlist.
    ///
    /// Whitespace is normalized before matching. Independent from `check_command`.
    pub fn check_pfe_command<'a>(
        &'a self,
        device: &str,
        pfe_command: &str,
        deny_action: A,
    ) -> Decision<'a, A> {
        let normalized = normalize_input(pfe_command);
        let rules = self.pfe_command_rules_for(device);
        match evaluate(&rules, &normalized) {
            Some(rule) if rule.action == deny_action => Decision::Deny {
                rule,
                source: rule.source,
                line_number: None,
            },
            _ => Decision::Allow,
        }
    }

    /// Decide whether `config_text` is allowed on `device` in the config domain.
    ///
    /// **Fail-open behaviour:** If no deny rule matches (or there are no rules), the
    /// config is **allowed**. This is a blocklist, not an allowlist.
    ///
    /// If `config_format` is not the expected format string and rules exist for this
    /// device, returns an error. Config text is checked line-by-line; comment lines
    /// (starting with `#`) and blank lines are skipped.
    ///
    /// # Errors
    ///
    /// Returns an error if `config_format` is not the expected format and the device
    /// has effective config rules. The expected format and error type are supplied by
    /// the caller.
    pub fn check_config<'a, E>(
        &'a self,
        device: &str,
        config_format: &str,
        config_text: &str,
        deny_action: A,
        expected_format: &str,
        error_builder: impl FnOnce(String) -> E,
    ) -> Result<Decision<'a, A>, E> {
        let rules = self.config_rules_for(device);
        if rules.is_empty() {
            return Ok(Decision::Allow);
        }
        if config_format != expected_format {
            return Err(error_builder(config_format.to_string()));
        }

        for (idx, raw_line) in config_text.lines().enumerate() {
            let line = normalize_input(raw_line);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(rule) = evaluate(&rules, &line)
                && rule.action == deny_action
            {
                return Ok(Decision::Deny {
                    rule,
                    source: rule.source,
                    line_number: Some(idx + 1),
                });
            }
        }
        Ok(Decision::Allow)
    }

    /// Counts for startup info logging.
    pub fn rule_counts(&self) -> PolicyCounts {
        let devices_with_rules = self
            .commands
            .device_specific
            .keys()
            .chain(self.config.device_specific.keys())
            .chain(self.pfe_commands.device_specific.keys())
            .collect::<std::collections::HashSet<_>>()
            .len();
        PolicyCounts {
            default_commands: self.commands.defaults.len(),
            default_config: self.config.defaults.len(),
            default_pfe_commands: self.pfe_commands.defaults.len(),
            devices_with_rules,
        }
    }
}

/// Summary numbers for startup logging.
#[derive(Debug, Clone, Copy)]
pub struct PolicyCounts {
    /// Number of default command rules.
    pub default_commands: usize,
    /// Number of default config rules.
    pub default_config: usize,
    /// Number of default PFE-command rules.
    pub default_pfe_commands: usize,
    /// Count of devices with at least one device-specific rule.
    pub devices_with_rules: usize,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    fn count_literal_chars_handles_wildcards_and_classes() {
        assert_eq!(count_literal_chars("request system reboot"), 21);
        assert_eq!(count_literal_chars("request system *"), 15);
        assert_eq!(count_literal_chars("*"), 0);
        assert_eq!(count_literal_chars("?abc"), 3);
        assert_eq!(count_literal_chars("ab[cd]ef"), 4);
        assert_eq!(count_literal_chars(r"\*literal"), 8);
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
    fn compile_rules_errors_with_scope_on_bad_glob() {
        let rules = vec![(TestAction::Deny, "[unterminated".to_string())];
        let result = compile_rules(
            &rules,
            "_blocklist_defaults.commands",
            RuleSource::Defaults,
            test_error_builder,
        );
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.scope, "_blocklist_defaults.commands");
        assert_eq!(err.pattern, "[unterminated");
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

    // Policy builder and decision tests

    fn make_policy_no_rules() -> Policy<TestAction> {
        Policy::new(
            DomainRules::default(),
            DomainRules::default(),
            DomainRules::default(),
        )
    }

    fn make_compiled_rule(
        action: TestAction,
        pattern: &str,
        source: RuleSource,
    ) -> CompiledRule<TestAction> {
        let rules = vec![(action, pattern.to_string())];
        compile_rules(&rules, "test", source, test_error_builder)
            .unwrap()
            .into_iter()
            .next()
            .unwrap()
    }

    #[test]
    fn policy_build_handles_no_rules() {
        let p = make_policy_no_rules();
        assert!(p.command_rules_for("r1").is_empty());
        assert!(p.config_rules_for("r1").is_empty());
        assert!(p.pfe_command_rules_for("r1").is_empty());
    }

    #[test]
    fn policy_merges_defaults_and_device_rules() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));
        commands.device_specific.insert(
            "r1".to_string(),
            vec![make_compiled_rule(
                TestAction::Allow,
                "request system reboot",
                RuleSource::Device,
            )],
        );

        let p = Policy::new(commands, DomainRules::default(), DomainRules::default());
        let r1_cmds = p.command_rules_for("r1");
        assert_eq!(r1_cmds.len(), 2);
        assert!(r1_cmds.iter().any(|r| r.source == RuleSource::Defaults));
        assert!(r1_cmds.iter().any(|r| r.source == RuleSource::Device));
    }

    #[test]
    fn policy_empty_per_device_blocklist_does_not_inflate_rule_counts() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "x",
            RuleSource::Defaults,
        ));

        let p = Policy::new(commands, DomainRules::default(), DomainRules::default());
        let counts = p.rule_counts();
        assert_eq!(counts.default_commands, 1);
        assert_eq!(counts.default_config, 0);
        assert_eq!(
            counts.devices_with_rules, 0,
            "r1 has empty blocklist; should not count"
        );
    }

    #[test]
    fn policy_check_command_no_rules_allows() {
        let p = make_policy_no_rules();
        assert!(matches!(
            p.check_command("r1", "show version", TestAction::Deny),
            Decision::Allow
        ));
    }

    #[test]
    fn policy_check_command_equal_specificity_device_wins() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));
        commands.device_specific.insert(
            "r1".to_string(),
            vec![make_compiled_rule(
                TestAction::Allow,
                "request system *",
                RuleSource::Device,
            )],
        );

        let p = Policy::new(commands, DomainRules::default(), DomainRules::default());
        assert!(matches!(
            p.check_command("r1", "request system reboot", TestAction::Deny),
            Decision::Allow
        ));
    }

    #[test]
    fn policy_check_command_more_specific_device_allow_overrides_broader_deny() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));
        commands.device_specific.insert(
            "r1".to_string(),
            vec![make_compiled_rule(
                TestAction::Allow,
                "request system reboot",
                RuleSource::Device,
            )],
        );

        let p = Policy::new(commands, DomainRules::default(), DomainRules::default());
        assert!(matches!(
            p.check_command("r1", "request system reboot", TestAction::Deny),
            Decision::Allow
        ));
        assert!(matches!(
            p.check_command("r1", "request system halt", TestAction::Deny),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn policy_check_command_whitespace_is_normalized() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system reboot",
            RuleSource::Defaults,
        ));

        let p = Policy::new(commands, DomainRules::default(), DomainRules::default());
        assert!(matches!(
            p.check_command("r1", "  request   system\treboot  ", TestAction::Deny),
            Decision::Deny { .. }
        ));
    }

    #[test]
    fn policy_check_command_deny_carries_matched_rule_metadata() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));

        let p = Policy::new(commands, DomainRules::default(), DomainRules::default());
        match p.check_command("r1", "request system reboot", TestAction::Deny) {
            Decision::Deny {
                rule,
                source,
                line_number,
            } => {
                assert_eq!(rule.pattern, "request system *");
                assert_eq!(source, RuleSource::Defaults);
                assert!(line_number.is_none());
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_config_no_rules_allows_any_format() {
        let p = make_policy_no_rules();
        let r = p
            .check_config(
                "r1",
                "xml",
                "<configuration/>",
                TestAction::Deny,
                "set",
                |f| f,
            )
            .unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn policy_check_config_non_expected_format_with_rules_errors() {
        let mut config = DomainRules::default();
        config.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "delete *",
            RuleSource::Defaults,
        ));

        let p = Policy::new(DomainRules::default(), config, DomainRules::default());
        let err = p
            .check_config("r1", "xml", "<x/>", TestAction::Deny, "set", |f| f)
            .unwrap_err();
        assert_eq!(err, "xml");
    }

    #[test]
    fn policy_check_config_per_line_match_rejects_first_offending_line() {
        let mut config = DomainRules::default();
        config.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "delete *",
            RuleSource::Defaults,
        ));

        let p = Policy::new(DomainRules::default(), config, DomainRules::default());
        let payload =
            "set interfaces ge-0/0/0 description ok\ndelete protocols bgp\nset system host-name r1";
        match p
            .check_config("r1", "set", payload, TestAction::Deny, "set", |f| f)
            .unwrap()
        {
            Decision::Deny {
                line_number, rule, ..
            } => {
                assert_eq!(line_number, Some(2));
                assert_eq!(rule.pattern, "delete *");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_config_comment_lines_are_skipped() {
        let mut config = DomainRules::default();
        config.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "delete *",
            RuleSource::Defaults,
        ));

        let p = Policy::new(DomainRules::default(), config, DomainRules::default());
        let payload = "# delete this is just a comment\nset system host-name r1";
        let r = p
            .check_config("r1", "set", payload, TestAction::Deny, "set", |f| f)
            .unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn policy_check_config_per_line_allow_carve_out_works() {
        let mut config = DomainRules::default();
        config.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "delete *",
            RuleSource::Defaults,
        ));
        config.device_specific.insert(
            "r1".to_string(),
            vec![make_compiled_rule(
                TestAction::Allow,
                "delete interfaces ge-0/0/0",
                RuleSource::Device,
            )],
        );

        let p = Policy::new(DomainRules::default(), config, DomainRules::default());
        let payload = "delete interfaces ge-0/0/0\nset interfaces ge-0/0/0 description new";
        let r = p
            .check_config("r1", "set", payload, TestAction::Deny, "set", |f| f)
            .unwrap();
        assert!(matches!(r, Decision::Allow));
    }

    #[test]
    fn policy_build_collects_pfe_commands_from_defaults_and_device() {
        let mut pfe_commands = DomainRules::default();
        pfe_commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "set *",
            RuleSource::Defaults,
        ));
        pfe_commands.device_specific.insert(
            "r1".to_string(),
            vec![make_compiled_rule(
                TestAction::Allow,
                "set debug *",
                RuleSource::Device,
            )],
        );

        let p = Policy::new(DomainRules::default(), DomainRules::default(), pfe_commands);
        let r1_pfe = p.pfe_command_rules_for("r1");
        assert_eq!(r1_pfe.len(), 2);
        assert!(r1_pfe.iter().any(|r| r.source == RuleSource::Defaults));
        assert!(r1_pfe.iter().any(|r| r.source == RuleSource::Device));
    }

    #[test]
    fn policy_pfe_rules_independent_from_command_rules() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));

        let mut pfe_commands = DomainRules::default();
        pfe_commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "set *",
            RuleSource::Defaults,
        ));

        let p = Policy::new(commands, DomainRules::default(), pfe_commands);
        assert_eq!(p.command_rules_for("r1").len(), 1);
        assert_eq!(p.pfe_command_rules_for("r1").len(), 1);
        assert_eq!(p.command_rules_for("r1")[0].pattern, "request system *");
        assert_eq!(p.pfe_command_rules_for("r1")[0].pattern, "set *");
    }

    #[test]
    fn policy_check_pfe_command_denies_when_pattern_matches() {
        let mut pfe_commands = DomainRules::default();
        pfe_commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "set *",
            RuleSource::Defaults,
        ));

        let p = Policy::new(DomainRules::default(), DomainRules::default(), pfe_commands);
        match p.check_pfe_command("r1", "set jnh 0 debug", TestAction::Deny) {
            Decision::Deny { rule, .. } => assert_eq!(rule.pattern, "set *"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn policy_check_pfe_command_allows_when_no_rules() {
        let p = make_policy_no_rules();
        assert!(matches!(
            p.check_pfe_command("r1", "show jnh 0 stats", TestAction::Deny),
            Decision::Allow
        ));
    }

    #[test]
    fn policy_check_pfe_command_does_not_consult_command_rules() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "set *",
            RuleSource::Defaults,
        ));

        let p = Policy::new(commands, DomainRules::default(), DomainRules::default());
        assert!(matches!(
            p.check_pfe_command("r1", "set anything", TestAction::Deny),
            Decision::Allow
        ));
    }
}
