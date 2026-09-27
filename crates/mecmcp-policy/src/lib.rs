//! Pure rule-evaluation logic for command guardrails.
//!
//! Provides two authorization models for the commands and pfe_commands
//! domains — a fail-closed token-prefix [`CommandMode::Allowlist`] and a
//! fail-open glob [`CommandMode::Blocklist`] — plus the config-domain
//! blocklist engine, all decoupled from any specific inventory format. These
//! primitives power policy checks in both Junos and PAN-OS MCP servers.

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

/// Which authorization model governs the commands and pfe_commands domains
/// of a [`Policy`]. Chosen once per policy; both domains share the same mode.
/// The config domain is unaffected — it is always a deny-pattern blocklist.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CommandMode {
    /// Fail-closed: a command is denied unless it matches an allowlist entry.
    /// **This is the default** (`CommandMode::default()`), so a policy built
    /// without picking a mode explicitly refuses every command.
    ///
    /// # Matching
    ///
    /// Allowlist entries are **command prefixes parsed as whitespace-separated
    /// tokens, never globs.** The input is normalized the same way
    /// [`normalize_input`] does (trimmed, whitespace collapsed) and split on
    /// whitespace; a command is allowed only if some entry's token sequence is
    /// a whole-token *prefix* of the input's tokens. `show interfaces` matches
    /// `show interfaces ge-0/0/0` but **not** `show interfaces-foo` — matching
    /// is exact, case-sensitive, and stops at token boundaries.
    ///
    /// **Abbreviations are refused, not expanded.** `sh ver` does not match a
    /// `show version` entry. Expanding abbreviations would require encoding
    /// vendor CLI grammar that changes between releases — exactly the kind of
    /// non-determinism a fail-closed allowlist exists to remove.
    ///
    /// Glob metacharacters (`*`, `?`, `[`) in an entry are rejected at compile
    /// time by [`compile_allowlist_entries`]; they are never treated as
    /// literals or silently allowed through.
    ///
    /// # Pipes and separators
    ///
    /// If the (pre-normalization) input contains `;`, `>`, `<`, a backtick, or
    /// a newline anywhere, it is refused outright — a
    /// [`AllowlistDenyReason::ForbiddenMetachar`] decision. Otherwise, if it
    /// contains `|`, the part before the first `|` is matched against the
    /// domain's allowlist entries and every stage after a `|` is matched
    /// against a separate `allowed_pipes` list, which defaults to empty — so a
    /// policy that doesn't configure `allowed_pipes` refuses every piped
    /// command, even one whose first stage is allowed.
    ///
    /// An empty allowlist (no entries at all) refuses every command,
    /// including the empty string.
    #[default]
    Allowlist,
    /// Fail-open: any input that does not match a deny rule is allowed. This
    /// is the pre-MEC-92 blocklist behaviour, unchanged; it is only used when
    /// explicitly requested by the caller. Nothing in this crate maps an
    /// absent mode to `Blocklist` — that mapping, if a deployment needs it for
    /// backward compatibility, belongs in the consumer that builds `Policy`.
    Blocklist,
}

/// Why a [`CommandMode::Allowlist`] check refused a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowlistDenyReason {
    /// No allowlist entry's token sequence is a whole-token prefix of the
    /// (first stage of the) input.
    NotAllowlisted,
    /// A `|`-separated stage after the first did not match any
    /// `allowed_pipes` entry.
    PipeNotAllowlisted,
    /// The input contains a forbidden separator or metacharacter (`;`, `>`,
    /// `<`, a backtick, or a newline) anywhere.
    ForbiddenMetachar,
}

impl AllowlistDenyReason {
    /// Stable, machine-readable string for audit logs (`snake_case`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAllowlisted => "not_allowlisted",
            Self::PipeNotAllowlisted => "pipe_not_allowlisted",
            Self::ForbiddenMetachar => "forbidden_metachar",
        }
    }
}

/// A single compiled allowlist entry: an ordered sequence of literal tokens.
///
/// Built only via [`compile_allowlist_entries`], which rejects glob
/// metacharacters and blank entries, so a live `AllowlistEntry` is always a
/// non-empty literal token sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowlistEntry {
    tokens: Vec<String>,
}

impl AllowlistEntry {
    /// The entry's tokens, in order.
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }
}

/// Why an allowlist entry string was rejected at compile time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowlistEntryErrorKind {
    /// The entry contains a glob metacharacter (`*`, `?`, or `[`). Allowlist
    /// entries are literal token prefixes, never globs.
    GlobMetachar(char),
    /// The entry is empty or all-whitespace and normalizes to zero tokens.
    Empty,
}

/// Compile a list of allowlist entry strings into [`AllowlistEntry`] token
/// sequences, attaching the given `scope` label used in compile-time error
/// messages.
///
/// Each entry is split on whitespace (same rule as [`normalize_input`]
/// applies to command input at check time): `"show version"` becomes the
/// token sequence `["show", "version"]`.
///
/// # Errors
///
/// Returns an error if any entry contains a glob metacharacter (`*`, `?`, or
/// `[`) or is empty/all-whitespace. Silently treating `*` as a literal would
/// be memory-safe but would hide an operator's typo as a policy gap, so this
/// is rejected up front instead.
pub fn compile_allowlist_entries<E>(
    entries: &[String],
    scope: &str,
    error_builder: impl Fn(String, String, AllowlistEntryErrorKind) -> E,
) -> Result<Vec<AllowlistEntry>, E> {
    entries
        .iter()
        .map(|entry| {
            if let Some(metachar) = entry.chars().find(|c| matches!(c, '*' | '?' | '[')) {
                return Err(error_builder(
                    scope.to_string(),
                    entry.clone(),
                    AllowlistEntryErrorKind::GlobMetachar(metachar),
                ));
            }
            let tokens: Vec<String> = entry.split_whitespace().map(str::to_string).collect();
            if tokens.is_empty() {
                return Err(error_builder(
                    scope.to_string(),
                    entry.clone(),
                    AllowlistEntryErrorKind::Empty,
                ));
            }
            Ok(AllowlistEntry { tokens })
        })
        .collect()
}

/// Fail-closed allowlist for one command-shaped domain (commands or
/// pfe_commands).
///
/// `entries` governs the whole command, or the first stage of a piped one.
/// `allowed_pipes` governs every stage after a `|` and defaults to empty, so
/// a `CommandAllowlist` that doesn't set it refuses all piped commands. See
/// [`CommandMode::Allowlist`] for the full matching rules.
#[derive(Debug, Clone, Default)]
pub struct CommandAllowlist {
    /// Token-prefix entries the command (or its first pipe stage) must match.
    pub entries: Vec<AllowlistEntry>,
    /// Token-prefix entries each `|` stage after the first must match.
    pub allowed_pipes: Vec<AllowlistEntry>,
}

/// Characters whose presence anywhere in an allowlist-mode command refuses it
/// unconditionally, because they open a second, ungoverned way to affect what
/// runs: `;` and newlines separate statements, `>`/`<` redirect, and a
/// backtick substitutes a command.
///
/// Checked against the *raw*, pre-normalization input: [`normalize_input`]
/// collapses all whitespace — including newlines — into plain spaces, which
/// would hide a line-injection attempt if checked afterwards.
fn contains_forbidden_metachar(raw: &str) -> bool {
    raw.chars()
        .any(|c| matches!(c, ';' | '>' | '<' | '`' | '\n' | '\r'))
}

/// True if `entry`'s tokens are a whole-token prefix of `input_tokens`.
fn is_token_prefix(entry: &AllowlistEntry, input_tokens: &[&str]) -> bool {
    entry.tokens.len() <= input_tokens.len()
        && entry
            .tokens
            .iter()
            .zip(input_tokens.iter())
            .all(|(entry_token, input_token)| entry_token == input_token)
}

/// True if any entry in `list` is a whole-token prefix of `input_tokens`.
fn matches_any_entry(list: &[AllowlistEntry], input_tokens: &[&str]) -> bool {
    list.iter()
        .any(|entry| is_token_prefix(entry, input_tokens))
}

/// Evaluate `command` against a [`CommandAllowlist`]. See
/// [`CommandMode::Allowlist`] for the full semantics.
fn evaluate_allowlist<'a, A>(command: &str, allowlist: &CommandAllowlist) -> Decision<'a, A> {
    let normalized = normalize_input(command);

    if contains_forbidden_metachar(command) {
        return Decision::DenyAllowlist {
            mode: CommandMode::Allowlist,
            reason: AllowlistDenyReason::ForbiddenMetachar,
            normalized,
        };
    }

    let mut stages = normalized.split('|');
    let first_stage_tokens: Vec<&str> = stages
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if !matches_any_entry(&allowlist.entries, &first_stage_tokens) {
        return Decision::DenyAllowlist {
            mode: CommandMode::Allowlist,
            reason: AllowlistDenyReason::NotAllowlisted,
            normalized,
        };
    }

    for stage in stages {
        let tokens: Vec<&str> = stage.split_whitespace().collect();
        if !matches_any_entry(&allowlist.allowed_pipes, &tokens) {
            return Decision::DenyAllowlist {
                mode: CommandMode::Allowlist,
                reason: AllowlistDenyReason::PipeNotAllowlisted,
                normalized,
            };
        }
    }

    Decision::Allow
}

/// Outcome of a policy check.
///
/// There are now two deny shapes (`Deny` and `DenyAllowlist`), so **never**
/// gate on `if let Decision::Deny { .. } = decision { refuse }` or a partial
/// match against a single variant — either shape denies, and code that only
/// recognizes one silently allows the other. Use [`Decision::is_allowed`], or
/// match all three variants exhaustively.
#[derive(Debug)]
#[must_use = "a Decision must be checked with `is_allowed()` (or matched exhaustively) or the policy check has no effect"]
pub enum Decision<'a, A> {
    /// The input is allowed.
    Allow,
    /// The input is denied by a matched blocklist rule (config domain, or the
    /// commands/pfe_commands domains under [`CommandMode::Blocklist`]).
    Deny {
        /// The rule that triggered the denial.
        rule: &'a CompiledRule<A>,
        /// Whether the rule came from defaults or device config.
        source: RuleSource,
        /// Set only for config-domain checks; identifies the offending line
        /// (1-indexed, comment lines counted).
        line_number: Option<usize>,
    },
    /// The input is denied under [`CommandMode::Allowlist`]. Carries enough
    /// for an audit log: the mode, the reason, and the normalized command.
    DenyAllowlist {
        /// The mode that produced this decision (currently always
        /// [`CommandMode::Allowlist`]; carried explicitly so the audit record
        /// is self-contained without out-of-band context).
        mode: CommandMode,
        /// Why the input was refused.
        reason: AllowlistDenyReason,
        /// The input after [`normalize_input`]: whitespace trimmed and
        /// collapsed to single spaces, including newlines. Log this field,
        /// never the raw input — the raw input may still contain the
        /// newline that triggered `ForbiddenMetachar`, which could smuggle a
        /// forged line into a log file.
        normalized: String,
    },
}

impl<A> Decision<'_, A> {
    /// True only for [`Decision::Allow`].
    ///
    /// Prefer this over matching a single deny variant: `Decision` has two
    /// deny shapes (`Deny`, `DenyAllowlist`), and a caller that only
    /// recognizes one — e.g. `if let Decision::Deny { .. } = d { refuse }
    /// else { allow }` — will silently allow the other. Either gate on
    /// `is_allowed()`, or match all three variants exhaustively.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
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

/// Blocklist rules plus a fail-closed allowlist for one command-shaped domain
/// (commands or pfe_commands). Which one is consulted is decided by the
/// owning [`Policy`]'s [`CommandMode`].
#[derive(Debug)]
pub struct CommandDomain<A> {
    /// Deny-pattern rules, consulted under [`CommandMode::Blocklist`].
    pub blocklist: DomainRules<A>,
    /// Token-prefix allowlist, consulted under [`CommandMode::Allowlist`].
    pub allowlist: CommandAllowlist,
}

impl<A> Default for CommandDomain<A> {
    fn default() -> Self {
        Self {
            blocklist: DomainRules::default(),
            allowlist: CommandAllowlist::default(),
        }
    }
}

/// Compiled, per-device command policy.
///
/// The **commands** and **pfe_commands** domains are governed by a single,
/// policy-wide [`CommandMode`]:
///
/// - **[`CommandMode::Allowlist`] — fail-closed, the default.** A command is
///   denied unless it is a whole-token prefix match of an allowlist entry. An
///   empty allowlist denies everything, including the empty string.
/// - **[`CommandMode::Blocklist`] — fail-open, opt-in.** Any input that does
///   not match a deny rule is allowed. This is the original guardrail model:
///   an operator lists what must never run, and everything else is
///   permitted. Kept unchanged for deployments that request it explicitly.
///
/// The **config** domain is unaffected by `CommandMode` and is always a
/// deny-pattern blocklist: any input that does not match a deny rule is
/// allowed.
///
/// The policy is built once at startup from pre-compiled rules and is cheap to clone via `Arc`.
/// Tool handlers consult it before any device interaction.
///
/// Generic over the action type `A` to support different action enums (e.g., Junos Allow/Deny,
/// PAN-OS equivalents). The action type must implement `Copy` and `PartialEq`.
#[derive(Debug)]
pub struct Policy<A> {
    /// Fail-closed vs fail-open mode, shared by the commands and
    /// pfe_commands domains.
    command_mode: CommandMode,
    /// Rules and allowlist for the "commands" domain.
    commands: CommandDomain<A>,
    /// Compiled rules for the "config" domain.
    config: DomainRules<A>,
    /// Rules and allowlist for the "pfe_commands" domain.
    pfe_commands: CommandDomain<A>,
}

impl<A> Policy<A>
where
    A: Copy + PartialEq,
{
    /// Build a policy from a [`CommandMode`] and three domain configs
    /// (commands, config, pfe_commands).
    ///
    /// The caller is responsible for compiling globs via `compile_rules()`
    /// and allowlist entries via [`compile_allowlist_entries`] before passing
    /// them in.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_policy::{CommandDomain, CommandMode, DomainRules, Policy};
    ///
    /// let commands = CommandDomain::default();
    /// let config = DomainRules::default();
    /// let pfe_commands = CommandDomain::default();
    ///
    /// let policy: Policy<()> = Policy::new(CommandMode::Blocklist, commands, config, pfe_commands);
    /// ```
    pub fn new(
        command_mode: CommandMode,
        commands: CommandDomain<A>,
        config: DomainRules<A>,
        pfe_commands: CommandDomain<A>,
    ) -> Self {
        Self {
            command_mode,
            commands,
            config,
            pfe_commands,
        }
    }

    /// Effective command blocklist rules for a device = defaults ⊕ device-specific.
    ///
    /// Only meaningful under [`CommandMode::Blocklist`].
    pub fn command_rules_for(&self, device: &str) -> Vec<&CompiledRule<A>> {
        self.commands
            .blocklist
            .defaults
            .iter()
            .chain(
                self.commands
                    .blocklist
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

    /// Effective PFE-command blocklist rules for a device = defaults ⊕ device-specific.
    ///
    /// Only meaningful under [`CommandMode::Blocklist`].
    pub fn pfe_command_rules_for(&self, device: &str) -> Vec<&CompiledRule<A>> {
        self.pfe_commands
            .blocklist
            .defaults
            .iter()
            .chain(
                self.pfe_commands
                    .blocklist
                    .device_specific
                    .get(device)
                    .into_iter()
                    .flat_map(|v| v.iter()),
            )
            .collect()
    }

    /// Decide whether `command` is allowed on `device` in the commands domain.
    ///
    /// Dispatches on the policy's [`CommandMode`]:
    ///
    /// - **`Allowlist`** (the default): fail-closed token-prefix matching
    ///   against the commands domain's allowlist. `device` is not consulted —
    ///   the allowlist is not per-device. See [`CommandMode::Allowlist`] for
    ///   the exact rules.
    /// - **`Blocklist`**: fail-open. If no deny rule matches (or there are no
    ///   rules), the command is allowed. Whitespace is normalized before
    ///   matching (trimmed and collapsed to single spaces). Byte-for-byte the
    ///   pre-MEC-92 behaviour.
    pub fn check_command<'a>(
        &'a self,
        device: &str,
        command: &str,
        deny_action: A,
    ) -> Decision<'a, A> {
        match self.command_mode {
            CommandMode::Allowlist => evaluate_allowlist(command, &self.commands.allowlist),
            CommandMode::Blocklist => {
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
        }
    }

    /// Decide whether `pfe_command` is allowed on `device` in the pfe_commands domain.
    ///
    /// Dispatches on the policy's [`CommandMode`], independently of
    /// `check_command`'s result. See `check_command` for the mode semantics;
    /// this method consults the pfe_commands domain's rules/allowlist
    /// instead of the commands domain's.
    pub fn check_pfe_command<'a>(
        &'a self,
        device: &str,
        pfe_command: &str,
        deny_action: A,
    ) -> Decision<'a, A> {
        match self.command_mode {
            CommandMode::Allowlist => evaluate_allowlist(pfe_command, &self.pfe_commands.allowlist),
            CommandMode::Blocklist => {
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
        }
    }

    /// Decide whether `config_text` is allowed on `device` in the config domain.
    ///
    /// **Fail-open behaviour:** If no deny rule matches (or there are no
    /// rules), the config is **allowed**. This is a blocklist, not an
    /// allowlist, and is unaffected by [`CommandMode`].
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
            .blocklist
            .device_specific
            .keys()
            .chain(self.config.device_specific.keys())
            .chain(self.pfe_commands.blocklist.device_specific.keys())
            .collect::<std::collections::HashSet<_>>()
            .len();
        PolicyCounts {
            default_commands: self.commands.blocklist.defaults.len(),
            default_config: self.config.defaults.len(),
            default_pfe_commands: self.pfe_commands.blocklist.defaults.len(),
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

    #[derive(Debug)]
    struct TestAllowlistError {
        scope: String,
        entry: String,
        kind: AllowlistEntryErrorKind,
    }

    fn test_allowlist_error_builder(
        scope: String,
        entry: String,
        kind: AllowlistEntryErrorKind,
    ) -> TestAllowlistError {
        TestAllowlistError { scope, entry, kind }
    }

    fn allowlist_entries(strs: &[&str]) -> Vec<AllowlistEntry> {
        let owned: Vec<String> = strs.iter().map(|s| s.to_string()).collect();
        compile_allowlist_entries(&owned, "test", test_allowlist_error_builder).unwrap()
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

    // Allowlist entry compilation

    #[test]
    fn compile_allowlist_entries_splits_on_whitespace() {
        let entries = vec!["show   version".to_string(), "request".to_string()];
        let compiled =
            compile_allowlist_entries(&entries, "test", test_allowlist_error_builder).unwrap();
        assert_eq!(
            compiled[0].tokens(),
            &["show".to_string(), "version".to_string()]
        );
        assert_eq!(compiled[1].tokens(), &["request".to_string()]);
    }

    #[test]
    fn compile_allowlist_entries_rejects_glob_star() {
        let entries = vec!["show *".to_string()];
        let err =
            compile_allowlist_entries(&entries, "scope", test_allowlist_error_builder).unwrap_err();
        assert_eq!(err.scope, "scope");
        assert_eq!(err.entry, "show *");
        assert_eq!(err.kind, AllowlistEntryErrorKind::GlobMetachar('*'));
    }

    #[test]
    fn compile_allowlist_entries_rejects_glob_question_mark() {
        let entries = vec!["sh?w version".to_string()];
        let err =
            compile_allowlist_entries(&entries, "scope", test_allowlist_error_builder).unwrap_err();
        assert_eq!(err.kind, AllowlistEntryErrorKind::GlobMetachar('?'));
    }

    #[test]
    fn compile_allowlist_entries_rejects_glob_bracket() {
        let entries = vec!["show [version]".to_string()];
        let err =
            compile_allowlist_entries(&entries, "scope", test_allowlist_error_builder).unwrap_err();
        assert_eq!(err.kind, AllowlistEntryErrorKind::GlobMetachar('['));
    }

    #[test]
    fn compile_allowlist_entries_rejects_blank_entry() {
        let entries = vec!["   ".to_string()];
        let err =
            compile_allowlist_entries(&entries, "scope", test_allowlist_error_builder).unwrap_err();
        assert_eq!(err.kind, AllowlistEntryErrorKind::Empty);
    }

    // Policy builder and decision tests

    fn make_policy_no_rules() -> Policy<TestAction> {
        Policy::new(
            CommandMode::Blocklist,
            CommandDomain::default(),
            DomainRules::default(),
            CommandDomain::default(),
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

    fn blocklist_domain(rules: DomainRules<TestAction>) -> CommandDomain<TestAction> {
        CommandDomain {
            blocklist: rules,
            allowlist: CommandAllowlist::default(),
        }
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            CommandDomain::default(),
            config,
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            CommandDomain::default(),
            config,
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            CommandDomain::default(),
            config,
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            CommandDomain::default(),
            config,
            CommandDomain::default(),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            CommandDomain::default(),
            DomainRules::default(),
            blocklist_domain(pfe_commands),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            blocklist_domain(pfe_commands),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            CommandDomain::default(),
            DomainRules::default(),
            blocklist_domain(pfe_commands),
        );
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

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            CommandDomain::default(),
        );
        assert!(matches!(
            p.check_pfe_command("r1", "set anything", TestAction::Deny),
            Decision::Allow
        ));
    }

    // Blocklist-mode regression table: every scenario the old fail-open engine
    // covered, re-run through the mode-dispatching `check_command`/
    // `check_pfe_command` to show `CommandMode::Blocklist` is behaviourally
    // unchanged.
    #[test]
    fn blocklist_mode_decisions_match_pre_mec_92_fixtures() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "delete *",
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

        let mut pfe_commands = DomainRules::default();
        pfe_commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));
        pfe_commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "delete *",
            RuleSource::Defaults,
        ));
        pfe_commands.device_specific.insert(
            "r1".to_string(),
            vec![make_compiled_rule(
                TestAction::Allow,
                "request system reboot",
                RuleSource::Device,
            )],
        );

        let p = Policy::new(
            CommandMode::Blocklist,
            blocklist_domain(commands),
            DomainRules::default(),
            blocklist_domain(pfe_commands),
        );

        let cases: &[(&str, &str, bool)] = &[
            ("r1", "show version", true),
            ("r1", "request system reboot", true),
            ("r1", "request system halt", false),
            ("r1", "delete protocols bgp", false),
            ("r2", "request system reboot", false),
            ("r2", "show version", true),
            ("r1", "  request   system\treboot  ", true),
            ("r1", "", true),
        ];

        for (device, command, expect_allow) in cases {
            let decision = p.check_command(device, command, TestAction::Deny);
            assert_eq!(
                decision.is_allowed(),
                *expect_allow,
                "check_command device={device:?} command={command:?} expected allow={expect_allow}"
            );
            let pfe_decision = p.check_pfe_command(device, command, TestAction::Deny);
            assert_eq!(
                pfe_decision.is_allowed(),
                *expect_allow,
                "check_pfe_command device={device:?} command={command:?} expected allow={expect_allow}"
            );
        }
    }

    // Allowlist-mode regression tests (MEC-92 acceptance criteria).

    fn allowlist_policy(entries: &[&str], allowed_pipes: &[&str]) -> Policy<TestAction> {
        let allowlist = CommandAllowlist {
            entries: allowlist_entries(entries),
            allowed_pipes: allowlist_entries(allowed_pipes),
        };
        let commands = CommandDomain {
            blocklist: DomainRules::default(),
            allowlist,
        };
        Policy::new(
            CommandMode::Allowlist,
            commands,
            DomainRules::default(),
            CommandDomain::default(),
        )
    }

    #[test]
    fn allowlist_unlisted_command_is_denied() {
        let p = allowlist_policy(&["show version"], &[]);
        assert!(matches!(
            p.check_command("r1", "clear interfaces statistics", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_abbreviation_is_refused_not_expanded() {
        let p = allowlist_policy(&["show version"], &[]);
        assert!(matches!(
            p.check_command("r1", "sh ver", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_empty_list_refuses_everything_including_empty_string() {
        let p = allowlist_policy(&[], &[]);
        assert!(matches!(
            p.check_command("r1", "show version", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            }
        ));
        assert!(matches!(
            p.check_command("r1", "", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_matches_token_prefix() {
        let p = allowlist_policy(&["show interfaces"], &[]);
        assert!(matches!(
            p.check_command("r1", "show interfaces ge-0/0/0", TestAction::Deny),
            Decision::Allow
        ));
    }

    #[test]
    fn allowlist_respects_token_boundary_not_substring() {
        let p = allowlist_policy(&["show interfaces"], &[]);
        assert!(matches!(
            p.check_command("r1", "show interfaces-foo", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_pipe_refused_when_no_pipes_allowlisted() {
        let p = allowlist_policy(&["show configuration"], &[]);
        assert!(matches!(
            p.check_command(
                "r1",
                "show configuration | save /var/tmp/x",
                TestAction::Deny
            ),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::PipeNotAllowlisted,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_pipe_allowed_when_stage_in_allowed_pipes() {
        let p = allowlist_policy(&["show configuration"], &["save"]);
        assert!(matches!(
            p.check_command(
                "r1",
                "show configuration | save /var/tmp/x",
                TestAction::Deny
            ),
            Decision::Allow
        ));
    }

    #[test]
    fn allowlist_pipe_stage_not_matching_allowed_pipes_is_refused() {
        let p = allowlist_policy(&["show configuration"], &["save"]);
        assert!(matches!(
            p.check_command("r1", "show configuration | match secret", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::PipeNotAllowlisted,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_semicolon_is_refused() {
        let p = allowlist_policy(&["show version"], &[]);
        assert!(matches!(
            p.check_command(
                "r1",
                "show version; request system reboot",
                TestAction::Deny
            ),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::ForbiddenMetachar,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_newline_is_refused() {
        let p = allowlist_policy(&["show version"], &[]);
        assert!(matches!(
            p.check_command(
                "r1",
                "show version\nrequest system reboot",
                TestAction::Deny
            ),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::ForbiddenMetachar,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_backtick_is_refused() {
        let p = allowlist_policy(&["show version"], &[]);
        assert!(matches!(
            p.check_command("r1", "show version `whoami`", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::ForbiddenMetachar,
                ..
            }
        ));
    }

    #[test]
    fn allowlist_redirect_chars_are_refused() {
        let p = allowlist_policy(&["show version"], &[]);
        assert!(matches!(
            p.check_command("r1", "show version > /tmp/x", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::ForbiddenMetachar,
                ..
            }
        ));
        assert!(matches!(
            p.check_command("r1", "show version < /tmp/x", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::ForbiddenMetachar,
                ..
            }
        ));
    }

    #[test]
    fn is_allowed_is_false_for_deny_allowlist_and_true_for_allow() {
        let p = allowlist_policy(&["show version"], &[]);
        assert!(
            !p.check_command("r1", "request system reboot", TestAction::Deny)
                .is_allowed()
        );
        assert!(
            p.check_command("r1", "show version", TestAction::Deny)
                .is_allowed()
        );
    }

    #[test]
    fn is_allowed_is_false_for_blocklist_deny() {
        let mut commands = DomainRules::default();
        commands.defaults.push(make_compiled_rule(
            TestAction::Deny,
            "request system *",
            RuleSource::Defaults,
        ));
        let p = Policy::new(
            CommandMode::Blocklist,
            CommandDomain {
                blocklist: commands,
                allowlist: CommandAllowlist::default(),
            },
            DomainRules::default(),
            CommandDomain::default(),
        );
        assert!(
            !p.check_command("r1", "request system reboot", TestAction::Deny)
                .is_allowed()
        );
        assert!(
            p.check_command("r1", "show version", TestAction::Deny)
                .is_allowed()
        );
    }

    #[test]
    fn allowlist_decision_carries_normalized_command_for_audit() {
        let p = allowlist_policy(&["show version"], &[]);
        match p.check_command("r1", "  sh   ver  ", TestAction::Deny) {
            Decision::DenyAllowlist {
                mode,
                reason,
                normalized,
            } => {
                assert_eq!(mode, CommandMode::Allowlist);
                assert_eq!(reason, AllowlistDenyReason::NotAllowlisted);
                assert_eq!(normalized, "sh ver");
            }
            other => panic!("expected DenyAllowlist, got {other:?}"),
        }
    }

    #[test]
    fn allowlist_mode_also_applies_to_pfe_commands_domain() {
        let pfe_allowlist = CommandAllowlist {
            entries: allowlist_entries(&["show jnh"]),
            allowed_pipes: Vec::new(),
        };
        let p = Policy::new(
            CommandMode::Allowlist,
            CommandDomain::default(),
            DomainRules::default(),
            CommandDomain {
                blocklist: DomainRules::default(),
                allowlist: pfe_allowlist,
            },
        );
        assert!(matches!(
            p.check_pfe_command("r1", "show jnh 0 stats", TestAction::Deny),
            Decision::Allow
        ));
        assert!(matches!(
            p.check_pfe_command("r1", "set jnh 0 debug", TestAction::Deny),
            Decision::DenyAllowlist {
                reason: AllowlistDenyReason::NotAllowlisted,
                ..
            }
        ));
    }

    #[test]
    fn command_mode_default_is_allowlist() {
        assert_eq!(CommandMode::default(), CommandMode::Allowlist);
    }
}
