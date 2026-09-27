//! The process-global redaction policy.
//!
//! There is deliberately no parameter on [`crate::redact_text`],
//! [`crate::redact_json_str`], or [`crate::redact_xml_str`] that a caller can
//! set per invocation. A tool call reaches those functions with no say over
//! whether they redact — the only way to change that is [`install`], which a
//! server binary calls at most once, at startup, from an operator-supplied
//! CLI flag. There is no code path from a tool argument to this module.

use std::sync::OnceLock;

/// The installed redaction policy. Absent [`install`], [`active`] defaults
/// this to [`RedactionPolicy::Enabled`] — redaction is on unless an operator
/// explicitly turned it off, never the reverse.
static POLICY: OnceLock<RedactionPolicy> = OnceLock::new();

/// Whether tool-output redaction runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionPolicy {
    /// Redaction runs. The default, and the only variant reachable without an
    /// explicit [`install`] call.
    Enabled,
    /// An operator disabled redaction via a CLI flag. Constructing this
    /// variant is only meaningful through [`install`], which is what emits
    /// the startup warning and audit-trail record — there is no silent way
    /// to reach this state.
    DisabledByOperator {
        /// The flag name the operator passed, e.g. `--no-redact`. Carried so
        /// the startup warning and audit record name the exact flag, not
        /// just "something disabled it".
        flag: &'static str,
    },
}

/// Install the process-global redaction policy.
///
/// Idempotent: a second call is a no-op, matching
/// `mecmcp_audit::redact::install`'s try-once semantics. Call this once, at
/// startup, before serving any request — [`active`] locks in
/// [`RedactionPolicy::Enabled`] the first time it is read, so an `install`
/// after that point would silently fail to take effect.
///
/// Installing [`RedactionPolicy::DisabledByOperator`] emits a `WARN`-level
/// `target: "audit"` event naming the flag. Every mecmcp server already
/// installs a tracing subscriber (`mecmcp_audit::init_tracing`) with a
/// console layer that prints anything at `WARN` or above and an audit-file /
/// journald layer filtered to exactly `target == "audit"` — so this one event
/// satisfies both "logs loudly at startup" and "recorded in the audit trail"
/// without this crate depending on `mecmcp-audit` at all.
pub fn install(policy: RedactionPolicy) {
    let disabled_flag = match &policy {
        RedactionPolicy::DisabledByOperator { flag } => Some(*flag),
        RedactionPolicy::Enabled => None,
    };
    match POLICY.set(policy) {
        Ok(()) => {
            if let Some(flag) = disabled_flag {
                tracing::warn!(
                    target: "audit",
                    event = "tool_output_redaction_disabled",
                    operator_flag = %flag,
                    "tool-output redaction disabled by operator flag {flag}: device secrets, \
                     keys, and tokens in tool output will reach the model unredacted",
                );
            }
        }
        Err(_) => {
            // `active()` already locked in a policy (or a previous `install`
            // won the race) — this call had no effect. Logging the disable
            // event here anyway would claim redaction is off when the
            // already-installed policy, not this one, is what's actually in
            // force.
            tracing::warn!(
                target: "audit",
                event = "tool_output_redaction_install_ignored",
                requested_disable_flag = disabled_flag.unwrap_or("<n/a>"),
                "install() called after the redaction policy was already locked in; \
                 the already-installed policy remains in effect",
            );
        }
    }
}

/// The active redaction policy. Defaults to [`RedactionPolicy::Enabled`] when
/// [`install`] was never called.
#[must_use]
pub fn active() -> RedactionPolicy {
    *POLICY.get_or_init(|| RedactionPolicy::Enabled)
}

// `POLICY` is process-global, so tests that call `install` or the first
// `active()` in a process live in their own `tests/*.rs` binaries — each
// integration test file is its own process — rather than here. See
// `tests/policy_default_enabled.rs` and `tests/policy_operator_override.rs`.
