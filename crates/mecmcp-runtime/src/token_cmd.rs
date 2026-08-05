//! Bearer-token management commands.
//!
//! Provides add, list, revoke, and rotate actions for token stores, with safe
//! SIGHUP hot-reload signalling via rustix.

use crate::cli::TokenAction;
use mecmcp_auth::{KnownNames, NoGrant, ScopeSet, StoredGrant, TokenStoreFile};
use std::io::Write;
use std::path::Path;
use thiserror::Error;

/// Whether replacing `current` with `next` grants anything it did not before.
///
/// Only a widening needs confirmation. Narrowing cannot grant access, so
/// requiring `--yes` to *reduce* a scope would train operators to pass it
/// reflexively — which is how the confirmation stops being one.
///
/// Conservative by construction: anything not provably a narrowing counts as a
/// widening. `Wildcard` -> `Allowlist` is the one clear narrowing; an allowlist
/// that gains a name, or any move to `Wildcard`, is a widening.
fn is_widening(current: &ScopeSet, next: Option<&ScopeSet>) -> bool {
    let Some(next) = next else {
        return false; // unchanged
    };
    match (current, next) {
        (ScopeSet::Wildcard, ScopeSet::Wildcard) => false,
        (ScopeSet::Wildcard, ScopeSet::Allowlist(_)) => false,
        (ScopeSet::Allowlist(_), ScopeSet::Wildcard) => true,
        (ScopeSet::Allowlist(have), ScopeSet::Allowlist(want)) => {
            want.iter().any(|name| !have.contains(name))
        }
    }
}

/// Token command execution error.
#[derive(Debug, Error)]
pub enum TokenCommandError {
    /// Token store operation failed.
    #[error(transparent)]
    Store(#[from] mecmcp_auth::FileError),

    /// Scope validation failed.
    #[error("invalid {field} scope: {message}")]
    Scope {
        /// Scope field name.
        field: &'static str,
        /// Diagnostic message.
        message: String,
    },

    /// Invalid command argument.
    #[error("{0}")]
    InvalidArgument(String),

    /// I/O operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// The four `token add` provenance flags, parsed and reconciled.
///
/// Ready to hand straight to `TokenStoreFile::add_with_options`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Provenance {
    /// Provider name, passed through unchanged.
    pub provider: Option<String>,
    /// Parsed provider tier.
    pub provider_tier: Option<mecmcp_auth::Tier>,
    /// The human on whose behalf the credential acts, passed through unchanged.
    pub on_behalf_of: Option<String>,
    /// Actor type, derived from `provider` when the caller omitted it.
    pub actor_type: Option<mecmcp_auth::ActorType>,
}

/// Parse and reconcile the provenance flags accepted by `token add`.
///
/// Consumers that cannot route through [`run`] — because they carry extra
/// fields such as mutation grants or expiry — call this directly so the
/// reconciliation rules live in exactly one place. Duplicating them per server
/// is how the two servers drift apart on what a token means.
///
/// # Errors
///
/// Returns [`TokenCommandError::InvalidArgument`] if a tier or actor type is
/// unrecognised, or if `--actor-type unknown` is combined with `--provider`.
pub fn parse_provenance(
    provider: Option<String>,
    provider_tier: Option<String>,
    on_behalf_of: Option<String>,
    actor_type: Option<String>,
) -> Result<Provenance, TokenCommandError> {
    let parsed_tier = provider_tier
        .as_ref()
        .map(|s| match s.as_str() {
            "public" => Ok(mecmcp_auth::Tier::Public),
            "private" => Ok(mecmcp_auth::Tier::Private),
            other => Err(TokenCommandError::InvalidArgument(format!(
                "provider_tier must be 'public' or 'private', got '{other}'"
            ))),
        })
        .transpose()?;

    let parsed_actor = actor_type
        .as_ref()
        .map(|s| match s.as_str() {
            "human" => Ok(mecmcp_auth::ActorType::Human),
            "agent" => Ok(mecmcp_auth::ActorType::Agent),
            "unknown" => Ok(mecmcp_auth::ActorType::Unknown),
            other => Err(TokenCommandError::InvalidArgument(format!(
                "actor_type must be 'human', 'agent', or 'unknown', got '{other}'"
            ))),
        })
        .transpose()?;

    // Declaring an LLM provider is only meaningful for an agent, and a token
    // entry carrying provider metadata with any other actor type is rejected at
    // validation. Derive it rather than making the operator pass --actor-type
    // agent to satisfy a rule they cannot see, but never override an actor type
    // they stated explicitly.
    let parsed_actor = match (parsed_actor, provider.as_ref()) {
        (None, Some(_)) => Some(mecmcp_auth::ActorType::Agent),
        // Here — and only here — an omitted flag is distinguishable from an
        // explicit `unknown`. On disk both deserialize to `Unknown`, so silently
        // deriving `Agent` would override a choice the operator actually made.
        // Refuse instead of guessing.
        (Some(mecmcp_auth::ActorType::Unknown), Some(_)) => {
            return Err(TokenCommandError::InvalidArgument(
                "--actor-type unknown cannot be combined with --provider: a provider \
                 belongs to an agent. Pass --actor-type agent, or omit the flag to have \
                 it derived."
                    .to_owned(),
            ));
        }
        (existing, _) => existing,
    };

    Ok(Provenance {
        provider,
        provider_tier: parsed_tier,
        on_behalf_of,
        actor_type: parsed_actor,
    })
}

/// Execute a token management command.
///
/// # Arguments
///
/// * `action` - The token action to perform
/// * `known_devices` - Device names to validate against (empty slice = no validation)
/// * `known_tools` - Tool names to validate against
///
/// # Errors
///
/// Returns error if the token operation fails, scope validation fails, or I/O fails.
pub fn run(
    action: TokenAction,
    known_devices: &[String],
    known_tools: &[&str],
) -> Result<(), TokenCommandError> {
    run_with_grant::<NoGrant>(action, known_devices, known_tools, None)
}

/// Execute a token management command against a store carrying vendor grants.
///
/// [`run`] is this function pinned to [`NoGrant`]. A consumer whose store holds
/// real grants must call this instead: the store is deserialized as `G`, so
/// `list`, `revoke`, and `rotate` round-trip existing grants untouched. Calling
/// [`run`] against such a store fails to deserialize (`invalid type: map,
/// expected unit struct NoGrant`) — the grant is not lost, but it is unreadable
/// through the shared command path, which is the whole reason this seam exists
/// (mecmcp#160).
///
/// `new_grant` applies to `add` only, and only to the token being created. It is
/// deliberately explicit rather than defaulted: a server that forgets to pass a
/// grant should mint a token that can mutate nothing, not one that inherits some
/// ambient default. Existing entries are never rewritten from it.
///
/// # Arguments
///
/// * `action` - The token action to perform
/// * `known_devices` - Device names to validate against (empty slice = no validation)
/// * `known_tools` - Tool names to validate against
/// * `new_grant` - Grant to attach to a newly added token; `None` mints a
///   grantless entry. Ignored by `list`, `revoke`, and `rotate`.
///
/// # Errors
///
/// Returns error if the token operation fails, scope validation fails,
/// `new_grant` is structurally invalid, or I/O fails.
pub fn run_with_grant<G>(
    action: TokenAction,
    known_devices: &[String],
    known_tools: &[&str],
    new_grant: Option<G>,
) -> Result<(), TokenCommandError>
where
    G: StoredGrant,
{
    let known = KnownNames {
        devices: if known_devices.is_empty() {
            None
        } else {
            Some(known_devices)
        },
        tools: known_tools,
    };

    match action {
        TokenAction::Add {
            tokens_file,
            name,
            devices,
            tools,
            provider,
            provider_tier,
            on_behalf_of,
            actor_type,
            server_pid,
        } => {
            let devices_scope = parse_scope(devices, "devices")?;
            let tools_scope = parse_scope(tools, "tools")?;

            let provenance = parse_provenance(provider, provider_tier, on_behalf_of, actor_type)?;

            // Not a safety check — the store already refuses an invalid grant
            // before writing: `add_with_options` builds a `TokenStore` (which
            // validates each entry, and so each grant) ahead of `write_atomic`,
            // so a malformed grant never reaches disk either way.
            //
            // This exists for the error the operator sees. Reaching it through
            // the store surfaces a nested `FileError::Store { Entry { Grant } }`
            // about a file; raising it here says "the grant you passed on the
            // command line is invalid" and classifies it as bad input rather
            // than a storage fault. The cost is validating twice, which is
            // cheap, and taking precedence over scope/reference errors.
            if let Some(grant) = new_grant.as_ref() {
                grant.validate().map_err(|error| {
                    TokenCommandError::InvalidArgument(format!("invalid grant: {error}"))
                })?;
            }

            let secret = TokenStoreFile::<G>::add_with_options(
                &tokens_file,
                &name,
                devices_scope,
                tools_scope,
                None, // expires_at
                new_grant,
                provenance.provider,
                provenance.provider_tier,
                provenance.on_behalf_of,
                provenance.actor_type,
                &known,
            )?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::SetScopes {
            tokens_file,
            name,
            devices,
            tools,
            yes,
            server_pid,
        } => {
            let devices_scope = devices.map(|v| parse_scope(v, "devices")).transpose()?;
            let tools_scope = tools.map(|v| parse_scope(v, "tools")).transpose()?;

            if devices_scope.is_none() && tools_scope.is_none() && new_grant.is_none() {
                return Err(TokenCommandError::InvalidArgument(
                    "set-scopes needs at least one of --devices, --tools, or a grant".to_owned(),
                ));
            }

            // Read the current scopes so the operator sees what is changing.
            // A scope change is a security event and previously left no trace
            // at all; showing before and after is the minimum that makes a
            // widening deliberate rather than a side effect of a typo.
            // Same reasoning as the Add arm: validate here so the operator is
            // told their grant is bad, not handed a nested storage error.
            if let Some(grant) = new_grant.as_ref() {
                grant.validate().map_err(|error| {
                    TokenCommandError::InvalidArgument(format!("invalid grant: {error}"))
                })?;
            }

            // Cloned out of the store: `store()` returns a guard, and holding
            // a borrow into it across the write below would not compile.
            let store_file = TokenStoreFile::<G>::load(&tokens_file)?;
            let (before_devices, before_tools) = {
                let store = store_file.store();
                let existing = store
                    .entries()
                    .iter()
                    .find(|entry| entry.name == name)
                    .ok_or_else(|| {
                        TokenCommandError::InvalidArgument(format!("token '{name}' does not exist"))
                    })?;
                (existing.devices.clone(), existing.tools.clone())
            };

            let widening = is_widening(&before_devices, devices_scope.as_ref())
                || is_widening(&before_tools, tools_scope.as_ref());

            println!("token: {name}");
            println!("  devices: {before_devices:?}");
            if let Some(next) = devices_scope.as_ref() {
                println!("        -> {next:?}");
            }
            println!("  tools:   {before_tools:?}");
            if let Some(next) = tools_scope.as_ref() {
                println!("        -> {next:?}");
            }
            if new_grant.is_some() {
                println!("  grant:   replaced");
            }

            if widening && !yes {
                return Err(TokenCommandError::InvalidArgument(
                    "this widens a scope, which is a privilege escalation; re-run with --yes"
                        .to_owned(),
                ));
            }

            TokenStoreFile::<G>::set_scopes(
                &tokens_file,
                &name,
                devices_scope,
                tools_scope,
                new_grant,
                &known,
            )?;

            // A scope change is a security event. Emitting it here means the
            // record exists even though the change is made by a CLI rather than
            // through the served API.
            tracing::info!(
                target: "audit",
                tool = "token_set_scopes",
                action = "set_scopes",
                result = "ok",
                metadata = format!("token={name} widening={widening}"),
                "token scopes changed",
            );

            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::List { tokens_file } => list::<G>(&tokens_file),
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let removed = TokenStoreFile::<G>::revoke(&tokens_file, &name, &known)?;
            if removed {
                eprintln!("revoked '{name}'");
            } else {
                eprintln!("no such token '{name}' (no-op)");
            }
            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::Rotate {
            tokens_file,
            name,
            server_pid,
        } => {
            let secret = TokenStoreFile::<G>::rotate(&tokens_file, &name, &known)?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
            Ok(())
        }
    }
}

fn parse_scope(values: Vec<String>, field: &'static str) -> Result<ScopeSet, TokenCommandError> {
    if values.is_empty() {
        return Err(TokenCommandError::Scope {
            field,
            message: "at least one exact name or '*' is required".to_owned(),
        });
    }
    if values.iter().any(|v| v == "*") {
        if values.len() == 1 {
            return Ok(ScopeSet::Wildcard);
        }
        return Err(TokenCommandError::Scope {
            field,
            message: "'*' cannot be mixed with exact names".to_owned(),
        });
    }
    Ok(ScopeSet::Allowlist(values))
}

fn list<G>(path: &Path) -> Result<(), TokenCommandError>
where
    G: StoredGrant,
{
    let store_file = TokenStoreFile::<G>::load(path)?;
    let store = store_file.store();
    if store.is_empty() {
        eprintln!("(no tokens)");
        return Ok(());
    }
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "{:<32} {:<24} {:<24} CREATED_AT",
        "NAME", "DEVICES", "TOOLS"
    )?;
    for entry in store.entries() {
        let devices = match &entry.devices {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        let tools = match &entry.tools {
            ScopeSet::Wildcard => "*".into(),
            ScopeSet::Allowlist(v) => v.join(","),
        };
        writeln!(
            out,
            "{:<32} {:<24} {:<24} {}",
            entry.name,
            devices,
            tools,
            entry.created_at.to_rfc3339()
        )?;
    }
    Ok(())
}

/// Send SIGHUP to the specified process for hot-reload.
///
/// # Errors
///
/// Returns error if the PID is invalid or the signal fails.
#[cfg(unix)]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    let Some(raw) = pid else {
        return Ok(());
    };
    let pid = rustix::process::Pid::from_raw(raw).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "server PID must be positive",
        )
    })?;
    rustix::process::kill_process(pid, rustix::process::Signal::HUP)
        .map_err(std::io::Error::from)?;
    Ok(())
}

/// No-op on non-Unix platforms.
///
/// # Errors
///
/// Returns error if a PID was provided on a non-Unix platform.
#[cfg(not(unix))]
fn signal_reload(pid: Option<i32>) -> Result<(), TokenCommandError> {
    if pid.is_some() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "SIGHUP reload is available only on Unix",
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn provenance_derives_agent_from_a_provider() {
        let parsed = parse_provenance(
            Some("anthropic".to_owned()),
            Some("private".to_owned()),
            Some("mharman".to_owned()),
            None,
        )
        .expect("valid provenance");

        assert_eq!(parsed.provider_tier, Some(mecmcp_auth::Tier::Private));
        assert_eq!(
            parsed.actor_type,
            Some(mecmcp_auth::ActorType::Agent),
            "a provider implies an agent, so the operator should not have to say so"
        );
    }

    #[test]
    fn provenance_preserves_an_explicit_actor_type() {
        let parsed = parse_provenance(
            None,
            None,
            Some("reviewer".to_owned()),
            Some("human".to_owned()),
        )
        .expect("valid provenance");

        assert_eq!(parsed.actor_type, Some(mecmcp_auth::ActorType::Human));
        assert_eq!(parsed.provider, None);
    }

    #[test]
    fn provenance_refuses_unknown_actor_type_with_a_provider() {
        // `unknown` and an omitted flag both deserialize to `Unknown` on disk,
        // so deriving `Agent` here would silently overwrite a stated choice.
        let err = parse_provenance(
            Some("anthropic".to_owned()),
            Some("private".to_owned()),
            None,
            Some("unknown".to_owned()),
        )
        .expect_err("unknown + provider must be refused");

        assert!(
            matches!(err, TokenCommandError::InvalidArgument(ref m) if m.contains("--actor-type agent")),
            "the error should name the fix, got: {err}"
        );
    }

    #[test]
    fn provenance_rejects_an_unrecognised_tier() {
        let err = parse_provenance(
            Some("anthropic".to_owned()),
            Some("secret".to_owned()),
            None,
            None,
        )
        .expect_err("an unrecognised tier must be refused");

        assert!(matches!(err, TokenCommandError::InvalidArgument(ref m) if m.contains("public")));
    }

    #[test]
    fn wildcard_is_exclusive() {
        assert!(matches!(
            parse_scope(vec!["*".to_owned()], "tools"),
            Ok(ScopeSet::Wildcard)
        ));
        assert!(parse_scope(vec!["*".to_owned(), "get_config".to_owned()], "tools").is_err());
        assert!(parse_scope(Vec::new(), "tools").is_err());
    }

    #[test]
    fn empty_scope_rejected() {
        let err = parse_scope(Vec::new(), "devices").unwrap_err();
        assert!(matches!(err, TokenCommandError::Scope { .. }));
    }

    #[test]
    fn mixed_wildcard_rejected() {
        let err = parse_scope(vec!["*".to_owned(), "device1".to_owned()], "devices").unwrap_err();
        if let TokenCommandError::Scope { field, message } = err {
            assert_eq!(field, "devices");
            assert!(message.contains("'*'"));
        } else {
            panic!("expected Scope error");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod widening_tests {
    use super::*;

    fn allow(names: &[&str]) -> ScopeSet {
        ScopeSet::Allowlist(names.iter().map(|n| (*n).to_owned()).collect())
    }

    /// Only a widening is confirmed. Requiring `--yes` to *narrow* would train
    /// operators to pass it reflexively, which is how a confirmation stops
    /// being one.
    #[test]
    fn narrowing_and_no_change_are_not_widenings() {
        assert!(!is_widening(&ScopeSet::Wildcard, None), "unchanged");
        assert!(
            !is_widening(&ScopeSet::Wildcard, Some(&allow(&["a"]))),
            "wildcard -> allowlist is the clearest narrowing there is"
        );
        assert!(
            !is_widening(&allow(&["a", "b"]), Some(&allow(&["a"]))),
            "dropping a name is a narrowing"
        );
        assert!(
            !is_widening(&allow(&["a"]), Some(&allow(&["a"]))),
            "the same allowlist is not a widening"
        );
        assert!(!is_widening(&ScopeSet::Wildcard, Some(&ScopeSet::Wildcard)));
    }

    #[test]
    fn adding_a_name_or_going_wildcard_is_a_widening() {
        assert!(
            is_widening(&allow(&["a"]), Some(&allow(&["a", "b"]))),
            "gaining a name grants something new"
        );
        assert!(
            is_widening(&allow(&["a"]), Some(&ScopeSet::Wildcard)),
            "allowlist -> wildcard grants everything"
        );
        assert!(
            is_widening(&allow(&[]), Some(&allow(&["a"]))),
            "empty -> one name is a widening"
        );
    }

    /// Reordering is not a widening — the set is what matters, not the order.
    #[test]
    fn reordering_an_allowlist_is_not_a_widening() {
        assert!(!is_widening(&allow(&["a", "b"]), Some(&allow(&["b", "a"]))));
    }

    /// A swap that both adds and removes still counts, because it grants
    /// something that was not permitted before.
    #[test]
    fn a_swap_that_adds_anything_is_a_widening() {
        assert!(is_widening(&allow(&["a"]), Some(&allow(&["b"]))));
    }
}
