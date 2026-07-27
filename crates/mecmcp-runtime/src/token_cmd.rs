//! Bearer-token management commands.
//!
//! Provides add, list, revoke, and rotate actions for token stores, with safe
//! SIGHUP hot-reload signalling via rustix.

use crate::cli::TokenAction;
use mecmcp_auth::{KnownNames, NoGrant, ScopeSet, TokenStoreFile};
use std::io::Write;
use std::path::Path;
use thiserror::Error;

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

            // Parse provider_tier if present
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

            // Parse actor_type if present
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

            // Declaring an LLM provider is only meaningful for an agent, and a
            // token entry carrying provider metadata with any other actor type is
            // rejected at validation. Derive it rather than making the operator
            // pass --actor-type agent to satisfy a rule they cannot see, but never
            // override an actor type they stated explicitly.
            let parsed_actor = match (parsed_actor, provider.as_ref()) {
                (None, Some(_)) => Some(mecmcp_auth::ActorType::Agent),
                (existing, _) => existing,
            };

            let secret = TokenStoreFile::<NoGrant>::add_with_options(
                &tokens_file,
                &name,
                devices_scope,
                tools_scope,
                None, // expires_at
                None, // grant
                provider.clone(),
                parsed_tier,
                on_behalf_of.clone(),
                parsed_actor,
                &known,
            )?;
            let mut out = std::io::stdout().lock();
            writeln!(out, "{}", secret.expose_secret())?;
            signal_reload(server_pid)?;
            Ok(())
        }
        TokenAction::List { tokens_file } => list(&tokens_file),
        TokenAction::Revoke {
            tokens_file,
            name,
            server_pid,
        } => {
            let removed = TokenStoreFile::<NoGrant>::revoke(&tokens_file, &name, &known)?;
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
            let secret = TokenStoreFile::<NoGrant>::rotate(&tokens_file, &name, &known)?;
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

fn list(path: &Path) -> Result<(), TokenCommandError> {
    let store_file = TokenStoreFile::<NoGrant>::load(path)?;
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
