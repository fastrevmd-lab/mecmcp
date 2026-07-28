//! Tool and target scope authorization.

use mecmcp_auth::{CallerCtx, Grant};

/// A handler-level scope denial safe to return to an MCP caller.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthorizationError {
    /// The caller's tool scope does not permit the requested tool.
    #[error("token '{token}' is not authorized for tool '{tool}'")]
    ToolNotInScope {
        /// Non-secret token name.
        token: String,
        /// Requested MCP tool.
        tool: String,
    },
    /// The caller's target scope does not permit the requested target.
    ///
    /// The display text deliberately does not reveal whether the target exists
    /// in inventory.
    #[error(
        "token '{token}' is not authorized for the requested target (tool '{tool}')"
    )]
    TargetNotInScope {
        /// Non-secret token name.
        token: String,
        /// Requested MCP tool.
        tool: String,
        /// Caller-supplied target, retained for structured handling.
        target: String,
    },
}

/// Require the caller's tool scope to permit `tool`.
///
/// `None` preserves the existing stdio/no-auth handler behavior. Wildcard
/// scopes exclude every entry in the consumer-supplied write-tool registry.
pub fn authorize_tool<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    write_tools: &[&str],
) -> Result<(), AuthorizationError> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if caller.tools.allows_tool(tool, write_tools) {
        return Ok(());
    }
    Err(AuthorizationError::ToolNotInScope {
        token: caller.token_name.clone(),
        tool: tool.to_owned(),
    })
}

/// Require the caller's target scope to permit `target`.
///
/// This function intentionally does not consult inventory. Authorization
/// therefore cannot disclose whether an out-of-scope target exists.
pub fn authorize_target<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    target: &str,
) -> Result<(), AuthorizationError> {
    let Some(caller) = caller else {
        return Ok(());
    };
    if caller.devices.allows(target) {
        return Ok(());
    }
    Err(AuthorizationError::TargetNotInScope {
        token: caller.token_name.clone(),
        tool: tool.to_owned(),
        target: target.to_owned(),
    })
}

/// Check tool scope followed by an optional target scope.
pub fn authorize_call<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &str,
    target: Option<&str>,
    write_tools: &[&str],
) -> Result<(), AuthorizationError> {
    authorize_tool(caller, tool, write_tools)?;
    if let Some(target) = target {
        authorize_target(caller, tool, target)?;
    }
    Ok(())
}
