//! Caller-aware audit-scope construction.

use mecmcp_audit::AuditScope;
use mecmcp_auth::{CallerCtx, Grant};

/// Construct an audit scope for an authenticated caller or the stdio path.
///
/// Attribution is copied into the scope, so the returned guard does not borrow
/// the caller context.
#[must_use]
pub fn audit_scope<G: Grant>(
    caller: Option<&CallerCtx<G>>,
    tool: &'static str,
    action: &'static str,
    targets: Vec<String>,
) -> AuditScope {
    match caller {
        Some(caller) => AuditScope::from_caller(caller, tool, action, targets),
        None => AuditScope::stdio(tool, action, targets),
    }
}
