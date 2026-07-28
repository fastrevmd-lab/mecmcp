//! Scope-aware MCP tool advertisement.

use mecmcp_auth::{CallerCtx, Grant};
use rmcp::model::Tool;

/// Filter tools down to the exact set the caller may invoke.
///
/// The predicate is the same write-aware [`mecmcp_auth::ScopeSet::allows_tool`]
/// used by handler authorization. `None` leaves the list unchanged for stdio
/// and explicitly unauthenticated local transports.
#[must_use]
pub fn filter_tools_for_scope<G: Grant>(
    tools: Vec<Tool>,
    caller: Option<&CallerCtx<G>>,
    write_tools: &[&str],
) -> Vec<Tool> {
    let Some(caller) = caller else {
        return tools;
    };
    tools
        .into_iter()
        .filter(|tool| caller.tools.allows_tool(tool.name.as_ref(), write_tools))
        .collect()
}
