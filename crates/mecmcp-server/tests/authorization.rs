//! Authorization and advertised-tool filtering contract tests.

use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};
use mecmcp_server::{
    AuthorizationError, authorize_call, authorize_target, authorize_tool, filter_tools_for_scope,
};
use rmcp::model::Tool;

const WRITE_TOOLS: &[&str] = &["change_config"];

fn caller(tools: ScopeSet, devices: ScopeSet) -> CallerCtx<NoGrant> {
    CallerCtx {
        token_name: "automation".to_owned(),
        devices,
        tools,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Agent,
    }
}

fn tool(name: &str) -> Tool {
    let mut tool = Tool::default();
    tool.name = name.to_owned().into();
    tool
}

#[test]
fn unauthenticated_stdio_is_admitted_for_handler_level_compatibility() {
    assert!(authorize_call::<NoGrant>(None, "show_facts", Some("edge"), WRITE_TOOLS).is_ok());
}

#[test]
fn explicit_tool_scope_allows_only_the_named_tool() {
    let caller = caller(
        ScopeSet::Allowlist(vec!["show_facts".to_owned()]),
        ScopeSet::Wildcard,
    );

    assert!(authorize_tool(Some(&caller), "show_facts", WRITE_TOOLS).is_ok());
    assert!(matches!(
        authorize_tool(Some(&caller), "show_config", WRITE_TOOLS),
        Err(AuthorizationError::ToolNotInScope { .. })
    ));
}

#[test]
fn wildcard_tool_scope_allows_reads_but_not_writes() {
    let caller = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);

    assert!(authorize_tool(Some(&caller), "show_facts", WRITE_TOOLS).is_ok());
    assert!(matches!(
        authorize_tool(Some(&caller), "change_config", WRITE_TOOLS),
        Err(AuthorizationError::ToolNotInScope { .. })
    ));
}

#[test]
fn explicit_tool_scope_can_grant_a_write() {
    let caller = caller(
        ScopeSet::Allowlist(vec!["change_config".to_owned()]),
        ScopeSet::Wildcard,
    );

    assert!(authorize_tool(Some(&caller), "change_config", WRITE_TOOLS).is_ok());
}

#[test]
fn target_scope_denial_does_not_claim_whether_target_exists() {
    let caller = caller(
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["edge-a".to_owned()]),
    );

    let error =
        authorize_target(Some(&caller), "show_facts", "edge-b").expect_err("target must be denied");

    assert!(matches!(error, AuthorizationError::TargetNotInScope { .. }));
    assert_eq!(
        error.to_string(),
        "token 'automation' is not authorized for the requested target (tool 'show_facts')"
    );
    assert!(!error.to_string().contains("exists"));
    assert!(!error.to_string().contains("unknown"));
}

#[test]
fn authorize_call_checks_both_tool_and_target() {
    let caller = caller(
        ScopeSet::Allowlist(vec!["show_facts".to_owned()]),
        ScopeSet::Allowlist(vec!["edge-a".to_owned()]),
    );

    assert!(authorize_call(Some(&caller), "show_facts", Some("edge-a"), WRITE_TOOLS).is_ok());
    assert!(authorize_call(Some(&caller), "show_facts", Some("edge-b"), WRITE_TOOLS).is_err());
    assert!(authorize_call(Some(&caller), "change_config", Some("edge-a"), WRITE_TOOLS).is_err());
}

#[test]
fn advertised_tools_use_the_same_write_aware_predicate() {
    let wildcard = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
    let filtered = filter_tools_for_scope(
        vec![tool("show_facts"), tool("change_config")],
        Some(&wildcard),
        WRITE_TOOLS,
    );

    assert_eq!(
        filtered
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>(),
        vec!["show_facts"]
    );

    let unfiltered = filter_tools_for_scope::<NoGrant>(
        vec![tool("show_facts"), tool("change_config")],
        None,
        WRITE_TOOLS,
    );
    assert_eq!(unfiltered.len(), 2);
}
