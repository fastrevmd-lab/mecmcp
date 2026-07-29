//! Configured JSON-RPC scope preflight contracts.

use mecmcp_auth::{CallerCtx, ScopeSet};
use mecmcp_transport::{
    CallerScopes, MalformedArgumentsPolicy, ScopePreflight, TargetField, ToolScopePreflight,
};

const WRITE_TOOLS: &[&str] = &["write"];

fn caller(tools: ScopeSet, devices: ScopeSet) -> CallerCtx {
    CallerCtx {
        token_name: "test".to_owned(),
        tools,
        devices,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: mecmcp_auth::ActorType::Human,
    }
}

fn junos_preflight() -> ToolScopePreflight {
    ToolScopePreflight::new(
        WRITE_TOOLS,
        [
            TargetField::scalar("router"),
            TargetField::scalar("router_name"),
            TargetField::non_empty_array("routers"),
            TargetField::non_empty_array("router_names"),
        ],
        MalformedArgumentsPolicy::Deny,
    )
}

#[test]
fn exact_tools_and_all_configured_target_shapes_are_checked() {
    let caller = caller(
        ScopeSet::Allowlist(vec!["read".to_owned()]),
        ScopeSet::Allowlist(vec!["r1".to_owned()]),
    );
    let scopes = CallerScopes::from(&caller);
    let preflight = junos_preflight();

    assert!(
        preflight
            .check(
                br#"{"method":"tools/call","params":{"name":"read","arguments":{"router":"r1","routers":["r1"]}}}"#,
                scopes,
            )
            .is_ok()
    );
    assert_eq!(
        preflight.check(
            br#"{"method":"tools/call","params":{"name":"write","arguments":{"router":"r1"}}}"#,
            scopes,
        ),
        Err("insufficient_scope".to_owned())
    );
    assert_eq!(
        preflight.check(
            br#"{"method":"tools/call","params":{"name":"read","arguments":{"router_names":["r1","r2"]}}}"#,
            scopes,
        ),
        Err("insufficient_scope".to_owned())
    );
}

#[test]
fn malformed_configured_targets_and_arguments_follow_fail_closed_policy() {
    let caller = caller(ScopeSet::Wildcard, ScopeSet::Wildcard);
    let scopes = CallerScopes::from(&caller);
    let preflight = junos_preflight();

    for body in [
        br#"{"method":"tools/call","params":{"name":"read","arguments":[]}}"#.as_slice(),
        br#"{"method":"tools/call","params":{"name":"read","arguments":{"router":7}}}"#.as_slice(),
        br#"{"method":"tools/call","params":{"name":"read","arguments":{"routers":[]}}}"#
            .as_slice(),
        br#"{"method":"tools/call","params":{"name":"read","arguments":{"routers":["r1",7]}}}"#
            .as_slice(),
    ] {
        assert_eq!(
            preflight.check(body, scopes),
            Err("insufficient_scope".to_owned()),
            "body={}",
            String::from_utf8_lossy(body)
        );
    }
}

#[test]
fn batches_and_panos_scalar_policy_are_supported_without_vendor_code() {
    let caller = caller(
        ScopeSet::Wildcard,
        ScopeSet::Allowlist(vec!["fw-a".to_owned()]),
    );
    let scopes = CallerScopes::from(&caller);
    let panos = ToolScopePreflight::new(
        WRITE_TOOLS,
        [TargetField::scalar_ignoring_malformed("device")],
        MalformedArgumentsPolicy::Ignore,
    );

    assert_eq!(
        panos.check(
            br#"[{"method":"initialize"},{"method":"tools/call","params":{"name":"read","arguments":{"device":"fw-b"}}}]"#,
            scopes,
        ),
        Err("insufficient_scope".to_owned())
    );
    assert!(
        panos
            .check(
                br#"{"method":"tools/call","params":{"name":"read","arguments":[]}}"#,
                scopes,
            )
            .is_ok()
    );
}
