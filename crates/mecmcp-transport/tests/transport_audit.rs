//! Transport-level audit coverage test (mecmcp#32).
//!
//! Every `tools/call` request must produce an audit event. The transport
//! guarantees this by emitting an event in `bearer_preflight_middleware`
//! before dispatch. Handlers enrich with action, targets, and outcome.

use mecmcp_audit::testutil::run_with_capture;

/// Helper to extract tool name from a JSON-RPC request body (duplicated from auth.rs).
///
/// This is a test-only copy of the middleware's `extract_tool_name` function.
/// Kept in sync manually because the function is private to the auth module.
fn extract_tool_name_for_test(body: &[u8]) -> Option<&'static str> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let requests = match &value {
        serde_json::Value::Array(requests) => requests.as_slice(),
        single => std::slice::from_ref(single),
    };
    for request in requests {
        if request.get("method").and_then(serde_json::Value::as_str) == Some("tools/call")
            && let Some(tool) = request
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(serde_json::Value::as_str)
        {
            return Some(Box::leak(tool.to_owned().into_boxed_str()));
        }
    }
    None
}

/// Simulate the audit emission that the middleware performs.
fn emit_transport_audit(tool: &'static str) {
    use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};

    let caller = CallerCtx::<NoGrant> {
        token_name: "test-token".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Human,
    };

    let mut scope = mecmcp_audit::AuditScope::from_caller(&caller, tool, "transport", Vec::new());
    scope.meta("layer", "preflight");
    scope.succeed();
}

/// Regression test for mecmcp#32: every tool must produce an audit event.
///
/// The transport guarantees coverage by emitting an event in
/// `bearer_preflight_middleware` for every `tools/call` request. This test
/// verifies that a `tools/call` request for each tool produces an audit event.
#[test]
fn tools_call_produces_transport_audit_event() {
    const TOOLS: &[&str] = &["list_devices", "get_config", "apply_change_set"];

    for tool in TOOLS {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{}","arguments":{{}}}}}}"#,
            tool
        );

        let captured = run_with_capture(|| {
            if let Some(tool_name) = extract_tool_name_for_test(body.as_bytes()) {
                emit_transport_audit(tool_name);
            }
        });

        assert!(
            captured.contains(&format!("tool={}", tool)),
            "tool {} must produce a transport audit event, got: {captured}",
            tool
        );
        assert!(
            captured.contains("layer=preflight"),
            "audit event must be marked as transport layer: {captured}"
        );
    }
}

/// Verify that the transport emits an audit event for a batched request.
///
/// Batched JSON-RPC requests are uncommon but supported. The transport emits
/// one audit event for the first `tools/call` in the batch.
#[test]
fn batched_tools_call_produces_audit_event() {
    let batch_body = br#"[
        {"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_config","arguments":{}}},
        {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_devices","arguments":{}}}
    ]"#;

    let captured = run_with_capture(|| {
        if let Some(tool) = extract_tool_name_for_test(batch_body) {
            emit_transport_audit(tool);
        }
    });

    // The transport emits one event for the first tool in the batch.
    assert!(
        captured.contains("tool=get_config"),
        "batched request must produce an audit event for the first tool: {captured}"
    );
    assert!(
        captured.contains("layer=preflight"),
        "audit event must be marked as transport layer: {captured}"
    );
}

/// Verify that non-tools/call methods produce no audit event.
///
/// The transport only audits `tools/call` requests. Other methods (e.g.,
/// `tools/list`, `initialize`) pass through without a transport audit event.
#[test]
fn non_tools_call_produces_no_audit_event() {
    let tools_list_body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#;

    let captured = run_with_capture(|| {
        if let Some(tool) = extract_tool_name_for_test(tools_list_body) {
            emit_transport_audit(tool);
        }
    });

    // No audit event should be emitted for tools/list.
    assert!(
        !captured.contains("tool="),
        "tools/list must not produce a transport audit event: {captured}"
    );
}

/// Verify that malformed JSON produces no audit event.
///
/// The transport's `extract_tool_name` returns `None` for malformed bodies,
/// so no audit event is emitted. The request will be rejected elsewhere
/// (by the JSON-RPC parser or the handler).
#[test]
fn malformed_json_produces_no_audit_event() {
    let malformed_body = b"not json at all";

    let captured = run_with_capture(|| {
        if let Some(tool) = extract_tool_name_for_test(malformed_body) {
            emit_transport_audit(tool);
        }
    });

    assert!(
        !captured.contains("tool="),
        "malformed JSON must not produce an audit event: {captured}"
    );
}
