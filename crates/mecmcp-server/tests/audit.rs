//! Audit-scope adapter contract tests.

use mecmcp_audit::testutil::run_with_capture;
use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};
use mecmcp_server::audit_scope;

fn caller() -> CallerCtx<NoGrant> {
    CallerCtx {
        token_name: "reviewed-agent".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: Some("operator@example.net".to_owned()),
        actor_type: ActorType::Agent,
    }
}

#[test]
fn authenticated_and_stdio_scopes_keep_distinct_principals() {
    let authenticated = run_with_capture(|| {
        let mut audit = audit_scope(
            Some(&caller()),
            "show_facts",
            "read",
            vec!["edge-a".to_owned()],
        );
        audit.succeed();
    });
    assert!(authenticated.contains("caller=reviewed-agent"));
    assert!(authenticated.contains("authorization=allowed"));
    assert!(authenticated.contains("actor_type=agent"));

    let stdio = run_with_capture(|| {
        let mut audit =
            audit_scope::<NoGrant>(None, "show_facts", "read", vec!["edge-a".to_owned()]);
        audit.succeed();
    });
    assert!(stdio.contains("caller=stdio"));
    assert!(stdio.contains("authorization=no_auth"));
    assert!(stdio.contains("actor_type=unknown"));
}

