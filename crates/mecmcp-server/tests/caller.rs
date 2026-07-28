//! Caller extraction contract tests.

use mecmcp_auth::{ActorType, CallerCtx, NoGrant, ScopeSet};
use rmcp::model::Extensions;

fn caller(name: &str) -> CallerCtx<NoGrant> {
    CallerCtx {
        token_name: name.to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Human,
    }
}

#[test]
fn stdio_extensions_have_no_authenticated_caller() {
    let extensions = Extensions::default();

    assert!(mecmcp_server::caller_from_extensions::<NoGrant>(&extensions).is_none());
}

#[test]
fn http_parts_without_authentication_have_no_caller() {
    let (parts, _) = http::Request::new(()).into_parts();
    let mut extensions = Extensions::default();
    extensions.insert(parts);

    assert!(mecmcp_server::caller_from_extensions::<NoGrant>(&extensions).is_none());
}

#[test]
fn caller_is_recovered_from_http_request_parts() {
    let mut request = http::Request::new(());
    request.extensions_mut().insert(caller("automation"));
    let (parts, _) = request.into_parts();
    let mut extensions = Extensions::default();
    extensions.insert(parts);

    let recovered = mecmcp_server::caller_from_extensions::<NoGrant>(&extensions)
        .expect("authenticated caller");

    assert_eq!(recovered.token_name, "automation");
    assert_eq!(recovered.actor_type, ActorType::Human);
}
