//! Shared authenticated HTTP boundary contracts.

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use mecmcp_auth::{ActorType, BearerSyntax, CallerCtx, Grant, GrantError, ScopeSet};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, MalformedArgumentsPolicy,
    TargetField, ToolScopePreflight, apply_bearer_boundary,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

#[derive(Debug, Clone)]
struct TestGrant;

impl Grant for TestGrant {
    type Action = ();

    fn allows_action(&self, _action: Self::Action) -> bool {
        true
    }

    fn allows_subject(&self, _subject: &str) -> bool {
        true
    }

    fn validate(&self) -> Result<(), GrantError> {
        Ok(())
    }
}

fn caller() -> CallerCtx<TestGrant> {
    CallerCtx {
        token_name: "operator".to_owned(),
        devices: ScopeSet::Allowlist(vec!["tenant-a".to_owned()]),
        tools: ScopeSet::Allowlist(vec!["read".to_owned()]),
        grant: Some(TestGrant),
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Human,
    }
}

fn boundary(profile: BearerResponseProfile) -> BearerBoundary<TestGrant> {
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    BearerBoundary::new(authenticator, profile, 1024).with_preflight(ToolScopePreflight::new(
        &["write"],
        [TargetField::scalar("tenant")],
        MalformedArgumentsPolicy::Deny,
    ))
}

fn app(profile: BearerResponseProfile) -> Router {
    let router = Router::new().route(
        "/",
        post(
            |Extension(caller): Extension<CallerCtx<TestGrant>>| async move {
                json!({
                    "token": caller.token_name,
                    "grant": caller.grant.is_some(),
                })
                .to_string()
            },
        ),
    );
    apply_bearer_boundary(router, boundary(profile))
}

fn request(authorization: Option<&str>, body: &'static str) -> Request<Body> {
    let mut builder = Request::builder().method("POST").uri("/");
    if let Some(value) = authorization {
        builder = builder.header(header::AUTHORIZATION, value);
    }
    builder.body(Body::from(body)).expect("request")
}

async fn json_body(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("response body");
    let body = serde_json::from_slice(&bytes).expect("JSON body");
    (status, body)
}

#[tokio::test]
async fn valid_auth_propagates_the_grant_bearing_caller() {
    let response = app(BearerResponseProfile::compact("test"))
        .oneshot(request(
            Some("Bearer secret"),
            r#"{"method":"tools/call","params":{"name":"read","arguments":{"tenant":"tenant-a"}}}"#,
        ))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"token": "operator", "grant": true}));
}

#[tokio::test]
async fn detailed_and_compact_profiles_preserve_error_contracts() {
    let detailed = app(BearerResponseProfile::detailed("jmcp"))
        .oneshot(request(None, "{}"))
        .await
        .expect("detailed");
    assert_eq!(detailed.status(), StatusCode::UNAUTHORIZED);
    let challenge = detailed
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("challenge")
        .to_str()
        .expect("text");
    assert_eq!(challenge, r#"Bearer realm="jmcp""#);
    let (_, detailed_body) = json_body(detailed).await;
    assert_eq!(detailed_body["error"], "invalid_request");

    let compact = app(BearerResponseProfile::compact("panos"))
        .oneshot(request(Some("Bearer wrong"), "{}"))
        .await
        .expect("compact");
    let (_, compact_body) = json_body(compact).await;
    assert_eq!(compact_body, json!({"error": "invalid_token"}));
}

#[tokio::test]
async fn scope_denials_and_oversized_bodies_stop_before_dispatch() {
    let denied = app(BearerResponseProfile::compact("test"))
        .oneshot(request(
            Some("Bearer secret"),
            r#"{"method":"tools/call","params":{"name":"read","arguments":{"tenant":"tenant-b"}}}"#,
        ))
        .await
        .expect("denied");
    let (status, body) = json_body(denied).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["error"], "insufficient_scope");

    let oversized = app(BearerResponseProfile::compact("test"))
        .oneshot(request(
            Some("Bearer secret"),
            Box::leak("x".repeat(1025).into_boxed_str()),
        ))
        .await
        .expect("oversized");
    let (status, body) = json_body(oversized).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "request_too_large");
}
