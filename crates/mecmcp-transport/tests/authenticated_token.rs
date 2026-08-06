#![allow(deprecated)]
//! Transport accounting must not depend on a vendor's grant type.

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use mecmcp_transport::{AuthenticatedToken, LimitsConfig, apply_rate_limit};
use tower::ServiceExt as _;

fn limited_config() -> LimitsConfig {
    LimitsConfig {
        max_requests_per_second_per_token: 1,
        max_request_burst_per_token: 1,
        ..Default::default()
    }
}

fn request(token: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/")
        .extension(AuthenticatedToken::new(token))
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn rate_limiting_uses_the_grant_neutral_authenticated_token() {
    let app = apply_rate_limit(
        Router::new().route("/", post(|| async { StatusCode::OK })),
        &limited_config(),
    );

    let first = app
        .clone()
        .oneshot(request("grant-bearing"))
        .await
        .expect("first response");
    let second = app
        .oneshot(request("grant-bearing"))
        .await
        .expect("second response");

    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn authenticated_token_preserves_name() {
    let token = AuthenticatedToken::new("test-token");
    assert_eq!(token.name(), "test-token");

    let cloned = token.clone();
    assert_eq!(cloned.name(), "test-token");
}

#[tokio::test]
async fn authenticated_token_equality() {
    let token1 = AuthenticatedToken::new("same");
    let token2 = AuthenticatedToken::new("same");
    let token3 = AuthenticatedToken::new("different");

    assert_eq!(token1, token2);
    assert_ne!(token1, token3);
}
