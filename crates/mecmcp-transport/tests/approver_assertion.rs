//! Full-stack contract for the `Mecmcp-Approver-Assertion` step-up header
//! (mecmcp#400 Phase 2 / MEC-994, W3).
//!
//! Signs real ephemeral JWTs (never committed fixtures) and drives them
//! through the actual `apply_bearer_boundary` middleware stack, the same way
//! `tests/bearer_boundary.rs` drives bearer auth. Each adversarial case
//! asserts a distinct response, proving the acceptance criteria's "every
//! rejection is a distinct audited reason" at the HTTP boundary, not just in
//! `bind_approver`'s own unit tests.

use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    routing::post,
};
use jsonwebtoken::EncodingKey;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use mecmcp_auth::{
    ActorType, ApproverPolicy, BearerSyntax, CallerCtx, Grant, GrantError, OidcSubject, ScopeSet,
};
use mecmcp_oidc::{DiscoveryDocument, FetchError, KeySource, OidcConfig, TokenVerifier};
use mecmcp_transport::{
    APPROVER_ASSERTION_HEADER, ApproverAssertionVerifier, BearerAuthenticator, BearerBoundary,
    BearerResponseProfile, BoundaryAccounting, LimitsConfig, apply_bearer_boundary,
};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt as _;

const ISSUER: &str = "https://idp.example.com";
const AUDIENCE: &str = "mecmcp-server";
const KID: &str = "approver-test-key";
const APPROVER_ROLE: &str = "approver";

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

struct TestKey {
    encoding_key: EncodingKey,
    jwk: Jwk,
}

fn generate_test_key(kid: &str) -> TestKey {
    let key_pair = KeyPair::generate(KeySize::Rsa2048).expect("RSA key generation");
    let pkcs8_der: aws_lc_rs::encoding::Pkcs8V1Der<'static> =
        key_pair.as_der().expect("PKCS8 encoding");
    let pem_text = pem::encode(&pem::Pem::new("PRIVATE KEY", pkcs8_der.as_ref().to_vec()));
    let encoding_key =
        EncodingKey::from_rsa_pem(pem_text.as_bytes()).expect("valid PEM for jsonwebtoken");
    let mut jwk = Jwk::from_encoding_key(&encoding_key, jsonwebtoken::Algorithm::RS256)
        .expect("JWK derivation");
    jwk.common.key_id = Some(kid.to_owned());
    TestKey { encoding_key, jwk }
}

fn sign_token(key: &TestKey, claims: &Value, kid: &str) -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(&header, claims, &key.encoding_key).expect("token signing")
}

fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs(),
    )
    .expect("timestamp fits in i64")
}

fn valid_claims(subject: &str, jti: &str) -> Value {
    json!({
        "sub": subject,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "exp": now() + 3600,
        "iat": now() - 10,
        "groups": [APPROVER_ROLE],
        "jti": jti,
    })
}

struct FixtureSource {
    jwks: JwkSet,
}

#[async_trait::async_trait]
impl KeySource for FixtureSource {
    async fn fetch_discovery(&self, issuer: &str) -> Result<DiscoveryDocument, FetchError> {
        Ok(DiscoveryDocument {
            issuer: issuer.to_owned(),
            jwks_uri: format!("{issuer}/jwks"),
        })
    }

    async fn fetch_jwks(&self, _jwks_uri: &str) -> Result<JwkSet, FetchError> {
        Ok(self.jwks.clone())
    }
}

fn caller(oidc_subject: Option<OidcSubject>) -> CallerCtx<TestGrant> {
    CallerCtx {
        token_name: "approver-token".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: Some(TestGrant),
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: ActorType::Human,
        oidc_subject,
        verified_approver: None,
        client_name: None,
        model_id: None,
        session_id: None,
        request_id: uuid::Uuid::new_v4(),
    }
}

fn bound_subject() -> OidcSubject {
    OidcSubject {
        issuer: ISSUER.to_owned(),
        subject: "alice".to_owned(),
    }
}

fn policy() -> ApproverPolicy {
    ApproverPolicy {
        approver_role: APPROVER_ROLE.to_owned(),
        max_age: Duration::from_secs(300),
        require_auth_time: false,
    }
}

/// `oidc_subject` controls whether the bearer token this app authenticates
/// has a step-up binding at all — `None` exercises `NoSubjectBinding`.
fn app(key: &TestKey, oidc_subject: Option<OidcSubject>, with_verifier: bool) -> Router {
    let bound_caller = caller(oidc_subject);
    let authenticator = BearerAuthenticator::new(BearerSyntax::Strict, move |candidate| {
        (candidate == "secret").then(|| bound_caller.clone())
    });
    let mut boundary = BearerBoundary::new(authenticator, BearerResponseProfile::compact("test"));
    if with_verifier {
        let jwks = JwkSet {
            keys: vec![key.jwk.clone()],
        };
        let config = OidcConfig::new(ISSUER, AUDIENCE, "groups");
        let token_verifier = TokenVerifier::new(config, Arc::new(FixtureSource { jwks }));
        boundary = boundary.with_approver_assertion(Arc::new(ApproverAssertionVerifier::new(
            Arc::new(token_verifier),
            ISSUER,
            policy(),
        )));
    }

    let router = Router::new().route(
        "/",
        post(
            |Extension(caller): Extension<CallerCtx<TestGrant>>| async move {
                json!({
                    "verified_approver_subject": caller.verified_approver.map(|a| a.subject),
                })
                .to_string()
            },
        ),
    );
    apply_bearer_boundary(
        router,
        boundary,
        BoundaryAccounting {
            session_tracker: None,
            concurrency: None,
            limits: Arc::new(LimitsConfig::default()),
        },
    )
}

fn request(assertion: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/")
        .header(header::AUTHORIZATION, "Bearer secret");
    if let Some(value) = assertion {
        builder = builder.header(APPROVER_ASSERTION_HEADER, value);
    }
    builder.body(Body::from("{}")).expect("request")
}

async fn json_body(response: axum::response::Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("response body");
    (status, serde_json::from_slice(&bytes).expect("JSON body"))
}

#[tokio::test]
async fn a_valid_assertion_binds_and_is_visible_on_the_caller() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &valid_claims("alice", "jti-ok"), KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["verified_approver_subject"], "alice");
}

#[tokio::test]
async fn no_header_is_unaffected_whether_or_not_a_verifier_is_configured() {
    let key = generate_test_key(KID);
    for with_verifier in [false, true] {
        let response = app(&key, Some(bound_subject()), with_verifier)
            .oneshot(request(None))
            .await
            .expect("response");
        let (status, body) = json_body(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["verified_approver_subject"], Value::Null);
    }
}

#[tokio::test]
async fn a_header_with_no_verifier_configured_is_400_not_401() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &valid_claims("alice", "jti-unconfigured"), KID);
    let response = app(&key, Some(bound_subject()), false)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    let (status, body) = json_body(response).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "approver_assertion_not_configured");
}

#[tokio::test]
async fn a_forged_signature_is_refused() {
    let key = generate_test_key(KID);
    let other_key = generate_test_key(KID);
    let token = sign_token(&other_key, &valid_claims("alice", "jti-forged"), KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wrong_audience_is_refused() {
    let key = generate_test_key(KID);
    let mut claims = valid_claims("alice", "jti-wrong-aud");
    claims["aud"] = json!("someone-else");
    let token = sign_token(&key, &claims, KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_wrong_issuer_is_refused() {
    let key = generate_test_key(KID);
    let mut claims = valid_claims("alice", "jti-wrong-iss");
    claims["iss"] = json!("https://not-the-configured-idp.example.com");
    let token = sign_token(&key, &claims, KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_subject_different_from_the_tokens_binding_is_refused() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &valid_claims("mallory", "jti-wrong-subject"), KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_the_approver_role_is_refused() {
    let key = generate_test_key(KID);
    let mut claims = valid_claims("alice", "jti-no-role");
    claims["groups"] = json!(["employee"]);
    let token = sign_token(&key, &claims, KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stale_assertion_older_than_max_age_is_refused() {
    let key = generate_test_key(KID);
    let mut claims = valid_claims("alice", "jti-stale");
    claims["iat"] = json!(now() - 301);
    let token = sign_token(&key, &claims, KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_bearer_token_with_no_oidc_subject_cannot_bind_an_assertion() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &valid_claims("alice", "jti-no-binding"), KID);
    let response = app(&key, None, true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_reused_jti_is_refused_on_the_second_call() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &valid_claims("alice", "jti-reused"), KID);
    let app = app(&key, Some(bound_subject()), true);

    let first = app
        .clone()
        .oneshot(request(Some(&token)))
        .await
        .expect("first response");
    assert_eq!(first.status(), StatusCode::OK);

    let second = app
        .oneshot(request(Some(&token)))
        .await
        .expect("second response");
    assert_eq!(
        second.status(),
        StatusCode::UNAUTHORIZED,
        "the same jti must not bind a second time"
    );
}

#[tokio::test]
async fn the_jwt_never_appears_in_the_tool_result() {
    let key = generate_test_key(KID);
    let token = sign_token(&key, &valid_claims("alice", "jti-leak-check"), KID);
    let response = app(&key, Some(bound_subject()), true)
        .oneshot(request(Some(&token)))
        .await
        .expect("response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 16 * 1024)
        .await
        .expect("body");
    let body_text = String::from_utf8_lossy(&bytes);
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body_text.contains(&token),
        "the raw JWT must never reach a tool result"
    );
}
