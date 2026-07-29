//! Shared bearer authentication and scope-preflight HTTP boundary.

use crate::{
    AuthenticatedToken,
    preflight::{CallerScopes, OptionalPreflight, ScopePreflight, run_preflight},
};
use axum::{
    Router,
    body::{Body, Bytes, to_bytes},
    extract::{Request, State},
    http::{StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use mecmcp_auth::{BearerSyntax, CallerCtx, Grant, parse_bearer_header};
use serde_json::json;
use std::sync::Arc;

type Authenticate<G> = dyn Fn(&str) -> Option<CallerCtx<G>> + Send + Sync;

/// Authenticates a presented bearer credential into a grant-bearing caller.
pub struct BearerAuthenticator<G: Grant> {
    syntax: BearerSyntax,
    authenticate: Arc<Authenticate<G>>,
}

impl<G: Grant> Clone for BearerAuthenticator<G> {
    fn clone(&self) -> Self {
        Self {
            syntax: self.syntax,
            authenticate: self.authenticate.clone(),
        }
    }
}

impl<G: Grant> BearerAuthenticator<G> {
    /// Construct an authenticator around an atomically reloadable lookup.
    #[must_use]
    pub fn new(
        syntax: BearerSyntax,
        authenticate: impl Fn(&str) -> Option<CallerCtx<G>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            syntax,
            authenticate: Arc::new(authenticate),
        }
    }

    fn authenticate(&self, candidate: &str) -> Option<CallerCtx<G>> {
        (self.authenticate)(candidate)
    }
}

/// Compatibility profile for bearer failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerResponseProfile {
    realm: String,
    style: BearerResponseStyle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BearerResponseStyle {
    Detailed,
    Compact,
}

impl BearerResponseProfile {
    /// RFC 6750 profile with distinct invalid-request and invalid-token bodies.
    #[must_use]
    pub fn detailed(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            style: BearerResponseStyle::Detailed,
        }
    }

    /// Compact profile returning `invalid_token` for every 401.
    #[must_use]
    pub fn compact(realm: impl Into<String>) -> Self {
        Self {
            realm: realm.into(),
            style: BearerResponseStyle::Compact,
        }
    }
}

/// Configuration for the shared authenticated request boundary.
pub struct BearerBoundary<G: Grant> {
    authenticator: BearerAuthenticator<G>,
    responses: BearerResponseProfile,
    body_limit: usize,
    preflight: OptionalPreflight,
}

impl<G: Grant> Clone for BearerBoundary<G> {
    fn clone(&self) -> Self {
        Self {
            authenticator: self.authenticator.clone(),
            responses: self.responses.clone(),
            body_limit: self.body_limit,
            preflight: self.preflight.clone(),
        }
    }
}

impl<G: Grant> BearerBoundary<G> {
    /// Construct a bearer boundary.
    #[must_use]
    pub fn new(
        authenticator: BearerAuthenticator<G>,
        responses: BearerResponseProfile,
        body_limit: usize,
    ) -> Self {
        Self {
            authenticator,
            responses,
            body_limit,
            preflight: None,
        }
    }

    /// Install a synchronous scope preflight.
    #[must_use]
    pub fn with_preflight(mut self, preflight: impl ScopePreflight + 'static) -> Self {
        self.preflight = Some(Arc::new(preflight));
        self
    }

    /// Install an optional dynamically dispatched scope preflight.
    #[must_use]
    pub fn with_optional_preflight(mut self, preflight: OptionalPreflight) -> Self {
        self.preflight = preflight;
        self
    }
}

#[derive(Debug, Clone)]
pub(crate) struct BufferedRequestBody(pub(crate) Bytes);

/// Apply bearer authentication, bounded buffering, and scope preflight.
pub fn apply_bearer_boundary<G: Grant>(router: Router, boundary: BearerBoundary<G>) -> Router {
    router.layer(axum::middleware::from_fn_with_state(
        boundary,
        bearer_boundary,
    ))
}

async fn bearer_boundary<G: Grant>(
    State(boundary): State<BearerBoundary<G>>,
    request: Request,
    next: Next,
) -> Response {
    let candidate = match bearer_candidate(&request, boundary.authenticator.syntax) {
        Ok(candidate) => candidate,
        Err(PresentationError::Missing) => {
            return unauthorized(&boundary.responses, "missing Authorization header");
        }
        Err(PresentationError::Malformed) => {
            return unauthorized(
                &boundary.responses,
                "Authorization header must use Bearer scheme",
            );
        }
    };
    let Some(caller) = boundary.authenticator.authenticate(candidate) else {
        tracing::warn!("auth_failed: no matching token");
        return invalid_token(&boundary.responses);
    };

    let (mut parts, body) = request.into_parts();
    let maximum = if boundary.body_limit == 0 {
        usize::MAX
    } else {
        boundary.body_limit
    };
    let body_bytes = match to_bytes(body, maximum).await {
        Ok(bytes) => bytes,
        Err(_) => return payload_too_large(),
    };

    if let Err(reason) = run_preflight(
        &boundary.preflight,
        &body_bytes,
        CallerScopes::from(&caller),
    ) {
        return forbidden(&boundary.responses.realm, &reason);
    }

    parts
        .extensions
        .insert(AuthenticatedToken::new(caller.token_name.clone()));
    parts
        .extensions
        .insert(BufferedRequestBody(body_bytes.clone()));
    parts.extensions.insert(caller);
    next.run(Request::from_parts(parts, Body::from(body_bytes)))
        .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PresentationError {
    Missing,
    Malformed,
}

fn bearer_candidate(request: &Request, syntax: BearerSyntax) -> Result<&str, PresentationError> {
    let mut values = request.headers().get_all(header::AUTHORIZATION).iter();
    let value = values.next().ok_or(PresentationError::Missing)?;
    if values.next().is_some() {
        return Err(PresentationError::Malformed);
    }
    let value = value.to_str().map_err(|_| PresentationError::Malformed)?;
    parse_bearer_header(value, syntax).map_err(|_| PresentationError::Malformed)
}

fn unauthorized(profile: &BearerResponseProfile, description: &str) -> Response {
    match profile.style {
        BearerResponseStyle::Detailed => response(
            StatusCode::UNAUTHORIZED,
            format!(r#"Bearer realm="{}""#, profile.realm),
            json!({
                "error": "invalid_request",
                "error_description": description,
            }),
        ),
        BearerResponseStyle::Compact => invalid_token(profile),
    }
}

fn invalid_token(profile: &BearerResponseProfile) -> Response {
    let body = match profile.style {
        BearerResponseStyle::Detailed => json!({
            "error": "invalid_token",
            "error_description": "invalid bearer token",
        }),
        BearerResponseStyle::Compact => json!({"error": "invalid_token"}),
    };
    let challenge = match profile.style {
        BearerResponseStyle::Detailed => format!(
            r#"Bearer realm="{}", error="invalid_token", error_description="The access token is invalid""#,
            profile.realm
        ),
        BearerResponseStyle::Compact => {
            format!(r#"Bearer realm="{}", error="invalid_token""#, profile.realm)
        }
    };
    response(StatusCode::UNAUTHORIZED, challenge, body)
}

fn forbidden(realm: &str, reason: &str) -> Response {
    response(
        StatusCode::FORBIDDEN,
        format!(r#"Bearer realm="{realm}", error="{reason}""#),
        json!({"error": reason}),
    )
}

fn response(status: StatusCode, challenge: String, body: serde_json::Value) -> Response {
    (
        status,
        [(header::WWW_AUTHENTICATE, challenge)],
        axum::Json(body),
    )
        .into_response()
}

fn payload_too_large() -> Response {
    (
        StatusCode::PAYLOAD_TOO_LARGE,
        axum::Json(json!({"error": "request_too_large"})),
    )
        .into_response()
}
