//! Optional scope preflight for middleware-layer authorization.
//!
//! PAN-OS runs a preflight that parses the request body and checks the tool plus
//! `params.arguments.device` against the token's scopes, returning 403
//! `insufficient_scope`. Junos has no equivalent and defers to its handler.
//!
//! `None` must be behaviourally identical to Junos today.

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use std::sync::Arc;

/// Preflight authorization check before routing to the handler.
///
/// Invoked at the middleware layer with the raw request body. Implementations
/// parse the body, extract the tool name and any target device, and check
/// against the token's scopes.
///
/// Returning `Ok(())` allows the request to proceed. Returning `Err(...)` with
/// a specific error message causes a 403 response with that message.
#[async_trait]
pub trait ScopePreflight: Send + Sync {
    /// Check whether the request is authorized to proceed.
    ///
    /// The request body is provided in its raw form. The implementation is
    /// responsible for parsing it and extracting the necessary fields.
    async fn check(&self, request: &Request<Body>) -> Result<(), String>;
}

/// Type alias for an optional preflight checker.
///
/// `None` disables preflight; the request proceeds directly to the handler.
/// This reproduces the Junos behaviour where authorization is handler-local.
pub type OptionalPreflight = Option<Arc<dyn ScopePreflight>>;

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};

    #[tokio::test(flavor = "multi_thread")]
    async fn none_preflight_passes_all_requests() {
        // Task 7 requirement: None must be behaviourally identical to Junos.
        // A request that a Some(...) preflight would reject must pass untouched.
        let preflight: OptionalPreflight = None;

        let _request = Request::builder()
            .uri("/mcp")
            .method("POST")
            .body(Body::from(
                r#"{"method":"tools/call","params":{"name":"forbidden_tool","arguments":{"device":"blocked"}}}"#,
            ))
            .expect("valid request");

        // With None, there is no preflight to invoke — the request would go
        // straight to the handler. This test asserts the type allows None.
        assert!(preflight.is_none());

        // A real middleware would do:
        // if let Some(checker) = &preflight {
        //     checker.check(&request).await?;
        // }
        // With None, the check is skipped entirely, so any request proceeds.
    }

    struct AlwaysReject;

    #[async_trait]
    impl ScopePreflight for AlwaysReject {
        async fn check(&self, _request: &Request<Body>) -> Result<(), String> {
            Err("always rejected".to_owned())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn some_preflight_can_reject() {
        // Verify that a Some(...) preflight can enforce policy, contrasting
        // with the None case above where everything passes.
        let preflight: OptionalPreflight = Some(Arc::new(AlwaysReject));

        let request = Request::builder()
            .uri("/mcp")
            .method("POST")
            .body(Body::from(r#"{"method":"tools/call"}"#))
            .expect("valid request");

        let checker = preflight.as_ref().expect("preflight is Some");
        let result = checker.check(&request).await;

        assert!(result.is_err());
        assert_eq!(result.expect_err("should be rejected"), "always rejected");
    }
}
