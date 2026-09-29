//! Liveness and readiness endpoints.
//!
//! `mecmcp-transport` owns the routes; it does not own an audit sink or an
//! inventory, so readiness is a set of named probes the consumer wires in.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use std::sync::Arc;

/// A single named readiness probe.
///
/// Each server supplies its own — audit sink writable, inventory loaded — via
/// [`crate::HttpTransportConfig::with_readiness_check`]. `mecmcp-transport`
/// has no dependency of its own to check, so with no checks configured
/// `/readyz` reports ready.
#[derive(Clone)]
pub struct ReadinessCheck {
    name: &'static str,
    probe: Arc<dyn Fn() -> Result<(), &'static str> + Send + Sync>,
}

impl ReadinessCheck {
    /// Build a check from a name and a probe closure.
    ///
    /// `probe` returns `Ok(())` when the dependency is ready, or an `Err`
    /// reason. `/readyz` is unauthenticated, so the reason is `&'static str`
    /// rather than `String`: a caller cannot format a filesystem path, an I/O
    /// error, or any other runtime value into it, only return a fixed literal
    /// such as `"audit sink is not writable"`. Log the runtime detail
    /// server-side instead.
    #[must_use]
    pub fn new(
        name: &'static str,
        probe: impl Fn() -> Result<(), &'static str> + Send + Sync + 'static,
    ) -> Self {
        Self {
            name,
            probe: Arc::new(probe),
        }
    }
}

impl std::fmt::Debug for ReadinessCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReadinessCheck")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// `GET /healthz`: the process is up. No dependency is consulted.
async fn healthz() -> Response {
    (StatusCode::OK, "ok").into_response()
}

#[derive(serde::Serialize)]
struct ReadyBody {
    status: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    failed: Vec<FailedCheck>,
}

#[derive(serde::Serialize)]
struct FailedCheck {
    name: &'static str,
    reason: &'static str,
}

/// `GET /readyz`: runs every configured [`ReadinessCheck`] and reports the
/// first failures. 200 when all pass (including when none are configured);
/// 503 listing the failed check names otherwise.
async fn readyz(State(checks): State<Arc<[ReadinessCheck]>>) -> Response {
    let failed: Vec<FailedCheck> = checks
        .iter()
        .filter_map(|check| {
            (check.probe)().err().map(|reason| FailedCheck {
                name: check.name,
                reason,
            })
        })
        .collect();

    if failed.is_empty() {
        (
            StatusCode::OK,
            Json(ReadyBody {
                status: "ok",
                failed,
            }),
        )
            .into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyBody {
                status: "not_ready",
                failed,
            }),
        )
            .into_response()
    }
}

/// Build an axum router serving `/healthz` and `/readyz`.
///
/// Merged into the main router unconditionally: a health probe is expected by
/// any operator running this under k8s or systemd, unlike `/metrics`, which is
/// opt-in.
pub(crate) fn health_router(checks: Arc<[ReadinessCheck]>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(checks)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt as _;

    async fn call(router: Router, path: &str) -> Response {
        router
            .oneshot(
                Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn healthz_is_200_with_no_checks_configured() {
        let router = health_router(Arc::from([]));
        let response = call(router, "/healthz").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_is_200_when_all_checks_pass() {
        let checks: Arc<[ReadinessCheck]> =
            Arc::from([ReadinessCheck::new("audit_sink", || Ok(()))]);
        let response = call(health_router(checks), "/readyz").await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn readyz_is_503_when_the_audit_sink_is_unwritable() {
        let checks: Arc<[ReadinessCheck]> = Arc::from([ReadinessCheck::new("audit_sink", || {
            Err("audit sink is not writable")
        })]);
        let response = call(health_router(checks), "/readyz").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("audit_sink"));
        assert!(text.contains("audit sink is not writable"));
    }

    #[tokio::test]
    async fn readyz_reports_every_failed_check() {
        let checks: Arc<[ReadinessCheck]> = Arc::from([
            ReadinessCheck::new("audit_sink", || Ok(())),
            ReadinessCheck::new("inventory", || Err("inventory not loaded")),
        ]);
        let response = call(health_router(checks), "/readyz").await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("inventory"));
        assert!(
            !text.contains("audit_sink"),
            "only failed checks are listed"
        );
    }

    #[tokio::test]
    async fn a_registered_auth_failure_tracker_flips_readyz() {
        // `mecmcp-secret::AuthFailureTracker` has no dependency on this
        // crate — its `probe()` closure satisfies `ReadinessCheck::new`'s
        // `Fn() -> Result<(), &'static str> + Send + Sync` bound by shape
        // alone. This proves that shape actually plugs in and that a
        // simulated auth failure is visible on `/readyz` (MEC-539).
        let tracker = mecmcp_secret::AuthFailureTracker::new();
        let checks: Arc<[ReadinessCheck]> = Arc::from([ReadinessCheck::new(
            "auth",
            tracker.probe("outbound authentication is failing"),
        )]);
        let router = health_router(checks);

        let response = call(router.clone(), "/readyz").await;
        assert_eq!(response.status(), StatusCode::OK, "starts ready");

        tracker.record_failure();
        let response = call(router.clone(), "/readyz").await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "a simulated auth failure must flip /readyz to failing"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(text.contains("auth"));
        assert!(text.contains("outbound authentication is failing"));

        tracker.record_success();
        let response = call(router, "/readyz").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "recovery must clear the failing state"
        );
    }

    #[tokio::test]
    async fn healthz_does_not_consult_readiness_checks() {
        // A readiness probe that would fail readyz must not affect healthz —
        // liveness has no dependencies by definition.
        let checks: Arc<[ReadinessCheck]> = Arc::from([ReadinessCheck::new("audit_sink", || {
            Err("audit sink is not writable")
        })]);
        let response = call(health_router(checks), "/healthz").await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
