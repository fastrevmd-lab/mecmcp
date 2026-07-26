//! Stable overload responses: HTTP 503 + `Retry-After`, load-shed semantics.

use axum::http::{
    StatusCode,
    header::{CONTENT_TYPE, RETRY_AFTER},
};
use axum::response::{IntoResponse, Response};

/// Seconds advertised in `Retry-After` on every shed response.
const RETRY_AFTER_SECS: u64 = 1;

/// Build a 429 Too Many Requests response with the given retry-after interval.
#[allow(dead_code)] // Used in phases 3-10
pub(crate) fn rate_limited_response(limit_kind: &'static str, retry_after_secs: u64) -> Response {
    crate::metrics::record_limit_hit(limit_kind, "request_rejected");
    let body = format!(r#"{{"error":"rate_limited","limit":"{limit_kind}"}}"#);
    (
        StatusCode::TOO_MANY_REQUESTS,
        [
            (RETRY_AFTER, retry_after_secs.to_string()),
            (CONTENT_TYPE, "application/json".to_owned()),
        ],
        body,
    )
        .into_response()
}

/// Build a stable overload response for the given limit kind
/// (e.g. `"global_concurrency"`, `"token_concurrency"`, `"session_cap"`).
///
/// **Documented limit kinds:** `"global_concurrency"`, `"token_concurrency"`,
/// `"target_concurrency"` (or the legacy alias `"router_concurrency"`),
/// `"session_cap"`, `"token_session_cap"`.
///
/// Passing a limit kind not in the documented set produces a response without
/// emitting a metric series, allowing future kinds to be added without breaking
/// compatibility.
pub fn overload_response(limit_kind: &'static str) -> Response {
    // Normalize the legacy "router_concurrency" alias to "target_concurrency"
    // for metric emission, preserving backward compatibility with existing
    // alert rules.
    let metric_kind = match limit_kind {
        "router_concurrency" => "target_concurrency",
        other => other,
    };

    if matches!(
        metric_kind,
        "global_concurrency"
            | "token_concurrency"
            | "target_concurrency"
            | "session_cap"
            | "token_session_cap"
    ) {
        crate::metrics::record_limit_hit(metric_kind, "request_rejected");
    }
    let body = format!(r#"{{"error":"overloaded","limit":"{limit_kind}"}}"#);
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(RETRY_AFTER, RETRY_AFTER_SECS.to_string())],
        body,
    )
        .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test(flavor = "current_thread")]
    async fn rate_limited_response_has_stable_contract_and_metric() {
        let (recorder, handle) = crate::metrics::test_recorder("junos");
        let response =
            metrics::with_local_recorder(&recorder, || rate_limited_response("token_rate", 3));

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "3");
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"rate_limited","limit":"token_rate"}"#
        );

        handle.run_upkeep();
        let text = handle.render();
        let sample = text
            .lines()
            .find(|line| {
                line.starts_with("junos_limit_hits_total{")
                    && line.contains("limit=\"token_rate\"")
                    && line.contains("event=\"request_rejected\"")
            })
            .expect("token-rate rejection metric");
        assert!(sample.ends_with(" 1"), "unexpected sample: {sample}");
        assert!(!sample.contains("token="));
    }

    #[test]
    fn overload_response_counts_each_fixed_limit_kind() {
        let (recorder, handle) = crate::metrics::test_recorder("junos");
        metrics::with_local_recorder(&recorder, || {
            for limit in [
                "global_concurrency",
                "token_concurrency",
                "target_concurrency",
                "session_cap",
                "token_session_cap",
            ] {
                let _ = overload_response(limit);
            }
        });
        handle.run_upkeep();
        let text = handle.render();
        for limit in [
            "global_concurrency",
            "token_concurrency",
            "target_concurrency",
            "session_cap",
            "token_session_cap",
        ] {
            assert!(
                text.lines().any(|line| {
                    line.starts_with("junos_limit_hits_total{")
                        && line.contains(&format!("limit=\"{limit}\""))
                        && line.contains("event=\"request_rejected\"")
                        && line.ends_with(" 1")
                }),
                "missing {limit} in:\n{text}"
            );
        }
    }

    #[test]
    fn router_concurrency_alias_maps_to_target_concurrency_metric() {
        let (recorder, handle) = crate::metrics::test_recorder("junos");
        metrics::with_local_recorder(&recorder, || {
            // Call with the legacy "router_concurrency" string
            let _ = overload_response("router_concurrency");
        });
        handle.run_upkeep();
        let text = handle.render();

        // The metric series should be emitted as "target_concurrency"
        assert!(
            text.lines().any(|line| {
                line.starts_with("junos_limit_hits_total{")
                    && line.contains("limit=\"target_concurrency\"")
                    && line.contains("event=\"request_rejected\"")
                    && line.ends_with(" 1")
            }),
            "missing target_concurrency metric (from router_concurrency alias) in:\n{text}"
        );

        // But the response body should preserve the original string
        let response = overload_response("router_concurrency");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn both_aliases_accepted_as_documented() {
        // This test asserts that both "target_concurrency" and "router_concurrency"
        // are valid limit kinds, as documented in the function's doc comment.
        let (recorder, handle) = crate::metrics::test_recorder("test");
        metrics::with_local_recorder(&recorder, || {
            let _ = overload_response("target_concurrency");
            let _ = overload_response("router_concurrency");
        });
        handle.run_upkeep();
        let text = handle.render();

        // Both calls should result in the same metric series (target_concurrency),
        // and the count should be 2.
        let sample = text
            .lines()
            .find(|line| {
                line.starts_with("test_limit_hits_total{")
                    && line.contains("limit=\"target_concurrency\"")
            })
            .expect("target_concurrency metric");
        assert!(sample.ends_with(" 2"), "expected count of 2, got: {sample}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_limit_preserves_response_without_metric_series() {
        let (recorder, handle) = crate::metrics::test_recorder("junos");
        let response =
            metrics::with_local_recorder(&recorder, || overload_response("future_limit_kind"));

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "1");
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"overloaded","limit":"future_limit_kind"}"#
        );

        handle.run_upkeep();
        let text = handle.render();
        assert!(
            !text
                .lines()
                .any(|line| line.starts_with("junos_limit_hits_total{")),
            "unexpected limit series in:\n{text}"
        );
    }
}
