//! Prometheus metrics runtime with vendor-neutral naming.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use metrics_exporter_prometheus::{BuildError, Matcher, PrometheusBuilder, PrometheusHandle};
use std::time::Duration;
use tokio::time::MissedTickBehavior;
use tokio_util::task::AbortOnDropHandle;

/// Prometheus OpenMetrics content type.
pub(crate) const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

const UPKEEP_INTERVAL: Duration = Duration::from_secs(5);
const TOOL_DURATION_BUCKETS: &[f64] = &[
    0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0,
];

/// Prometheus metrics runtime with vendor-specific naming.
///
/// All four metric names — active sessions, limit hits, tool duration, sessions
/// reaped — are derived from the `metric_prefix` passed to `install`. There is
/// no default prefix; a default is how the wrong name ships.
pub struct PrometheusRuntime {
    handle: PrometheusHandle,
    _upkeep: AbortOnDropHandle<()>,
    #[allow(dead_code)] // Used in phases 3-10
    active_sessions_name: String,
    #[allow(dead_code)] // Used in phases 3-10
    limit_hits_name: String,
    #[allow(dead_code)] // Used in phases 3-10
    tool_duration_name: String,
    #[allow(dead_code)] // Used in phases 3-10
    sessions_reaped_name: String,
}

impl PrometheusRuntime {
    /// Install the Prometheus recorder with the given metric prefix and server label.
    ///
    /// **Metric names:**
    /// - `{prefix}_active_sessions`
    /// - `{prefix}_limit_hits_total`
    /// - `{prefix}_tool_duration_seconds`
    /// - `{prefix}_sessions_reaped_total`
    ///
    /// The `server` parameter becomes the global `server` label on all metrics.
    pub fn install(metric_prefix: &str, server: &str) -> Result<Self, BuildError> {
        let active_sessions_name = format!("{metric_prefix}_active_sessions");
        let limit_hits_name = format!("{metric_prefix}_limit_hits_total");
        let tool_duration_name = format!("{metric_prefix}_tool_duration_seconds");
        let sessions_reaped_name = format!("{metric_prefix}_sessions_reaped_total");

        let handle = prometheus_builder(server, &tool_duration_name)?.install_recorder()?;
        describe_metrics(
            &active_sessions_name,
            &limit_hits_name,
            &tool_duration_name,
            &sessions_reaped_name,
        );
        metrics::gauge!(active_sessions_name.clone()).set(0.0);

        // Publish the names process-globally so middleware on any worker thread
        // can read them. `set` returns Err if a second runtime is installed in
        // the same process; the first install wins and that is the contract.
        let _ = METRIC_NAMES.set(MetricNames {
            active_sessions: active_sessions_name.clone(),
            limit_hits: limit_hits_name.clone(),
            sessions_reaped: sessions_reaped_name.clone(),
        });

        let upkeep_handle = handle.clone();
        let upkeep = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut interval = tokio::time::interval(UPKEEP_INTERVAL);
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                upkeep_handle.run_upkeep();
            }
        }));

        Ok(Self {
            handle,
            _upkeep: upkeep,
            active_sessions_name,
            limit_hits_name,
            tool_duration_name,
            sessions_reaped_name,
        })
    }

    /// Build an axum router serving `/metrics`.
    pub fn router(&self) -> Router {
        metrics_router(self.handle.clone())
    }

    /// Record a limit hit event.
    #[allow(dead_code)] // Used in phases 3-10
    pub(crate) fn record_limit_hit(&self, limit: &'static str, event: &'static str) {
        metrics::counter!(
            self.limit_hits_name.clone(),
            "limit" => limit,
            "event" => event
        )
        .increment(1);
    }

    /// Increment the active sessions gauge.
    #[allow(dead_code)] // Used in phases 3-10
    pub(crate) fn increment_active_sessions(&self) {
        metrics::gauge!(self.active_sessions_name.clone()).increment(1.0);
    }

    /// Decrement the active sessions gauge.
    #[allow(dead_code)] // Used in phases 3-10
    pub(crate) fn decrement_active_sessions(&self) {
        metrics::gauge!(self.active_sessions_name.clone()).decrement(1.0);
    }

    /// Record a session reap event.
    #[allow(dead_code)] // Used in phases 3-10
    pub(crate) fn record_session_reaped(&self, reason: &'static str) {
        metrics::counter!(self.sessions_reaped_name.clone(), "reason" => reason).increment(1);
    }
}

fn prometheus_builder(
    server: &str,
    tool_duration_name: &str,
) -> Result<PrometheusBuilder, BuildError> {
    PrometheusBuilder::new()
        .add_global_label("server", server)
        .set_buckets_for_metric(
            Matcher::Full(tool_duration_name.to_owned()),
            TOOL_DURATION_BUCKETS,
        )
}

fn describe_metrics(
    active_sessions: &str,
    limit_hits: &str,
    tool_duration: &str,
    sessions_reaped: &str,
) {
    let active_sessions = active_sessions.to_owned();
    let limit_hits = limit_hits.to_owned();
    let tool_duration = tool_duration.to_owned();
    let sessions_reaped = sessions_reaped.to_owned();

    metrics::describe_gauge!(
        active_sessions,
        "Current MCP sessions tracked by the HTTP session manager."
    );
    metrics::describe_counter!(
        limit_hits,
        "HTTP resource-limit rejections and manager-level session cap hits."
    );
    metrics::describe_histogram!(
        tool_duration,
        metrics::Unit::Seconds,
        "Elapsed MCP tool-handler duration by tool and terminal result."
    );
    metrics::describe_counter!(
        sessions_reaped,
        "MCP sessions removed by the idle/lifetime reaper."
    );
}

fn metrics_router(handle: PrometheusHandle) -> Router {
    Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(handle)
}

async fn render_metrics(State(handle): State<PrometheusHandle>) -> Response {
    handle.run_upkeep();
    (
        [(
            CONTENT_TYPE,
            HeaderValue::from_static(PROMETHEUS_CONTENT_TYPE),
        )],
        handle.render(),
    )
        .into_response()
}

// Module-level metric name storage for use by overload responses and other
// middleware that don't have direct access to PrometheusRuntime.
/// The prefix-derived metric names, resolved once at `install()`.
#[derive(Debug)]
pub(crate) struct MetricNames {
    /// Read by the session tracker, which lands in Task 5.
    #[allow(dead_code)] // Used in phases 3-10
    pub(crate) active_sessions: String,
    pub(crate) limit_hits: String,
    /// Read by the session reaper, which lands in Task 5.
    #[allow(dead_code)] // Used in phases 3-10
    pub(crate) sessions_reaped: String,
}

/// Process-global, deliberately **not** thread-local.
///
/// These names are read by middleware running on tokio worker threads, while
/// `install()` runs on whichever thread starts the server. A `thread_local`
/// here is silently wrong: the worker sees `None` and the metric is never
/// recorded — no panic, no log, just a series that stops existing. A
/// `current_thread` test runtime hides it, because there the setter and the
/// reader are the same thread.
///
/// `OnceLock` because a process serves exactly one server, so the names are
/// fixed for its lifetime. This matches `mecmcp_audit::install_duration_metric_name`.
static METRIC_NAMES: std::sync::OnceLock<MetricNames> = std::sync::OnceLock::new();

// Test-only per-thread override.
//
// Production reads METRIC_NAMES, which is process-global and therefore visible
// from every tokio worker thread — that is the bug fix. But the unit tests
// install several different prefixes in one process and run in parallel, which
// a OnceLock cannot serve. This override gives each test thread its own names
// while leaving the production path global.
//
// It is #[cfg(test)]: no override exists in a release build, so there is no way
// for this to mask the cross-thread bug it is carved out around.
#[cfg(test)]
thread_local! {
    static TEST_METRIC_NAMES: std::cell::RefCell<Option<MetricNames>> =
        const { std::cell::RefCell::new(None) };
}

/// Set the calling thread's metric names for the duration of a test.
#[cfg(test)]
pub(crate) fn set_test_metric_names(prefix: &str) {
    TEST_METRIC_NAMES.with(|cell| {
        *cell.borrow_mut() = Some(MetricNames {
            active_sessions: format!("{prefix}_active_sessions"),
            limit_hits: format!("{prefix}_limit_hits_total"),
            sessions_reaped: format!("{prefix}_sessions_reaped_total"),
        });
    });
}

/// The `<prefix>_limit_hits_total` name, or `None` before `install()` has run.
pub(crate) fn limit_hits_metric_name() -> Option<String> {
    #[cfg(test)]
    {
        if let Some(name) =
            TEST_METRIC_NAMES.with(|cell| cell.borrow().as_ref().map(|n| n.limit_hits.clone()))
        {
            return Some(name);
        }
    }
    METRIC_NAMES.get().map(|names| names.limit_hits.clone())
}

/// Metric names resolved at install, or `None` before `install()` has run.
#[allow(dead_code)] // Used in phases 3-10
pub(crate) fn metric_names() -> Option<&'static MetricNames> {
    METRIC_NAMES.get()
}

/// Record a limit hit using the installed metric names.
///
/// This function is called by overload response builders that don't have
/// direct access to the PrometheusRuntime instance.
pub(crate) fn record_limit_hit(limit: &'static str, event: &'static str) {
    if let Some(name) = limit_hits_metric_name() {
        metrics::counter!(
            name,
            "limit" => limit,
            "event" => event
        )
        .increment(1);
    }
}

#[cfg(test)]
pub(crate) fn test_recorder(
    prefix: &str,
) -> (
    metrics_exporter_prometheus::PrometheusRecorder,
    PrometheusHandle,
) {
    let active_sessions_name = format!("{prefix}_active_sessions");
    let limit_hits_name = format!("{prefix}_limit_hits_total");
    let tool_duration_name = format!("{prefix}_tool_duration_seconds");
    let sessions_reaped_name = format!("{prefix}_sessions_reaped_total");

    // Per-thread, not the process global: several prefixes coexist in one test
    // binary. See set_test_metric_names for why this carve-out is safe.
    set_test_metric_names(prefix);

    let recorder = prometheus_builder("test", &tool_duration_name)
        .expect("fixed non-empty histogram buckets")
        .build_recorder();
    let handle = recorder.handle();
    describe_metrics(
        &active_sessions_name,
        &limit_hits_name,
        &tool_duration_name,
        &sessions_reaped_name,
    );
    (recorder, handle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header::CONTENT_TYPE};
    use metrics::with_local_recorder;
    use tower::ServiceExt as _;

    fn sample_with<'a>(text: &'a str, prefix: &str, fragments: &[&str]) -> &'a str {
        text.lines()
            .find(|line| {
                line.starts_with(prefix) && fragments.iter().all(|fragment| line.contains(fragment))
            })
            .unwrap_or_else(|| panic!("missing {prefix} with {fragments:?} in:\n{text}"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn renders_exact_metric_contract_and_content_type() {
        let (recorder, handle) = test_recorder("junosmcp");
        mecmcp_audit::install_duration_metric_name("junosmcp_tool_duration_seconds");
        with_local_recorder(&recorder, || {
            metrics::gauge!("junosmcp_active_sessions").set(2.0);
            record_limit_hit("global_concurrency", "request_rejected");
            metrics::counter!("junosmcp_sessions_reaped_total", "reason" => "idle").increment(1);
            // Use AuditScope to emit mecmcp_tool_duration_seconds, not a direct
            // metrics::histogram! call. This tests the real code path.
            let mut audit =
                mecmcp_audit::AuditScope::stdio("get_router_list", "read", vec!["r1".into()]);
            audit.succeed();
        });
        handle.run_upkeep();

        let response = metrics_router(handle)
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap(),
            PROMETHEUS_CONTENT_TYPE
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let text = std::str::from_utf8(&body).unwrap();

        sample_with(
            text,
            "junosmcp_active_sessions{",
            &["server=\"test\"", "} 2"],
        );
        sample_with(
            text,
            "junosmcp_limit_hits_total{",
            &[
                "server=\"test\"",
                "limit=\"global_concurrency\"",
                "event=\"request_rejected\"",
                "} 1",
            ],
        );
        sample_with(
            text,
            "junosmcp_sessions_reaped_total{",
            &["server=\"test\"", "reason=\"idle\"", "} 1"],
        );
        // mecmcp-audit emits summary metrics, not histograms
        sample_with(
            text,
            "junosmcp_tool_duration_seconds",
            &[
                "server=\"test\"",
                "tool=\"get_router_list\"",
                "result=\"ok\"",
            ],
        );
        assert!(!text.contains("junosmcp_limit_hits_total_total"));
    }

    #[test]
    fn different_prefixes_emit_disjoint_metric_names() {
        // Regression test: mecmcp-audit shipped with a hardcoded "junosmcp_"
        // prefix and silently renamed a consumer's public Prometheus series.
        let (recorder_alpha, handle_alpha) = test_recorder("alpha");
        let (recorder_beta, handle_beta) = test_recorder("beta");

        with_local_recorder(&recorder_alpha, || {
            metrics::gauge!("alpha_active_sessions").set(1.0);
            metrics::counter!("alpha_limit_hits_total", "limit" => "test").increment(1);
        });

        with_local_recorder(&recorder_beta, || {
            metrics::gauge!("beta_active_sessions").set(2.0);
            metrics::counter!("beta_limit_hits_total", "limit" => "test").increment(1);
        });

        handle_alpha.run_upkeep();
        handle_beta.run_upkeep();

        let text_alpha = handle_alpha.render();
        let text_beta = handle_beta.render();

        // Alpha's output must contain only "alpha_" prefixed metrics
        assert!(text_alpha.contains("alpha_active_sessions{"));
        assert!(text_alpha.contains("alpha_limit_hits_total{"));
        assert!(!text_alpha.contains("beta_"));

        // Beta's output must contain only "beta_" prefixed metrics
        assert!(text_beta.contains("beta_active_sessions{"));
        assert!(text_beta.contains("beta_limit_hits_total{"));
        assert!(!text_beta.contains("alpha_"));

        // Neither should emit a "junosmcp_" series unless that prefix was
        // explicitly requested
        assert!(!text_alpha.contains("junosmcp_"));
        assert!(!text_beta.contains("junosmcp_"));
    }

    /// Regression: the metric names must be readable from a **different thread**
    /// than the one that published them.
    ///
    /// An earlier implementation kept them in `thread_local!` storage.
    /// `install()` runs on whichever thread starts the server; the middleware
    /// that records limit hits runs on tokio worker threads. The worker read
    /// `None`, so `record_limit_hit` silently did nothing and
    /// `<prefix>_limit_hits_total` stopped existing — no panic, no log.
    ///
    /// Deliberately prefix-agnostic: it asserts the invariant (same value on
    /// any thread) rather than a specific name, so it does not race the other
    /// tests over the `OnceLock`. A `current_thread` runtime cannot fail this
    /// way, which is precisely why the original test missed the bug.
    #[test]
    fn metric_names_are_visible_across_threads() {
        let _ = METRIC_NAMES.set(MetricNames {
            active_sessions: "xthread_active_sessions".into(),
            limit_hits: "xthread_limit_hits_total".into(),
            sessions_reaped: "xthread_sessions_reaped_total".into(),
        });

        let on_main = metric_names().map(|n| n.limit_hits.clone());
        assert!(on_main.is_some(), "names unset on the publishing thread");

        let on_worker = std::thread::spawn(|| metric_names().map(|n| n.limit_hits.clone()))
            .join()
            .expect("worker thread panicked");

        assert_eq!(
            on_main, on_worker,
            "metric names differ across threads — this is the thread_local \
             regression: middleware on a tokio worker would record nothing"
        );
    }
}
