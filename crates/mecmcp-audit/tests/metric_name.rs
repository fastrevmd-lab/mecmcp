//! The tool-duration metric name is caller-supplied.
//!
//! This lives in an integration test rather than a unit test because the name is
//! held in a process-global `OnceLock`. A unit test that installs a name leaks it
//! into every other test in the same binary — which is exactly what happened
//! first time round, breaking a sibling test that asserts the default. Each
//! integration test binary gets its own process, so the global starts fresh.

use mecmcp_audit::{DEFAULT_DURATION_METRIC, duration_metric_name, install_duration_metric_name};

#[test]
fn a_consumer_can_keep_its_own_metric_name() {
    // Adopting this crate must not silently rename a metric that a consuming
    // server's dashboards and alerts already query.
    assert_eq!(
        duration_metric_name(),
        DEFAULT_DURATION_METRIC,
        "an un-installed name must fall back to the default"
    );

    install_duration_metric_name("junosmcp_tool_duration_seconds");
    assert_eq!(duration_metric_name(), "junosmcp_tool_duration_seconds");

    // Idempotent, matching `redact::install`: a later call cannot change the
    // name out from under bucket configuration already registered for it.
    install_duration_metric_name("something_else");
    assert_eq!(
        duration_metric_name(),
        "junosmcp_tool_duration_seconds",
        "install must be idempotent so the emitted name cannot drift"
    );
}
