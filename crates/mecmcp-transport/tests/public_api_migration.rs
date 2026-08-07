//! Verify public API migration paths are reachable.
//!
//! This test exists because the `build_rmcp_server_config` re-export was
//! twice made private by accident. An integration test catches the regression
//! at build time rather than in review.

use mecmcp_transport::{HostOriginPolicy, LimitsConfig, build_rmcp_server_config};
use tokio_util::sync::CancellationToken;

#[test]
fn build_rmcp_server_config_is_public() {
    // The migration note from config::streamable_http_server_config points here.
    // If this import fails, the migration path is broken.
    let policy = HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new());
    let limits = LimitsConfig::default();
    let shutdown = CancellationToken::new();

    let _config = build_rmcp_server_config(&policy, &limits, shutdown);
}
