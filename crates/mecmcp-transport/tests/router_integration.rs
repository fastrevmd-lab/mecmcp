//! Integration tests for `build_streamable_http_router`.
//!
//! Drives the router builder end-to-end to verify features that shipped inert
//! because they were wired in middleware but never called by the assembly.
//! Regression guard for mecmcp#53 and the test gap described in mecmcp#251.

use mecmcp_auth::NoGrant;
use mecmcp_transport::{
    HostOriginPolicy, HttpTransportConfig, LimitsConfig, NoAuthAcknowledgement,
    TransportIdentity, build_streamable_http_router, serve_router,
    test_client::McpClient,
};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use tokio_util::sync::CancellationToken;

/// Minimal test server that implements ServerHandler.
#[derive(Clone)]
struct TestServer;

impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("test-server", "0.1"))
    }
}

/// The assembly mounts the session manager, not just the middleware.
///
/// This test drives `build_streamable_http_router` and verifies the returned router
/// can complete an `initialize` handshake, proving the session manager is wired
/// through the assembly (not just the middleware unit tests).
///
/// Regression guard for mecmcp#53: the feature (session tracking) shipped inert
/// because the middleware was correct but `build_streamable_http_router` never
/// wired the session tracker. This test would have caught it.
#[tokio::test]
async fn router_assembly_mounts_session_management() {
    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        TransportIdentity::new("testmcp", "test", "test", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );

    let plan =
        build_streamable_http_router(|| Ok::<_, std::io::Error>(TestServer), config)
            .expect("router build failed");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let port = listener.local_addr().expect("no local addr").port();
    drop(listener);

    let serving = tokio::spawn(serve_router(
        plan,
        format!("127.0.0.1:{port}").parse().expect("address"),
        None,
        std::time::Duration::from_millis(50),
    ));

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Run blocking HTTP client in spawn_blocking
    let session_id = tokio::task::spawn_blocking(move || {
        let client =
            McpClient::new(format!("http://127.0.0.1:{port}")).expect("client creation failed");
        client
            .initialize()
            .expect("initialize failed — session manager not mounted")
    })
    .await
    .expect("blocking task failed");

    assert!(!session_id.is_empty(), "session ID should not be empty");

    shutdown.cancel();
    serving.await.expect("serving task failed").expect("serve_router failed");
}

/// Unauthenticated routers serve requests without bearer middleware.
///
/// Verifies that `build_streamable_http_router` builds a working router even
/// when no bearer boundary is configured.
#[tokio::test]
async fn unauthenticated_router_serves_requests() {
    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        TransportIdentity::new("testmcp", "test", "test", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );

    let plan =
        build_streamable_http_router(|| Ok::<_, std::io::Error>(TestServer), config)
            .expect("router build failed");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind failed");
    let port = listener.local_addr().expect("no local addr").port();
    drop(listener);

    let serving = tokio::spawn(serve_router(
        plan,
        format!("127.0.0.1:{port}").parse().expect("address"),
        None,
        std::time::Duration::from_millis(50),
    ));

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let session_id = tokio::task::spawn_blocking(move || {
        let client =
            McpClient::new(format!("http://127.0.0.1:{port}")).expect("client creation failed");
        client
            .initialize()
            .expect("unauthenticated initialize failed")
    })
    .await
    .expect("blocking task failed");

    assert!(
        !session_id.is_empty(),
        "unauthenticated session ID should not be empty"
    );

    shutdown.cancel();
    serving.await.expect("serving task failed").expect("serve_router failed");
}
