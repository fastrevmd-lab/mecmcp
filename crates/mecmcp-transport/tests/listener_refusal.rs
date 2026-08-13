//! `serve_router` refuses an inadmissible listener, and refuses it *before*
//! binding (mecmcp#273).
//!
//! The ordering matters as much as the refusal. These tests use 192.0.2.1
//! (TEST-NET-1, RFC 5737), an address the host cannot bind: if the check ran
//! after the bind, the error would be `HttpServeError::Bind`. Asserting
//! `Refused` therefore proves the check runs first, without needing to inspect
//! socket state.

use mecmcp_auth::{BearerSyntax, NoGrant};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpServeError, HttpTransportConfig, LimitsConfig, ListenerRefusal, NoAuthAcknowledgement,
    TransportIdentity, build_streamable_http_router, serve_router,
};
use rmcp::ServerHandler;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
struct TestServer;

impl ServerHandler for TestServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("test-server", "0.1"))
    }
}

fn unbindable() -> SocketAddr {
    "192.0.2.1:30031".parse().expect("address")
}

fn boundary() -> BearerBoundary<NoGrant> {
    let authenticator = BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |_| None);
    BearerBoundary::new(authenticator, BearerResponseProfile::detailed("test"))
}

fn identity() -> TransportIdentity {
    TransportIdentity::new("testmcp", "test", "test", ["device"])
}

async fn serve_with(config: HttpTransportConfig<NoGrant>, address: SocketAddr) -> HttpServeError {
    let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(TestServer), config)
        .expect("router build failed");
    serve_router(plan, address, None, Duration::from_secs(1))
        .await
        .expect_err("this listener must be refused")
}

#[tokio::test]
async fn unauthenticated_off_loopback_is_refused_before_binding() {
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(["host"], ["https://origin"]),
        CancellationToken::new(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );

    match serve_with(config, unbindable()).await {
        HttpServeError::Refused(ListenerRefusal::UnauthenticatedOffLoopback { address }) => {
            assert_eq!(address, unbindable());
        }
        other => panic!("expected a refusal before the bind, got {other:?}"),
    }
}

#[tokio::test]
async fn plaintext_off_loopback_is_refused_before_binding() {
    let config = HttpTransportConfig::authenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(["host"], ["https://origin"]),
        CancellationToken::new(),
        boundary(),
    );

    match serve_with(config, unbindable()).await {
        HttpServeError::Refused(ListenerRefusal::InsecureBindNotAcknowledged { address }) => {
            assert_eq!(address, unbindable());
        }
        other => panic!("expected a refusal before the bind, got {other:?}"),
    }
}

#[tokio::test]
async fn missing_allowlists_are_refused_before_binding() {
    use mecmcp_transport::InsecureBindAcknowledgement;

    let config = HttpTransportConfig::authenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        CancellationToken::new(),
        boundary(),
    )
    .with_insecure_bind(InsecureBindAcknowledgement::operator_allowed_insecure_bind());

    match serve_with(config, unbindable()).await {
        HttpServeError::Refused(ListenerRefusal::AllowedHostRequired { .. }) => {}
        other => panic!("expected AllowedHostRequired, got {other:?}"),
    }
}

/// The loopback carve-out must survive, or every local deployment breaks.
///
/// Serves for real on an ephemeral loopback port with no auth, no TLS and no
/// allowlists, then shuts down. Reaching the shutdown proves the listener was
/// admitted and bound.
#[tokio::test]
async fn loopback_serves_without_auth_tls_or_allowlists() {
    let shutdown = CancellationToken::new();
    let config = HttpTransportConfig::<NoGrant>::unauthenticated(
        identity(),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        shutdown.clone(),
        NoAuthAcknowledgement::operator_allowed_no_auth(),
    );
    let plan = build_streamable_http_router(|| Ok::<_, std::io::Error>(TestServer), config)
        .expect("router build failed");

    let serving = tokio::spawn(serve_router(
        plan,
        "127.0.0.1:0".parse().expect("address"),
        None,
        Duration::from_millis(50),
    ));

    tokio::time::sleep(Duration::from_millis(200)).await;
    shutdown.cancel();

    serving
        .await
        .expect("serve task panicked")
        .expect("loopback listener must be admitted and serve");
}
