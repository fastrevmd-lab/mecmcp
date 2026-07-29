//! Shared rmcp router-composition contracts.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use mecmcp_auth::{BearerSyntax, CallerCtx, NoGrant, ScopeSet};
use mecmcp_transport::{
    BearerAuthenticator, BearerBoundary, BearerResponseProfile, HostOriginPolicy,
    HttpTransportConfig, LimitsConfig, TransportIdentity, build_streamable_http_router,
    loopback_origins, streamable_http_server_config,
};
use rmcp::{
    ServerHandler,
    model::{Implementation, ServerCapabilities, ServerInfo},
};
use tower::ServiceExt as _;

#[derive(Debug, Clone, Default)]
struct EmptyServer;

impl ServerHandler for EmptyServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("empty", "1"))
    }
}

fn caller() -> CallerCtx {
    CallerCtx {
        token_name: "test".to_owned(),
        devices: ScopeSet::Wildcard,
        tools: ScopeSet::Wildcard,
        grant: None,
        provider: None,
        provider_tier: None,
        on_behalf_of: None,
        actor_type: mecmcp_auth::ActorType::Human,
    }
}

#[test]
fn host_origin_policy_preserves_defaults_extensions_and_explicit_disable() {
    let policy = HostOriginPolicy::enforced(["mcp.example.test"], ["https://client.example.test"]);
    let config = streamable_http_server_config(&policy);
    assert!(config.allowed_hosts.contains(&"localhost".to_owned()));
    assert!(
        config
            .allowed_hosts
            .contains(&"mcp.example.test".to_owned())
    );
    assert_eq!(
        config.allowed_origins,
        vec!["https://client.example.test".to_owned()]
    );

    let disabled = streamable_http_server_config(&HostOriginPolicy::disabled());
    assert!(disabled.allowed_hosts.is_empty());
}

#[test]
fn loopback_origins_are_deterministic_and_include_consumer_additions() {
    assert_eq!(
        loopback_origins(9443, true, ["https://client.example.test"]),
        vec![
            "https://127.0.0.1:9443",
            "https://[::1]:9443",
            "https://client.example.test",
            "https://localhost:9443",
        ]
    );
}

#[tokio::test]
async fn composed_router_applies_the_shared_bearer_boundary() {
    let auth = BearerAuthenticator::<NoGrant>::new(BearerSyntax::Strict, |candidate| {
        (candidate == "secret").then(caller)
    });
    let config = HttpTransportConfig::new(
        TransportIdentity::new("testmcp", "test", "test", ["target"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
    )
    .with_bearer(BearerBoundary::new(
        auth,
        BearerResponseProfile::compact("test"),
        1024,
    ));

    let router = build_streamable_http_router(|| Ok::<_, std::io::Error>(EmptyServer), config)
        .expect("router");
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .body(Body::from("{}"))
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
