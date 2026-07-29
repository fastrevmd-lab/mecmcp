//! Streamable HTTP rmcp router and listener composition.

use crate::{
    BearerBoundary, ConcurrencyState, LimitedSessionManager, LimitsConfig, LimitsConfigError,
    PrometheusRuntime, TransportIdentity, apply_bearer_boundary, apply_body_limit,
    apply_rate_limit, concurrency_middleware,
};
use axum::{Extension, Router};
use mecmcp_auth::Grant;
use rmcp::{
    RoleServer,
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService, session::local::LocalSessionManager,
    },
};
use std::{net::SocketAddr, sync::Arc};

/// Host and browser-Origin validation policy for the rmcp endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostOriginPolicy {
    /// Keep rmcp's loopback Host defaults and extend them with exact values.
    Enforced {
        /// Additional accepted Host authorities.
        allowed_hosts: Vec<String>,
        /// Exact accepted browser origins.
        allowed_origins: Vec<String>,
    },
    /// Disable Host validation explicitly.
    Disabled {
        /// Exact accepted browser origins; empty leaves Origin validation off.
        allowed_origins: Vec<String>,
    },
}

impl HostOriginPolicy {
    /// Enforce rmcp's loopback defaults plus consumer-owned additions.
    #[must_use]
    pub fn enforced(
        allowed_hosts: impl IntoIterator<Item = impl Into<String>>,
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::Enforced {
            allowed_hosts: allowed_hosts.into_iter().map(Into::into).collect(),
            allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
        }
    }

    /// Disable Host validation and leave Origin validation disabled.
    #[must_use]
    pub fn disabled() -> Self {
        Self::Disabled {
            allowed_origins: Vec::new(),
        }
    }

    /// Disable Host validation while retaining an explicit Origin allowlist.
    #[must_use]
    pub fn disabled_with_origins(
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self::Disabled {
            allowed_origins: allowed_origins.into_iter().map(Into::into).collect(),
        }
    }
}

/// Build the underlying rmcp Host/Origin configuration.
#[must_use]
pub fn streamable_http_server_config(policy: &HostOriginPolicy) -> StreamableHttpServerConfig {
    let mut config = StreamableHttpServerConfig::default();
    match policy {
        HostOriginPolicy::Enforced {
            allowed_hosts,
            allowed_origins,
        } => {
            config.allowed_hosts.extend(allowed_hosts.iter().cloned());
            if !allowed_origins.is_empty() {
                config = config.with_allowed_origins(allowed_origins.iter().cloned());
            }
        }
        HostOriginPolicy::Disabled { allowed_origins } => {
            tracing::warn!("streamable-http Host allowlist disabled; accepting any Host header");
            config = config.disable_allowed_hosts();
            if !allowed_origins.is_empty() {
                config = config.with_allowed_origins(allowed_origins.iter().cloned());
            }
        }
    }
    config
}

/// Construct exact loopback browser origins for one listener.
#[must_use]
pub fn loopback_origins(
    port: u16,
    tls: bool,
    additional: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    let scheme = if tls { "https" } else { "http" };
    let mut origins = vec![
        format!("{scheme}://localhost:{port}"),
        format!("{scheme}://127.0.0.1:{port}"),
        format!("{scheme}://[::1]:{port}"),
    ];
    origins.extend(additional.into_iter().map(Into::into));
    origins.sort();
    origins.dedup();
    origins
}

/// Complete shared HTTP composition settings.
pub struct HttpTransportConfig<G: Grant> {
    identity: TransportIdentity,
    limits: LimitsConfig,
    host_origin: HostOriginPolicy,
    bearer: Option<BearerBoundary<G>>,
    enable_metrics: bool,
}

impl<G: Grant> HttpTransportConfig<G> {
    /// Construct unauthenticated transport settings.
    ///
    /// Off-loopback no-auth policy is a runtime CLI decision; callers must
    /// validate it before building the router.
    #[must_use]
    pub fn new(
        identity: TransportIdentity,
        limits: LimitsConfig,
        host_origin: HostOriginPolicy,
    ) -> Self {
        Self {
            identity,
            limits,
            host_origin,
            bearer: None,
            enable_metrics: false,
        }
    }

    /// Enable bearer authentication.
    #[must_use]
    pub fn with_bearer(mut self, bearer: BearerBoundary<G>) -> Self {
        self.bearer = Some(bearer);
        self
    }

    /// Enable the unauthenticated `/metrics` endpoint.
    #[must_use]
    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.enable_metrics = enabled;
        self
    }
}

/// Router construction failure.
#[derive(Debug, thiserror::Error)]
pub enum HttpTransportBuildError {
    /// Resource limits are internally inconsistent.
    #[error("invalid HTTP resource limits: {0}")]
    Limits(#[from] LimitsConfigError),
    /// Prometheus recorder installation failed.
    #[error("Prometheus metrics initialization failed: {0}")]
    Metrics(String),
}

/// Build the fully protected `/mcp` router.
///
/// Middleware request order is body limit, bearer/preflight, rate limiting,
/// concurrency/session limits, then rmcp dispatch.
pub fn build_streamable_http_router<S, G>(
    service_factory: impl Fn() -> Result<S, std::io::Error> + Send + Sync + 'static,
    config: HttpTransportConfig<G>,
) -> Result<Router, HttpTransportBuildError>
where
    S: rmcp::Service<RoleServer> + Send + 'static,
    G: Grant,
{
    config.limits.validate()?;
    config.limits.log_effective();

    let metrics_runtime = if config.enable_metrics {
        Some(Arc::new(
            PrometheusRuntime::install(
                &config.identity.metric_prefix,
                &config.identity.server_label,
            )
            .map_err(|error| HttpTransportBuildError::Metrics(error.to_string()))?,
        ))
    } else {
        None
    };

    let session_manager =
        LimitedSessionManager::new(LocalSessionManager::default(), &config.limits);
    let concurrency = ConcurrencyState::new(
        &config.limits,
        config.identity.target_keys.clone(),
        Some(session_manager.tracker()),
    );
    let service = StreamableHttpService::new(
        service_factory,
        session_manager,
        streamable_http_server_config(&config.host_origin),
    );
    let mut router =
        Router::new()
            .nest_service("/mcp", service)
            .layer(axum::middleware::from_fn_with_state(
                concurrency,
                concurrency_middleware,
            ));
    router = apply_rate_limit(router, &config.limits);
    if let Some(bearer) = config.bearer {
        router = apply_bearer_boundary(router, bearer);
    }
    router = apply_body_limit(router, &config.limits);
    if let Some(runtime) = metrics_runtime {
        router = router.merge(runtime.router()).layer(Extension(runtime));
    }
    Ok(router)
}

/// Listener setup or runtime failure.
#[derive(Debug, thiserror::Error)]
pub enum HttpServeError {
    /// Binding the TCP listener failed.
    #[error("failed to bind {address}: {error}")]
    Bind {
        /// Requested address.
        address: SocketAddr,
        /// Underlying socket error.
        #[source]
        error: std::io::Error,
    },
    /// The HTTP server exited with an error.
    #[error("Streamable HTTP server failed: {0}")]
    Serve(#[from] std::io::Error),
}

/// Serve a composed router over plain HTTP or a supplied rustls configuration.
pub async fn serve_router(
    router: Router,
    address: SocketAddr,
    tls: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), HttpServeError> {
    if let Some(config) = tls {
        tracing::info!(%address, "Streamable HTTP listening with TLS");
        let config = axum_server::tls_rustls::RustlsConfig::from_config(config);
        axum_server::bind_rustls(address, config)
            .serve(router.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
        return Ok(());
    }

    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|error| HttpServeError::Bind { address, error })?;
    tracing::info!(%address, "Streamable HTTP listening");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
