//! Vendor-neutral streamable-HTTP hardening layer for mechub MCP servers.
//!
//! This crate provides host/Origin validation, bearer middleware, rate limits,
//! concurrency and session caps, overload responses, metrics, and TLS loading.
//! Every consumer-owned choice — metric names, target argument keys, realm,
//! server label — is passed as a parameter rather than baked in.

mod auth;
mod caller;
mod client_info;
mod concurrency;
mod config;
mod identity;
mod metrics;
mod overload;
pub mod preflight;
mod rate_limit;
mod server;
mod session;
mod target;
pub mod test_client;
pub mod tls;

pub use auth::{
    BearerAuthError, BearerAuthenticator, BearerBoundary, BearerResponseProfile,
    BearerResponseStyle, BoundaryAccounting, apply_bearer_boundary,
};
pub use client_info::ClientInfo;

// Internal types and functions exported only for testing
#[doc(hidden)]
pub mod tests {
    pub use crate::auth::{
        AuthState, PreflightState, bearer_auth_middleware, bearer_preflight_middleware,
    };
}
pub use caller::AuthenticatedToken;
#[allow(deprecated)]
pub use concurrency::{
    ConcurrencyState, apply_body_limit, concurrency_middleware, target_concurrency_middleware,
    token_concurrency_middleware,
};
#[allow(deprecated)]
pub use config::{LimitsConfig, LimitsConfigError, streamable_http_server_config};
pub use identity::TransportIdentity;
pub use metrics::PrometheusRuntime;
pub use overload::overload_response;
pub use preflight::{
    CallerScopes, MalformedArgumentsPolicy, MalformedTargetPolicy, OptionalPreflight,
    ScopePreflight, TargetField, TargetValueShape, ToolScopePreflight,
};
#[allow(deprecated)]
pub use rate_limit::{apply_ip_rate_limit, apply_rate_limit, apply_token_rate_limit};
pub use server::{
    HostOriginPolicy, HttpServeError, HttpShutdown, HttpTransportBuildError, HttpTransportConfig,
    build_streamable_http_router, loopback_origins, serve_router,
    streamable_http_server_config as build_rmcp_server_config,
};
pub use session::{LimitedSessionManager, LimitedSessionManagerError, SessionTracker};
pub use target::{TargetLimiter, extract_targets};
pub use tls::{TlsError, load as load_tls};
