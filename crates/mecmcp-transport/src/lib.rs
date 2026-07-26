//! Vendor-neutral streamable-HTTP hardening layer for mechub MCP servers.
//!
//! This crate provides host/Origin validation, bearer middleware, rate limits,
//! concurrency and session caps, overload responses, metrics, and TLS loading.
//! Every consumer-owned choice — metric names, target argument keys, realm,
//! server label — is passed as a parameter rather than baked in.

mod concurrency;
mod config;
mod identity;
mod metrics;
mod overload;
pub mod preflight;
mod rate_limit;
mod session;
mod target;
pub mod tls;

pub use concurrency::{ConcurrencyState, apply_body_limit, concurrency_middleware};
pub use config::{LimitsConfig, LimitsConfigError};
pub use identity::TransportIdentity;
pub use metrics::PrometheusRuntime;
pub use overload::overload_response;
pub use preflight::{OptionalPreflight, ScopePreflight};
pub use rate_limit::apply_rate_limit;
pub use session::{LimitedSessionManager, LimitedSessionManagerError, SessionTracker};
pub use target::{TargetLimiter, extract_targets};
pub use tls::{TlsError, load as load_tls};
