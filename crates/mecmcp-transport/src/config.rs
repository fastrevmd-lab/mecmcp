//! Tunable resource limits for the streamable-HTTP endpoints.

use std::fmt;
use std::time::Duration;

/// Error type for limits configuration validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsConfigError {
    /// Rate and burst must both be zero (disabled) or both positive (enabled).
    IncompleteTokenRateLimit {
        /// Configured rate value.
        rate: u64,
        /// Configured burst value.
        burst: u64,
    },
    /// Per-IP rate and burst must both be zero (disabled) or both positive (enabled).
    IncompleteIpRateLimit {
        /// Configured rate value.
        rate: u64,
        /// Configured burst value.
        burst: u64,
    },
}

impl fmt::Display for LimitsConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteTokenRateLimit { rate, burst } => write!(
                f,
                "per-token request rate and burst must both be zero (disabled) or both be positive (rate={rate}, burst={burst})"
            ),
            Self::IncompleteIpRateLimit { rate, burst } => write!(
                f,
                "per-IP request rate and burst must both be zero (disabled) or both be positive (rate={rate}, burst={burst})"
            ),
        }
    }
}

impl std::error::Error for LimitsConfigError {}

/// All HTTP resource / session limits. Every numeric field uses `0` as an
/// "unlimited / disabled" escape hatch.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct LimitsConfig {
    /// Max request body size in bytes before rejecting with 413. `0` disables.
    pub max_request_body_bytes: usize,
    /// Max concurrent in-flight requests across all callers. `0` disables.
    pub max_inflight_requests: usize,
    /// Max concurrent in-flight requests per bearer token. `0` disables.
    pub max_inflight_requests_per_token: usize,
    /// Max requests per second per source IP address. `0` disables with burst `0`.
    pub max_requests_per_second_per_ip: u64,
    /// Max immediate request burst per source IP address. `0` disables with rate `0`.
    pub max_request_burst_per_ip: u64,
    /// Max requests per second per bearer token. `0` disables with burst `0`.
    pub max_requests_per_second_per_token: u64,
    /// Max immediate request burst per bearer token. `0` disables with rate `0`.
    pub max_request_burst_per_token: u64,
    /// Max concurrent in-flight requests per target device. `0` disables.
    ///
    /// The canonical field name is `max_inflight_requests_per_device` —
    /// "device" is the vendor-neutral term. `max_inflight_requests_per_router`
    /// and `max_inflight_requests_per_target` are accepted as aliases for
    /// backward compatibility with deployed configurations.
    #[serde(
        alias = "max_inflight_requests_per_router",
        alias = "max_inflight_requests_per_target"
    )]
    pub max_inflight_requests_per_device: usize,
    /// Max concurrent MCP sessions. `0` disables.
    pub max_sessions: usize,
    /// Max concurrent MCP sessions per bearer token. `0` disables.
    pub max_sessions_per_token: usize,
    /// Idle timeout (seconds) after which a session is reaped. `0` disables.
    pub session_idle_timeout_secs: u64,
    /// Max session lifetime (seconds) after which it is reaped. `0` disables.
    pub session_max_lifetime_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: 10 * 1024 * 1024,
            max_inflight_requests: 64,
            max_inflight_requests_per_token: 16,
            max_requests_per_second_per_ip: 0,
            max_request_burst_per_ip: 0,
            max_requests_per_second_per_token: 0,
            max_request_burst_per_token: 0,
            max_inflight_requests_per_device: 4,
            max_sessions: 128,
            max_sessions_per_token: 16,
            session_idle_timeout_secs: 300,
            session_max_lifetime_secs: 3600,
        }
    }
}

impl LimitsConfig {
    /// Deprecated accessor for backward compatibility. Use `max_inflight_requests_per_device` instead.
    #[deprecated(
        since = "0.2.0",
        note = "renamed to max_inflight_requests_per_device; access the field directly or use the new name"
    )]
    pub fn max_inflight_requests_per_router(&self) -> usize {
        self.max_inflight_requests_per_device
    }

    /// Validate that configuration values are internally consistent.
    pub fn validate(&self) -> Result<(), LimitsConfigError> {
        let token_rate = self.max_requests_per_second_per_token;
        let token_burst = self.max_request_burst_per_token;
        if (token_rate == 0) != (token_burst == 0) {
            return Err(LimitsConfigError::IncompleteTokenRateLimit {
                rate: token_rate,
                burst: token_burst,
            });
        }

        let ip_rate = self.max_requests_per_second_per_ip;
        let ip_burst = self.max_request_burst_per_ip;
        if (ip_rate == 0) != (ip_burst == 0) {
            return Err(LimitsConfigError::IncompleteIpRateLimit {
                rate: ip_rate,
                burst: ip_burst,
            });
        }
        Ok(())
    }

    /// Returns `true` if per-IP rate limiting is enabled.
    pub fn ip_rate_limit_enabled(&self) -> bool {
        self.max_requests_per_second_per_ip > 0 && self.max_request_burst_per_ip > 0
    }

    /// Returns `true` if per-token rate limiting is enabled.
    pub fn token_rate_limit_enabled(&self) -> bool {
        self.max_requests_per_second_per_token > 0 && self.max_request_burst_per_token > 0
    }

    /// Idle timeout as a `Duration`, or `None` when disabled (`0`).
    pub fn idle_timeout(&self) -> Option<Duration> {
        (self.session_idle_timeout_secs > 0)
            .then(|| Duration::from_secs(self.session_idle_timeout_secs))
    }

    /// Max lifetime as a `Duration`, or `None` when disabled (`0`).
    pub fn max_lifetime(&self) -> Option<Duration> {
        (self.session_max_lifetime_secs > 0)
            .then(|| Duration::from_secs(self.session_max_lifetime_secs))
    }

    /// Emit the effective configuration at startup.
    pub fn log_effective(&self) {
        tracing::info!(
            max_request_body_bytes = self.max_request_body_bytes,
            max_inflight_requests = self.max_inflight_requests,
            max_inflight_requests_per_token = self.max_inflight_requests_per_token,
            max_requests_per_second_per_ip = self.max_requests_per_second_per_ip,
            max_request_burst_per_ip = self.max_request_burst_per_ip,
            max_requests_per_second_per_token = self.max_requests_per_second_per_token,
            max_request_burst_per_token = self.max_request_burst_per_token,
            max_inflight_requests_per_device = self.max_inflight_requests_per_device,
            max_sessions = self.max_sessions,
            max_sessions_per_token = self.max_sessions_per_token,
            session_idle_timeout_secs = self.session_idle_timeout_secs,
            session_max_lifetime_secs = self.session_max_lifetime_secs,
            "http resource limits configured"
        );
    }
}

/// Build rmcp's `StreamableHttpServerConfig` from this crate's [`LimitsConfig`].
///
/// # Deprecated
///
/// This function is deprecated in favor of the three-parameter
/// `mecmcp_transport::build_rmcp_server_config` which also configures
/// Host/Origin policy and shutdown token. It is kept for internal tests that
/// verify the body-size mapping in isolation.
///
/// Use this rather than `StreamableHttpServerConfig::default()`. rmcp 3 added
/// its own `max_request_body_bytes`, defaulting to **4 MiB**, enforced *inside*
/// rmcp after this crate's `apply_body_limit` layer has already accepted the
/// request. A consumer whose `LimitsConfig` allows more than 4 MiB — the default
/// here is 10 MiB — would find requests between the two silently rejected with
/// 413 by a limit it never configured and cannot see.
///
/// `max_request_body_bytes: 0` means unlimited in [`LimitsConfig`], which rmcp
/// has no spelling for, so it maps to `usize::MAX`.
///
/// `legacy_session_mode` is left at rmcp's default (`true`): the `initialize`
/// handshake and `Mcp-Session-Id` stay available for pre-2026-07-28 clients,
/// while clients declaring `2026-07-28` are routed statelessly per request.
/// Both are served simultaneously; this is not a cutover.
#[deprecated(
    since = "0.7.0",
    note = "Use mecmcp_transport::build_rmcp_server_config instead"
)]
pub fn streamable_http_server_config(
    cfg: &LimitsConfig,
) -> rmcp::transport::streamable_http_server::StreamableHttpServerConfig {
    let mut server = rmcp::transport::streamable_http_server::StreamableHttpServerConfig::default();
    server.max_request_body_bytes = if cfg.max_request_body_bytes == 0 {
        usize::MAX
    } else {
        cfg.max_request_body_bytes
    };
    server
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_generous_and_enabled() {
        let c = LimitsConfig::default();
        assert_eq!(c.max_request_body_bytes, 10 * 1024 * 1024);
        assert_eq!(c.max_inflight_requests, 64);
        assert_eq!(c.max_inflight_requests_per_token, 16);
        assert_eq!(c.max_inflight_requests_per_device, 4);
        assert_eq!(c.max_sessions, 128);
        assert_eq!(c.max_sessions_per_token, 16);
        assert_eq!(c.idle_timeout(), Some(Duration::from_secs(300)));
        assert_eq!(c.max_lifetime(), Some(Duration::from_secs(3600)));
    }

    #[test]
    fn zero_disables_timeouts() {
        let c = LimitsConfig {
            session_idle_timeout_secs: 0,
            session_max_lifetime_secs: 0,
            ..Default::default()
        };
        assert_eq!(c.idle_timeout(), None);
        assert_eq!(c.max_lifetime(), None);
    }

    #[test]
    fn rate_limits_default_disabled_and_valid() {
        let config = LimitsConfig::default();
        assert_eq!(config.max_requests_per_second_per_ip, 0);
        assert_eq!(config.max_request_burst_per_ip, 0);
        assert_eq!(config.max_requests_per_second_per_token, 0);
        assert_eq!(config.max_request_burst_per_token, 0);
        assert!(!config.ip_rate_limit_enabled());
        assert!(!config.token_rate_limit_enabled());
        assert_eq!(config.validate(), Ok(()));
    }

    #[test]
    fn token_rate_requires_rate_and_burst_together() {
        for (rate, burst) in [(5, 0), (0, 8)] {
            let config = LimitsConfig {
                max_requests_per_second_per_token: rate,
                max_request_burst_per_token: burst,
                ..Default::default()
            };
            assert_eq!(
                config.validate(),
                Err(LimitsConfigError::IncompleteTokenRateLimit { rate, burst })
            );
            assert!(!config.token_rate_limit_enabled());
        }

        let enabled = LimitsConfig {
            max_requests_per_second_per_token: 5,
            max_request_burst_per_token: 8,
            ..Default::default()
        };
        assert_eq!(enabled.validate(), Ok(()));
        assert!(enabled.token_rate_limit_enabled());
    }

    #[test]
    fn ip_rate_requires_rate_and_burst_together() {
        for (rate, burst) in [(5, 0), (0, 8)] {
            let config = LimitsConfig {
                max_requests_per_second_per_ip: rate,
                max_request_burst_per_ip: burst,
                ..Default::default()
            };
            assert_eq!(
                config.validate(),
                Err(LimitsConfigError::IncompleteIpRateLimit { rate, burst })
            );
            assert!(!config.ip_rate_limit_enabled());
        }

        let enabled = LimitsConfig {
            max_requests_per_second_per_ip: 5,
            max_request_burst_per_ip: 8,
            ..Default::default()
        };
        assert_eq!(enabled.validate(), Ok(()));
        assert!(enabled.ip_rate_limit_enabled());
    }

    #[test]
    fn legacy_router_alias_deserializes_to_device_field() {
        // Backward compatibility: deployed config files use max_inflight_requests_per_router
        let json = r#"{
            "max_request_body_bytes": 1000,
            "max_inflight_requests": 10,
            "max_inflight_requests_per_token": 5,
            "max_requests_per_second_per_ip": 0,
            "max_request_burst_per_ip": 0,
            "max_requests_per_second_per_token": 0,
            "max_request_burst_per_token": 0,
            "max_inflight_requests_per_router": 3,
            "max_sessions": 50,
            "max_sessions_per_token": 10,
            "session_idle_timeout_secs": 300,
            "session_max_lifetime_secs": 3600
        }"#;
        let config: LimitsConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.max_inflight_requests_per_device, 3);
    }

    #[test]
    fn legacy_target_alias_deserializes_to_device_field() {
        // Backward compatibility: some configs may use max_inflight_requests_per_target
        let json = r#"{
            "max_request_body_bytes": 1000,
            "max_inflight_requests": 10,
            "max_inflight_requests_per_token": 5,
            "max_requests_per_second_per_ip": 0,
            "max_request_burst_per_ip": 0,
            "max_requests_per_second_per_token": 0,
            "max_request_burst_per_token": 0,
            "max_inflight_requests_per_target": 7,
            "max_sessions": 50,
            "max_sessions_per_token": 10,
            "session_idle_timeout_secs": 300,
            "session_max_lifetime_secs": 3600
        }"#;
        let config: LimitsConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.max_inflight_requests_per_device, 7);
    }

    #[test]
    fn canonical_device_name_deserializes() {
        let json = r#"{
            "max_request_body_bytes": 1000,
            "max_inflight_requests": 10,
            "max_inflight_requests_per_token": 5,
            "max_requests_per_second_per_ip": 0,
            "max_request_burst_per_ip": 0,
            "max_requests_per_second_per_token": 0,
            "max_request_burst_per_token": 0,
            "max_inflight_requests_per_device": 4,
            "max_sessions": 50,
            "max_sessions_per_token": 10,
            "session_idle_timeout_secs": 300,
            "session_max_lifetime_secs": 3600
        }"#;
        let config: LimitsConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(config.max_inflight_requests_per_device, 4);
    }
}
