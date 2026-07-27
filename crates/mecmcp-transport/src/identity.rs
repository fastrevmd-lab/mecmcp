//! Vendor-owned identity parameters for the transport layer.

/// Consumer-owned choices for the transport layer.
///
/// This parameter object carries every vendor-specific string — metric names,
/// server labels, bearer realms, and target argument keys — so the shared
/// transport crate never bakes in a consumer's public API surface.
#[derive(Debug, Clone)]
pub struct TransportIdentity {
    /// Prometheus metric name prefix (e.g. `"junosmcp"`, `"panosmcp"`).
    ///
    /// All four metrics — active sessions, limit hits, tool duration, sessions
    /// reaped — derive from this prefix. **There is no default.** A default is
    /// how the wrong name ships.
    pub metric_prefix: String,

    /// Server label value for the global `server` Prometheus label.
    ///
    /// Typically a short server identifier like `"junos"` or `"panos"`.
    pub server_label: String,

    /// Bearer authentication realm string for `WWW-Authenticate` challenges.
    ///
    /// Example: `"rust-panosmcp"`, `"rust-junosmcp"`.
    pub bearer_realm: String,

    /// Argument keys used to extract target device names from MCP request bodies.
    ///
    /// Junos uses `["device", "device_name", "devices", "device_names"]` (canonical)
    /// or deprecated `["router", "router_name", "routers", "router_names"]`;
    /// PAN-OS uses `["device", "devices"]`.
    pub target_keys: Vec<String>,
}

impl TransportIdentity {
    /// Create a new transport identity with the given parameters.
    pub fn new(
        metric_prefix: impl Into<String>,
        server_label: impl Into<String>,
        bearer_realm: impl Into<String>,
        target_keys: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            metric_prefix: metric_prefix.into(),
            server_label: server_label.into(),
            bearer_realm: bearer_realm.into(),
            target_keys: target_keys.into_iter().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn junos_identity_example() {
        let identity = TransportIdentity::new(
            "junosmcp",
            "junos",
            "rust-junosmcp",
            ["device", "device_name", "devices", "device_names"],
        );
        assert_eq!(identity.metric_prefix, "junosmcp");
        assert_eq!(identity.server_label, "junos");
        assert_eq!(identity.bearer_realm, "rust-junosmcp");
        assert_eq!(
            identity.target_keys,
            vec!["device", "device_name", "devices", "device_names"]
        );
    }

    #[test]
    fn panos_identity_example() {
        let identity =
            TransportIdentity::new("panosmcp", "panos", "rust-panosmcp", ["device", "devices"]);
        assert_eq!(identity.metric_prefix, "panosmcp");
        assert_eq!(identity.server_label, "panos");
        assert_eq!(identity.bearer_realm, "rust-panosmcp");
        assert_eq!(identity.target_keys, vec!["device", "devices"]);
    }
}
