//! Client identity capture from MCP initialize.
//!
//! The `initialize` request carries `clientInfo` (name and version), which
//! identifies the MCP client program — not the model or the user. This module
//! bounds and interns those client-asserted strings so they can be stored
//! per-session and propagated to audit events without unbounded memory growth.

use dashmap::DashMap;
use std::sync::LazyLock;

/// Maximum distinct client names ever interned.
///
/// The name comes from the `initialize` request body, which is client-asserted
/// and untrusted. Without a cap, every novel name would leak a fresh allocation
/// and add unbounded cardinality to audit output.
const MAX_INTERNED_CLIENT_NAMES: usize = 64;

/// Maximum length for a client name or version string.
///
/// Longer strings are rejected and replaced with a placeholder. This prevents
/// memory exhaustion from clients sending arbitrarily large names.
const MAX_CLIENT_INFO_LEN: usize = 128;

/// Placeholder recorded when a client name is implausible or the intern table is full.
const UNKNOWN_CLIENT: &str = "unknown";

static INTERNED_CLIENT_NAMES: LazyLock<DashMap<&'static str, ()>> =
    LazyLock::new(|| DashMap::with_capacity(MAX_INTERNED_CLIENT_NAMES));

/// Client identity from the MCP `initialize` request.
///
/// This data is **client-asserted**. Nothing authenticates it. The client name
/// identifies the **client program** (e.g. "claude-code"), not the model or the
/// user. It must never be used for authorization decisions or scope checks.
///
/// Captured per-session and propagated to `AgentIdentity.client_name` for audit
/// attribution only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// Interned client name, bounded and validated.
    name: &'static str,
    /// Client version, bounded but not interned (high cardinality).
    version: Option<String>,
}

impl ClientInfo {
    /// Parse client info from an MCP `initialize` params object.
    ///
    /// Expects a JSON object with optional `clientInfo` field:
    /// ```json
    /// {
    ///   "protocolVersion": "2025-03-26",
    ///   "clientInfo": { "name": "claude-code", "version": "1.0" }
    /// }
    /// ```
    ///
    /// Missing or malformed `clientInfo` produces `None`. Names and versions are
    /// bounded and sanitized; implausible values become placeholders.
    ///
    /// # Trust boundary
    ///
    /// This is **client-asserted data**. Do not use it for authorization. It
    /// appears in audit events for attribution only, and must be labeled as
    /// untrusted when presented to an auditor.
    pub fn from_initialize_params(params: &serde_json::Value) -> Option<Self> {
        let client_info = params.get("clientInfo")?;
        let name = client_info.get("name")?.as_str()?;
        let version = client_info.get("version").and_then(|v| v.as_str());

        Some(Self {
            name: intern_client_name(name),
            version: version.and_then(bound_version),
        })
    }

    /// Return the interned client name.
    #[must_use]
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Return the client version, if present and plausible.
    #[must_use]
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }
}

/// Intern a client name into a bounded set, returning a `&'static str`.
///
/// Names longer than `MAX_CLIENT_INFO_LEN`, containing non-ASCII or control
/// characters, or arriving after the table is full are replaced with
/// `UNKNOWN_CLIENT`. This prevents unbounded memory growth and metrics
/// cardinality from attacker-controlled input.
fn intern_client_name(name: &str) -> &'static str {
    if name.is_empty() || name.len() > MAX_CLIENT_INFO_LEN {
        return UNKNOWN_CLIENT;
    }
    // Allow alphanumerics, hyphens, underscores, dots, and forward slashes
    // (covers "claude-code", "mcp-client/1.0", "my.client" patterns)
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'/')
    {
        return UNKNOWN_CLIENT;
    }

    // Fast path: already interned
    if let Some(entry) = INTERNED_CLIENT_NAMES.get(name) {
        return entry.key();
    }

    // Slow path: try to intern
    if INTERNED_CLIENT_NAMES.len() >= MAX_INTERNED_CLIENT_NAMES {
        return UNKNOWN_CLIENT;
    }

    let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
    INTERNED_CLIENT_NAMES.insert(leaked, ());
    leaked
}

/// Bound and validate a version string.
///
/// Versions are not interned (high cardinality), but are still length-bounded
/// and charset-restricted. Returns `None` for implausible values.
fn bound_version(version: &str) -> Option<String> {
    if version.is_empty() || version.len() > MAX_CLIENT_INFO_LEN {
        return None;
    }
    // Allow alphanumerics, dots, hyphens, and plus signs (covers semantic versioning)
    if !version
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'+')
    {
        return None;
    }
    Some(version.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_valid_client_info() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "claude-code", "version": "1.0.0" }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.name(), "claude-code");
        assert_eq!(info.version(), Some("1.0.0"));
    }

    #[test]
    fn parse_client_info_without_version() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "mcp-client" }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.name(), "mcp-client");
        assert_eq!(info.version(), None);
    }

    #[test]
    fn missing_client_info_returns_none() {
        let params = json!({"protocolVersion": "2025-03-26"});
        assert!(ClientInfo::from_initialize_params(&params).is_none());
    }

    #[test]
    fn malformed_client_info_returns_none() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": "not-an-object"
        });
        assert!(ClientInfo::from_initialize_params(&params).is_none());
    }

    #[test]
    fn oversized_client_name_becomes_unknown() {
        let long_name = "a".repeat(MAX_CLIENT_INFO_LEN + 1);
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": long_name }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        assert_eq!(info.name(), UNKNOWN_CLIENT);
    }

    #[test]
    fn oversized_version_is_dropped() {
        let long_version = "1.".to_owned() + &"0".repeat(MAX_CLIENT_INFO_LEN);
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test", "version": long_version }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        assert_eq!(info.name(), "test");
        assert_eq!(info.version(), None);
    }

    #[test]
    fn invalid_characters_in_name_become_unknown() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "bad<script>", "version": "1.0" }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        assert_eq!(info.name(), UNKNOWN_CLIENT);
    }

    #[test]
    fn invalid_characters_in_version_are_dropped() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test", "version": "1.0; drop table" }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        assert_eq!(info.name(), "test");
        assert_eq!(info.version(), None);
    }

    #[test]
    fn empty_name_becomes_unknown() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "" }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        assert_eq!(info.name(), UNKNOWN_CLIENT);
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn interning_is_stable() {
        let params1 = json!({"clientInfo": { "name": "client-a" }});
        let params2 = json!({"clientInfo": { "name": "client-a" }});
        let info1 = ClientInfo::from_initialize_params(&params1).unwrap();
        let info2 = ClientInfo::from_initialize_params(&params2).unwrap();
        assert!(std::ptr::eq(info1.name(), info2.name()));
    }

    #[test]
    fn intern_table_cap_enforced() {
        // Prefill the intern table to capacity
        for i in 0..MAX_INTERNED_CLIENT_NAMES {
            let name = format!("client-{i}");
            let _ = intern_client_name(&name);
        }

        // Next unique name should be rejected
        let params = json!({"clientInfo": { "name": "overflow-client" }});
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        assert_eq!(info.name(), UNKNOWN_CLIENT);
    }

    #[test]
    fn allowed_characters_in_name() {
        for name in [
            "claude-code",
            "mcp_client",
            "my.client",
            "client/1.0",
            "ABC-123_test.v2",
        ] {
            let params = json!({"clientInfo": { "name": name }});
            let info = ClientInfo::from_initialize_params(&params).expect("valid name");
            assert_eq!(info.name(), name);
        }
    }

    #[test]
    fn allowed_characters_in_version() {
        for version in ["1.0.0", "2.1.3-beta", "1.0+build.123", "0.0.1-rc.1+meta"] {
            let params = json!({"clientInfo": { "name": "test", "version": version }});
            let info = ClientInfo::from_initialize_params(&params).expect("valid version");
            assert_eq!(info.version(), Some(version));
        }
    }

    /// Prove that removing the length cap breaks: oversized names must be rejected.
    ///
    /// This test documents the safety contract. If you remove `MAX_CLIENT_INFO_LEN`,
    /// this MUST fail. The contract: client-asserted strings arriving from a
    /// request body must never leak unbounded allocations.
    #[test]
    fn removing_length_cap_would_leak_unbounded_allocations() {
        let oversized_name = "a".repeat(MAX_CLIENT_INFO_LEN + 1);
        let params = json!({"clientInfo": { "name": oversized_name }});
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        // If the length check were removed, this would leak a 129-byte string.
        // With the check, it becomes UNKNOWN_CLIENT (a static, no leak).
        assert_eq!(
            info.name(),
            UNKNOWN_CLIENT,
            "oversized client name must be rejected, not leaked"
        );
    }

    /// Prove that removing the interning cap breaks: the table must reject overflow.
    ///
    /// This test documents the safety contract. If you remove
    /// `MAX_INTERNED_CLIENT_NAMES`, this MUST fail. The contract: an
    /// authenticated caller with no tool scopes can still reach this code by
    /// sending initialize, so the attacker controls the name. Without a cap,
    /// they can exhaust memory and metrics cardinality.
    #[test]
    fn removing_interning_cap_would_leak_unbounded_table() {
        // Prefill to capacity
        for i in 0..MAX_INTERNED_CLIENT_NAMES {
            let params = json!({"clientInfo": { "name": format!("cap-test-{i}") }});
            let _ = ClientInfo::from_initialize_params(&params);
        }

        // One more distinct name must be rejected
        let params = json!({"clientInfo": { "name": "overflow" }});
        let info = ClientInfo::from_initialize_params(&params).expect("name present");
        assert_eq!(
            info.name(),
            UNKNOWN_CLIENT,
            "interning table overflow must be rejected, not leaked"
        );
    }

    /// Prove that removing the charset restriction breaks: injection must be rejected.
    ///
    /// This test documents the safety contract. If you allow arbitrary
    /// characters, malicious client names can inject into logs, metrics labels,
    /// or audit output. The charset must be bounded.
    #[test]
    fn removing_charset_restriction_would_allow_injection() {
        for bad in [
            "<script>",
            "'; DROP TABLE",
            "name\nwith\nnewlines",
            "\n\r\0",
            "spaces not allowed",
        ] {
            let params = json!({"clientInfo": { "name": bad }});
            let info = ClientInfo::from_initialize_params(&params).expect("name present");
            assert_eq!(
                info.name(),
                UNKNOWN_CLIENT,
                "invalid characters must be rejected, got: {}",
                bad
            );
        }
    }
}
