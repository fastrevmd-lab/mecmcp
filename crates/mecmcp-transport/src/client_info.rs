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

/// Maximum distinct model IDs ever interned.
///
/// Model IDs arrive in `_meta.mecmcp/provenance.model_id` within the initialize
/// request. They are low cardinality (a handful of model names like "claude-opus-5"),
/// so interning them prevents duplicate allocations. The cap prevents unbounded
/// growth from untrusted input.
const MAX_INTERNED_MODEL_IDS: usize = 64;

/// Maximum length for a client name or version string.
///
/// Longer strings are rejected and replaced with a placeholder. This prevents
/// memory exhaustion from clients sending arbitrarily large names.
const MAX_CLIENT_INFO_LEN: usize = 128;

/// Placeholder recorded when a client name is implausible or the intern table is full.
const UNKNOWN_CLIENT: &str = "unknown";

/// Placeholder recorded when a model ID is implausible or the intern table is full.
const UNKNOWN_MODEL: &str = "unknown";

/// Maximum length for a session ID.
///
/// Session IDs are high cardinality (one per session), so they are NOT interned.
/// This cap prevents memory exhaustion from malicious clients.
const MAX_SESSION_ID_LEN: usize = 128;

static INTERNED_CLIENT_NAMES: LazyLock<DashMap<&'static str, ()>> =
    LazyLock::new(|| DashMap::with_capacity(MAX_INTERNED_CLIENT_NAMES));

static INTERNED_MODEL_IDS: LazyLock<DashMap<&'static str, ()>> =
    LazyLock::new(|| DashMap::with_capacity(MAX_INTERNED_MODEL_IDS));

/// Client-asserted provenance from the MCP `_meta.mecmcp/provenance` block.
///
/// This is **entirely client-asserted** and must never be used for authorization.
/// The model_id is interned (low cardinality), while session_id is bounded but
/// not interned (high cardinality — one per session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientProvenance {
    /// Interned model ID (e.g., "claude-opus-5"), bounded and validated.
    model_id: &'static str,
    /// Session ID, bounded but not interned (high cardinality).
    session_id: Option<String>,
}

/// Client identity from the MCP `initialize` request.
///
/// This data is **client-asserted**. Nothing authenticates it. The client name
/// identifies the **client program** (e.g. "claude-code"), not the model or the
/// user. It must never be used for authorization decisions or scope checks.
///
/// Captured per-session by `LimitedSessionManager::initialize_session`.
///
/// Propagated to `AgentIdentity.client_name` as of #253: the middleware reads the
/// captured name off the session and sets it on `CallerCtx`, so handler-side audit
/// events carry the same name the transport event does. Before that, only the
/// transport event had it and the handler event showed empty.
///
/// The bounds below are the security-relevant half and landed first, because the
/// name arrives in a request body. `intern_tool_name` is bounded the same way
/// (256 names, 128 bytes, falling back to a placeholder) — an earlier revision of
/// this comment described it as an unbounded `Box::leak`, which is no longer true.
///
/// As of #267, this also parses and stores client-asserted provenance (model_id
/// and session_id) from the `_meta` extension block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInfo {
    /// Interned client name, bounded and validated.
    name: &'static str,
    /// Client version, bounded but not interned (high cardinality).
    version: Option<String>,
    /// Client-asserted provenance (model_id, session_id), if present.
    provenance: Option<ClientProvenance>,
}

impl ClientInfo {
    /// Parse client info from an MCP `initialize` params object.
    ///
    /// Expects a JSON object with optional `clientInfo` field and optional
    /// `_meta.mecmcp/provenance` extension:
    /// ```json
    /// {
    ///   "protocolVersion": "2025-03-26",
    ///   "clientInfo": { "name": "claude-code", "version": "1.0" },
    ///   "_meta": {
    ///     "mecmcp/provenance": {
    ///       "model_id": "claude-opus-5",
    ///       "session_id": "01J..."
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// Missing or malformed `clientInfo` produces `None`. Names and versions are
    /// bounded and sanitized; implausible values become placeholders. The `_meta`
    /// block is optional; absent or malformed provenance is silently ignored.
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

        // Parse optional provenance from _meta.mecmcp/provenance.
        // Absent or malformed provenance is not an error — clients that don't
        // know about this extension keep working unchanged.
        let provenance = params
            .get("_meta")
            .and_then(|meta| meta.get("mecmcp/provenance"))
            .and_then(parse_provenance);

        Some(Self {
            name: intern_client_name(name),
            version: version.and_then(bound_version),
            provenance,
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

    /// Return the interned model ID, if provenance was provided.
    #[must_use]
    pub fn model_id(&self) -> Option<&'static str> {
        self.provenance.as_ref().map(|p| p.model_id)
    }

    /// Return the session ID, if provenance was provided and plausible.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.provenance
            .as_ref()
            .and_then(|p| p.session_id.as_deref())
    }
}

/// Client-asserted provenance read from a single request's `_meta` (#288).
///
/// The session path captures this once, at `initialize`, and keys it by
/// `Mcp-Session-Id`. A client declaring MCP `2026-07-28` is routed statelessly
/// and never sends that header, so nothing was captured for it at all — a fully
/// successful call audited with all three fields empty even though it carried
/// every one of them on the request.
///
/// Nothing here is a new wire format. These are the keys such a client already
/// sends, observed on the wire against LXC 611. The only difference from
/// [`ClientInfo::from_initialize_params`] is where the client name lives:
/// per-request, the spec carries it under `io.modelcontextprotocol/clientInfo`,
/// while `initialize` uses a bare `clientInfo` sibling of `_meta`.
///
/// Bounding and interning are the same functions the session path uses, so the
/// caps on untrusted strings apply identically. Like everything else on this
/// type, the contents are **client-asserted** and must never be used for
/// authorization or marked server-verified.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestProvenance {
    /// Interned client name from `io.modelcontextprotocol/clientInfo`.
    pub client_name: Option<&'static str>,
    /// Interned model ID from `mecmcp/provenance`.
    pub model_id: Option<&'static str>,
    /// Bounded session ID from `mecmcp/provenance`.
    pub session_id: Option<String>,
}

impl RequestProvenance {
    /// Parse provenance out of a request's `params._meta` object.
    ///
    /// Returns `None` when the block carries none of the three fields, so a
    /// client that knows nothing about either extension is unaffected. A
    /// malformed or partial block is not an error: whatever parses is kept and
    /// the rest stays absent, matching how the initialize path already treats
    /// partial provenance.
    #[must_use]
    pub fn from_request_meta(meta: &serde_json::Value) -> Option<Self> {
        let provenance = meta.get("mecmcp/provenance").and_then(parse_provenance);

        let client_name = meta
            .get("io.modelcontextprotocol/clientInfo")
            .and_then(|info| info.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(intern_client_name);

        let parsed = Self {
            client_name,
            model_id: provenance.as_ref().map(|p| p.model_id),
            session_id: provenance.and_then(|p| p.session_id),
        };

        if parsed.client_name.is_none() && parsed.model_id.is_none() && parsed.session_id.is_none()
        {
            return None;
        }

        Some(parsed)
    }
}

/// Parse provenance from the `mecmcp/provenance` object within `_meta`.
///
/// Returns `None` if required fields are missing or implausible. Partial
/// provenance (e.g., only model_id present) is accepted.
fn parse_provenance(prov: &serde_json::Value) -> Option<ClientProvenance> {
    let model_id_str = prov.get("model_id").and_then(|v| v.as_str());
    let session_id_str = prov.get("session_id").and_then(|v| v.as_str());

    // At least one field must be present and plausible.
    if model_id_str.is_none() && session_id_str.is_none() {
        return None;
    }

    let model_id = model_id_str.map_or(UNKNOWN_MODEL, intern_model_id);
    let session_id = session_id_str.and_then(bound_session_id);

    Some(ClientProvenance {
        model_id,
        session_id,
    })
}

/// Intern a client name into a bounded set, returning a `&'static str`.
///
/// Names longer than `MAX_CLIENT_INFO_LEN`, containing non-ASCII or control
/// characters, or arriving after the table is full are replaced with
/// `UNKNOWN_CLIENT`. This prevents unbounded memory growth and metrics
/// cardinality from attacker-controlled input.
fn intern_client_name(name: &str) -> &'static str {
    intern_into(&INTERNED_CLIENT_NAMES, name, UNKNOWN_CLIENT)
}

/// Intern a model ID into a bounded set, returning a `&'static str`.
///
/// Model IDs are low cardinality (a handful of model names). Interning them
/// prevents duplicate allocations. Implausible values or overflow become
/// `UNKNOWN_MODEL`.
fn intern_model_id(model_id: &str) -> &'static str {
    intern_into(&INTERNED_MODEL_IDS, model_id, UNKNOWN_MODEL)
}

/// Intern into a caller-supplied table.
///
/// Split out from [`intern_client_name`] so the cap can be tested without
/// touching the process-global table. It genuinely mattered: the cap test fills
/// the table to capacity and never empties it, Rust runs tests in a module
/// concurrently, and any test asserting a specific name back would then get
/// `unknown` depending on scheduling. That reproduced as roughly one failure in
/// six runs, passed locally often enough to look fine, and failed in CI.
///
/// The table capacity is not passed — the table itself carries its own limit.
/// The caller specifies the placeholder to use on rejection.
fn intern_into(
    table: &DashMap<&'static str, ()>,
    name: &str,
    placeholder: &'static str,
) -> &'static str {
    if name.is_empty() || name.len() > MAX_CLIENT_INFO_LEN {
        return placeholder;
    }
    // Allow alphanumerics, hyphens, underscores, dots, and forward slashes
    // (covers "claude-code", "mcp-client/1.0", "my.client" patterns, and model
    // IDs like "claude-opus-5")
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'/')
    {
        return placeholder;
    }

    // Fast path: already interned
    if let Some(entry) = table.get(name) {
        return entry.key();
    }

    // Slow path: try to intern
    // The table's initial capacity is its limit, not a performance hint. Both
    // tables (client names and model IDs) use 64.
    if table.len() >= MAX_INTERNED_CLIENT_NAMES {
        return placeholder;
    }

    let leaked: &'static str = Box::leak(name.to_owned().into_boxed_str());
    table.insert(leaked, ());
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

/// Bound and validate a session ID.
///
/// Session IDs are high cardinality (one per session), so they are NOT interned.
/// They are length-bounded and charset-restricted. Returns `None` for implausible
/// values.
fn bound_session_id(session_id: &str) -> Option<String> {
    if session_id.is_empty() || session_id.len() > MAX_SESSION_ID_LEN {
        return None;
    }
    // Allow alphanumerics, hyphens, and underscores (covers ULIDs like "01J...")
    if !session_id
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    Some(session_id.to_owned())
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
    /// The cap is a safety contract, not an optimisation. An authenticated
    /// caller with no tool scopes reaches this code merely by sending
    /// `initialize`, so the name is attacker-controlled: without a bound they
    /// can exhaust memory and blow up metrics cardinality. Remove
    /// `MAX_INTERNED_CLIENT_NAMES` and this must fail.
    fn intern_table_cap_enforced() {
        // A LOCAL table, not the process-global one. Filling the global table
        // here leaks into every other test in this module — Rust runs them
        // concurrently, so any test asserting a specific name back would then
        // get `unknown` depending on scheduling. That is not hypothetical: it
        // failed about one run in six and took a CI failure to notice.
        let table: DashMap<&'static str, ()> = DashMap::new();
        for i in 0..MAX_INTERNED_CLIENT_NAMES {
            let name = format!("client-{i}");
            assert_ne!(
                intern_into(&table, &name, UNKNOWN_CLIENT),
                UNKNOWN_CLIENT,
                "names below the cap must intern"
            );
        }
        assert_eq!(table.len(), MAX_INTERNED_CLIENT_NAMES);

        // The next distinct name is refused rather than growing the table.
        assert_eq!(
            intern_into(&table, "overflow-client", UNKNOWN_CLIENT),
            UNKNOWN_CLIENT
        );
        assert_eq!(table.len(), MAX_INTERNED_CLIENT_NAMES);

        // An already-interned name still resolves, cap or no cap.
        assert_eq!(intern_into(&table, "client-0", UNKNOWN_CLIENT), "client-0");
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

    #[test]
    fn parse_provenance_with_both_fields() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "claude-code", "version": "1.0" },
            "_meta": {
                "mecmcp/provenance": {
                    "model_id": "claude-opus-5",
                    "session_id": "01J5KZ8X9Y7W6V5U4T3S2R1Q0P"
                }
            }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.name(), "claude-code");
        assert_eq!(info.model_id(), Some("claude-opus-5"));
        assert_eq!(info.session_id(), Some("01J5KZ8X9Y7W6V5U4T3S2R1Q0P"));
    }

    #[test]
    fn parse_provenance_with_only_model_id() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test" },
            "_meta": {
                "mecmcp/provenance": {
                    "model_id": "claude-sonnet-4"
                }
            }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.model_id(), Some("claude-sonnet-4"));
        assert_eq!(info.session_id(), None);
    }

    #[test]
    fn parse_provenance_with_only_session_id() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test" },
            "_meta": {
                "mecmcp/provenance": {
                    "session_id": "01JXYZ123456"
                }
            }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.model_id(), Some(UNKNOWN_MODEL));
        assert_eq!(info.session_id(), Some("01JXYZ123456"));
    }

    #[test]
    fn missing_meta_block_works() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test" }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.name(), "test");
        assert_eq!(info.model_id(), None);
        assert_eq!(info.session_id(), None);
    }

    #[test]
    fn malformed_provenance_is_ignored() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test" },
            "_meta": {
                "mecmcp/provenance": "not-an-object"
            }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.name(), "test");
        assert_eq!(info.model_id(), None);
        assert_eq!(info.session_id(), None);
    }

    #[test]
    fn empty_provenance_object_is_ignored() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test" },
            "_meta": {
                "mecmcp/provenance": {}
            }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.name(), "test");
        assert_eq!(info.model_id(), None);
        assert_eq!(info.session_id(), None);
    }

    #[test]
    fn oversized_session_id_is_dropped() {
        let long_session_id = "01J".to_owned() + &"X".repeat(MAX_SESSION_ID_LEN);
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test" },
            "_meta": {
                "mecmcp/provenance": {
                    "model_id": "claude-opus-5",
                    "session_id": long_session_id
                }
            }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.model_id(), Some("claude-opus-5"));
        assert_eq!(info.session_id(), None);
    }

    #[test]
    fn invalid_characters_in_session_id_are_dropped() {
        let params = json!({
            "protocolVersion": "2025-03-26",
            "clientInfo": { "name": "test" },
            "_meta": {
                "mecmcp/provenance": {
                    "session_id": "01J<script>"
                }
            }
        });
        let info = ClientInfo::from_initialize_params(&params).expect("valid clientInfo");
        assert_eq!(info.session_id(), None);
    }

    #[test]
    fn model_id_is_interned() {
        let params1 = json!({
            "clientInfo": { "name": "test" },
            "_meta": { "mecmcp/provenance": { "model_id": "claude-opus-5" } }
        });
        let params2 = json!({
            "clientInfo": { "name": "test" },
            "_meta": { "mecmcp/provenance": { "model_id": "claude-opus-5" } }
        });
        let info1 = ClientInfo::from_initialize_params(&params1).expect("valid");
        let info2 = ClientInfo::from_initialize_params(&params2).expect("valid");
        let model1 = info1.model_id().expect("model_id present");
        let model2 = info2.model_id().expect("model_id present");
        assert!(std::ptr::eq(model1, model2), "model_id must be interned");
    }

    #[test]
    /// Session IDs are high cardinality (one per session), so they must NOT be
    /// interned. This test proves that many distinct session IDs do not degrade
    /// to a placeholder or exhaust a fixed-size table.
    fn session_id_is_not_interned() {
        for i in 0..100 {
            let session_id = format!("01J{i:0>24}");
            let params = json!({
                "clientInfo": { "name": "test" },
                "_meta": { "mecmcp/provenance": { "session_id": session_id } }
            });
            let info = ClientInfo::from_initialize_params(&params).expect("valid");
            assert_eq!(
                info.session_id(),
                Some(session_id.as_str()),
                "session {i} must not degrade to placeholder"
            );
        }
    }
}
