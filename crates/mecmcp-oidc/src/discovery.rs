//! The OIDC discovery document (`/.well-known/openid-configuration`).

use serde::Deserialize;

/// The subset of the discovery document this crate needs.
///
/// Deliberately minimal: unknown fields are ignored by `serde`'s default
/// behaviour, so a real IdP's much larger document (authorization_endpoint,
/// scopes_supported, ...) deserializes fine even though only `issuer` and
/// `jwks_uri` are read.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscoveryDocument {
    /// The issuer identifier. Compared against the configured issuer and
    /// against each token's `iss` claim.
    pub issuer: String,
    /// The URL to fetch the JWKS from.
    pub jwks_uri: String,
}

/// Build the well-known discovery URL for an issuer.
///
/// Per RFC 8414 / the OIDC Discovery spec, the well-known path is appended to
/// the issuer's path component, not the origin: `https://idp.example/tenant`
/// becomes `https://idp.example/tenant/.well-known/openid-configuration`.
#[must_use]
pub fn discovery_url(issuer: &str) -> String {
    format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn discovery_url_appends_well_known_path() {
        assert_eq!(
            discovery_url("https://idp.example.com"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_strips_trailing_slash() {
        assert_eq!(
            discovery_url("https://idp.example.com/"),
            "https://idp.example.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_url_preserves_issuer_path() {
        assert_eq!(
            discovery_url("https://idp.example.com/tenant/mechub"),
            "https://idp.example.com/tenant/mechub/.well-known/openid-configuration"
        );
    }

    #[test]
    fn discovery_document_ignores_unknown_fields() {
        let json = r#"{
            "issuer": "https://idp.example.com",
            "jwks_uri": "https://idp.example.com/jwks",
            "authorization_endpoint": "https://idp.example.com/auth",
            "scopes_supported": ["openid", "profile"]
        }"#;
        let doc: DiscoveryDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.issuer, "https://idp.example.com");
        assert_eq!(doc.jwks_uri, "https://idp.example.com/jwks");
    }
}
