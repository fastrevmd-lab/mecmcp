//! One token as persisted on disk, in a shape both existing servers can load.

use crate::grant::{Grant, GrantError, NoGrant};
use crate::scope::{ScopeError, ScopeSet};
use crate::token::TokenDigest;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Maximum length of an operator-facing token name.
pub const MAX_TOKEN_NAME: usize = 128;

/// Rejection reason for a malformed token entry.
#[derive(Debug, thiserror::Error)]
pub enum EntryError {
    /// A scope failed validation.
    #[error("token '{name}': {source}")]
    Scope {
        /// The offending token's name.
        name: String,
        /// The underlying scope error.
        #[source]
        source: ScopeError,
    },
    /// A grant failed validation.
    #[error("token '{name}': {source}")]
    Grant {
        /// The offending token's name.
        name: String,
        /// The underlying grant error.
        #[source]
        source: GrantError,
    },
    /// The entry failed a structural check.
    #[error("{0}")]
    Invalid(String),
}

/// One digest-only token entry.
///
/// Field names are canonical (`digest`, `devices`); the aliases accept the
/// spellings `rustjunosmcp` wrote before extraction so deployed `tokens.json`
/// files load unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry<G: Grant = NoGrant> {
    /// Operator-facing, non-secret token name. Used for audit attribution.
    pub name: String,

    /// Versioned token digest. Never plaintext.
    #[serde(alias = "hash")]
    pub digest: TokenDigest,

    /// Devices this token may address.
    #[serde(alias = "routers", default = "wildcard")]
    pub devices: ScopeSet,

    /// MCP tools this token may call.
    #[serde(default = "wildcard")]
    pub tools: ScopeSet,

    /// Creation or last-rotation time.
    ///
    /// Accepts RFC 3339 under `created_at` (the `rustjunosmcp` spelling) or a
    /// Unix timestamp under `created_at_unix` (the `rustpanosmcp` spelling).
    #[serde(alias = "created_at_unix", with = "timestamp")]
    pub created_at: DateTime<Utc>,

    /// Optional absolute expiry. An expired token never authenticates.
    #[serde(
        default,
        alias = "expires_at_unix",
        with = "optional_timestamp",
        skip_serializing_if = "Option::is_none"
    )]
    pub expires_at: Option<DateTime<Utc>>,

    /// Optional vendor-specific write authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<G>,
}

fn wildcard() -> ScopeSet {
    ScopeSet::Wildcard
}

impl<G: Grant> TokenEntry<G> {
    /// Whether this token is expired at the given instant.
    #[must_use]
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.is_some_and(|expiry| now >= expiry)
    }

    /// Validate name, scopes, and grant.
    ///
    /// # Errors
    /// Returns [`EntryError`] describing the first failing check.
    pub fn validate(&self) -> Result<(), EntryError> {
        if self.name.is_empty() || self.name.len() > MAX_TOKEN_NAME {
            return Err(EntryError::Invalid(format!(
                "token name must be 1-{MAX_TOKEN_NAME} characters"
            )));
        }
        if self.name.contains('\0') || self.name.contains(char::is_whitespace) {
            return Err(EntryError::Invalid(format!(
                "token name '{}' contains whitespace or a null byte",
                self.name
            )));
        }
        self.devices
            .validate("devices")
            .map_err(|source| EntryError::Scope {
                name: self.name.clone(),
                source,
            })?;
        self.tools
            .validate("tools")
            .map_err(|source| EntryError::Scope {
                name: self.name.clone(),
                source,
            })?;
        if let Some(grant) = &self.grant {
            grant.validate().map_err(|source| EntryError::Grant {
                name: self.name.clone(),
                source,
            })?;
        }
        Ok(())
    }
}

/// Accept a timestamp as either RFC 3339 (`rustjunosmcp`) or Unix seconds
/// (`rustpanosmcp`); always write RFC 3339.
mod timestamp {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    /// Either on-disk spelling of an instant.
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Rfc3339(DateTime<Utc>),
        Unix(i64),
    }

    impl Raw {
        fn into_datetime<E: serde::de::Error>(self) -> Result<DateTime<Utc>, E> {
            match self {
                Self::Rfc3339(value) => Ok(value),
                Self::Unix(seconds) => DateTime::from_timestamp(seconds, 0)
                    .ok_or_else(|| E::custom(format!("timestamp {seconds} is out of range"))),
            }
        }
    }

    pub(super) fn serialize<S: Serializer>(
        value: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_rfc3339())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        Raw::deserialize(deserializer)?.into_datetime()
    }

    /// The `Option` form, for fields that may be absent entirely.
    pub(super) mod optional {
        use super::Raw;
        use chrono::{DateTime, Utc};
        use serde::{Deserialize, Deserializer, Serializer};

        pub(in super::super) fn serialize<S: Serializer>(
            value: &Option<DateTime<Utc>>,
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            match value {
                Some(value) => serializer.serialize_str(&value.to_rfc3339()),
                None => serializer.serialize_none(),
            }
        }

        pub(in super::super) fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Option<DateTime<Utc>>, D::Error> {
            match Option::<Raw>::deserialize(deserializer)? {
                Some(raw) => raw.into_datetime().map(Some),
                None => Ok(None),
            }
        }
    }
}

use timestamp::optional as optional_timestamp;

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly the shape rustjunosmcp 0.9.1 writes today.
    const JUNOS_SHAPE: &str = r#"{
        "name": "lab",
        "hash": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "routers": ["edge-fw", "core-fw"],
        "tools": ["*"],
        "created_at": "2026-07-12T10:00:00Z"
    }"#;

    /// Exactly the shape rustpanosmcp 0.2.2 writes today.
    const PANOS_SHAPE: &str = r#"{
        "name": "lab",
        "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
        "devices": ["panosvm"],
        "tools": ["get_panos_config"],
        "created_at_unix": 1783850400
    }"#;

    #[test]
    fn loads_the_junos_on_disk_shape() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse junos shape");
        assert_eq!(entry.name, "lab");
        assert_eq!(
            entry.devices,
            ScopeSet::Allowlist(vec!["edge-fw".to_owned(), "core-fw".to_owned()])
        );
        assert_eq!(entry.tools, ScopeSet::Wildcard);
        assert!(entry.digest.verify("test"));
        assert!(entry.expires_at.is_none());
    }

    #[test]
    fn loads_the_panos_on_disk_shape() {
        let entry: TokenEntry = serde_json::from_str(PANOS_SHAPE).expect("parse panos shape");
        assert_eq!(entry.name, "lab");
        assert_eq!(entry.devices, ScopeSet::Allowlist(vec!["panosvm".to_owned()]));
        assert!(entry.digest.verify("test"));
    }

    #[test]
    fn both_shapes_produce_an_identical_entry() {
        let junos: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("junos");
        let panos: TokenEntry = serde_json::from_str(PANOS_SHAPE).expect("panos");
        assert_eq!(junos.created_at, panos.created_at);
        assert_eq!(junos.digest, panos.digest);
    }

    #[test]
    fn a_token_without_expiry_never_expires() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        let far_future = DateTime::from_timestamp(4_102_444_800, 0).expect("timestamp");
        assert!(!entry.is_expired_at(far_future));
    }

    #[test]
    fn a_token_past_its_expiry_is_expired() {
        let raw = r#"{
            "name": "lab",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["*"],
            "tools": ["*"],
            "created_at_unix": 1783850400,
            "expires_at_unix": 1783936800
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        let before = DateTime::from_timestamp(1_783_886_400, 0).expect("timestamp");
        let after = DateTime::from_timestamp(1_784_023_200, 0).expect("timestamp");
        assert!(!entry.is_expired_at(before));
        assert!(entry.is_expired_at(after));
    }

    #[test]
    fn an_entry_with_an_invalid_scope_fails_validation() {
        let raw = r#"{
            "name": "lab",
            "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
            "devices": ["a", "a"],
            "tools": ["*"],
            "created_at_unix": 1783850400
        }"#;
        let entry: TokenEntry = serde_json::from_str(raw).expect("parse");
        assert!(entry.validate().is_err());
    }

    #[test]
    fn an_entry_with_an_out_of_range_name_fails_validation() {
        let raw = format!(
            r#"{{
                "name": "{}",
                "digest": "sha256:n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg",
                "devices": ["*"],
                "tools": ["*"],
                "created_at_unix": 1783850400
            }}"#,
            "x".repeat(200)
        );
        let entry: TokenEntry = serde_json::from_str(&raw).expect("parse");
        assert!(entry.validate().is_err());
    }

    #[test]
    fn serializing_writes_the_canonical_field_names() {
        let entry: TokenEntry = serde_json::from_str(JUNOS_SHAPE).expect("parse");
        let json = serde_json::to_string(&entry).expect("serialize");
        assert!(json.contains("\"digest\""));
        assert!(json.contains("\"devices\""));
        assert!(!json.contains("\"hash\""));
        assert!(!json.contains("\"routers\""));
    }
}
