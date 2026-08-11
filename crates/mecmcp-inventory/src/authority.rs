//! Configuration authority tracking.
//!
//! Devices can be managed by different control planes: locally (by this server),
//! or by a management plane (Mist, Security Director, Panorama, Strata Cloud Manager).
//! When a device is owned by a management plane, changes made through this server
//! may be overwritten at the next push from the owning plane.
//!
//! This module provides a vendor-neutral `ConfigAuthority` type that consumers
//! can embed in their device records to track ownership and guide policy decisions.

use serde::{Deserialize, Serialize};

/// Configuration authority for a device.
///
/// Generic over the authority enum type `A`, which is supplied by the consumer
/// (e.g., `JunosAuthority`, `PanosAuthority`). Consumers define their own
/// authority values based on their vendor ecosystem.
///
/// # Design rationale
///
/// The authority type is generic rather than a shared enum because the set of
/// possible owners is vendor-specific and evolves independently:
///
/// - **Junos**: `local`, `mist`, `security-director-cloud`, `security-director-onprem`
/// - **PAN-OS**: `local`, `panorama`, `strata-cloud-manager`
///
/// A fixed enum would couple releases across consumers or force one to wait on
/// another. An open string would never catch typos and never enforce a schema.
/// A generic bounded by a consumer-supplied enum splits the difference: the
/// shared crate stays vendor-neutral, and each consumer's enum is checkable and
/// versioned independently.
///
/// # Serialization
///
/// Serializes as a plain string (the authority discriminant), not a wrapper object.
/// When embedded in a device record as `config_authority: Option<ConfigAuthority<A>>`,
/// the JSON representation is:
///
/// ```json
/// { "config_authority": "mist" }
/// ```
///
/// not `{ "config_authority": { "authority": "mist" } }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConfigAuthority<A> {
    authority: A,
}

impl<A> ConfigAuthority<A> {
    /// Constructs a new config authority.
    pub fn new(authority: A) -> Self {
        Self { authority }
    }

    /// Returns the authority value.
    pub fn authority(&self) -> &A {
        &self.authority
    }

    /// Unwraps into the inner authority value.
    pub fn into_inner(self) -> A {
        self.authority
    }
}

impl<A> ConfigAuthority<A>
where
    A: LocalAuthority,
{
    /// Returns `true` if this authority is the local server (owned by us).
    ///
    /// Consumers implement `LocalAuthority` on their enum to define which
    /// discriminant means "local".
    pub fn is_local(&self) -> bool {
        self.authority.is_local()
    }
}

/// Trait for authority enums to declare which value means "local" (owned by us).
///
/// Consumers implement this on their authority enum to support `is_local()`:
///
/// ```ignore
/// #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
/// #[serde(rename_all = "kebab-case")]
/// enum JunosAuthority {
///     Local,
///     Mist,
///     SecurityDirectorCloud,
///     Unknown,
/// }
///
/// impl LocalAuthority for JunosAuthority {
///     fn is_local(&self) -> bool {
///         matches!(self, Self::Local)
///     }
/// }
/// ```
///
/// The `Unknown` variant is NOT local — it means "nobody annotated this device",
/// not "we own it". For behavior purposes, `Unknown` is treated as `Local`
/// (permitting writes), but audit events record it distinctly so the trail can
/// tell "we own it" from "nobody said".
pub trait LocalAuthority {
    /// Returns `true` if this authority value represents local ownership.
    fn is_local(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
    #[serde(rename_all = "kebab-case")]
    enum TestAuthority {
        Local,
        Remote,
        Unknown,
    }

    impl LocalAuthority for TestAuthority {
        fn is_local(&self) -> bool {
            matches!(self, Self::Local)
        }
    }

    #[test]
    fn config_authority_is_local() {
        let local = ConfigAuthority::new(TestAuthority::Local);
        assert!(local.is_local());

        let remote = ConfigAuthority::new(TestAuthority::Remote);
        assert!(!remote.is_local());

        let unknown = ConfigAuthority::new(TestAuthority::Unknown);
        assert!(!unknown.is_local(), "unknown is not local");
    }

    #[test]
    fn config_authority_serializes_as_string() {
        let authority = ConfigAuthority::new(TestAuthority::Local);
        let json = serde_json::to_string(&authority).expect("serialize");
        assert_eq!(json, r#""local""#);
    }

    #[test]
    fn config_authority_deserializes_from_string() {
        let json = r#""remote""#;
        let authority: ConfigAuthority<TestAuthority> =
            serde_json::from_str(json).expect("deserialize");
        assert_eq!(authority.authority(), &TestAuthority::Remote);
    }

    #[test]
    fn config_authority_round_trips() {
        let original = ConfigAuthority::new(TestAuthority::Remote);
        let json = serde_json::to_string(&original).expect("serialize");
        let deserialized: ConfigAuthority<TestAuthority> =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(original, deserialized);
    }
}
