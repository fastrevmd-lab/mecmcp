//! Credential lifetime tracking.
//!
//! Tracks when a credential was issued or last rotated, and how old it is
//! now. `mecmcp-secret` loads and hardens credentials but previously
//! discarded all provenance once the bytes were in an [`crate::OutboundSecret`]
//! — nothing in a running server could answer "how old is this token" for
//! an operator's freshness check or an audit report. Both problems are the
//! same shape: a name plus an issuance time.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

/// When a single credential was issued or last rotated, and its current age.
///
/// `issued_at` is a best-effort provenance timestamp, not a cryptographic
/// claim: for a file-backed credential it is the file's mtime (the last time
/// its contents changed on disk); for anything else it is whatever the
/// caller supplies, commonly "now" at load time. Neither proves the
/// credential value actually changed at that instant, only that this is the
/// most recent contents mechub observed.
#[derive(Debug, Clone, Copy)]
pub struct CredentialLifetime {
    issued_at: SystemTime,
}

impl CredentialLifetime {
    /// Build a lifetime from an explicit issuance timestamp.
    #[must_use]
    pub fn new(issued_at: SystemTime) -> Self {
        Self { issued_at }
    }

    /// Build a lifetime stamped with the current time — the right choice
    /// when no better provenance (such as a file's mtime) is available.
    #[must_use]
    pub fn now() -> Self {
        Self::new(SystemTime::now())
    }

    /// When the credential was issued or last rotated.
    #[must_use]
    pub fn issued_at(&self) -> SystemTime {
        self.issued_at
    }

    /// How long ago the credential was issued or last rotated.
    ///
    /// Clamped to zero rather than returning an error: `SystemTime` is not
    /// monotonic, so a clock adjustment between issuance and now can put
    /// `issued_at` slightly in the future. Reporting a negative age makes no
    /// sense for a freshness check; zero is the honest floor.
    #[must_use]
    pub fn age(&self) -> Duration {
        SystemTime::now()
            .duration_since(self.issued_at)
            .unwrap_or(Duration::ZERO)
    }
}

/// A thread-safe registry of named credentials' lifetimes.
///
/// A server that loads several credentials (device auth token, MCP client
/// bearer tokens, an OIDC client secret) registers each one here under a
/// stable name, then exposes age/lifetime for any of them — in a status
/// endpoint, an audit event, or an operator-facing report — without each
/// call site re-deriving provenance itself.
#[derive(Debug, Default)]
pub struct CredentialRegistry {
    entries: RwLock<HashMap<String, CredentialLifetime>>,
}

impl CredentialRegistry {
    /// Build an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a credential under `name`, recording `lifetime` for it.
    ///
    /// Registering again under the same name replaces the prior lifetime —
    /// this is how a rotation is recorded: register again with a fresh
    /// [`CredentialLifetime`].
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned, i.e. another thread panicked
    /// while holding it. This mirrors `std::sync::Mutex`/`RwLock` panic
    /// behavior elsewhere in the workspace: a poisoned lock means state may
    /// be inconsistent, and silently swallowing that would hide the original
    /// panic's cause.
    pub fn register(&self, name: impl Into<String>, lifetime: CredentialLifetime) {
        #[allow(clippy::unwrap_used)]
        let mut entries = self.entries.write().unwrap();
        entries.insert(name.into(), lifetime);
    }

    /// Convenience for [`register`](Self::register) with `CredentialLifetime::now()`.
    pub fn register_now(&self, name: impl Into<String>) {
        self.register(name, CredentialLifetime::now());
    }

    /// The lifetime recorded for `name`, if it has been registered.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned; see [`register`](Self::register).
    #[must_use]
    pub fn lifetime(&self, name: &str) -> Option<CredentialLifetime> {
        #[allow(clippy::unwrap_used)]
        let entries = self.entries.read().unwrap();
        entries.get(name).copied()
    }

    /// The current age of the credential registered under `name`, if any.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned; see [`register`](Self::register).
    #[must_use]
    pub fn age(&self, name: &str) -> Option<Duration> {
        self.lifetime(name).map(|lifetime| lifetime.age())
    }

    /// Remove a credential's tracked lifetime, e.g. when it is unloaded.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned; see [`register`](Self::register).
    pub fn remove(&self, name: &str) {
        #[allow(clippy::unwrap_used)]
        let mut entries = self.entries.write().unwrap();
        entries.remove(name);
    }

    /// Every registered credential's name and lifetime.
    ///
    /// Returns an owned `Vec` rather than an iterator borrowing the lock, so
    /// a caller building a status report does not hold the lock while
    /// formatting.
    ///
    /// # Panics
    /// Panics if the internal lock is poisoned; see [`register`](Self::register).
    #[must_use]
    pub fn all(&self) -> Vec<(String, CredentialLifetime)> {
        #[allow(clippy::unwrap_used)]
        let entries = self.entries.read().unwrap();
        entries
            .iter()
            .map(|(name, lifetime)| (name.clone(), *lifetime))
            .collect()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn age_of_a_fresh_lifetime_is_near_zero() {
        let lifetime = CredentialLifetime::now();
        assert!(lifetime.age() < Duration::from_secs(1));
    }

    #[test]
    fn age_grows_from_an_explicit_issuance_time() {
        let issued_at = SystemTime::now() - Duration::from_secs(3600);
        let lifetime = CredentialLifetime::new(issued_at);
        assert!(lifetime.age() >= Duration::from_secs(3600));
        assert!(lifetime.age() < Duration::from_secs(3601));
    }

    #[test]
    fn age_clamps_to_zero_for_a_future_issuance_time() {
        let issued_at = SystemTime::now() + Duration::from_secs(60);
        let lifetime = CredentialLifetime::new(issued_at);
        assert_eq!(lifetime.age(), Duration::ZERO);
    }

    #[test]
    fn registry_reports_no_lifetime_for_an_unregistered_credential() {
        let registry = CredentialRegistry::new();
        assert!(registry.lifetime("device-token").is_none());
        assert!(registry.age("device-token").is_none());
    }

    #[test]
    fn registry_exposes_age_for_a_registered_credential() {
        let registry = CredentialRegistry::new();
        let issued_at = SystemTime::now() - Duration::from_secs(120);
        registry.register("device-token", CredentialLifetime::new(issued_at));

        let age = registry.age("device-token").unwrap();
        assert!(age >= Duration::from_secs(120));
        assert!(age < Duration::from_secs(121));
    }

    #[test]
    fn re_registering_replaces_the_lifetime_recording_a_rotation() {
        let registry = CredentialRegistry::new();
        let old_issued_at = SystemTime::now() - Duration::from_secs(86_400);
        registry.register("device-token", CredentialLifetime::new(old_issued_at));
        assert!(registry.age("device-token").unwrap() >= Duration::from_secs(86_400));

        registry.register_now("device-token");
        assert!(registry.age("device-token").unwrap() < Duration::from_secs(1));
    }

    #[test]
    fn remove_drops_a_registered_credential() {
        let registry = CredentialRegistry::new();
        registry.register_now("device-token");
        assert!(registry.lifetime("device-token").is_some());

        registry.remove("device-token");
        assert!(registry.lifetime("device-token").is_none());
    }

    #[test]
    fn all_lists_every_registered_credential() {
        let registry = CredentialRegistry::new();
        registry.register_now("device-token");
        registry.register_now("oidc-client-secret");

        let mut names: Vec<String> = registry.all().into_iter().map(|(name, _)| name).collect();
        names.sort();
        assert_eq!(names, vec!["device-token", "oidc-client-secret"]);
    }
}
