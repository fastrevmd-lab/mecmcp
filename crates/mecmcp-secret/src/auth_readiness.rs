//! A vendor-neutral auth-failure readiness probe.
//!
//! Every vendor MCP server authenticates outbound to a device or a cloud
//! API using a credential from this crate, and every one of them wants the
//! same answer on `/readyz`: "is outbound auth currently working?" Without
//! a shared helper each server hand-rolls its own flag, and a subtly
//! different one for each vendor is exactly the kind of divergence that
//! lets one server's readiness probe quietly stop meaning what it says.
//!
//! This crate does not depend on `mecmcp-transport` — a low-level secret
//! crate must not pull in an HTTP stack — so [`AuthFailureTracker::probe`]
//! returns a plain closure. `mecmcp-transport::health::ReadinessCheck::new`
//! accepts any `Fn() -> Result<(), &'static str> + Send + Sync`, so the
//! closure this returns satisfies it by shape, with no direct dependency
//! between the two crates.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Tracks whether outbound authentication is currently failing.
///
/// Cheap to clone — clones share the same underlying flag — so a server
/// wires one tracker into both its auth call sites (via
/// [`record_success`](Self::record_success) /
/// [`record_failure`](Self::record_failure)) and its `/readyz` probe (via
/// [`probe`](Self::probe)).
///
/// Starts ready: a server with no completed auth attempt yet is not known
/// to be broken, and treating "unknown" as "failing" would make every fresh
/// deployment fail its own readiness check before its first request.
#[derive(Debug, Clone)]
pub struct AuthFailureTracker {
    failing: Arc<AtomicBool>,
}

impl Default for AuthFailureTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthFailureTracker {
    /// Build a tracker that starts in the ready (not-failing) state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            failing: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Record a successful outbound authentication, clearing any prior
    /// failure.
    pub fn record_success(&self) {
        self.failing.store(false, Ordering::Relaxed);
    }

    /// Record a failed outbound authentication.
    pub fn record_failure(&self) {
        self.failing.store(true, Ordering::Relaxed);
    }

    /// Whether the tracker is currently in the failing state.
    #[must_use]
    pub fn is_failing(&self) -> bool {
        self.failing.load(Ordering::Relaxed)
    }

    /// Build a `/readyz` probe closure for this tracker.
    ///
    /// `reason` is a fixed `&'static str`, matching
    /// `mecmcp-transport::health::ReadinessCheck`'s constraint: `/readyz` is
    /// unauthenticated, so the reason returned to a caller cannot carry a
    /// formatted runtime value (a device hostname, an error detail) — only
    /// a literal such as `"outbound authentication is failing"`. Log the
    /// runtime detail server-side at the `record_failure` call site instead.
    ///
    /// Registering this against `/readyz` is the "one call" a vendor server
    /// makes:
    /// ```ignore
    /// let auth = AuthFailureTracker::new();
    /// let config = config.with_readiness_check(
    ///     ReadinessCheck::new("auth", auth.probe("outbound authentication is failing")),
    /// );
    /// ```
    pub fn probe(
        &self,
        reason: &'static str,
    ) -> impl Fn() -> Result<(), &'static str> + Send + Sync + Clone + use<> {
        let tracker = self.clone();
        move || {
            if tracker.is_failing() {
                Err(reason)
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_tracker_probes_ready() {
        let tracker = AuthFailureTracker::new();
        let probe = tracker.probe("auth is failing");
        assert_eq!(probe(), Ok(()));
    }

    #[test]
    fn recording_a_failure_flips_the_probe_to_failing() {
        let tracker = AuthFailureTracker::new();
        let probe = tracker.probe("auth is failing");
        assert_eq!(probe(), Ok(()));

        tracker.record_failure();
        assert_eq!(probe(), Err("auth is failing"));
    }

    #[test]
    fn recording_a_success_clears_a_prior_failure() {
        let tracker = AuthFailureTracker::new();
        tracker.record_failure();
        assert!(tracker.is_failing());

        tracker.record_success();
        assert!(!tracker.is_failing());
        assert_eq!(tracker.probe("auth is failing")(), Ok(()));
    }

    #[test]
    fn clones_share_the_same_underlying_state() {
        let tracker = AuthFailureTracker::new();
        let clone = tracker.clone();

        clone.record_failure();
        assert!(tracker.is_failing(), "state must be shared, not copied");

        tracker.record_success();
        assert!(!clone.is_failing());
    }

    #[test]
    fn probe_reflects_state_recorded_after_it_was_built() {
        // The probe closure must observe live state, not a snapshot taken
        // when `probe()` was called — `/readyz` calls it repeatedly over the
        // process lifetime.
        let tracker = AuthFailureTracker::new();
        let probe = tracker.probe("auth is failing");

        tracker.record_failure();
        assert_eq!(probe(), Err("auth is failing"));

        tracker.record_success();
        assert_eq!(probe(), Ok(()));
    }
}
