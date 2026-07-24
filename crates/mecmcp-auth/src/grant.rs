//! The vendor seam: per-token write authority over opaque subjects.

use serde::{Deserialize, Serialize};

/// Rejection reason for a malformed grant.
#[derive(Debug, thiserror::Error)]
pub enum GrantError {
    /// The grant failed a structural check.
    #[error("{0}")]
    Invalid(String),
}

/// Per-token write authority.
///
/// A "subject" is an opaque, vendor-defined address of a configuration region —
/// an XPath subtree, a configuration path, a policy container. This crate never
/// interprets it; it only asks the implementing type whether a given subject and
/// action are permitted.
pub trait Grant: Clone + std::fmt::Debug + Send + Sync + 'static {
    /// The set of mutating actions this vendor distinguishes.
    type Action: Copy + Eq + std::fmt::Debug;

    /// Whether this grant permits an action.
    fn allows_action(&self, action: Self::Action) -> bool;

    /// Whether this grant permits mutating a subject.
    fn allows_subject(&self, subject: &str) -> bool;

    /// Structural validation, run at token-store load time.
    ///
    /// # Errors
    /// Returns [`GrantError::Invalid`] when the grant is malformed.
    fn validate(&self) -> Result<(), GrantError>;
}

/// The grant type for servers that do not yet model write authority.
///
/// Permits no action and no subject, so a token carrying it can never be
/// mistaken for one with write authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoGrant;

/// The uninhabited action set of [`NoGrant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoAction {}

impl Grant for NoGrant {
    type Action = NoAction;

    fn allows_action(&self, _action: Self::Action) -> bool {
        false
    }

    fn allows_subject(&self, _subject: &str) -> bool {
        false
    }

    fn validate(&self) -> Result<(), GrantError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stand-in for a vendor grant: prefix-matched subjects, enumerated actions.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct PrefixGrant {
        roots: Vec<String>,
        actions: Vec<TestAction>,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestAction {
        Set,
        Delete,
    }

    impl Grant for PrefixGrant {
        type Action = TestAction;

        fn allows_action(&self, action: Self::Action) -> bool {
            self.actions.contains(&action)
        }

        fn allows_subject(&self, subject: &str) -> bool {
            self.roots.iter().any(|root| {
                subject == root
                    || subject
                        .strip_prefix(root.as_str())
                        .is_some_and(|rest| rest.starts_with('/'))
            })
        }

        fn validate(&self) -> Result<(), GrantError> {
            if self.roots.is_empty() {
                return Err(GrantError::Invalid("grant needs at least one root".into()));
            }
            Ok(())
        }
    }

    fn grant() -> PrefixGrant {
        PrefixGrant {
            roots: vec!["/a/b".to_owned()],
            actions: vec![TestAction::Set],
        }
    }

    #[test]
    fn grant_permits_only_enumerated_actions() {
        assert!(grant().allows_action(TestAction::Set));
        assert!(!grant().allows_action(TestAction::Delete));
    }

    #[test]
    fn grant_permits_a_root_and_its_descendants() {
        assert!(grant().allows_subject("/a/b"));
        assert!(grant().allows_subject("/a/b/c"));
    }

    #[test]
    fn grant_rejects_a_sibling_that_merely_shares_a_prefix() {
        assert!(!grant().allows_subject("/a/bc"));
        assert!(!grant().allows_subject("/a"));
    }

    #[test]
    fn no_grant_permits_nothing() {
        assert!(!NoGrant.allows_subject("/a/b"));
        assert!(NoGrant.validate().is_ok());
    }
}
