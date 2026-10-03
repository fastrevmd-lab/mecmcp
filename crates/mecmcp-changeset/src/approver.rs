//! The identity of the principal approving a change set (MEC-994 W4).
//!
//! Replaces the old `approver_actor_type: ActorType` parameter to
//! `approve_change_set`: an actor type alone says "this token is declared
//! human", which is a label the token's own owner chose at `token add` time.
//! It says nothing about who is actually holding it. [`ApproverIdentity`]
//! carries that distinction through the rest of the crate so the approval
//! digest and the strict-mode gate can tell the two apart.

/// Identity of the principal approving a change set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverIdentity {
    /// The approver is known only by their bearer token's declared actor
    /// type — the identity assertion that predates MEC-994, and the only
    /// one available when no IdP is configured.
    TokenAsserted {
        /// Principal identifier (token name).
        principal: String,
        /// The token's declared actor type. Must be `Human` for the
        /// approval to succeed; carried here rather than checked by the
        /// caller so every call site is judged by the same rule.
        actor_type: mecmcp_audit::ActorType,
    },
    /// The approver additionally presented a fresh IdP-issued JWT, verified
    /// and bound to their token by `mecmcp_auth::bind_approver` (W3). A
    /// bound assertion only ever comes from a `human` token, so this variant
    /// never needs a separate actor-type check.
    OidcVerified {
        /// Principal identifier (token name).
        principal: String,
        /// The IdP issuer that signed the verified assertion.
        issuer: String,
        /// The IdP's `sub` claim for the approver.
        subject: String,
    },
}

impl ApproverIdentity {
    /// The principal identifier, regardless of how it was asserted.
    #[must_use]
    pub fn principal(&self) -> &str {
        match self {
            Self::TokenAsserted { principal, .. } | Self::OidcVerified { principal, .. } => {
                principal
            }
        }
    }

    /// Whether this identity satisfies the house rule that a human approves.
    pub(crate) fn is_human(&self) -> bool {
        match self {
            Self::TokenAsserted { actor_type, .. } => *actor_type == mecmcp_audit::ActorType::Human,
            Self::OidcVerified { .. } => true,
        }
    }

    /// The mechanism name signed into the v7 approval digest.
    pub(crate) fn mechanism(&self) -> &'static str {
        match self {
            Self::TokenAsserted { .. } => "token",
            Self::OidcVerified { .. } => "oidc",
        }
    }

    /// The verified `(issuer, subject)` pair, when this identity carries one.
    pub(crate) fn oidc_subject(&self) -> Option<(&str, &str)> {
        match self {
            Self::OidcVerified {
                issuer, subject, ..
            } => Some((issuer.as_str(), subject.as_str())),
            Self::TokenAsserted { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_asserted_human_is_human() {
        let identity = ApproverIdentity::TokenAsserted {
            principal: "alice".to_owned(),
            actor_type: mecmcp_audit::ActorType::Human,
        };
        assert!(identity.is_human());
        assert_eq!(identity.mechanism(), "token");
        assert_eq!(identity.oidc_subject(), None);
    }

    #[test]
    fn token_asserted_agent_is_not_human() {
        let identity = ApproverIdentity::TokenAsserted {
            principal: "agent-1".to_owned(),
            actor_type: mecmcp_audit::ActorType::Agent,
        };
        assert!(!identity.is_human());
    }

    #[test]
    fn oidc_verified_is_human_and_carries_subject() {
        let identity = ApproverIdentity::OidcVerified {
            principal: "bob".to_owned(),
            issuer: "https://idp.example".to_owned(),
            subject: "bob-sub".to_owned(),
        };
        assert!(identity.is_human());
        assert_eq!(identity.mechanism(), "oidc");
        assert_eq!(
            identity.oidc_subject(),
            Some(("https://idp.example", "bob-sub"))
        );
        assert_eq!(identity.principal(), "bob");
    }
}
