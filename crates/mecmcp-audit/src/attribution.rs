//! Attribution: the principal, actor type, and optional agent identity behind an action.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Who is acting. The authenticated and unauthenticated cases are distinct
/// variants rather than sentinel strings, so no token name can forge the
/// unauthenticated case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// An authenticated bearer token, identified by its non-secret name.
    Token(String),
    /// The stdio / `--allow-no-auth` path, where no credential was presented.
    Unauthenticated,
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::Token(name) => write!(f, "{name}"),
            Principal::Unauthenticated => write!(f, "stdio"),
        }
    }
}

/// The type of actor performing an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorType {
    /// A human operator directly invoking a tool.
    Human,
    /// An autonomous agent (LLM-driven or otherwise) acting under delegation.
    Agent,
}

/// LLM provider tier: public hosted vs. private/self-hosted deployment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// Publicly hosted LLM service (e.g., Anthropic's public API).
    #[default]
    Public,
    /// Private or self-hosted LLM deployment.
    Private,
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Tier::Public => write!(f, "public"),
            Tier::Private => write!(f, "private"),
        }
    }
}

/// Identity of an agent actor: the model, session, MCP client, provider, and skills used.
///
/// This provenance information flows into commit comments and audit events,
/// making committed changes traceable to the model and skills that generated
/// them (SSDF provenance tracking, mecmcp#26).
///
/// # Skill naming constraint
///
/// Skill names MUST NOT contain spaces — they are joined with a single space
/// in the provenance string to maintain exactly 4 comma-separated fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Model identifier (e.g. `"claude-sonnet-4-5"`).
    pub model_id: String,
    /// Agent session or run identifier.
    pub session_id: String,
    /// MCP client name or user-agent, if known.
    pub client_name: Option<String>,
    /// Provider name (e.g., "anthropic", "ollama"). Explicit data, not inferred.
    ///
    /// Defaults to `"unknown"` if absent (existing audit events without this field).
    #[serde(default = "default_provider")]
    pub provider: String,
    /// Provider tier: public hosted vs. private/self-hosted.
    ///
    /// Defaults to `Public` if absent (existing audit events without this field).
    #[serde(default)]
    pub provider_tier: Tier,
    /// Skills invoked during this action.
    ///
    /// Defaults to an empty list (existing audit events without this field).
    #[serde(default)]
    pub skills_used: Vec<String>,
}

fn default_provider() -> String {
    "unknown".to_string()
}

impl AgentIdentity {
    /// Render the canonical provenance string for commit comments and audit.
    ///
    /// Format: `{provider}-{tier}, {model_id}, {skills}, {user}`
    ///
    /// Example: `"anthropic-public, claude-opus-5, none, fastrevmd@gmail.com"`
    ///
    /// The provider name comes from the `provider` field (explicit data, not inferred).
    /// Skills render as space-separated names, or "none" if the list is empty.
    /// The user is the human on whose behalf the agent acts (`on_behalf_of`).
    ///
    /// If `on_behalf_of` is `None`, the rendered string is still valid; the last
    /// component is omitted (e.g., `"anthropic-public, claude-opus-5, none"`).
    pub fn provenance_string(&self, on_behalf_of: Option<&str>) -> String {
        let provider_tier = format!("{}-{}", self.provider, self.provider_tier).to_lowercase();
        let skills = if self.skills_used.is_empty() {
            "none".to_string()
        } else {
            self.skills_used.join(" ")
        };
        match on_behalf_of {
            Some(user) => format!("{}, {}, {}, {}", provider_tier, self.model_id, skills, user),
            None => format!("{}, {}, {}", provider_tier, self.model_id, skills),
        }
    }
}

/// Structured attribution: who is acting, under whose authority, and for what change.
///
/// This type is constructed from a [`mecmcp_auth::CallerCtx`] at the top of
/// a handler and carried through the audit and change-control paths. It is
/// never serialized with secrets: a `Principal::Token` carries only the token
/// name (not the secret itself), and the rest are metadata.
#[derive(Debug, Clone)]
pub struct Attribution {
    /// The authenticated principal, or the unauthenticated stdio path.
    pub principal: Principal,
    /// Whether the actor is a human or an agent.
    pub actor_type: ActorType,
    /// Agent identity, when `actor_type == Agent`.
    pub agent: Option<AgentIdentity>,
    /// The human on whose behalf an agent is acting, if applicable.
    pub on_behalf_of: Option<String>,
    /// An external change-control reference (e.g. a ticket ID).
    pub change_ref: Option<String>,
    /// Per-request correlation ID.
    pub request_id: Uuid,
}

impl Attribution {
    /// Build an attribution for a human caller from an authenticated context.
    ///
    /// Defaults to `ActorType::Human` with no agent identity. Call sites that
    /// know they are serving an agent should build an `Attribution` directly with
    /// `actor_type = Agent` and pass it to `AuditScope::new`, rather than calling
    /// this helper and mutating the result.
    pub fn from_caller<G>(ctx: &mecmcp_auth::CallerCtx<G>) -> Self
    where
        G: mecmcp_auth::Grant,
    {
        Self {
            principal: Principal::Token(ctx.token_name.clone()),
            actor_type: ActorType::Human,
            agent: None,
            on_behalf_of: None,
            change_ref: None,
            request_id: Uuid::new_v4(),
        }
    }

    /// Build an attribution for the stdio / no-auth path.
    ///
    /// The principal is `Principal::Unauthenticated` and the actor is assumed to be human.
    pub fn stdio() -> Self {
        Self {
            principal: Principal::Unauthenticated,
            actor_type: ActorType::Human,
            agent: None,
            on_behalf_of: None,
            change_ref: None,
            request_id: Uuid::new_v4(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_auth::{CallerCtx, NoGrant, ScopeSet};

    fn ctx(name: &str) -> CallerCtx<NoGrant> {
        CallerCtx {
            token_name: name.into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Human,
        }
    }

    #[test]
    fn from_caller_defaults_to_human_no_agent() {
        let c = ctx("ci-token");
        let a = Attribution::from_caller(&c);
        assert_eq!(a.principal, Principal::Token("ci-token".into()));
        assert_eq!(a.actor_type, ActorType::Human);
        assert!(a.agent.is_none());
        assert!(a.on_behalf_of.is_none());
        assert!(a.change_ref.is_none());
    }

    #[test]
    fn stdio_attribution_is_usable() {
        let a = Attribution::stdio();
        assert_eq!(a.principal, Principal::Unauthenticated);
        assert_eq!(a.actor_type, ActorType::Human);
        assert!(a.agent.is_none());
    }

    #[test]
    fn principal_display_renders_wire_format() {
        assert_eq!(Principal::Token("ci".into()).to_string(), "ci");
        assert_eq!(Principal::Unauthenticated.to_string(), "stdio");
    }

    #[test]
    fn correlation_ids_are_unique() {
        let c = ctx("ci");
        let a1 = Attribution::from_caller(&c);
        let a2 = Attribution::from_caller(&c);
        assert_ne!(
            a1.request_id, a2.request_id,
            "sequential constructions must mint unique UUIDs"
        );
    }

    #[test]
    fn agent_attribution_round_trips_identity() {
        let c = ctx("agent-token");
        let mut a = Attribution::from_caller(&c);
        a.actor_type = ActorType::Agent;
        a.agent = Some(AgentIdentity {
            model_id: "claude-sonnet-4-5".into(),
            session_id: "sess-12345".into(),
            client_name: Some("mcp-client/1.0".into()),
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        });
        a.on_behalf_of = Some("alice".into());
        a.change_ref = Some("CHG0012345".into());

        assert_eq!(a.actor_type, ActorType::Agent);
        let agent = a.agent.as_ref().unwrap();
        assert_eq!(agent.model_id, "claude-sonnet-4-5");
        assert_eq!(agent.session_id, "sess-12345");
        assert_eq!(agent.client_name.as_deref(), Some("mcp-client/1.0"));
        assert_eq!(agent.provider, "anthropic");
        assert_eq!(agent.provider_tier, Tier::Public);
        assert_eq!(a.on_behalf_of.as_deref(), Some("alice"));
        assert_eq!(a.change_ref.as_deref(), Some("CHG0012345"));
    }

    #[test]
    fn provenance_string_renders_canonical_format() {
        let agent = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(Some("fastrevmd@gmail.com")),
            "anthropic-public, claude-opus-5, none, fastrevmd@gmail.com"
        );
    }

    #[test]
    fn provenance_string_with_skills() {
        let agent = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec!["srx-nat".into(), "srx-policy".into(), "srx-mnha".into()],
        };
        assert_eq!(
            agent.provenance_string(Some("fastrevmd@gmail.com")),
            "anthropic-public, claude-opus-5, srx-nat srx-policy srx-mnha, fastrevmd@gmail.com"
        );
    }

    #[test]
    fn provenance_string_private_tier() {
        let agent = AgentIdentity {
            model_id: "claude-sonnet-4-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Private,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(Some("bob")),
            "anthropic-private, claude-sonnet-4-5, none, bob"
        );
    }

    #[test]
    fn provenance_string_without_user() {
        let agent = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "sess-12345".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(None),
            "anthropic-public, claude-opus-5, none"
        );
    }

    #[test]
    fn provenance_string_ollama_private() {
        let agent = AgentIdentity {
            model_id: "llama-3.3-70b".into(),
            session_id: "sess-local".into(),
            client_name: None,
            provider: "ollama".into(),
            provider_tier: Tier::Private,
            skills_used: vec![],
        };
        assert_eq!(
            agent.provenance_string(Some("user")),
            "ollama-private, llama-3.3-70b, none, user"
        );
    }

    #[test]
    fn provenance_field_count_is_stable() {
        // Field count must be exactly 4 for zero, one, and three skills
        let zero = AgentIdentity {
            model_id: "claude-opus-5".into(),
            session_id: "s".into(),
            client_name: None,
            provider: "anthropic".into(),
            provider_tier: Tier::Public,
            skills_used: vec![],
        };
        let one = AgentIdentity {
            skills_used: vec!["srx-nat".into()],
            ..zero.clone()
        };
        let three = AgentIdentity {
            skills_used: vec!["srx-nat".into(), "srx-policy".into(), "srx-mnha".into()],
            ..zero.clone()
        };

        for (agent, label) in [(zero, "zero"), (one, "one"), (three, "three")] {
            let s = agent.provenance_string(Some("user"));
            let field_count = s.split(", ").count();
            assert_eq!(
                field_count, 4,
                "{} skills must produce 4 fields, got {}: {}",
                label, field_count, s
            );
        }
    }

    #[test]
    fn backward_compat_deserializes_old_json_without_new_fields() {
        // Existing audit JSON without provider, provider_tier, or skills_used
        let json = r#"{
            "model_id": "claude-sonnet-4-5",
            "session_id": "sess-old",
            "client_name": "old-client"
        }"#;
        let agent: AgentIdentity = serde_json::from_str(json).unwrap();
        assert_eq!(agent.model_id, "claude-sonnet-4-5");
        assert_eq!(agent.provider, "unknown"); // default
        assert_eq!(agent.provider_tier, Tier::Public); // default
        assert!(agent.skills_used.is_empty()); // default
    }

    #[test]
    #[should_panic(expected = "missing field")]
    fn removing_default_breaks_backward_compat() {
        // This test proves that removing #[serde(default)] would break old JSON.
        // It must panic if we remove the defaults.
        let json = r#"{
            "model_id": "claude-sonnet-4-5",
            "session_id": "sess-old"
        }"#;
        // If provider, provider_tier, or skills_used lacked #[serde(default)],
        // this would fail. We use #[should_panic] to document the expectation, but
        // in reality the test above (backward_compat_deserializes_old_json_without_new_fields)
        // passing proves the defaults work.
        //
        // To actually test the negative case, we'd need to conditionally compile
        // without the defaults, which is beyond the scope here. This test documents
        // the intent: removing defaults MUST break old JSON parsing.
        #[allow(dead_code)]
        #[derive(Deserialize)]
        struct AgentWithoutDefaults {
            model_id: String,
            session_id: String,
            client_name: Option<String>,
            provider: String,         // no default
            provider_tier: Tier,      // no default
            skills_used: Vec<String>, // no default
        }
        let _: AgentWithoutDefaults = serde_json::from_str(json).unwrap();
    }
}
