//! Attribution: the principal, actor type, and optional agent identity behind an action.

use uuid::Uuid;

/// The type of actor performing an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorType {
    /// A human operator directly invoking a tool.
    Human,
    /// An autonomous agent (LLM-driven or otherwise) acting under delegation.
    Agent,
}

/// Identity of an agent actor: the model, session, and MCP client name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    /// Model identifier (e.g. `"claude-sonnet-4-5"`).
    pub model_id: String,
    /// Agent session or run identifier.
    pub session_id: String,
    /// MCP client name or user-agent, if known.
    pub client_name: Option<String>,
}

/// Structured attribution: who is acting, under whose authority, and for what change.
///
/// This type is constructed from a [`mecmcp_auth::CallerCtx`] at the top of
/// a handler and carried through the audit and change-control paths. It is
/// never serialized with secrets: `principal` is a token name (not the token
/// itself), and the rest are metadata.
#[derive(Debug, Clone)]
pub struct Attribution {
    /// The authenticated principal. A token name today; an OIDC subject later.
    pub principal: String,
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
    /// know they are serving an agent should construct `Attribution` explicitly
    /// and set `actor_type = Agent` + the `agent` field.
    pub fn from_caller<G>(ctx: &mecmcp_auth::CallerCtx<G>) -> Self
    where
        G: mecmcp_auth::Grant,
    {
        Self {
            principal: ctx.token_name.clone(),
            actor_type: ActorType::Human,
            agent: None,
            on_behalf_of: None,
            change_ref: None,
            request_id: Uuid::new_v4(),
        }
    }

    /// Build an attribution for the stdio / no-auth path.
    ///
    /// The principal is `"stdio"` and the actor is assumed to be human.
    pub fn stdio() -> Self {
        Self {
            principal: "stdio".into(),
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
        }
    }

    #[test]
    fn from_caller_defaults_to_human_no_agent() {
        let c = ctx("ci-token");
        let a = Attribution::from_caller(&c);
        assert_eq!(a.principal, "ci-token");
        assert_eq!(a.actor_type, ActorType::Human);
        assert!(a.agent.is_none());
        assert!(a.on_behalf_of.is_none());
        assert!(a.change_ref.is_none());
    }

    #[test]
    fn stdio_attribution_is_usable() {
        let a = Attribution::stdio();
        assert_eq!(a.principal, "stdio");
        assert_eq!(a.actor_type, ActorType::Human);
        assert!(a.agent.is_none());
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
        });
        a.on_behalf_of = Some("alice".into());
        a.change_ref = Some("CHG0012345".into());

        assert_eq!(a.actor_type, ActorType::Agent);
        let agent = a.agent.as_ref().unwrap();
        assert_eq!(agent.model_id, "claude-sonnet-4-5");
        assert_eq!(agent.session_id, "sess-12345");
        assert_eq!(agent.client_name.as_deref(), Some("mcp-client/1.0"));
        assert_eq!(a.on_behalf_of.as_deref(), Some("alice"));
        assert_eq!(a.change_ref.as_deref(), Some("CHG0012345"));
    }
}
