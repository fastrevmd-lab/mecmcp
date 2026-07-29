//! Optional scope preflight for middleware-layer authorization.

use mecmcp_auth::{CallerCtx, Grant, ScopeSet};
use serde_json::Value;
use std::sync::Arc;

/// Grant-neutral borrowed view of an authenticated caller's scopes.
#[derive(Debug, Clone, Copy)]
pub struct CallerScopes<'a> {
    /// Stable, non-secret token name.
    pub token_name: &'a str,
    /// Exact target-device scope.
    pub devices: &'a ScopeSet,
    /// Exact MCP tool scope.
    pub tools: &'a ScopeSet,
}

impl<'a, G: Grant> From<&'a CallerCtx<G>> for CallerScopes<'a> {
    fn from(caller: &'a CallerCtx<G>) -> Self {
        Self {
            token_name: &caller.token_name,
            devices: &caller.devices,
            tools: &caller.tools,
        }
    }
}

/// Preflight authorization check, run before the request reaches the handler.
///
/// Returning `Ok(())` allows the request to proceed. Returning `Err(reason)`
/// causes a 403 carrying that reason. The trait is synchronous because the
/// complete bounded body and caller scopes are already in memory.
pub trait ScopePreflight: Send + Sync {
    /// Check whether `caller` may issue the request carried in `body`.
    fn check(&self, body: &[u8], caller: CallerScopes<'_>) -> Result<(), String>;
}

/// An optional preflight. `None` disables it entirely.
pub type OptionalPreflight = Option<Arc<dyn ScopePreflight>>;

/// Run a preflight if one is configured.
pub fn run_preflight(
    preflight: &OptionalPreflight,
    body: &[u8],
    caller: CallerScopes<'_>,
) -> Result<(), String> {
    match preflight {
        Some(check) => check.check(body, caller),
        None => Ok(()),
    }
}

/// Handling for a present `params.arguments` value that is not an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedArgumentsPolicy {
    /// Reject the request before dispatch.
    Deny,
    /// Leave malformed protocol diagnosis to rmcp.
    Ignore,
}

/// Handling for a configured target field whose value has the wrong shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedTargetPolicy {
    /// Reject the request before dispatch.
    Deny,
    /// Ignore the field and leave validation to the handler.
    Ignore,
}

/// Supported target argument value shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetValueShape {
    /// One exact target name encoded as a JSON string.
    Scalar,
    /// One or more exact target names encoded as a JSON string array.
    NonEmptyArray,
}

/// One consumer-owned JSON-RPC target argument field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetField {
    name: &'static str,
    shape: TargetValueShape,
    malformed: MalformedTargetPolicy,
}

impl TargetField {
    /// A scalar string target that rejects malformed values.
    #[must_use]
    pub const fn scalar(name: &'static str) -> Self {
        Self {
            name,
            shape: TargetValueShape::Scalar,
            malformed: MalformedTargetPolicy::Deny,
        }
    }

    /// A scalar target whose malformed values remain for handler validation.
    #[must_use]
    pub const fn scalar_ignoring_malformed(name: &'static str) -> Self {
        Self {
            name,
            shape: TargetValueShape::Scalar,
            malformed: MalformedTargetPolicy::Ignore,
        }
    }

    /// A non-empty string-array target that rejects malformed values.
    #[must_use]
    pub const fn non_empty_array(name: &'static str) -> Self {
        Self {
            name,
            shape: TargetValueShape::NonEmptyArray,
            malformed: MalformedTargetPolicy::Deny,
        }
    }
}

/// Reusable JSON-RPC `tools/call` scope preflight.
#[derive(Debug, Clone)]
pub struct ToolScopePreflight {
    write_tools: &'static [&'static str],
    target_fields: Vec<TargetField>,
    malformed_arguments: MalformedArgumentsPolicy,
}

impl ToolScopePreflight {
    /// Construct a preflight from consumer-owned tool and target vocabulary.
    #[must_use]
    pub fn new(
        write_tools: &'static [&'static str],
        target_fields: impl IntoIterator<Item = TargetField>,
        malformed_arguments: MalformedArgumentsPolicy,
    ) -> Self {
        Self {
            write_tools,
            target_fields: target_fields.into_iter().collect(),
            malformed_arguments,
        }
    }

    fn request_exceeds_scope(&self, value: &Value, caller: CallerScopes<'_>) -> bool {
        if value.get("method").and_then(Value::as_str) != Some("tools/call") {
            return false;
        }
        let Some(params) = value.get("params") else {
            return false;
        };
        let Some(tool) = params.get("name").and_then(Value::as_str) else {
            return false;
        };
        if !caller.tools.allows_tool(tool, self.write_tools) {
            return true;
        }

        let Some(arguments_value) = params.get("arguments") else {
            return false;
        };
        let Some(arguments) = arguments_value.as_object() else {
            return self.malformed_arguments == MalformedArgumentsPolicy::Deny;
        };

        self.target_fields.iter().any(|field| {
            arguments
                .get(field.name)
                .is_some_and(|value| !target_value_in_scope(value, *field, caller.devices))
        })
    }
}

impl ScopePreflight for ToolScopePreflight {
    fn check(&self, body: &[u8], caller: CallerScopes<'_>) -> Result<(), String> {
        if body.is_empty() {
            return Ok(());
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return Ok(());
        };
        let denied = match value {
            Value::Array(values) => values
                .iter()
                .any(|value| self.request_exceeds_scope(value, caller)),
            value => self.request_exceeds_scope(&value, caller),
        };
        if denied {
            Err("insufficient_scope".to_owned())
        } else {
            Ok(())
        }
    }
}

fn target_value_in_scope(value: &Value, field: TargetField, devices: &ScopeSet) -> bool {
    let valid = match field.shape {
        TargetValueShape::Scalar => value.as_str().is_some_and(|name| devices.allows(name)),
        TargetValueShape::NonEmptyArray => value.as_array().is_some_and(|names| {
            !names.is_empty()
                && names
                    .iter()
                    .all(|name| name.as_str().is_some_and(|name| devices.allows(name)))
        }),
    };
    valid
        || field.malformed == MalformedTargetPolicy::Ignore && !value_has_shape(value, field.shape)
}

fn value_has_shape(value: &Value, shape: TargetValueShape) -> bool {
    match shape {
        TargetValueShape::Scalar => value.is_string(),
        TargetValueShape::NonEmptyArray => value
            .as_array()
            .is_some_and(|values| !values.is_empty() && values.iter().all(Value::is_string)),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const FORBIDDEN: &[u8] = br#"{"method":"tools/call","params":{"name":"forbidden_tool"}}"#;

    fn caller() -> CallerCtx {
        CallerCtx {
            token_name: "t1".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
            provider: None,
            provider_tier: None,
            on_behalf_of: None,
            actor_type: mecmcp_auth::ActorType::Human,
        }
    }

    struct AlwaysReject;
    impl ScopePreflight for AlwaysReject {
        fn check(&self, _body: &[u8], _caller: CallerScopes<'_>) -> Result<(), String> {
            Err("insufficient_scope".to_owned())
        }
    }

    #[test]
    fn none_admits_a_body_that_some_rejects() {
        let caller = caller();
        let scopes = CallerScopes::from(&caller);
        let rejecting: OptionalPreflight = Some(Arc::new(AlwaysReject));
        assert_eq!(
            run_preflight(&rejecting, FORBIDDEN, scopes),
            Err("insufficient_scope".to_owned())
        );
        assert_eq!(run_preflight(&None, FORBIDDEN, scopes), Ok(()));
    }

    #[test]
    fn body_reaches_the_implementation_unaltered() {
        struct Capture(std::sync::Mutex<Vec<u8>>);
        impl ScopePreflight for Capture {
            fn check(&self, body: &[u8], _caller: CallerScopes<'_>) -> Result<(), String> {
                *self.0.lock().unwrap() = body.to_vec();
                Ok(())
            }
        }

        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        let preflight: OptionalPreflight = Some(capture.clone());
        let caller = caller();
        run_preflight(&preflight, FORBIDDEN, CallerScopes::from(&caller)).unwrap();
        assert_eq!(capture.0.lock().unwrap().as_slice(), FORBIDDEN);
    }
}
