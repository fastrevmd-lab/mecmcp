//! Optional scope preflight for middleware-layer authorization.
//!
//! PAN-OS runs a preflight that parses the request body and checks the tool plus
//! `params.arguments.device` against the token's scopes, returning 403
//! `insufficient_scope`. Junos has no equivalent and defers to its handler.
//!
//! `None` must be behaviourally identical to Junos today.

use mecmcp_auth::CallerCtx;
use std::sync::Arc;

/// Preflight authorization check, run before the request reaches the handler.
///
/// Returning `Ok(())` allows the request to proceed. Returning `Err(reason)`
/// causes a 403 carrying that reason.
///
/// # Why this is synchronous
///
/// The body arrives as `&[u8]` rather than as a `Request`, and the method does
/// not return a future. Both follow from what the only real implementation
/// does: `rustpanosmcp`'s `request_exceeds_scope(bytes: &[u8], caller:
/// &CallerContext) -> bool` and its `tool_call_exceeds_scope` contain **zero**
/// `await` points — they parse an in-memory buffer and compare against scopes
/// already loaded in `CallerCtx`.
///
/// The middleware has those bytes in hand regardless, because it must buffer
/// the body to enforce the size limit. Making this `async` would therefore add
/// an `async-trait` dependency and a `Box<dyn Future>` allocation on the hot
/// path of every MCP request, to await nothing. If a future implementation
/// genuinely needs to await — consulting a remote authorization service, say —
/// this trait changes then, and the crate has no external consumers yet to
/// break.
pub trait ScopePreflight: Send + Sync {
    /// Check whether `caller` may issue the request carried in `body`.
    ///
    /// `body` is the complete, already-buffered request body. `Err` should
    /// carry a reason safe to return to the caller.
    fn check(&self, body: &[u8], caller: &CallerCtx) -> Result<(), String>;
}

/// An optional preflight. `None` disables it entirely.
pub type OptionalPreflight = Option<Arc<dyn ScopePreflight>>;

/// Run a preflight if one is configured.
///
/// This is the whole of the `None` contract: with no preflight there is no
/// check, and every request proceeds exactly as it does on a server that never
/// had one. Middleware calls this rather than matching on the `Option` itself,
/// so the skip semantics live in one place and are testable.
pub fn run_preflight(
    preflight: &OptionalPreflight,
    body: &[u8],
    caller: &CallerCtx,
) -> Result<(), String> {
    match preflight {
        Some(check) => check.check(body, caller),
        None => Ok(()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use mecmcp_auth::ScopeSet;

    /// Body that a scope-checking preflight would reject: a tool call naming a
    /// tool and device the caller has no claim to.
    const FORBIDDEN: &[u8] = br#"{"method":"tools/call","params":{"name":"forbidden_tool","arguments":{"device":"blocked"}}}"#;

    fn caller() -> CallerCtx {
        CallerCtx {
            token_name: "t1".into(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
        }
    }

    struct AlwaysReject;
    impl ScopePreflight for AlwaysReject {
        fn check(&self, _body: &[u8], _caller: &CallerCtx) -> Result<(), String> {
            Err("insufficient_scope".to_owned())
        }
    }

    /// Task 7's requirement, asserted on behaviour rather than on the shape of
    /// the `Option`: the *same* body that `Some(...)` rejects must be admitted
    /// when the preflight is `None`. Checking only `preflight.is_none()` would
    /// pass even if `run_preflight` rejected everything.
    #[test]
    fn none_admits_a_body_that_some_rejects() {
        let caller = caller();

        let rejecting: OptionalPreflight = Some(Arc::new(AlwaysReject));
        assert_eq!(
            run_preflight(&rejecting, FORBIDDEN, &caller),
            Err("insufficient_scope".to_owned()),
            "the fixture must actually be rejected, or the None case proves nothing"
        );

        let disabled: OptionalPreflight = None;
        assert_eq!(
            run_preflight(&disabled, FORBIDDEN, &caller),
            Ok(()),
            "None must admit every request — this is the Junos behaviour"
        );
    }

    /// The preflight sees the body the middleware buffered, unmodified.
    #[test]
    fn body_reaches_the_implementation_unaltered() {
        struct Capture(std::sync::Mutex<Vec<u8>>);
        impl ScopePreflight for Capture {
            fn check(&self, body: &[u8], _caller: &CallerCtx) -> Result<(), String> {
                *self.0.lock().unwrap() = body.to_vec();
                Ok(())
            }
        }

        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        let preflight: OptionalPreflight = Some(capture.clone());

        run_preflight(&preflight, FORBIDDEN, &caller()).unwrap();

        assert_eq!(capture.0.lock().unwrap().as_slice(), FORBIDDEN);
    }
}
