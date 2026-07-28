//! Authenticated caller extraction from `rmcp` request extensions.

use mecmcp_auth::{CallerCtx, Grant};
use rmcp::model::Extensions;

/// Recover the authenticated caller inserted by the HTTP authentication layer.
///
/// `rmcp` stores the original HTTP request parts as one extension. The bearer
/// middleware's caller context therefore remains nested inside those parts.
/// Stdio requests contain no HTTP parts and return `None`.
#[must_use]
pub fn caller_from_extensions<G: Grant>(extensions: &Extensions) -> Option<&CallerCtx<G>> {
    extensions
        .get::<http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<CallerCtx<G>>())
}
