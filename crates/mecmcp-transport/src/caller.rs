//! Grant-neutral authenticated caller identity for transport accounting.

use http::Extensions;

/// Non-secret token identity inserted by the shared bearer boundary.
///
/// Transport resource accounting needs only a stable token name. Keeping this
/// separate from generic `mecmcp_auth::CallerCtx<G>` lets a server retain its
/// vendor grant type without manufacturing a second, lossy
/// `CallerCtx<NoGrant>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedToken {
    name: String,
}

impl AuthenticatedToken {
    /// Construct an authenticated token identity.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Stable, non-secret token name used for resource accounting.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

pub(crate) fn token_name(extensions: &Extensions) -> Option<&str> {
    extensions
        .get::<AuthenticatedToken>()
        .map(AuthenticatedToken::name)
        .or_else(|| {
            extensions
                .get::<mecmcp_auth::CallerCtx>()
                .map(|caller| caller.token_name.as_str())
        })
}
