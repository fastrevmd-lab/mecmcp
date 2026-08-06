//! Grant-neutral authenticated caller identity for transport accounting.

use http::Extensions;

/// Non-secret token identity inserted by the shared bearer boundary.
///
/// Transport resource accounting needs only a stable token name. Keeping this
/// separate from generic `mecmcp_auth::CallerCtx<G>` lets a server retain its
/// vendor grant type without manufacturing a second, lossy
/// `CallerCtx<NoGrant>`.
///
/// # Inserted by the bearer boundary
///
/// `bearer_boundary` middleware inserts this into request extensions alongside
/// `CallerCtx<G>`. Rate limiting and session tracking use this rather than
/// `CallerCtx` because they must work regardless of whether the consumer's
/// grant type is `NoGrant`, `SdGrant`, or something else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedToken {
    name: String,
}

impl AuthenticatedToken {
    /// Construct an authenticated token identity.
    ///
    /// # Example
    ///
    /// ```
    /// use mecmcp_transport::AuthenticatedToken;
    ///
    /// let token = AuthenticatedToken::new("operator");
    /// assert_eq!(token.name(), "operator");
    /// ```
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }

    /// Stable, non-secret token name used for resource accounting.
    ///
    /// This is the same name stored in `CallerCtx::token_name`, but available
    /// without knowing the grant type `G`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Extract the token name from request extensions.
///
/// Checks `AuthenticatedToken` first, then falls back to `CallerCtx`. This
/// allows transport accounting (rate limiting, session tracking) to work
/// regardless of whether the caller was authenticated by the bearer boundary
/// or inserted manually for testing.
///
/// Returns `None` if neither extension is present.
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
