//! Allocation-free parsing for HTTP bearer credentials.

/// Maximum accepted `Authorization` header length.
///
/// This is deliberately generous enough for future OAuth access tokens while
/// placing a hard ceiling on attacker-controlled input.
const MAX_AUTHORIZATION_HEADER_BYTES: usize = 4096;

/// Compatibility policy for whitespace before the Bearer scheme.
///
/// # Examples
///
/// ```
/// use mecmcp_auth::{BearerSyntax, parse_bearer_header};
///
/// // Strict rejects leading whitespace
/// assert!(parse_bearer_header(" Bearer token", BearerSyntax::Strict).is_err());
///
/// // Trimmed accepts it
/// assert_eq!(
///     parse_bearer_header(" Bearer token", BearerSyntax::Trimmed),
///     Ok("token")
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerSyntax {
    /// Require the scheme to begin at byte zero.
    ///
    /// Whitespace separating the scheme from the credential and trailing
    /// horizontal whitespace remain accepted for PAN-OS compatibility.
    Strict,
    /// Trim outer whitespace before parsing.
    ///
    /// This preserves the deployed Junos parser's behavior.
    Trimmed,
}

/// A bearer-header parsing failure.
///
/// Variants never retain or display the presented credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BearerHeaderError {
    /// The header exceeds the configured hard limit.
    #[error("authorization header is too large")]
    TooLarge,
    /// The header is not valid visible ASCII or horizontal whitespace.
    #[error("authorization header contains invalid characters")]
    InvalidCharacters,
    /// The authorization scheme is absent or is not Bearer.
    #[error("authorization header must use the Bearer scheme")]
    WrongScheme,
    /// No credential follows the Bearer scheme.
    #[error("bearer credential is empty")]
    Empty,
    /// Whitespace appears inside the credential.
    #[error("bearer credential contains whitespace")]
    EmbeddedWhitespace,
}

/// Parse an HTTP `Authorization: Bearer …` value without allocating.
///
/// The scheme is case-insensitive. Whitespace around the credential is
/// tolerated, while embedded whitespace and control bytes are rejected.
/// [`BearerSyntax`] controls whether whitespace before the scheme is accepted.
///
/// # Examples
///
/// ```
/// use mecmcp_auth::{BearerSyntax, parse_bearer_header};
///
/// // Basic usage
/// assert_eq!(
///     parse_bearer_header("Bearer token123", BearerSyntax::Strict),
///     Ok("token123")
/// );
///
/// // Case-insensitive scheme
/// assert_eq!(
///     parse_bearer_header("bearer token123", BearerSyntax::Strict),
///     Ok("token123")
/// );
///
/// // Whitespace handling
/// assert_eq!(
///     parse_bearer_header("Bearer  token123  ", BearerSyntax::Strict),
///     Ok("token123")
/// );
/// ```
///
/// # Errors
///
/// Returns a stable, credential-free [`BearerHeaderError`] for malformed input:
///
/// ```
/// use mecmcp_auth::{BearerHeaderError, BearerSyntax, parse_bearer_header};
///
/// // Wrong scheme
/// assert_eq!(
///     parse_bearer_header("Basic token", BearerSyntax::Strict),
///     Err(BearerHeaderError::WrongScheme)
/// );
///
/// // Empty credential
/// assert_eq!(
///     parse_bearer_header("Bearer  ", BearerSyntax::Strict),
///     Err(BearerHeaderError::Empty)
/// );
///
/// // Embedded whitespace
/// assert_eq!(
///     parse_bearer_header("Bearer tok en", BearerSyntax::Strict),
///     Err(BearerHeaderError::EmbeddedWhitespace)
/// );
/// ```
pub fn parse_bearer_header(value: &str, syntax: BearerSyntax) -> Result<&str, BearerHeaderError> {
    if value.len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return Err(BearerHeaderError::TooLarge);
    }
    if !value
        .bytes()
        .all(|byte| byte == b'\t' || (byte.is_ascii() && !byte.is_ascii_control()))
    {
        return Err(BearerHeaderError::InvalidCharacters);
    }

    let value = match syntax {
        BearerSyntax::Strict => value,
        BearerSyntax::Trimmed => {
            value.trim_matches(|character: char| character.is_ascii_whitespace())
        }
    };
    let Some(separator) = value.find(|character: char| character.is_ascii_whitespace()) else {
        return if value.eq_ignore_ascii_case("bearer") {
            Err(BearerHeaderError::Empty)
        } else {
            Err(BearerHeaderError::WrongScheme)
        };
    };
    let (scheme, remainder) = value.split_at(separator);
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(BearerHeaderError::WrongScheme);
    }

    let credential = remainder.trim_matches(|character: char| character.is_ascii_whitespace());
    if credential.is_empty() {
        return Err(BearerHeaderError::Empty);
    }
    if credential
        .chars()
        .any(|character| character.is_ascii_whitespace())
    {
        return Err(BearerHeaderError::EmbeddedWhitespace);
    }

    Ok(credential)
}
