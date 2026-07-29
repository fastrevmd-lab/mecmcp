//! Public bearer-header parsing contracts.

use mecmcp_auth::{BearerHeaderError, BearerSyntax, parse_bearer_header};

#[test]
fn strict_syntax_preserves_the_panos_outer_whitespace_behavior() {
    assert_eq!(
        parse_bearer_header("bEaReR token-123", BearerSyntax::Strict),
        Ok("token-123")
    );
    assert_eq!(
        parse_bearer_header("Bearer\t  token-123 \t", BearerSyntax::Strict),
        Ok("token-123")
    );
    assert_eq!(
        parse_bearer_header("Bearer one two", BearerSyntax::Strict),
        Err(BearerHeaderError::EmbeddedWhitespace)
    );
}

#[test]
fn trimmed_syntax_preserves_the_deployed_junos_behavior() {
    assert_eq!(
        parse_bearer_header(" Bearer    token-123   ", BearerSyntax::Trimmed),
        Ok("token-123")
    );
}

#[test]
fn invalid_schemes_and_empty_credentials_have_stable_errors() {
    assert_eq!(
        parse_bearer_header("Basic abc", BearerSyntax::Strict),
        Err(BearerHeaderError::WrongScheme)
    );
    assert_eq!(
        parse_bearer_header("Bearer ", BearerSyntax::Trimmed),
        Err(BearerHeaderError::Empty)
    );
}
