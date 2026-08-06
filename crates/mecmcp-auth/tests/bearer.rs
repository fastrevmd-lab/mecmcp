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

#[test]
fn scheme_is_case_insensitive() {
    assert_eq!(
        parse_bearer_header("bearer token", BearerSyntax::Strict),
        Ok("token")
    );
    assert_eq!(
        parse_bearer_header("BEARER token", BearerSyntax::Strict),
        Ok("token")
    );
    assert_eq!(
        parse_bearer_header("BeArEr token", BearerSyntax::Strict),
        Ok("token")
    );
}

#[test]
fn leading_whitespace_rejected_in_strict_mode() {
    assert_eq!(
        parse_bearer_header(" Bearer token", BearerSyntax::Strict),
        Err(BearerHeaderError::WrongScheme)
    );
    assert_eq!(
        parse_bearer_header("\tBearer token", BearerSyntax::Strict),
        Err(BearerHeaderError::WrongScheme)
    );
}

#[test]
fn leading_whitespace_accepted_in_trimmed_mode() {
    assert_eq!(
        parse_bearer_header(" Bearer token", BearerSyntax::Trimmed),
        Ok("token")
    );
    assert_eq!(
        parse_bearer_header("\t\tBearer token", BearerSyntax::Trimmed),
        Ok("token")
    );
    assert_eq!(
        parse_bearer_header("  \t  Bearer token  \t  ", BearerSyntax::Trimmed),
        Ok("token")
    );
}

#[test]
fn trailing_whitespace_is_trimmed() {
    assert_eq!(
        parse_bearer_header("Bearer token   ", BearerSyntax::Strict),
        Ok("token")
    );
    assert_eq!(
        parse_bearer_header("Bearer token\t\t", BearerSyntax::Strict),
        Ok("token")
    );
}

#[test]
fn interior_whitespace_in_credential_is_rejected() {
    assert_eq!(
        parse_bearer_header("Bearer one two", BearerSyntax::Strict),
        Err(BearerHeaderError::EmbeddedWhitespace)
    );
    assert_eq!(
        parse_bearer_header("Bearer one\ttwo", BearerSyntax::Trimmed),
        Err(BearerHeaderError::EmbeddedWhitespace)
    );
    assert_eq!(
        parse_bearer_header("Bearer a b c", BearerSyntax::Strict),
        Err(BearerHeaderError::EmbeddedWhitespace)
    );
}

#[test]
fn empty_credential_is_rejected() {
    assert_eq!(
        parse_bearer_header("Bearer", BearerSyntax::Strict),
        Err(BearerHeaderError::Empty)
    );
    assert_eq!(
        parse_bearer_header("Bearer   ", BearerSyntax::Strict),
        Err(BearerHeaderError::Empty)
    );
    assert_eq!(
        parse_bearer_header("Bearer\t\t", BearerSyntax::Trimmed),
        Err(BearerHeaderError::Empty)
    );
}

#[test]
fn non_ascii_characters_are_rejected() {
    assert_eq!(
        parse_bearer_header("Bearer tok€n", BearerSyntax::Strict),
        Err(BearerHeaderError::InvalidCharacters)
    );
    assert_eq!(
        parse_bearer_header("Bearer tökën", BearerSyntax::Trimmed),
        Err(BearerHeaderError::InvalidCharacters)
    );
    assert_eq!(
        parse_bearer_header("Bearer 你好", BearerSyntax::Strict),
        Err(BearerHeaderError::InvalidCharacters)
    );
}

#[test]
fn control_characters_except_tab_are_rejected() {
    assert_eq!(
        parse_bearer_header("Bearer tok\nen", BearerSyntax::Strict),
        Err(BearerHeaderError::InvalidCharacters)
    );
    assert_eq!(
        parse_bearer_header("Bearer tok\ren", BearerSyntax::Strict),
        Err(BearerHeaderError::InvalidCharacters)
    );
    assert_eq!(
        parse_bearer_header("Bearer tok\0en", BearerSyntax::Strict),
        Err(BearerHeaderError::InvalidCharacters)
    );
    // Tab is allowed as whitespace separator, not inside credential
    assert_eq!(
        parse_bearer_header("Bearer\ttoken", BearerSyntax::Strict),
        Ok("token")
    );
}

#[test]
fn header_exactly_at_4096_bytes_is_accepted() {
    // "Bearer " = 7 bytes, so credential should be 4089 bytes
    let credential = "x".repeat(4089);
    let header = format!("Bearer {}", credential);
    assert_eq!(header.len(), 4096);
    assert_eq!(
        parse_bearer_header(&header, BearerSyntax::Strict),
        Ok(credential.as_str())
    );
}

#[test]
fn header_exceeding_4096_bytes_is_rejected() {
    // "Bearer " = 7 bytes, so credential of 4090 bytes = 4097 total
    let credential = "x".repeat(4090);
    let header = format!("Bearer {}", credential);
    assert_eq!(header.len(), 4097);
    assert_eq!(
        parse_bearer_header(&header, BearerSyntax::Strict),
        Err(BearerHeaderError::TooLarge)
    );
}

#[test]
fn wrong_scheme_is_rejected() {
    assert_eq!(
        parse_bearer_header("Basic token", BearerSyntax::Strict),
        Err(BearerHeaderError::WrongScheme)
    );
    assert_eq!(
        parse_bearer_header("Digest abc", BearerSyntax::Trimmed),
        Err(BearerHeaderError::WrongScheme)
    );
    assert_eq!(
        parse_bearer_header("OAuth token", BearerSyntax::Strict),
        Err(BearerHeaderError::WrongScheme)
    );
}

#[test]
fn error_messages_never_contain_credential() {
    let test_cases = vec![
        ("Bearer secret123", BearerHeaderError::Empty), // won't match, but let's test error rendering
        ("Bearer sec ret", BearerHeaderError::EmbeddedWhitespace),
        ("Basic secret123", BearerHeaderError::WrongScheme),
    ];

    for (input, _expected_error) in test_cases {
        if let Err(error) = parse_bearer_header(input, BearerSyntax::Strict) {
            let error_display = error.to_string();
            let error_debug = format!("{:?}", error);

            assert!(
                !error_display.contains("secret"),
                "Display output must not contain credential part: {}",
                error_display
            );
            assert!(
                !error_debug.contains("secret"),
                "Debug output must not contain credential part: {}",
                error_debug
            );
            assert!(
                !error_display.contains("123"),
                "Display output must not contain credential part: {}",
                error_display
            );
            assert!(
                !error_debug.contains("123"),
                "Debug output must not contain credential part: {}",
                error_debug
            );
        }
    }

    // Explicitly test that the actual error variants have safe messages
    let embedded_whitespace_error = BearerHeaderError::EmbeddedWhitespace;
    assert!(!embedded_whitespace_error.to_string().contains("sec"));
    assert!(!format!("{:?}", embedded_whitespace_error).contains("sec"));
}

#[test]
fn multiple_whitespace_between_scheme_and_credential() {
    assert_eq!(
        parse_bearer_header("Bearer     token", BearerSyntax::Strict),
        Ok("token")
    );
    assert_eq!(
        parse_bearer_header("Bearer\t\t\t\ttoken", BearerSyntax::Strict),
        Ok("token")
    );
    assert_eq!(
        parse_bearer_header("Bearer \t \t token", BearerSyntax::Strict),
        Ok("token")
    );
}
