//! Shared fail-closed remote-listener validation.

use mecmcp_runtime::{
    cli::Transport,
    cli_validate::{CliRefusal, ServeValidation, validate_serve},
};
use std::path::Path;

fn base<'a>() -> ServeValidation<'a> {
    ServeValidation {
        transport: Transport::StreamableHttp,
        host: "127.0.0.1",
        tokens_file: Some(Path::new("/tmp/tokens.json")),
        tls_cert: None,
        tls_key: None,
        allow_no_auth: false,
        allow_insecure_bind: false,
        allowed_hosts: &[],
        allowed_origins: &[],
        require_allowed_host_off_loopback: false,
        require_allowed_origin_off_loopback: false,
    }
}

#[test]
fn auth_mode_numeric_host_and_absolute_sensitive_paths_are_strict() {
    let mut config = base();
    config.allow_no_auth = true;
    assert_eq!(validate_serve(&config), Err(CliRefusal::AuthConflict));

    config.allow_no_auth = false;
    config.host = "localhost";
    assert!(matches!(
        validate_serve(&config),
        Err(CliRefusal::NonNumericHost { .. })
    ));

    config.host = "127.0.0.1";
    config.tokens_file = Some(Path::new("tokens.json"));
    assert_eq!(
        validate_serve(&config),
        Err(CliRefusal::AbsolutePathRequired {
            flag: "--tokens-file"
        })
    );
}

#[test]
fn off_loopback_policy_can_require_exact_host_and_origin_entries() {
    let mut config = base();
    config.host = "0.0.0.0";
    config.allow_insecure_bind = true;
    config.require_allowed_host_off_loopback = true;
    config.require_allowed_origin_off_loopback = true;

    assert_eq!(
        validate_serve(&config),
        Err(CliRefusal::AllowedHostRequired)
    );
    config.allowed_hosts = &["mcp.example.test"];
    assert_eq!(
        validate_serve(&config),
        Err(CliRefusal::AllowedOriginRequired)
    );
    config.allowed_origins = &["https://client.example.test"];
    assert!(validate_serve(&config).is_ok());
}

#[test]
fn malformed_host_and_origin_entries_are_rejected_without_echoing_secrets() {
    let mut config = base();
    config.allowed_hosts = &["https://wrong-shape"];
    assert!(matches!(
        validate_serve(&config),
        Err(CliRefusal::InvalidAllowedHost { .. })
    ));
    config.allowed_hosts = &[];
    config.allowed_origins = &["ftp://client.example.test"];
    assert!(matches!(
        validate_serve(&config),
        Err(CliRefusal::InvalidAllowedOrigin { .. })
    ));
}
