//! The evidence pipeline's CLI surface, defined once for all five servers.
//!
//! Without these flags the sink is unreachable from a deployment: `mecmcp-audit`
//! can build a pipeline but nothing tells it an endpoint, an identity or a
//! spool path, so credentials on a host would be read by no code at all
//! (mecmcp#292).

#![allow(clippy::unwrap_used)]

use clap::Parser;
use mecmcp_runtime::cli::EvidenceArgs;
use std::io::Write;

#[derive(Debug, Parser)]
struct Harness {
    #[command(flatten)]
    evidence: EvidenceArgs,
}

fn parse(args: &[&str]) -> EvidenceArgs {
    let mut argv = vec!["test"];
    argv.extend_from_slice(args);
    Harness::parse_from(argv).evidence
}

fn secret(dir: &std::path::Path, name: &str, value: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(value.as_bytes()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    path
}

/// Absent flags mean absent pipeline. Evidence is a deployment choice.
#[test]
fn no_endpoint_means_no_evidence() {
    assert!(parse(&[]).into_config().unwrap().is_none());
}

/// The full flag set produces a usable config.
#[test]
fn a_configured_endpoint_produces_a_pipeline_config() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret\n");
    let verify = secret(dir.path(), "v", "verify-secret");

    let config = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .unwrap()
    .expect("an endpoint was given");

    assert_eq!(config.server_id, "junos-950");
    assert_eq!(config.sink.endpoint, "https://ch.example:8443");
    assert_eq!(config.sink.username, "ssdf_audit");
    assert_eq!(config.sink.verify_username, "ssdf_audit_verify");
    // Trailing newline stripped: a password file written with an editor ends
    // in one, and sending it would fail auth in a way that reads like a wrong
    // password rather than a stray byte.
    assert_eq!(config.sink.password, "write-secret");
    assert_eq!(config.sink.verify_password, "verify-secret");
    assert!(
        !config.run_id.is_empty() && config.run_id != config.server_id,
        "each process lifetime needs its own run id: {config:?}"
    );
}

/// An endpoint with no credentials is a misconfiguration, not a default.
#[test]
fn an_endpoint_without_credentials_is_refused() {
    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
    ])
    .into_config()
    .expect_err("no password file was given");
    assert!(
        format!("{error}").contains("password"),
        "the error must name what is missing: {error}"
    );
}

/// A world-readable password file is refused, matching the token-file rule.
#[cfg(unix)]
#[test]
fn a_loose_password_file_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    std::fs::set_permissions(&write, std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
    ])
    .into_config()
    .expect_err("0644 on a credential must be refused");
    assert!(
        format!("{error}").contains("0600") || format!("{error}").contains("permissions"),
        "the error must say what is wrong with the file: {error}"
    );
}

/// An endpoint without a chain identity is refused.
///
/// The chain is keyed by `server_id`. Defaulting it to something incidental —
/// the hostname, say — means a rename starts a second root, and a fork
/// verifies as two valid chains, so nothing downstream would report it. This
/// fleet has already renamed its hosts once.
#[test]
fn an_endpoint_without_a_server_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
    ])
    .into_config()
    .expect_err("no chain identity was given");

    assert!(
        format!("{error}").contains("--ssdf-audit-server-id"),
        "the error must name the flag to set: {error}"
    );
}
