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

/// A stand-in trust anchor. Never parsed here — `into_config` only checks that
/// a path was given; the transport is what reads it.
fn anchor(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("ca.pem");
    std::fs::write(&path, "-----BEGIN CERTIFICATE-----\n").unwrap();
    path
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
    let ca = anchor(dir.path());
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
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
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
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
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
    let ca = anchor(dir.path());
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
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
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
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("no chain identity was given");

    assert!(
        format!("{error}").contains("--ssdf-audit-server-id"),
        "the error must name the flag to set: {error}"
    );
}

/// A zero delivery interval is refused at parse time.
///
/// `Duration::ZERO` makes the drain's `wait_timeout` return immediately every
/// iteration, reloading the outbox in a tight loop — a busy spin on CPU and
/// disk that presents as a wedged server rather than as a misconfiguration.
#[test]
fn a_zero_delivery_interval_is_refused() {
    let parsed = Harness::try_parse_from(["test", "--ssdf-audit-interval-secs", "0"]);
    let error = parsed.expect_err("zero must not parse").to_string();
    assert!(
        error.contains("at least 1 second"),
        "the error must say what to use instead: {error}"
    );
}

/// Run ids must not be derived from clock and pid.
///
/// Delivery identity is `(server_id, run_id, segment_seq)`, so a repeated run
/// id makes a new run's segment 0 collide with one already delivered and be
/// skipped as landed — losing the head of the chain. A snapshot restore brings
/// back both the clock and pid 1.
#[test]
fn run_ids_do_not_repeat() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    let args = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ]);

    let seen: std::collections::HashSet<String> = (0..64)
        .map(|_| args.into_config().unwrap().unwrap().run_id)
        .collect();

    assert_eq!(
        seen.len(),
        64,
        "run ids repeated within one process, so they cannot be distinguishing \
         two runs of one server either"
    );
}

/// A password ending in real whitespace keeps it; only one line ending goes.
///
/// `trim_end` would eat the trailing space, and the resulting auth failure
/// reads as a wrong password rather than a mangled one.
#[test]
fn only_one_line_ending_is_stripped_from_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "trailing space \n");
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
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .unwrap()
    .expect("configured");

    assert_eq!(config.sink.password, "trailing space ");
}

/// An empty credential file is a configuration error, not an empty password.
#[test]
fn an_empty_password_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "\n");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ])
    .into_config()
    .expect_err("an empty credential must be refused");
    assert!(!format!("{error}").is_empty());
}

/// Spool paths have no default, because no default is writable anywhere.
#[test]
fn an_endpoint_without_spool_paths_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    let ca = anchor(dir.path());

    let error = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
    ])
    .into_config()
    .expect_err("no spool path was given");
    assert!(
        format!("{error}").contains("--ssdf-audit-outbox"),
        "the error must name the flag: {error}"
    );
}

/// A blank chain identity is refused.
///
/// `--ssdf-audit-server-id ""` is what a unit file produces when the variable
/// behind it is unset, and clap hands it over as `Some("")`. Every writer that
/// did it would share the empty chain key, which is a fork — and a fork
/// verifies as two valid chains, so nothing downstream would say so.
#[test]
fn a_blank_server_id_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    for blank in ["", "   "] {
        let error = parse(&[
            "--ssdf-audit-endpoint",
            "https://ch.example:8443",
            "--ssdf-audit-server-id",
            blank,
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
        .expect_err("a blank chain identity must be refused");
        assert!(
            format!("{error}").contains("empty"),
            "the error must name the problem for {blank:?}: {error}"
        );
    }
}

/// Run ids must sort in the order they were created.
///
/// `SegmentArchive::archive` requires run ids to be non-decreasing and rejects
/// anything else as `RunIdNotMonotonic`, so a purely random id fails archival
/// on roughly half of all ordinary restarts — unique but unusable.
#[test]
fn run_ids_sort_in_creation_order() {
    let dir = tempfile::tempdir().unwrap();
    let ca = anchor(dir.path());
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");
    let args = parse(&[
        "--ssdf-audit-endpoint",
        "https://ch.example:8443",
        "--ssdf-audit-server-id",
        "junos-950",
        "--ssdf-audit-password-file",
        write.to_str().unwrap(),
        "--ssdf-audit-verify-password-file",
        verify.to_str().unwrap(),
        "--ssdf-audit-ca-file",
        ca.to_str().unwrap(),
        "--ssdf-audit-outbox",
        dir.path().join("outbox").to_str().unwrap(),
        "--ssdf-audit-ledger",
        dir.path().join("ledger").to_str().unwrap(),
    ]);

    // No sleep. An earlier version of this test paused 2ms between ids, which
    // hid the case that actually breaks: two ids inside one clock tick share
    // their prefix, and the random half then decides the order. Generating them
    // back to back is what exercises it.
    let mut previous = args.into_config().unwrap().unwrap().run_id;
    for _ in 0..256 {
        let next = args.into_config().unwrap().unwrap().run_id;
        assert!(
            next > previous,
            "run ids must not sort below their predecessor: {next} after {previous}"
        );
        previous = next;
    }
}

/// An https endpoint without a trust anchor is refused at configuration time.
///
/// The transport refuses it too, but there it surfaces as a failed delivery
/// once per interval, which reads as an outage. Catching it here fails the
/// server at startup, where a missing flag looks like a missing flag.
#[test]
fn an_https_endpoint_without_a_ca_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let write = secret(dir.path(), "w", "write-secret");
    let verify = secret(dir.path(), "v", "verify-secret");

    let error = parse(&[
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
    .expect_err("https without a CA must be refused");

    assert!(
        format!("{error}").contains("--ssdf-audit-ca-file"),
        "the error must name the flag: {error}"
    );
}
