//! Validates the parsed CLI args against the design's refusal matrix.

use crate::cli::{Cli, Transport};
use std::net::IpAddr;

/// A CLI combination with no safe unambiguous interpretation.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum CliRefusal {
    /// Remote transport needs authentication.
    #[error("--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)")]
    AuthRequired,
    /// No-auth listeners are loopback-only.
    #[error("--allow-no-auth refuses to bind off-loopback (host '{host}' is not 127.0.0.1 or ::1)")]
    NoAuthOffLoopback {
        /// Refused bind value.
        host: String,
    },
    /// Off-loopback plaintext is an explicit proxy-only exception.
    #[error(
        "non-loopback bind '{host}' over plain HTTP requires --allow-insecure-bind (or supply --tls-cert/--tls-key)"
    )]
    InsecureBindRequired {
        /// Refused bind value.
        host: String,
    },
    /// Certificate and key form one atomic setting.
    #[error("--tls-cert and --tls-key must be set together (got cert={cert}, key={key})")]
    TlsPairIncomplete {
        /// Whether cert was set.
        cert: bool,
        /// Whether key was set.
        key: bool,
    },
}

/// Validate all serve arguments before inventory, secrets, sockets, or TLS load.
///
/// This function validates the common CLI arguments that apply to all vendors.
/// Vendor-specific validation should be performed separately.
pub fn validate(cli: &Cli) -> Result<(), CliRefusal> {
    // Stdio needs no transport validation.
    if cli.transport == Transport::Stdio {
        return Ok(());
    }

    // TLS pair must be complete or absent.
    let tls_configured = match (cli.tls_cert.is_some(), cli.tls_key.is_some()) {
        (true, true) => true,
        (false, false) => false,
        (cert, key) => return Err(CliRefusal::TlsPairIncomplete { cert, key }),
    };

    // Determine if host is loopback.
    let host_is_loopback = match cli.host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false, // hostnames are treated as non-loopback
    };

    // Auth requirement.
    if cli.tokens_file.is_none() && !cli.allow_no_auth {
        return Err(CliRefusal::AuthRequired);
    }
    if cli.tokens_file.is_none() && cli.allow_no_auth && !host_is_loopback {
        return Err(CliRefusal::NoAuthOffLoopback {
            host: cli.host.clone(),
        });
    }

    // Insecure-bind requirement.
    if !host_is_loopback && !tls_configured && !cli.allow_insecure_bind {
        return Err(CliRefusal::InsecureBindRequired {
            host: cli.host.clone(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("test-server").chain(args.iter().copied()))
    }

    #[test]
    fn stdio_always_ok() {
        assert!(validate(&parse(&[])).is_ok());
        assert!(validate(&parse(&["-t", "stdio", "-H", "10.0.0.1"])).is_ok());
    }

    #[test]
    fn http_requires_tokens_file() {
        let r = validate(&parse(&["-t", "streamable-http"]));
        assert_eq!(r, Err(CliRefusal::AuthRequired));
    }

    #[test]
    fn http_no_auth_loopback_ok() {
        let r = validate(&parse(&["-t", "streamable-http", "--allow-no-auth"]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_no_auth_off_loopback_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--allow-no-auth",
            "-H",
            "0.0.0.0",
        ]));
        assert!(matches!(r, Err(CliRefusal::NoAuthOffLoopback { .. })));
    }

    #[test]
    fn http_with_tokens_loopback_ok() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
        ]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_off_loopback_plain_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
        ]));
        assert!(matches!(r, Err(CliRefusal::InsecureBindRequired { .. })));
    }

    #[test]
    fn http_off_loopback_insecure_bind_ok() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--allow-insecure-bind",
        ]));
        assert!(r.is_ok());
    }

    #[test]
    fn http_off_loopback_tls_ok() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "0.0.0.0",
            "--tls-cert",
            "/tmp/c.pem",
            "--tls-key",
            "/tmp/k.pem",
        ]));
        assert!(r.is_ok());
    }

    #[test]
    fn tls_pair_incomplete_refused() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "--tls-cert",
            "/tmp/c.pem",
        ]));
        assert!(matches!(r, Err(CliRefusal::TlsPairIncomplete { .. })));
    }

    #[test]
    fn ipv6_loopback_recognized() {
        let r = validate(&parse(&[
            "-t",
            "streamable-http",
            "--tokens-file",
            "/tmp/t.json",
            "-H",
            "::1",
        ]));
        assert!(r.is_ok());
    }
}
