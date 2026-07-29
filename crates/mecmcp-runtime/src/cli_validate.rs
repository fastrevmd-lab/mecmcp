//! Fail-closed validation for shared remote-listener settings.

use crate::cli::{Cli, Transport};
use std::{net::IpAddr, path::Path};

/// A CLI combination with no safe unambiguous interpretation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CliRefusal {
    /// Remote transport needs authentication.
    #[error("--transport streamable-http requires --tokens-file (or --allow-no-auth on loopback)")]
    AuthRequired,
    /// Auth may not be both configured and disabled.
    #[error("--tokens-file and --allow-no-auth are mutually exclusive")]
    AuthConflict,
    /// No-auth listeners are loopback-only.
    #[error("--allow-no-auth refuses to bind off-loopback (host '{host}')")]
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
    /// Bind address must not involve DNS resolution.
    #[error("--host must be a numeric IPv4 or IPv6 address, got '{host}'")]
    NonNumericHost {
        /// Refused bind value.
        host: String,
    },
    /// Off-loopback hosts must be explicit DNS-rebinding policy entries.
    #[error("non-loopback Streamable HTTP requires at least one --allowed-host")]
    AllowedHostRequired,
    /// Off-loopback browser callers must have explicit CSRF origin policy.
    #[error("non-loopback Streamable HTTP requires at least one --allowed-origin")]
    AllowedOriginRequired,
    /// One Host allowlist entry is malformed.
    #[error("invalid --allowed-host authority '{value}'")]
    InvalidAllowedHost {
        /// Refused value.
        value: String,
    },
    /// One Origin allowlist entry is malformed or is not an HTTP(S) origin.
    #[error("invalid --allowed-origin URL '{value}'")]
    InvalidAllowedOrigin {
        /// Refused value.
        value: String,
    },
    /// Sensitive files are anchored to absolute operator paths.
    #[error("{flag} path must be absolute")]
    AbsolutePathRequired {
        /// Flag whose value was relative.
        flag: &'static str,
    },
}

/// Borrowed, consumer-independent listener settings.
#[derive(Debug, Clone, Copy)]
pub struct ServeValidation<'a> {
    /// MCP transport selection.
    pub transport: Transport,
    /// Numeric bind address text.
    pub host: &'a str,
    /// Optional digest-only bearer-token file.
    pub tokens_file: Option<&'a Path>,
    /// Optional listener certificate.
    pub tls_cert: Option<&'a Path>,
    /// Optional listener private key.
    pub tls_key: Option<&'a Path>,
    /// Explicit loopback-only no-auth mode.
    pub allow_no_auth: bool,
    /// Explicit off-loopback plaintext exception.
    pub allow_insecure_bind: bool,
    /// Additional exact Host authorities.
    pub allowed_hosts: &'a [&'a str],
    /// Additional exact browser origins.
    pub allowed_origins: &'a [&'a str],
    /// Whether an off-loopback listener requires a Host addition.
    pub require_allowed_host_off_loopback: bool,
    /// Whether an off-loopback listener requires an Origin addition.
    pub require_allowed_origin_off_loopback: bool,
}

/// Successfully validated listener facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedServe {
    /// Parsed numeric bind address.
    pub host: IpAddr,
    /// Whether listener TLS is configured.
    pub tls: bool,
}

/// Validate shared serve arguments before inventory, secrets, sockets, or TLS load.
pub fn validate(cli: &Cli) -> Result<(), CliRefusal> {
    if cli.transport == Transport::Stdio {
        return Ok(());
    }
    let allowed_hosts = cli
        .allowed_host
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let allowed_origins = cli
        .allowed_origin
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    validate_values(
        cli.transport,
        &cli.host,
        cli.tokens_file.as_deref(),
        cli.tls_cert.as_deref(),
        cli.tls_key.as_deref(),
        cli.allow_no_auth,
        cli.allow_insecure_bind,
        &allowed_hosts,
        &allowed_origins,
        false,
        false,
    )
    .map(|_| ())
}

/// Validate an independent listener configuration.
///
/// # Errors
///
/// Returns [`CliRefusal`] for the first unsafe or ambiguous setting.
pub fn validate_serve(config: &ServeValidation<'_>) -> Result<ValidatedServe, CliRefusal> {
    validate_values(
        config.transport,
        config.host,
        config.tokens_file,
        config.tls_cert,
        config.tls_key,
        config.allow_no_auth,
        config.allow_insecure_bind,
        config.allowed_hosts,
        config.allowed_origins,
        config.require_allowed_host_off_loopback,
        config.require_allowed_origin_off_loopback,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_values(
    transport: Transport,
    host: &str,
    tokens_file: Option<&Path>,
    tls_cert: Option<&Path>,
    tls_key: Option<&Path>,
    allow_no_auth: bool,
    allow_insecure_bind: bool,
    allowed_hosts: &[&str],
    allowed_origins: &[&str],
    require_allowed_host_off_loopback: bool,
    require_allowed_origin_off_loopback: bool,
) -> Result<ValidatedServe, CliRefusal> {
    if transport == Transport::Stdio {
        return Ok(ValidatedServe {
            host: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            tls: false,
        });
    }

    let host_ip = host
        .parse::<IpAddr>()
        .map_err(|_| CliRefusal::NonNumericHost {
            host: host.to_owned(),
        })?;
    let loopback = host_ip.is_loopback();
    let tls = match (tls_cert, tls_key) {
        (Some(cert), Some(key)) => {
            require_absolute(cert, "--tls-cert")?;
            require_absolute(key, "--tls-key")?;
            true
        }
        (None, None) => false,
        (cert, key) => {
            return Err(CliRefusal::TlsPairIncomplete {
                cert: cert.is_some(),
                key: key.is_some(),
            });
        }
    };

    match (tokens_file, allow_no_auth) {
        (None, false) => return Err(CliRefusal::AuthRequired),
        (Some(_), true) => return Err(CliRefusal::AuthConflict),
        (None, true) if !loopback => {
            return Err(CliRefusal::NoAuthOffLoopback {
                host: host.to_owned(),
            });
        }
        (Some(path), false) => require_absolute(path, "--tokens-file")?,
        _ => {}
    }
    if !loopback && !tls && !allow_insecure_bind {
        return Err(CliRefusal::InsecureBindRequired {
            host: host.to_owned(),
        });
    }
    if !loopback && require_allowed_host_off_loopback && allowed_hosts.is_empty() {
        return Err(CliRefusal::AllowedHostRequired);
    }
    if !loopback && require_allowed_origin_off_loopback && allowed_origins.is_empty() {
        return Err(CliRefusal::AllowedOriginRequired);
    }
    for value in allowed_hosts {
        validate_allowed_host(value)?;
    }
    for value in allowed_origins {
        validate_allowed_origin(value)?;
    }
    Ok(ValidatedServe { host: host_ip, tls })
}

/// Validate one exact Host authority.
pub fn validate_allowed_host(value: &str) -> Result<(), CliRefusal> {
    if value.is_empty()
        || value.len() > 255
        || value.trim() != value
        || value.contains('@')
        || http::uri::Authority::try_from(value).is_err()
    {
        return Err(CliRefusal::InvalidAllowedHost {
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Validate one exact HTTP(S) browser origin.
pub fn validate_allowed_origin(value: &str) -> Result<(), CliRefusal> {
    let valid = value
        .parse::<http::Uri>()
        .ok()
        .filter(|uri| matches!(uri.scheme_str(), Some("http" | "https")))
        .filter(|uri| {
            uri.authority()
                .is_some_and(|authority| !authority.as_str().contains('@'))
        })
        .is_some_and(|uri| uri.query().is_none() && (uri.path().is_empty() || uri.path() == "/"));
    if !valid || value.len() > 2048 {
        return Err(CliRefusal::InvalidAllowedOrigin {
            value: value.to_owned(),
        });
    }
    Ok(())
}

/// Require an absolute operator-managed path.
pub fn require_absolute(path: &Path, flag: &'static str) -> Result<(), CliRefusal> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(CliRefusal::AbsolutePathRequired { flag })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert_eq!(
            validate(&parse(&["-t", "streamable-http"])),
            Err(CliRefusal::AuthRequired)
        );
    }

    #[test]
    fn http_no_auth_loopback_ok() {
        assert!(validate(&parse(&["-t", "streamable-http", "--allow-no-auth"])).is_ok());
    }

    #[test]
    fn http_no_auth_off_loopback_refused() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--allow-no-auth",
                "-H",
                "0.0.0.0",
            ])),
            Err(CliRefusal::NoAuthOffLoopback { .. })
        ));
    }

    #[test]
    fn http_off_loopback_plain_refused() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "-H",
                "0.0.0.0",
            ])),
            Err(CliRefusal::InsecureBindRequired { .. })
        ));
    }

    #[test]
    fn tls_pair_incomplete_refused() {
        assert!(matches!(
            validate(&parse(&[
                "-t",
                "streamable-http",
                "--tokens-file",
                "/tmp/t.json",
                "--tls-cert",
                "/tmp/c.pem",
            ])),
            Err(CliRefusal::TlsPairIncomplete { .. })
        ));
    }
}
