//! Command-line arguments for MCP servers.
//!
//! Defines the common CLI surface shared by all vendor servers, with an
//! extensible command enum for vendor-specific subcommands.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// MCP transport mode.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Transport {
    /// Local child-process transport with no listening socket.
    Stdio,
    /// MCP Streamable HTTP transport.
    StreamableHttp,
}

/// Parse the shared CLI, reporting the consumer's own identity.
///
/// The shared `Cli` carries no version of its own, so a consumer parsing it
/// directly gets clap exit status 2 for `--version` — which breaks the
/// package-identity smoke test every deployment wants to run (#159). Pass the
/// consumer's `CARGO_PKG_NAME`/`CARGO_PKG_VERSION` and both `--version` and
/// `--help` report the binary rather than this crate.
///
/// # Examples
/// ```no_run
/// let cli = mecmcp_runtime::cli::parse_for(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
/// # let _ = cli;
/// ```
#[must_use]
pub fn parse_for(binary_name: &'static str, version: &'static str) -> Cli {
    parse_with_provenance(binary_name, version).cli
}

/// Parse, and record which arguments the operator actually supplied.
///
/// The provenance is the point. A consumer that also reads these values from
/// product configuration cannot otherwise tell an explicitly supplied
/// `--approval-timeout-secs 900` from clap's default of the same number, so it
/// cannot implement any precedence rule at all without guessing (#162).
///
/// # Examples
/// ```no_run
/// let parsed = mecmcp_runtime::cli::parse_with_provenance(
///     env!("CARGO_PKG_NAME"),
///     env!("CARGO_PKG_VERSION"),
/// );
/// // CLI wins only when it was actually given. `host` stands in here for any
/// // value a consumer also keeps in product configuration; the change-set
/// // flags this rule exists for are defined by each server, not shared.
/// let host = if parsed.was_supplied("host") {
///     parsed.cli.host.clone()
/// } else {
///     "from-product-config".to_owned()
/// };
/// # let _ = host;
/// ```
#[must_use]
pub fn parse_with_provenance(binary_name: &'static str, version: &'static str) -> ParsedCli {
    match try_parse_from(binary_name, version, std::env::args_os()) {
        Ok(parsed) => parsed,
        Err(error) => error.exit(),
    }
}

/// The real parse, over an explicit argument list.
///
/// Split out so tests drive the same code the binaries do. Building an
/// equivalent `Command` in a test was not enough: a mutation that corrupted the
/// version passed here went undetected, because the test exercised its own copy
/// of the composition rather than this function.
///
/// # Errors
/// Returns the clap error, including the `DisplayVersion` and `DisplayHelp`
/// cases, which are not failures.
pub fn try_parse_from<I, T>(
    binary_name: &'static str,
    version: &'static str,
    args: I,
) -> Result<ParsedCli, clap::Error>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    use clap::{CommandFactory, FromArgMatches};

    let command = <Cli as CommandFactory>::command()
        .name(binary_name)
        .version(version);
    // Captured before `try_get_matches_from` consumes the command.
    let argument_ids = argument_ids_of(&command);
    let matches = command.try_get_matches_from(args)?;

    let supplied = supplied_ids_from(&argument_ids, &matches);
    let cli = <Cli as FromArgMatches>::from_arg_matches(&matches)?;

    Ok(ParsedCli { cli, supplied })
}

/// Collect the argument ids that came from the command line.
///
/// `ArgMatches::ids()` also yields the `ArgGroup` clap's derive creates for the
/// struct itself — an id named `Cli` that is not an argument at all and would
/// otherwise be reported as something the operator supplied. Groups are
/// excluded by intersecting against the command's real arguments; `try_get_raw`
/// does not distinguish them, which a test caught.
fn supplied_ids_from(
    argument_ids: &std::collections::HashSet<String>,
    matches: &clap::ArgMatches,
) -> std::collections::HashSet<String> {
    matches
        .ids()
        .filter(|id| argument_ids.contains(id.as_str()))
        .filter(|id| {
            matches.value_source(id.as_str()) == Some(clap::parser::ValueSource::CommandLine)
        })
        .map(|id| id.as_str().to_owned())
        .collect()
}

/// Every real argument id on a command, excluding groups.
fn argument_ids_of(command: &clap::Command) -> std::collections::HashSet<String> {
    command
        .get_arguments()
        .map(|arg| arg.get_id().as_str().to_owned())
        .collect()
}

/// A parsed CLI plus which of its arguments the operator actually typed.
#[derive(Debug)]
pub struct ParsedCli {
    /// The parsed arguments.
    pub cli: Cli,
    /// Argument ids that came from the command line rather than a default.
    supplied: std::collections::HashSet<String>,
}

impl ParsedCli {
    /// Whether `id` was supplied on the command line rather than defaulted.
    ///
    /// `id` is the field name as clap sees it — `approval_timeout_secs`, not
    /// `--approval-timeout-secs`.
    ///
    /// This is the mechanism behind the precedence rule in `docs/PACKAGING.md`:
    /// an explicit CLI value wins over product configuration, and a defaulted
    /// one does not. Without it a consumer cannot distinguish the two, and
    /// would either ignore a flag the operator typed or override a config value
    /// with a default the operator never chose.
    #[must_use]
    pub fn was_supplied(&self, id: &str) -> bool {
        self.supplied.contains(id)
    }

    /// Every argument id the operator supplied.
    #[must_use]
    pub fn supplied_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.supplied.iter().map(String::as_str).collect();
        ids.sort_unstable();
        ids
    }
}

/// Common CLI arguments for MCP servers.
///
/// This struct holds only the flags every vendor needs. Vendor servers
/// should wrap this in their own struct and add vendor-specific fields.
#[derive(Debug, Parser)]
#[command(name = "mecmcp-server")]
pub struct Cli {
    /// Optional management command.
    #[command(subcommand)]
    pub command: Option<Command>,

    /// JSON file with device mapping.
    #[arg(short = 'f', long, default_value = "devices.json", global = true)]
    pub device_mapping: PathBuf,

    /// MCP transport.
    #[arg(short = 't', long, value_enum, default_value = "stdio")]
    pub transport: Transport,

    /// Bind host (streamable-http only).
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Bind port (streamable-http only).
    #[arg(short = 'p', long, default_value_t = 30030)]
    pub port: u16,

    /// Bearer-token file. Required for streamable-http unless --allow-no-auth.
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// PEM-encoded TLS cert (streamable-http only). Pair with --tls-key.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS key (streamable-http only). Pair with --tls-cert.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Disable bearer-token auth. Refuses to bind off-loopback.
    #[arg(long)]
    pub allow_no_auth: bool,

    /// Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured.
    #[arg(long)]
    pub allow_insecure_bind: bool,

    /// Additional accepted HTTP Host authority. Repeat for multiple values.
    #[arg(long)]
    pub allowed_host: Vec<String>,

    /// Accepted browser Origin URL. Repeat for multiple values.
    #[arg(long)]
    pub allowed_origin: Vec<String>,

    /// Audit/log output format: text or json.
    #[arg(long, default_value = "text")]
    pub audit_format: String,

    /// Optional file to append JSON audit lines to (in addition to stderr).
    #[arg(long)]
    pub audit_log_file: Option<PathBuf>,

    /// Also send structured audit events directly to journald.
    #[arg(long)]
    pub audit_journald: bool,

    /// Per-field audit redaction, e.g. `devices=hmac,host=drop`.
    /// Fields: devices, host, name, basename, command, pfe_command.
    /// Transforms: keep, drop, hmac. Empty = disabled.
    #[arg(long, default_value = "")]
    pub audit_redact: String,

    /// File containing the HMAC key used by any `=hmac` redaction. Required
    /// when audit-redact requests hmac. Path only; the key is never a flag/env value.
    #[arg(long)]
    pub audit_hmac_key_file: Option<PathBuf>,
}

/// Top-level management commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the bearer-token store.
    Token {
        /// Token action.
        #[command(subcommand)]
        action: TokenAction,
    },
}

/// Token-store action.
#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Mint a new token and append to the file.
    Add {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Stable audit name for the token.
        #[arg(long)]
        name: String,
        /// Comma-separated device names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        devices: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Provider name (e.g., "anthropic", "ollama"). Optional.
        #[arg(long)]
        provider: Option<String>,
        /// Provider tier: "public" or "private". Required if provider is set.
        #[arg(long)]
        provider_tier: Option<String>,
        /// The human on whose behalf this credential acts. Optional.
        #[arg(long)]
        on_behalf_of: Option<String>,
        /// Actor type: "human", "agent", or "unknown". Optional.
        #[arg(long)]
        actor_type: Option<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List token names + scopes (never the hash or secret).
    List {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Remove a token by name.
    Revoke {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke + re-add under the same scopes; prints a new secret.
    Rotate {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn defaults() {
        let cli = Cli::parse_from(["test-server"]);
        assert_eq!(cli.transport, Transport::Stdio);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30030);
        assert!(cli.command.is_none());
        assert!(cli.tokens_file.is_none());
        assert!(!cli.allow_no_auth);
        assert!(!cli.allow_insecure_bind);
        assert!(!cli.audit_journald);
        assert_eq!(cli.audit_format, "text");
        assert_eq!(cli.audit_redact, "");
    }

    #[test]
    fn parses_streamable_http() {
        let cli = Cli::parse_from(["test-server", "-t", "streamable-http"]);
        assert_eq!(cli.transport, Transport::StreamableHttp);
    }

    #[test]
    fn parses_short_flags() {
        let cli = Cli::parse_from(["test-server", "-f", "/etc/mcp/devices.json"]);
        assert_eq!(cli.device_mapping, PathBuf::from("/etc/mcp/devices.json"));
    }

    #[test]
    fn parses_token_add_subcommand() {
        let cli = Cli::parse_from([
            "test-server",
            "token",
            "add",
            "--tokens-file",
            "/tmp/t.json",
            "--name",
            "alice",
            "--devices",
            "*",
            "--tools",
            "*",
        ]);
        assert!(matches!(cli.command, Some(Command::Token { .. })));
    }

    #[test]
    fn audit_journald_defaults_off_and_parses() {
        let default_cli = Cli::parse_from(["test-server"]);
        assert!(!default_cli.audit_journald);

        let enabled = Cli::parse_from(["test-server", "--audit-journald"]);
        assert!(enabled.audit_journald);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod composition_tests {
    use super::*;

    /// Every test here goes through `try_parse_from`, the same code the
    /// binaries run. An earlier version built an equivalent `Command` instead
    /// and a mutation to the real function slipped past it.
    fn parse(args: &[&str]) -> Result<ParsedCli, clap::Error> {
        try_parse_from("consumer-mcp", "9.9.9", args)
    }

    #[test]
    fn version_reports_the_consumers_identity_not_this_crate() {
        let error = parse(&["consumer-mcp", "--version"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);

        let rendered = error.to_string();
        assert!(rendered.contains("consumer-mcp"), "got {rendered}");
        assert!(rendered.contains("9.9.9"), "got {rendered}");
        assert!(
            !rendered.contains("mecmcp-server"),
            "the shared default name leaked into the consumer's version: {rendered}"
        );
    }

    /// Before #159 this was clap exit status 2, which breaks the
    /// package-identity smoke test a deployment wants to run.
    #[test]
    fn version_is_not_an_unknown_argument() {
        let error = parse(&["consumer-mcp", "--version"]).unwrap_err();
        assert_ne!(
            error.kind(),
            clap::error::ErrorKind::UnknownArgument,
            "--version must be understood, not rejected"
        );
    }

    #[test]
    fn help_also_names_the_consumer() {
        let error = parse(&["consumer-mcp", "--help"]).unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("consumer-mcp"));
    }

    /// The distinction #162 needs: supplied and defaulted are otherwise
    /// indistinguishable.
    #[test]
    fn supplied_and_defaulted_values_are_distinguishable() {
        let parsed = parse(&["consumer-mcp", "--host", "10.0.0.1"]).unwrap();

        assert!(
            parsed.was_supplied("host"),
            "an explicit --host must read as supplied"
        );
        assert!(
            !parsed.was_supplied("transport"),
            "a defaulted value must not read as supplied"
        );
        assert_eq!(parsed.cli.host, "10.0.0.1");
    }

    /// The case a `value == default` check gets wrong: typing the default.
    #[test]
    fn a_value_equal_to_the_default_still_counts_as_supplied() {
        let parsed = parse(&["consumer-mcp", "--host", "127.0.0.1"]).unwrap();
        assert!(
            parsed.was_supplied("host"),
            "127.0.0.1 is also the default; provenance must not be inferred from the value"
        );
    }

    /// The `ArgGroup` clap's derive creates for the struct must not be reported
    /// as something the operator supplied.
    #[test]
    fn supplied_ids_are_sorted_and_exclude_the_struct_group() {
        let parsed = parse(&["consumer-mcp", "--host", "0.0.0.0", "--port", "9999"]).unwrap();
        assert_eq!(parsed.supplied_ids(), vec!["host", "port"]);
    }

    #[test]
    fn nothing_supplied_means_nothing_reported() {
        let parsed = parse(&["consumer-mcp"]).unwrap();
        assert!(
            parsed.supplied_ids().is_empty(),
            "got {:?}",
            parsed.supplied_ids()
        );
    }
}
