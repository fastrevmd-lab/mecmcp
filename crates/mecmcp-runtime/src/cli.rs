//! Command-line arguments for MCP servers.
//!
//! Defines the common CLI surface shared by all vendor servers, with an
//! extensible command enum for vendor-specific subcommands.

use clap::{Parser, Subcommand, ValueEnum};
use std::collections::{BTreeMap, HashSet};
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
/// For a server that adds flags of its own, parse the server's own type with
/// [`parse_with_provenance`] instead — this function understands only the
/// shared arguments and rejects anything else as unknown.
///
/// # Examples
/// ```no_run
/// let cli = mecmcp_runtime::cli::parse_for(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
/// # let _ = cli;
/// ```
#[must_use]
pub fn parse_for(binary_name: &'static str, version: &'static str) -> Cli {
    parse_with_provenance::<Cli>(binary_name, version).cli
}

/// Parse the consumer's CLI, and record which arguments the operator supplied.
///
/// The provenance is the point. A consumer that also reads these values from
/// product configuration cannot otherwise tell an explicitly supplied
/// `--approval-timeout-secs 900` from clap's default of the same number, so it
/// cannot implement any precedence rule at all without guessing (#162).
///
/// `C` is the *consumer's* parser, not the shared [`Cli`]. That is the whole
/// point: `approval_timeout_secs` and the rest of the flags this precedence
/// rule exists for are defined by each server, so a parser hard-wired to the
/// shared type would reject them as unknown and could never report their
/// provenance. A server flattens [`Cli`] into its own struct and passes that.
///
/// # Examples
/// ```no_run
/// use clap::Parser;
/// use mecmcp_runtime::cli::{Cli, parse_with_provenance};
///
/// #[derive(Debug, Parser)]
/// struct ServerCli {
///     #[command(flatten)]
///     shared: Cli,
///     /// A vendor flag the shared type knows nothing about.
///     #[arg(long, default_value_t = 900)]
///     approval_timeout_secs: u64,
/// }
///
/// let parsed = parse_with_provenance::<ServerCli>(
///     env!("CARGO_PKG_NAME"),
///     env!("CARGO_PKG_VERSION"),
/// );
/// // CLI wins only when it was actually given.
/// let approval_timeout_secs = if parsed.was_supplied("approval_timeout_secs") {
///     parsed.cli.approval_timeout_secs
/// } else {
///     600 // from product configuration
/// };
/// # let _ = approval_timeout_secs;
/// ```
#[must_use]
pub fn parse_with_provenance<C>(binary_name: &'static str, version: &'static str) -> ParsedCli<C>
where
    C: clap::CommandFactory + clap::FromArgMatches,
{
    match try_parse_from::<C, _, _>(binary_name, version, std::env::args_os()) {
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
pub fn try_parse_from<C, I, T>(
    binary_name: &'static str,
    version: &'static str,
    args: I,
) -> Result<ParsedCli<C>, clap::Error>
where
    C: clap::CommandFactory + clap::FromArgMatches,
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let mut command = C::command().name(binary_name).version(version);
    // Built explicitly, then read, then parsed. `try_get_matches_from` builds
    // too, but only after this function has already captured the tree — and an
    // unbuilt tree has not yet had global arguments propagated into its
    // subcommands, so what gets captured would depend on that ordering rather
    // than on a stated rule. Building first makes the tree the real one and puts
    // the global handling in `argument_ids_of`, where it is visible.
    command.build();
    let argument_ids = argument_ids_of(&command);
    let matches = command.try_get_matches_from(args)?;

    let supplied = supplied_arguments_from(&argument_ids, &matches);
    let cli = C::from_arg_matches(&matches)?;

    Ok(ParsedCli { cli, supplied })
}

/// An argument the operator typed, and where in the command tree it sits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SuppliedArgument {
    /// Subcommand path, outermost first. Empty for a top-level argument.
    ///
    /// `token add --tokens-file x` yields `["token", "add"]`.
    pub command_path: Vec<String>,
    /// The clap argument id — the field name, not the flag spelling.
    pub id: String,
}

/// Every real argument id in a command tree, keyed by subcommand path.
///
/// Global arguments are recorded only at the level that declares them. Clap
/// propagates a global into every descendant's matches, so counting it again
/// deeper would report `--device-mapping` as supplied to `token add` when the
/// operator typed it once, before the subcommand.
fn argument_ids_of(command: &clap::Command) -> BTreeMap<Vec<String>, HashSet<String>> {
    fn walk(
        command: &clap::Command,
        path: Vec<String>,
        into: &mut BTreeMap<Vec<String>, HashSet<String>>,
    ) {
        let ids: HashSet<String> = command
            .get_arguments()
            .filter(|arg| path.is_empty() || !arg.is_global_set())
            .map(|arg| arg.get_id().as_str().to_owned())
            .collect();
        for subcommand in command.get_subcommands() {
            let mut child = path.clone();
            child.push(subcommand.get_name().to_owned());
            walk(subcommand, child, into);
        }
        into.insert(path, ids);
    }

    let mut ids = BTreeMap::new();
    walk(command, Vec::new(), &mut ids);
    ids
}

/// Collect the arguments that came from the command line, at every depth.
///
/// Clap keeps a subcommand's own arguments in a child `ArgMatches`, so a walk
/// of the root alone reported nothing for `token add --tokens-file x` and
/// `supplied_ids()` quietly contradicted its every-argument contract.
///
/// `ArgMatches::ids()` also yields the `ArgGroup` clap's derive creates for the
/// struct itself — an id named `Cli` that is not an argument at all and would
/// otherwise be reported as something the operator supplied. Groups are
/// excluded by intersecting against the command's real arguments; `try_get_raw`
/// does not distinguish them, which a test caught.
fn supplied_arguments_from(
    argument_ids: &BTreeMap<Vec<String>, HashSet<String>>,
    matches: &clap::ArgMatches,
) -> Vec<SuppliedArgument> {
    fn walk(
        argument_ids: &BTreeMap<Vec<String>, HashSet<String>>,
        matches: &clap::ArgMatches,
        path: Vec<String>,
        into: &mut Vec<SuppliedArgument>,
    ) {
        if let Some(known) = argument_ids.get(&path) {
            for id in matches.ids() {
                let id = id.as_str();
                if known.contains(id)
                    && matches.value_source(id) == Some(clap::parser::ValueSource::CommandLine)
                {
                    into.push(SuppliedArgument {
                        command_path: path.clone(),
                        id: id.to_owned(),
                    });
                }
            }
        }

        if let Some((name, child_matches)) = matches.subcommand() {
            let mut child = path;
            child.push(name.to_owned());
            walk(argument_ids, child_matches, child, into);
        }
    }

    let mut supplied = Vec::new();
    walk(argument_ids, matches, Vec::new(), &mut supplied);
    supplied.sort_unstable();
    supplied
}

/// A parsed CLI plus which of its arguments the operator actually typed.
///
/// `C` defaults to the shared [`Cli`] so a server with no flags of its own can
/// name the type without a parameter.
#[derive(Debug)]
pub struct ParsedCli<C = Cli> {
    /// The parsed arguments.
    pub cli: C,
    /// Arguments that came from the command line rather than a default.
    supplied: Vec<SuppliedArgument>,
}

impl<C> ParsedCli<C> {
    /// Whether a top-level `id` was supplied on the command line.
    ///
    /// `id` is the field name as clap sees it — `approval_timeout_secs`, not
    /// `--approval-timeout-secs`.
    ///
    /// Top-level only, deliberately. `tokens_file` names both a server flag and
    /// an argument of `token add`; answering `true` for the second would tell a
    /// server the operator had chosen a value for the first. Use
    /// [`was_supplied_in`](Self::was_supplied_in) for a subcommand.
    ///
    /// This is the mechanism behind the precedence rule in `docs/PACKAGING.md`:
    /// an explicit CLI value wins over product configuration, and a defaulted
    /// one does not. Without it a consumer cannot distinguish the two, and
    /// would either ignore a flag the operator typed or override a config value
    /// with a default the operator never chose.
    #[must_use]
    pub fn was_supplied(&self, id: &str) -> bool {
        self.was_supplied_in(&[], id)
    }

    /// Whether `id` was supplied to the subcommand at `command_path`.
    ///
    /// `was_supplied_in(&["token", "add"], "tokens_file")` answers for
    /// `token add --tokens-file x`. An empty path is the top level.
    #[must_use]
    pub fn was_supplied_in(&self, command_path: &[&str], id: &str) -> bool {
        self.supplied
            .iter()
            .any(|argument| argument.id == id && argument.command_path == command_path)
    }

    /// Every top-level argument id the operator supplied, sorted.
    ///
    /// Subcommand arguments are in [`supplied_arguments`](Self::supplied_arguments),
    /// which carries the path that tells them apart.
    #[must_use]
    pub fn supplied_ids(&self) -> Vec<&str> {
        self.supplied
            .iter()
            .filter(|argument| argument.command_path.is_empty())
            .map(|argument| argument.id.as_str())
            .collect()
    }

    /// Every argument the operator supplied anywhere in the command tree.
    #[must_use]
    pub fn supplied_arguments(&self) -> &[SuppliedArgument] {
        &self.supplied
    }
}

/// Server-common approver-tooling switches. Flatten into a server's CLI with
/// `#[command(flatten)]` so every mecmcp-based server exposes the same flag.
#[derive(Debug, Clone, Copy, Default, clap::Args)]
pub struct WebApproverArgs {
    /// Include staged actions in change-set status responses (approver
    /// tooling, e.g. the mechub approval webapp). Off by default: exposes
    /// staged config content to any caller with status scope.
    #[arg(long)]
    pub web_enabled_approver: bool,
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
    /// Change an existing token's scopes without touching its secret.
    ///
    /// The alternatives all mint a new secret: `rotate` preserves scopes and
    /// changes the secret — the exact inverse of what is wanted — and
    /// `revoke`+`add` does the same. Hand-editing `tokens.json` keeps the secret
    /// but skips every validation this path performs (#163).
    SetScopes {
        /// Absolute token-store path.
        #[arg(long)]
        tokens_file: PathBuf,
        /// Token audit name.
        #[arg(long)]
        name: String,
        /// Replacement device scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Replacement tool scope. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        /// Apply a widening without the interactive confirmation.
        ///
        /// Widening is a privilege escalation, so it is confirmed by default.
        /// Narrowing is not: reducing a scope cannot grant anything.
        #[arg(long)]
        yes: bool,
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
        try_parse_from::<Cli, _, _>("consumer-mcp", "9.9.9", args)
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

    /// The API's reason for existing, which it could not actually do.
    ///
    /// `approval_timeout_secs` is the flag the doc example names and the one
    /// #162 was raised for, and it is defined by the *server*, not by the shared
    /// type. A parser hard-wired to `Cli` rejected it as unknown, so no consumer
    /// could have implemented the precedence rule this API documents.
    #[test]
    fn a_consumers_own_flag_parses_and_reports_provenance() {
        #[derive(Debug, Parser)]
        struct ServerCli {
            #[command(flatten)]
            shared: Cli,
            #[arg(long, default_value_t = 900)]
            approval_timeout_secs: u64,
        }

        let parsed: ParsedCli<ServerCli> = try_parse_from(
            "consumer-mcp",
            "9.9.9",
            ["consumer-mcp", "--approval-timeout-secs", "60"],
        )
        .expect("a consumer's own flag must parse");

        assert_eq!(parsed.cli.approval_timeout_secs, 60);
        assert!(
            parsed.was_supplied("approval_timeout_secs"),
            "the vendor flag must report as supplied"
        );
        // The shared arguments still work through the flattened struct.
        assert_eq!(parsed.cli.shared.host, "127.0.0.1");
        assert!(!parsed.was_supplied("host"));
    }

    /// Clap stores a subcommand's own arguments in a child `ArgMatches`, so a
    /// walk of the root alone reported nothing for them.
    #[test]
    fn subcommand_arguments_are_collected_with_their_path() {
        let parsed = parse(&[
            "consumer-mcp",
            "token",
            "add",
            "--tokens-file",
            "/etc/t.json",
            "--name",
            "writer",
            "--devices",
            "*",
            "--tools",
            "*",
        ])
        .unwrap();

        assert!(
            parsed.was_supplied_in(&["token", "add"], "tokens_file"),
            "supplied {:?}",
            parsed.supplied_arguments()
        );
        assert!(parsed.was_supplied_in(&["token", "add"], "name"));
    }

    /// The reason subcommand provenance carries a path rather than joining one
    /// flat set: `tokens_file` names both a server flag and an argument of
    /// `token add`, and a server asking about its own flag must not be told
    /// "yes" because the operator typed the other one.
    #[test]
    fn a_subcommand_argument_does_not_answer_for_the_top_level_flag_of_the_same_name() {
        let parsed = parse(&[
            "consumer-mcp",
            "token",
            "add",
            "--tokens-file",
            "/etc/t.json",
            "--name",
            "writer",
            "--devices",
            "*",
            "--tools",
            "*",
        ])
        .unwrap();

        assert!(parsed.was_supplied_in(&["token", "add"], "tokens_file"));
        assert!(
            !parsed.was_supplied("tokens_file"),
            "the server's own --tokens-file was never typed"
        );
        assert!(
            !parsed.supplied_ids().contains(&"tokens_file"),
            "top-level ids must stay top-level: {:?}",
            parsed.supplied_ids()
        );
    }

    /// A global typed once, before the subcommand, is supplied once. Clap
    /// propagates globals into every descendant's matches, so counting them at
    /// each level would invent supplies the operator never made.
    #[test]
    fn a_global_is_reported_once_at_the_level_it_was_typed() {
        let parsed = parse(&[
            "consumer-mcp",
            "--device-mapping",
            "/etc/devices.json",
            "token",
            "list",
            "--tokens-file",
            "/etc/t.json",
        ])
        .unwrap();

        assert!(parsed.was_supplied("device_mapping"));
        let mappings: Vec<_> = parsed
            .supplied_arguments()
            .iter()
            .filter(|argument| argument.id == "device_mapping")
            .collect();
        assert_eq!(
            mappings.len(),
            1,
            "a global typed once must be reported once: {mappings:?}"
        );
    }

    #[test]
    fn web_approver_args_defaults_to_false() {
        let args = WebApproverArgs::default();
        assert!(!args.web_enabled_approver);
    }

    #[test]
    fn web_approver_args_parses_flag() {
        #[derive(Debug, Parser)]
        struct TestCli {
            #[command(flatten)]
            approver: WebApproverArgs,
        }

        let cli = TestCli::parse_from(["test", "--web-enabled-approver"]);
        assert!(cli.approver.web_enabled_approver);
    }

    #[test]
    fn web_approver_args_flattens_without_conflict() {
        #[derive(Debug, Parser)]
        struct ServerCli {
            #[command(flatten)]
            shared: Cli,
            #[command(flatten)]
            approver: WebApproverArgs,
            #[arg(long, default_value_t = 900)]
            approval_timeout_secs: u64,
        }

        let parsed: ParsedCli<ServerCli> = try_parse_from(
            "consumer-mcp",
            "9.9.9",
            [
                "consumer-mcp",
                "--web-enabled-approver",
                "--approval-timeout-secs",
                "60",
            ],
        )
        .expect("WebApproverArgs must flatten without conflict");

        assert!(parsed.cli.approver.web_enabled_approver);
        assert_eq!(parsed.cli.approval_timeout_secs, 60);
        assert!(parsed.was_supplied("web_enabled_approver"));
        assert!(parsed.was_supplied("approval_timeout_secs"));
    }
}
