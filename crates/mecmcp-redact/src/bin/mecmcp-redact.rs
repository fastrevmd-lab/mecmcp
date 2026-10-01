//! `mecmcp-redact`: run the shared redaction engine from the command line.
//!
//! Every Rust MCP server in this fleet reaches [`mecmcp_redact::redact_text`]
//! / `redact_json_str` / `redact_xml_str` directly. A non-Rust consumer
//! (`mechubbench` is Python) cannot link the crate, so this binary is the
//! same engine reached over stdin/stdout instead: pipe a tool-output body
//! in, get the redacted body out, with the exact same rules a server
//! applies.
//!
//! # Why there is no `--profile` flag yet
//!
//! The consolidation epic this binary is part of (MEC-1231) found that most
//! vendor "redaction rule sets" surveyed either already live entirely in
//! [`mecmcp_redact`]'s shared denylist (nothing left to select between) or
//! are not key/value rules at all (an XML element-name/log-line engine, or
//! JSON field allowlists tied to a vendor's own Rust types) and cannot
//! become a flag value here without inventing behavior this crate cannot yet
//! back up. Shipping a `--profile <vendor>` flag that silently applied the
//! same rules for every vendor would be worse than not shipping it: a
//! redaction tool's flags are claims about what it does, and a no-op vendor
//! flag is exactly the kind of claim that is dangerous to get wrong. The
//! flag lands once a vendor profile actually changes behavior.
use std::io::{self, Read, Write};
use std::process::ExitCode;

use clap::{Parser, ValueEnum};
use mecmcp_redact::Format;

/// A tool output's wire format, mirroring [`mecmcp_redact::Format`].
///
/// A local copy rather than `#[derive(ValueEnum)]` on the library's own
/// [`Format`]: that type is part of the library's public API and must not
/// carry a `clap` dependency into every consumer that links the crate for
/// `redact_text`/`redact_json_str`/etc. and never builds this binary.
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
enum CliFormat {
    Text,
    Json,
    Xml,
}

impl From<CliFormat> for Format {
    fn from(value: CliFormat) -> Self {
        match value {
            CliFormat::Text => Format::Text,
            CliFormat::Json => Format::Json,
            CliFormat::Xml => Format::Xml,
        }
    }
}

/// Redact secret-shaped values from a tool-output body, stdin to stdout.
#[derive(Debug, Parser)]
#[command(name = "mecmcp-redact", version)]
struct Cli {
    /// The input's wire format.
    #[arg(long, value_enum, default_value_t = CliFormat::Text)]
    format: CliFormat,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let mut input = String::new();
    if let Err(error) = io::stdin().read_to_string(&mut input) {
        eprintln!("mecmcp-redact: failed to read stdin: {error}");
        return ExitCode::FAILURE;
    }

    let redacted = match Format::from(cli.format) {
        Format::Text => Ok(mecmcp_redact::redact_text(&input)),
        Format::Json => mecmcp_redact::redact_json_str(&input),
        Format::Xml => mecmcp_redact::redact_xml_str(&input),
    };

    match redacted {
        Ok(output) => {
            if let Err(error) = io::stdout().write_all(output.as_bytes()) {
                eprintln!("mecmcp-redact: failed to write stdout: {error}");
                return ExitCode::FAILURE;
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            // Fail closed: never fall back to printing the unredacted input
            // just because it didn't parse (same contract `redact_json_str`
            // / `redact_xml_str` document).
            eprintln!("mecmcp-redact: {error}");
            ExitCode::FAILURE
        }
    }
}
