//! Device commit log parsing for audit verification.
//!
//! This module parses device commit logs in two formats:
//!
//! 1. **Git log format**: Output from config backup systems (Oxidized/RANCID)
//!    with git-style `commit <sha>` and `Device: <id>` headers.
//!
//! 2. **Junos native format**: Output from `show system commit` on Junos devices.
//!    Each entry has an index, timestamp, and indented comment lines.
//!
//! Both formats extract provenance metadata containing `request.id=<uuid>` to
//! enable mecmcp-verify to join device commits with audit records.
//!
//! ## Known Limitation
//!
//! Only commits containing `request.id=` are parsed into `DeviceCommitRef`s.
//! Commits without this metadata (manual changes, rollbacks, scenario setup)
//! are silently skipped. This means the audit join can detect "an audited-looking
//! commit we have no evidence for" but **not** "a change nobody audited at all",
//! which is the more likely unauthorized case. This behavior is intentional for
//! now to avoid flagging every legitimate unaudited operation as a violation.

use std::io::{BufRead, BufReader};
use std::path::Path;

/// Log format type for device commit parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// Git log format with `commit <sha>` and `Device: <id>` lines.
    Git,
    /// Junos native format from `show system commit`.
    JunosNative,
}

/// A device commit reference parsed from a device log.
///
/// Represents one commit that contains a provenance line with a request ID.
/// Used by mecmcp-verify to join device commits with audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCommitRef {
    /// Device identifier.
    ///
    /// For git log format: extracted from `Device: <id>` line.
    /// For Junos native format: provided as a parameter to the parser.
    pub device_id: String,
    /// Commit identifier.
    ///
    /// For git log format: the SHA from `commit <sha>` line.
    /// For Junos native format: normalized ISO 8601 timestamp from the commit entry
    /// (e.g., `2026-08-12T18:36:55Z`). Junos does not provide commit SHAs;
    /// timestamps provide stable identifiers that don't shift when new commits land.
    pub commit_sha: String,
    /// Request identifier extracted from `request.id=<uuid>` in provenance line.
    pub request_id: String,
}

/// Parse device commit references from a device log file.
///
/// The device log is expected to contain git commit messages with the format:
///
/// ```text
/// commit <sha>
/// Author: <name> <email>
/// Date:   <timestamp>
///
/// Device: <device-id>
///     <commit message line>
///     <provenance line containing request.id=<uuid>>
/// ```
///
/// The parser extracts (device_id, commit_sha, request_id) tuples from lines
/// containing "request.id=". The format is:
///
/// - "request.id=" followed by the UUID
/// - UUID terminated by comma, whitespace, or end of line
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
///
/// # Example
///
/// ```no_run
/// # use mecmcp_audit::device_log::parse_device_log_file;
/// # use std::path::Path;
/// let refs = parse_device_log_file(Path::new("device.log"))?;
/// for commit_ref in refs {
///     println!("{} @ {} -> {}", commit_ref.device_id, commit_ref.commit_sha, commit_ref.request_id);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_device_log_file(
    path: &Path,
) -> Result<Vec<DeviceCommitRef>, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    Ok(parse_device_log(reader))
}

/// Detect the log format by examining content shape.
///
/// Returns `LogFormat::Git` if the content contains `commit ` lines followed by hex strings.
/// Returns `LogFormat::JunosNative` if the content starts with numeric indices and timestamps.
///
/// If neither pattern is detected clearly, defaults to `LogFormat::Git` for backward compatibility.
fn detect_format(content: &str) -> LogFormat {
    // Look for git-style commit lines: "commit <hex-sha>"
    for line in content.lines().take(50) {
        if line.starts_with("commit ")
            && let Some(sha_part) = line.strip_prefix("commit ").map(str::trim)
        {
            // Git SHAs are hexadecimal, typically 40 chars but can be abbreviated
            if !sha_part.is_empty() && sha_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return LogFormat::Git;
            }
        }
    }

    // Look for Junos native format: "<index>   <timestamp> UTC by ..."
    // Example: "0   2026-08-12 18:36:55 UTC by netconf via netconf"
    for line in content.lines().take(50) {
        let trimmed = line.trim_start();
        // Check if line starts with a digit followed by whitespace and timestamp-like content
        if trimmed.chars().next().is_some_and(|c| c.is_ascii_digit())
            && (trimmed.contains("UTC by") || trimmed.contains("UTC via"))
        {
            return LogFormat::JunosNative;
        }
    }

    // Default to git format for backward compatibility
    LogFormat::Git
}

/// Parse device commit references from a Junos native commit log.
///
/// Junos `show system commit` output has the format:
///
/// ```text
/// 0   2026-08-12 18:36:55 UTC by netconf via netconf
///     CHG001 by demo-agent (agent) on-behalf-of=mharman request.id=123e4567-e89b-12d3-a456-426614174000
/// 1   2026-08-12 17:58:05 UTC by netconf via netconf
///     rollback to 1 via rollback_config
/// ```
///
/// Each entry has:
/// - Index number (positional, not stable)
/// - Timestamp in `YYYY-MM-DD HH:MM:SS UTC` format
/// - User and method information
/// - Indented comment lines (may span multiple lines)
///
/// The parser extracts (device_id, timestamp, request_id) tuples from entries
/// containing `request.id=`. The timestamp is normalized to ISO 8601 format
/// (e.g., `2026-08-12T18:36:55Z`) and used as the commit identifier.
///
/// # Arguments
///
/// * `reader` - Input stream containing Junos commit log
/// * `device_id` - Device identifier to use for all extracted commits
///
/// # Known Limitation
///
/// Only commits containing `request.id=` are returned. Manual changes, rollbacks,
/// and other unaudited operations are silently skipped. See module-level docs.
fn parse_junos_native_log<R: BufRead>(reader: R, device_id: &str) -> Vec<DeviceCommitRef> {
    let mut device_commits = Vec::new();
    let mut current_timestamp: Option<String> = None;
    let mut in_comment_block = false;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        // Check if this is a new commit entry: starts with digit(s), whitespace, then timestamp
        // Example: "0   2026-08-12 18:36:55 UTC by netconf via netconf"
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let trimmed = line.trim_start();
            if trimmed.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                // Extract timestamp: look for YYYY-MM-DD HH:MM:SS UTC pattern
                if let Some(timestamp) = extract_junos_timestamp(&line) {
                    current_timestamp = Some(timestamp);
                    in_comment_block = false;
                }
            }
        } else {
            // Indented line is part of the commit comment
            in_comment_block = true;
        }

        // Look for request.id in comment lines
        if in_comment_block
            && line.contains("request.id=")
            && let Some(timestamp) = &current_timestamp
            && let Some(req_id_part) = line.split("request.id=").nth(1)
        {
            let req_id = req_id_part
                .split(',')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !req_id.is_empty() {
                device_commits.push(DeviceCommitRef {
                    device_id: device_id.to_string(),
                    commit_sha: timestamp.clone(),
                    request_id: req_id,
                });
            }
        }
    }

    device_commits
}

/// Extract and normalize a Junos timestamp to ISO 8601 format.
///
/// Input format: "0   2026-08-12 18:36:55 UTC by netconf via netconf"
/// Output format: "2026-08-12T18:36:55Z"
fn extract_junos_timestamp(line: &str) -> Option<String> {
    // Find "UTC" to anchor the timestamp
    let utc_pos = line.find("UTC")?;

    // Extract the part before "UTC", which should contain the timestamp
    let before_utc = &line[..utc_pos].trim();

    // Split by whitespace and find date and time components
    let parts: Vec<&str> = before_utc.split_whitespace().collect();

    // We need at least index, date, and time
    // Example parts: ["0", "2026-08-12", "18:36:55"]
    if parts.len() >= 3 {
        let date = parts[parts.len() - 2];
        let time = parts[parts.len() - 1];

        // Basic validation: date should have dashes, time should have colons
        if date.contains('-') && time.contains(':') {
            return Some(format!("{}T{}Z", date, time));
        }
    }

    None
}

/// Parse device commit references from a device log reader in git format.
///
/// This is the core parsing function used by both [`parse_device_log_file`] and
/// mecmcp-verify. See [`parse_device_log_file`] for format details.
pub fn parse_device_log<R: BufRead>(reader: R) -> Vec<DeviceCommitRef> {
    let mut device_commits = Vec::new();
    let mut current_commit_sha: Option<String> = None;
    let mut current_device_id: Option<String> = None;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue, // Skip unparseable lines
        };

        // Example: "commit abc123def456"
        if line.starts_with("commit ")
            && let Some(sha) = line.strip_prefix("commit ").map(|s| s.trim().to_string())
        {
            current_commit_sha = Some(sha);
            current_device_id = None;
        }

        // Example: "Device: vsrx-prod"
        if line.contains("Device:")
            && let Some(device) = line.split("Device:").nth(1).map(|s| s.trim().to_string())
        {
            current_device_id = Some(device);
        }

        // Example: "Provenance: request.id=550e8400-e29b-41d4-a716-446655440000, ..."
        if line.contains("request.id=")
            && let (Some(sha), Some(device)) = (&current_commit_sha, &current_device_id)
        {
            // Extract request_id
            if let Some(req_id_part) = line.split("request.id=").nth(1) {
                let req_id = req_id_part
                    .split(',')
                    .next()
                    .unwrap_or("")
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !req_id.is_empty() {
                    device_commits.push(DeviceCommitRef {
                        device_id: device.clone(),
                        commit_sha: sha.clone(),
                        request_id: req_id,
                    });
                }
            }
        }
    }

    device_commits
}

/// Parse device commit references with explicit format specification.
///
/// For [`LogFormat::Git`], parses git-style logs with `commit <sha>` and `Device: <id>` lines.
/// The `device_id` parameter is ignored for git format (device ID comes from the log).
///
/// For [`LogFormat::JunosNative`], parses Junos `show system commit` output.
/// The `device_id` parameter is required and used for all extracted commits.
///
/// # Arguments
///
/// * `reader` - Input stream containing the device log
/// * `format` - Log format to use for parsing
/// * `device_id` - Device identifier (required for Junos native format, ignored for git format)
///
/// # Example
///
/// ```
/// # use mecmcp_audit::device_log::{parse_device_log_with_format, LogFormat};
/// # use std::io::Cursor;
/// let junos_log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
///     CHG001 request.id=550e8400-e29b-41d4-a716-446655440000
/// "#;
/// let refs = parse_device_log_with_format(
///     Cursor::new(junos_log),
///     LogFormat::JunosNative,
///     Some("vsrx-prod")
/// );
/// assert_eq!(refs.len(), 1);
/// assert_eq!(refs[0].device_id, "vsrx-prod");
/// assert_eq!(refs[0].commit_sha, "2026-08-12T18:36:55Z");
/// ```
pub fn parse_device_log_with_format<R: BufRead>(
    reader: R,
    format: LogFormat,
    device_id: Option<&str>,
) -> Vec<DeviceCommitRef> {
    match format {
        LogFormat::Git => parse_device_log(reader),
        LogFormat::JunosNative => {
            let device = device_id.unwrap_or("unknown");
            parse_junos_native_log(reader, device)
        }
    }
}

/// Parse device commit references with automatic format detection.
///
/// Reads the input to detect whether it's git log format or Junos native format,
/// then parses accordingly.
///
/// For Junos native format, the `device_id` parameter is required.
/// For git format, `device_id` is ignored (extracted from the log).
///
/// # Arguments
///
/// * `content` - Complete log content as a string
/// * `device_id` - Device identifier (required for Junos native format, ignored for git format)
///
/// # Example
///
/// ```
/// # use mecmcp_audit::device_log::parse_device_log_auto;
/// let junos_log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
///     CHG001 request.id=550e8400-e29b-41d4-a716-446655440000
/// "#;
/// let refs = parse_device_log_auto(junos_log, Some("vsrx-prod"));
/// assert_eq!(refs.len(), 1);
/// ```
pub fn parse_device_log_auto(content: &str, device_id: Option<&str>) -> Vec<DeviceCommitRef> {
    let format = detect_format(content);
    let cursor = std::io::Cursor::new(content);
    parse_device_log_with_format(cursor, format, device_id)
}

/// Parse device commit references from a file with automatic format detection.
///
/// Reads the file, detects its format, and parses accordingly.
///
/// For Junos native format, the `device_id` parameter is required.
/// For git format, `device_id` is ignored (extracted from the log).
///
/// # Errors
///
/// Returns an error if the file cannot be opened or read.
///
/// # Example
///
/// ```no_run
/// # use mecmcp_audit::device_log::parse_device_log_file_auto;
/// # use std::path::Path;
/// let refs = parse_device_log_file_auto(Path::new("junos-commits.log"), Some("vsrx-prod"))?;
/// for commit_ref in refs {
///     println!("{} @ {} -> {}", commit_ref.device_id, commit_ref.commit_sha, commit_ref.request_id);
/// }
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn parse_device_log_file_auto(
    path: &Path,
    device_id: Option<&str>,
) -> Result<Vec<DeviceCommitRef>, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    Ok(parse_device_log_auto(&content, device_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_single_commit() {
        let log = r#"commit abc123def456
Author: Alice <alice@example.org>
Date:   Fri Aug 9 14:01:00 2026 +0000

Device: vsrx-prod
    Fix BGP peering | anthropic-public, claude-opus-5 request.id=550e8400-e29b-41d4-a716-446655440000
"#;

        let refs = parse_device_log(Cursor::new(log));

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].device_id, "vsrx-prod");
        assert_eq!(refs[0].commit_sha, "abc123def456");
        assert_eq!(refs[0].request_id, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn parse_multiple_commits() {
        let log = r#"commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Device: vsrx-prod
    request.id=11111111-1111-1111-1111-111111111111

commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Device: vsrx-lab
    request.id=22222222-2222-2222-2222-222222222222
"#;

        let refs = parse_device_log(Cursor::new(log));

        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].request_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(refs[1].request_id, "22222222-2222-2222-2222-222222222222");
    }

    #[test]
    fn missing_request_id_field() {
        let log = r#"commit abc123
Device: vsrx-prod
    Fix NAT policy | anthropic-public, claude-opus-5
"#;

        let refs = parse_device_log(Cursor::new(log));
        assert_eq!(refs.len(), 0);
    }

    #[test]
    fn request_id_terminated_by_comma() {
        let log = r#"commit abc123
Device: vsrx-prod
    request.id=deadbeef-dead-beef-dead-beefdeadbeef, more text
"#;

        let refs = parse_device_log(Cursor::new(log));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].request_id, "deadbeef-dead-beef-dead-beefdeadbeef");
    }

    #[test]
    fn request_id_terminated_by_whitespace() {
        let log = r#"commit abc123
Device: vsrx-prod
    request.id=deadbeef-dead-beef-dead-beefdeadbeef more text
"#;

        let refs = parse_device_log(Cursor::new(log));
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].request_id, "deadbeef-dead-beef-dead-beefdeadbeef");
    }

    #[test]
    fn parse_junos_native_single_commit() {
        let log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
    CHG001 by demo-agent (agent) on-behalf-of=mharman via anthropic-public model=x request.id=123e4567-e89b-12d3-a456-426614174000
"#;

        let refs = parse_junos_native_log(Cursor::new(log), "vsrx-prod");

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].device_id, "vsrx-prod");
        assert_eq!(refs[0].commit_sha, "2026-08-12T18:36:55Z");
        assert_eq!(refs[0].request_id, "123e4567-e89b-12d3-a456-426614174000");
    }

    #[test]
    fn parse_junos_native_multiple_commits() {
        let log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
    CHG001 request.id=11111111-1111-1111-1111-111111111111
1   2026-08-12 17:58:05 UTC by netconf via netconf
    rollback to 1 via rollback_config
2   2026-08-12 16:22:10 UTC by root via cli
    CHG002 request.id=22222222-2222-2222-2222-222222222222
"#;

        let refs = parse_junos_native_log(Cursor::new(log), "vsrx-lab");

        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].request_id, "11111111-1111-1111-1111-111111111111");
        assert_eq!(refs[0].commit_sha, "2026-08-12T18:36:55Z");
        assert_eq!(refs[1].request_id, "22222222-2222-2222-2222-222222222222");
        assert_eq!(refs[1].commit_sha, "2026-08-12T16:22:10Z");
    }

    #[test]
    fn junos_native_skip_commits_without_request_id() {
        let log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
    Manual config change via CLI
1   2026-08-12 17:58:05 UTC by netconf via netconf
    rollback to 1 via rollback_config
"#;

        let refs = parse_junos_native_log(Cursor::new(log), "vsrx-prod");
        assert_eq!(refs.len(), 0);
    }

    #[test]
    fn junos_native_multiline_comment_with_request_id_on_second_line() {
        let log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
    CHG001 by demo-agent (agent) on-behalf-of=mharman
    via anthropic-public model=claude-opus-5 request.id=deadbeef-dead-beef-dead-beefdeadbeef
"#;

        let refs = parse_junos_native_log(Cursor::new(log), "vsrx-prod");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].request_id, "deadbeef-dead-beef-dead-beefdeadbeef");
    }

    #[test]
    fn junos_timestamp_normalization_consistency() {
        let log1 = "0   2026-08-12 18:36:55 UTC by netconf via netconf\n    request.id=test-id";
        let log2 = "1   2026-08-12 18:36:55 UTC by root via cli\n    request.id=test-id-2";

        let refs1 = parse_junos_native_log(Cursor::new(log1), "device1");
        let refs2 = parse_junos_native_log(Cursor::new(log2), "device2");

        // Same timestamp should normalize to same value
        assert_eq!(refs1[0].commit_sha, refs2[0].commit_sha);
        assert_eq!(refs1[0].commit_sha, "2026-08-12T18:36:55Z");
    }

    #[test]
    fn detect_git_format() {
        let git_log = r#"commit abc123def456
Author: Alice <alice@example.org>
Date:   Fri Aug 9 14:01:00 2026 +0000

Device: vsrx-prod
    Fix BGP peering
"#;

        assert_eq!(detect_format(git_log), LogFormat::Git);
    }

    #[test]
    fn detect_junos_native_format() {
        let junos_log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
    CHG001 by demo-agent
1   2026-08-12 17:58:05 UTC by netconf via netconf
    rollback to 1
"#;

        assert_eq!(detect_format(junos_log), LogFormat::JunosNative);
    }

    #[test]
    fn parse_with_format_git() {
        let log = r#"commit abc123
Device: vsrx-prod
    request.id=550e8400-e29b-41d4-a716-446655440000
"#;

        let refs = parse_device_log_with_format(Cursor::new(log), LogFormat::Git, None);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].commit_sha, "abc123");
    }

    #[test]
    fn parse_with_format_junos_native() {
        let log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
    request.id=550e8400-e29b-41d4-a716-446655440000
"#;

        let refs = parse_device_log_with_format(
            Cursor::new(log),
            LogFormat::JunosNative,
            Some("vsrx-prod"),
        );

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].device_id, "vsrx-prod");
        assert_eq!(refs[0].commit_sha, "2026-08-12T18:36:55Z");
    }

    #[test]
    fn parse_auto_detects_git_format() {
        let log = r#"commit abc123
Device: vsrx-prod
    request.id=550e8400-e29b-41d4-a716-446655440000
"#;

        let refs = parse_device_log_auto(log, None);

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].commit_sha, "abc123");
    }

    #[test]
    fn parse_auto_detects_junos_native_format() {
        let log = r#"0   2026-08-12 18:36:55 UTC by netconf via netconf
    request.id=550e8400-e29b-41d4-a716-446655440000
"#;

        let refs = parse_device_log_auto(log, Some("vsrx-prod"));

        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].device_id, "vsrx-prod");
        assert_eq!(refs[0].commit_sha, "2026-08-12T18:36:55Z");
    }

    #[test]
    fn git_format_regression_test() {
        // Ensure existing git format parsing is not broken
        let log = r#"commit aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Author: Alice <alice@example.org>
Date:   Fri Aug 9 14:01:00 2026 +0000

Device: vsrx-prod
    Fix BGP peering | anthropic-public, claude-opus-5 request.id=550e8400-e29b-41d4-a716-446655440000

commit bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
Author: Bob <bob@example.org>
Date:   Thu Aug 8 12:30:00 2026 +0000

Device: vsrx-lab
    Update firewall rules request.id=deadbeef-dead-beef-dead-beefdeadbeef
"#;

        let refs = parse_device_log(Cursor::new(log));

        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].device_id, "vsrx-prod");
        assert_eq!(
            refs[0].commit_sha,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(refs[0].request_id, "550e8400-e29b-41d4-a716-446655440000");
        assert_eq!(refs[1].device_id, "vsrx-lab");
        assert_eq!(
            refs[1].commit_sha,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(refs[1].request_id, "deadbeef-dead-beef-dead-beefdeadbeef");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn junos_timestamp_extraction() {
        let line1 = "0   2026-08-12 18:36:55 UTC by netconf via netconf";
        let line2 = "123   2026-01-01 00:00:00 UTC by root via cli";

        assert_eq!(
            extract_junos_timestamp(line1).unwrap(),
            "2026-08-12T18:36:55Z"
        );
        assert_eq!(
            extract_junos_timestamp(line2).unwrap(),
            "2026-01-01T00:00:00Z"
        );
    }

    #[test]
    fn malformed_junos_input_no_panic() {
        let bad_logs = vec![
            "",
            "garbage\nmore garbage",
            "0   not-a-timestamp",
            "   indented but no header",
            "request.id=orphaned-without-timestamp",
        ];

        for bad_log in bad_logs {
            let refs = parse_junos_native_log(Cursor::new(bad_log), "device");
            // Should not panic, just return empty or partial results
            assert!(refs.is_empty() || refs.iter().all(|r| !r.request_id.is_empty()));
        }
    }
}
