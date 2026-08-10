//! Device commit log parsing for audit verification.
//!
//! This module parses device commit logs (e.g., git logs from Junos/PAN-OS) to
//! extract provenance metadata attached by the commit-metadata hook. The parsed
//! references enable mecmcp-verify to join device commits with audit records.

use std::io::{BufRead, BufReader};
use std::path::Path;

/// A device commit reference parsed from a device log.
///
/// Represents one commit that contains a provenance line with a request ID.
/// Used by mecmcp-verify to join device commits with audit records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCommitRef {
    /// Device identifier (from "Device: <id>" line).
    pub device_id: String,
    /// Commit SHA (from "commit <sha>" line).
    pub commit_sha: String,
    /// Request identifier extracted from "request.id=<uuid>" in provenance line.
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

/// Parse device commit references from a device log reader.
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
}
