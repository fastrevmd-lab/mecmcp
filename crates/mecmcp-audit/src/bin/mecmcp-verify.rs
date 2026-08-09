//! Verification tool for evidence-first audit runs.
//!
//! Reads closed evidence segments from multiple audit servers, verifies chain
//! integrity, segment-head signatures, run-manifest completeness, and the
//! device↔audit join.
//!
//! ## Run Manifest Format
//!
//! A run manifest is a JSON file that defines the expected state of a complete
//! audit run. It MUST contain:
//!
//! - `run_id`: The audit run identifier
//! - `cutoff`: ISO 8601 timestamp when the run was closed
//! - `servers`: Array of server manifests, each containing:
//!   - `server_id`: The audit server identifier
//!   - `segments`: Array of segment manifests, each containing:
//!     - `segment_seq`: Segment sequence number (0-based)
//!     - `final_seq`: Final record sequence in this segment
//!     - `head_hash`: The segment head hash (sha256:...)
//!
//! Example manifest:
//!
//! ```json
//! {
//!   "run_id": "run_20260809_143210",
//!   "cutoff": "2026-08-09T14:35:30Z",
//!   "servers": [
//!     {
//!       "server_id": "rustsdcmcp-606",
//!       "segments": [
//!         {
//!           "segment_seq": 0,
//!           "final_seq": 3,
//!           "head_hash": "sha256:..."
//!         }
//!       ]
//!     },
//!     {
//!       "server_id": "rustsdcmcp-607",
//!       "segments": [
//!         {
//!           "segment_seq": 0,
//!           "final_seq": 2,
//!           "head_hash": "sha256:..."
//!         }
//!       ]
//!     }
//!   ]
//! }
//! ```
//!
//! ## Exit Codes
//!
//! - 0: Verification passed
//! - 1: Verification failed (violations listed to stderr)
//! - 2: Usage or I/O error

use mecmcp_audit::evidence::ClosedSegment;
use mecmcp_audit::signing::{VerifyingKey, decode_signature, load_verifying_key, verify_head};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

/// Run manifest: expected state of a complete audit run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunManifest {
    /// Audit run identifier.
    pub run_id: String,
    /// ISO 8601 timestamp when the run was closed.
    pub cutoff: String,
    /// Expected server chains.
    pub servers: Vec<ServerManifest>,
}

/// Server manifest: expected segments from one audit server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerManifest {
    /// Audit server identifier.
    pub server_id: String,
    /// Expected segments.
    pub segments: Vec<SegmentManifest>,
}

/// Segment manifest: expected head hash and record count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentManifest {
    /// Segment sequence number (0-based).
    pub segment_seq: u64,
    /// Final record sequence in this segment.
    pub final_seq: u64,
    /// Segment head hash.
    pub head_hash: String,
}

/// Verification violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "violation_type")]
pub enum Violation {
    /// Server chain expected by manifest is missing.
    #[serde(rename = "missing_server_chain")]
    MissingServerChain {
        /// Audit server identifier.
        server_id: String,
    },
    /// Segment expected by manifest is missing.
    #[serde(rename = "missing_segment")]
    MissingSegment {
        /// Audit server identifier.
        server_id: String,
        /// Segment sequence number.
        segment_seq: u64,
    },
    /// Record hash mismatch (tampering detected).
    #[serde(rename = "record_hash_mismatch")]
    RecordHashMismatch {
        /// Audit server identifier.
        server_id: String,
        /// Segment sequence number.
        segment_seq: u64,
        /// Record index within segment.
        record_index: usize,
        /// Expected hash.
        expected: String,
        /// Actual hash.
        actual: String,
    },
    /// Segment prev_hash doesn't match previous segment's head.
    #[serde(rename = "segment_chain_break")]
    SegmentChainBreak {
        /// Audit server identifier.
        server_id: String,
        /// Segment sequence number.
        segment_seq: u64,
        /// Expected prev_hash.
        expected_prev: String,
        /// Actual prev_hash.
        actual_prev: String,
    },
    /// Segment head hash doesn't match manifest.
    #[serde(rename = "head_hash_mismatch")]
    HeadHashMismatch {
        /// Audit server identifier.
        server_id: String,
        /// Segment sequence number.
        segment_seq: u64,
        /// Expected head hash.
        expected: String,
        /// Actual head hash.
        actual: String,
    },
    /// Signature verification failed.
    #[serde(rename = "signature_verification_failed")]
    SignatureVerificationFailed {
        /// Audit server identifier.
        server_id: String,
        /// Segment sequence number.
        segment_seq: u64,
        /// Public key name.
        pubkey_name: String,
        /// Error message.
        error: String,
    },
    /// Device commit references request_id not found in audit records.
    #[serde(rename = "orphaned_device_commit")]
    OrphanedDeviceCommit {
        /// Device identifier.
        device_id: String,
        /// Commit SHA.
        commit_sha: String,
        /// Request identifier.
        request_id: String,
    },
    /// Audit record has no matching device commit.
    #[serde(rename = "orphaned_audit_record")]
    OrphanedAuditRecord {
        /// Audit server identifier.
        server_id: String,
        /// Request identifier.
        request_id: String,
    },
}

/// Verification result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationResult {
    /// Whether verification passed.
    pub passed: bool,
    /// List of violations (empty if passed).
    pub violations: Vec<Violation>,
    /// Summary statistics.
    pub summary: VerificationSummary,
}

/// Verification summary statistics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Number of servers verified.
    pub servers_verified: usize,
    /// Total segments verified.
    pub segments_verified: usize,
    /// Total records verified.
    pub records_verified: usize,
    /// Number of device commits checked.
    pub device_commits_checked: usize,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        print_usage(&args[0]);
        std::process::exit(if args.len() < 2 { 2 } else { 0 });
    }

    // Parse arguments
    let mut run_id: Option<String> = None;
    let mut chains_dir: Option<PathBuf> = None;
    let mut manifest_path: Option<PathBuf> = None;
    let mut pubkeys_dir: Option<PathBuf> = None;
    let mut device_log_path: Option<PathBuf> = None;
    let mut json_output = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--run" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --run requires a value");
                    std::process::exit(2);
                }
                run_id = Some(args[i + 1].clone());
                i += 2;
            }
            "--chains" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --chains requires a value");
                    std::process::exit(2);
                }
                chains_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--manifest" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --manifest requires a value");
                    std::process::exit(2);
                }
                manifest_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--pubkeys" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --pubkeys requires a value");
                    std::process::exit(2);
                }
                pubkeys_dir = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--device-log" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --device-log requires a value");
                    std::process::exit(2);
                }
                device_log_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--json" => {
                json_output = true;
                i += 1;
            }
            _ => {
                eprintln!("Error: unknown argument: {}", args[i]);
                print_usage(&args[0]);
                std::process::exit(2);
            }
        }
    }

    // Validate required arguments
    let run_id = run_id.unwrap_or_else(|| {
        eprintln!("Error: --run is required");
        std::process::exit(2);
    });
    let chains_dir = chains_dir.unwrap_or_else(|| {
        eprintln!("Error: --chains is required");
        std::process::exit(2);
    });
    let manifest_path = manifest_path.unwrap_or_else(|| {
        eprintln!("Error: --manifest is required");
        std::process::exit(2);
    });
    let pubkeys_dir = pubkeys_dir.unwrap_or_else(|| {
        eprintln!("Error: --pubkeys is required");
        std::process::exit(2);
    });

    // Run verification
    match verify_run(
        &run_id,
        &chains_dir,
        &manifest_path,
        &pubkeys_dir,
        device_log_path.as_deref(),
    ) {
        Ok(result) => {
            if json_output {
                let json = serde_json::to_string_pretty(&result)
                    .expect("VerificationResult serialization is infallible");
                println!("{}", json);
            } else {
                print_result(&result);
            }
            std::process::exit(if result.passed { 0 } else { 1 });
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(2);
        }
    }
}

fn print_usage(program: &str) {
    eprintln!("Usage: {} [OPTIONS]", program);
    eprintln!();
    eprintln!("Verify evidence-first audit run integrity.");
    eprintln!();
    eprintln!("Required arguments:");
    eprintln!("  --run <run_id>              Audit run identifier to verify");
    eprintln!("  --chains <dir>              Directory containing server chain files");
    eprintln!("  --manifest <file>           Run manifest JSON file");
    eprintln!("  --pubkeys <dir>             Directory containing server public keys");
    eprintln!();
    eprintln!("Optional arguments:");
    eprintln!("  --device-log <file>         Device commit log for join verification");
    eprintln!("  --json                      Output verification result as JSON");
    eprintln!("  -h, --help                  Show this help message");
}

fn verify_run(
    run_id: &str,
    chains_dir: &std::path::Path,
    manifest_path: &std::path::Path,
    pubkeys_dir: &std::path::Path,
    device_log_path: Option<&std::path::Path>,
) -> Result<VerificationResult, Box<dyn std::error::Error>> {
    // Load manifest
    let manifest_json = std::fs::read_to_string(manifest_path)?;
    let manifest: RunManifest = serde_json::from_str(&manifest_json)?;

    if manifest.run_id != run_id {
        return Err(format!(
            "Manifest run_id '{}' doesn't match requested run_id '{}'",
            manifest.run_id, run_id
        )
        .into());
    }

    let mut violations = Vec::new();
    let mut total_segments = 0;
    let mut total_records = 0;

    // Load all server chains
    let mut server_chains: HashMap<String, Vec<ClosedSegment>> = HashMap::new();
    for server_manifest in &manifest.servers {
        let chain_file = chains_dir.join(format!("{}.jsonl", server_manifest.server_id));

        if !chain_file.exists() {
            violations.push(Violation::MissingServerChain {
                server_id: server_manifest.server_id.clone(),
            });
            continue;
        }

        let segments = load_chain_segments(&chain_file, run_id)?;
        server_chains.insert(server_manifest.server_id.clone(), segments);
    }

    // Load public keys
    let mut pubkeys: HashMap<String, VerifyingKey> = HashMap::new();
    for entry in std::fs::read_dir(pubkeys_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("pub") {
            let server_id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("Invalid pubkey filename")?
                .to_string();
            let key = load_verifying_key(&path)?;
            pubkeys.insert(server_id, key);
        }
    }

    // Verify each server chain
    for server_manifest in &manifest.servers {
        let segments = match server_chains.get(&server_manifest.server_id) {
            Some(segs) => segs,
            None => continue, // Already reported as MissingServerChain
        };

        // Check manifest completeness
        for seg_manifest in &server_manifest.segments {
            let segment = segments
                .iter()
                .find(|s| s.segment_seq == seg_manifest.segment_seq);

            let segment = match segment {
                Some(seg) => seg,
                None => {
                    violations.push(Violation::MissingSegment {
                        server_id: server_manifest.server_id.clone(),
                        segment_seq: seg_manifest.segment_seq,
                    });
                    continue;
                }
            };

            // Verify head hash matches manifest
            if segment.head_hash != seg_manifest.head_hash {
                violations.push(Violation::HeadHashMismatch {
                    server_id: server_manifest.server_id.clone(),
                    segment_seq: segment.segment_seq,
                    expected: seg_manifest.head_hash.clone(),
                    actual: segment.head_hash.clone(),
                });
            }

            total_segments += 1;
            total_records += segment.records().len();
        }

        // Verify chain integrity (prev_hash links)
        for i in 1..segments.len() {
            let prev_segment = &segments[i - 1];
            let curr_segment = &segments[i];

            if curr_segment.prev_hash != prev_segment.head_hash {
                violations.push(Violation::SegmentChainBreak {
                    server_id: server_manifest.server_id.clone(),
                    segment_seq: curr_segment.segment_seq,
                    expected_prev: prev_segment.head_hash.clone(),
                    actual_prev: curr_segment.prev_hash.clone(),
                });
            }
        }

        // Verify record hashes within each segment
        for segment in segments {
            match verify_segment_records(segment) {
                Ok(_) => {}
                Err(violation) => violations.push(violation),
            }
        }

        // Verify signatures
        if let Some(pubkey) = pubkeys.get(&server_manifest.server_id) {
            for segment in segments {
                // Load signature file
                let sig_file = chains_dir.join(format!(
                    "{}_seg{}.sig",
                    server_manifest.server_id, segment.segment_seq
                ));

                if !sig_file.exists() {
                    violations.push(Violation::SignatureVerificationFailed {
                        server_id: server_manifest.server_id.clone(),
                        segment_seq: segment.segment_seq,
                        pubkey_name: server_manifest.server_id.clone(),
                        error: "Signature file not found".to_string(),
                    });
                    continue;
                }

                let sig_b64 = std::fs::read_to_string(&sig_file)?.trim().to_string();
                match decode_signature(&sig_b64) {
                    Ok(signature) => {
                        if let Err(e) = verify_head(segment, &signature, pubkey) {
                            violations.push(Violation::SignatureVerificationFailed {
                                server_id: server_manifest.server_id.clone(),
                                segment_seq: segment.segment_seq,
                                pubkey_name: server_manifest.server_id.clone(),
                                error: format!("{}", e),
                            });
                        }
                    }
                    Err(e) => {
                        violations.push(Violation::SignatureVerificationFailed {
                            server_id: server_manifest.server_id.clone(),
                            segment_seq: segment.segment_seq,
                            pubkey_name: server_manifest.server_id.clone(),
                            error: format!("Invalid signature encoding: {}", e),
                        });
                    }
                }
            }
        }
    }

    // Verify device↔audit join if device log provided
    let device_commits_checked = if let Some(device_log) = device_log_path {
        verify_device_join(device_log, &server_chains, &mut violations)?
    } else {
        0
    };

    let result = VerificationResult {
        passed: violations.is_empty(),
        violations,
        summary: VerificationSummary {
            servers_verified: manifest.servers.len(),
            segments_verified: total_segments,
            records_verified: total_records,
            device_commits_checked,
        },
    };

    Ok(result)
}

/// Load chain segments for a specific run from a JSONL file.
fn load_chain_segments(
    path: &std::path::Path,
    run_id: &str,
) -> Result<Vec<ClosedSegment>, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut segments = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let segment: ClosedSegment = serde_json::from_str(&line)?;
        if segment.run_id == run_id {
            segments.push(segment);
        }
    }

    // Sort by segment_seq
    segments.sort_by_key(|s| s.segment_seq);

    Ok(segments)
}

/// Verify record hashes within a segment (recompute and compare).
fn verify_segment_records(segment: &ClosedSegment) -> Result<(), Violation> {
    use mecmcp_audit::evidence::{ChainSegment, EvidenceRecord, append, close};

    // Reconstruct the segment by re-appending records
    let mut verify_seg = ChainSegment::new(
        segment.run_id.clone(),
        segment.server_id.clone(),
        segment.segment_seq,
        segment.prev_hash.clone(),
    );

    for (index, record) in segment.records().iter().enumerate() {
        let mut cleared_record = record.clone();

        // Clear envelope fields so append() can validate and inject them
        match &mut cleared_record {
            EvidenceRecord::Proposal(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
            EvidenceRecord::Approval(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
            EvidenceRecord::ApplyIntent(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
            EvidenceRecord::ResultReceipt(r) => {
                r.run_id.clear();
                r.server_id.clear();
                r.segment_seq = 0;
                r.prev_hash.clear();
            }
        }

        if append(&mut verify_seg, cleared_record).is_err() {
            // This would only fail if envelope mismatch, which shouldn't happen
            // since we're using the same segment context
            return Err(Violation::RecordHashMismatch {
                server_id: segment.server_id.clone(),
                segment_seq: segment.segment_seq,
                record_index: index,
                expected: "unknown".to_string(),
                actual: "envelope_mismatch".to_string(),
            });
        }
    }

    let verify_closed = close(verify_seg).map_err(|_| Violation::RecordHashMismatch {
        server_id: segment.server_id.clone(),
        segment_seq: segment.segment_seq,
        record_index: 0,
        expected: segment.head_hash.clone(),
        actual: "close_failed".to_string(),
    })?;

    if verify_closed.head_hash != segment.head_hash {
        return Err(Violation::RecordHashMismatch {
            server_id: segment.server_id.clone(),
            segment_seq: segment.segment_seq,
            record_index: 0,
            expected: segment.head_hash.clone(),
            actual: verify_closed.head_hash.clone(),
        });
    }

    Ok(())
}

/// Verify device↔audit join: parse request_ids from device log and match with audit records.
///
/// The device log is expected to contain git commit messages with lines like:
/// ```
/// Provenance: request.id=<uuid>, ...
/// ```
fn verify_device_join(
    device_log_path: &std::path::Path,
    server_chains: &HashMap<String, Vec<ClosedSegment>>,
    violations: &mut Vec<Violation>,
) -> Result<usize, Box<dyn std::error::Error>> {
    use std::io::{BufRead, BufReader};

    let file = std::fs::File::open(device_log_path)?;
    let reader = BufReader::new(file);

    // Parse device commits: extract (device_id, commit_sha, request_id)
    let mut device_commits: Vec<(String, String, String)> = Vec::new();
    let mut current_commit_sha: Option<String> = None;
    let mut current_device_id: Option<String> = None;

    for line in reader.lines() {
        let line = line?;

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
                    .trim()
                    .to_string();
                if !req_id.is_empty() {
                    device_commits.push((device.clone(), sha.clone(), req_id));
                }
            }
        }
    }

    // Collect all request_ids from audit records
    let mut audit_request_ids: HashSet<String> = HashSet::new();
    for segments in server_chains.values() {
        for segment in segments {
            for record in segment.records() {
                use mecmcp_audit::evidence::EvidenceRecord;
                let request_id = match record {
                    EvidenceRecord::Proposal(r) => &r.request_id,
                    EvidenceRecord::Approval(r) => &r.request_id,
                    EvidenceRecord::ApplyIntent(r) => &r.request_id,
                    EvidenceRecord::ResultReceipt(r) => &r.request_id,
                };
                audit_request_ids.insert(request_id.clone());
            }
        }
    }

    // Check for orphaned device commits (not in audit)
    for (device_id, commit_sha, request_id) in &device_commits {
        if !audit_request_ids.contains(request_id) {
            violations.push(Violation::OrphanedDeviceCommit {
                device_id: device_id.clone(),
                commit_sha: commit_sha.clone(),
                request_id: request_id.clone(),
            });
        }
    }

    // Check for orphaned audit records (not in device commits)
    let device_request_ids: HashSet<String> = device_commits
        .iter()
        .map(|(_, _, req_id)| req_id.clone())
        .collect();

    for (server_id, segments) in server_chains {
        for segment in segments {
            for record in segment.records() {
                use mecmcp_audit::evidence::EvidenceRecord;
                let request_id = match record {
                    EvidenceRecord::Proposal(r) => &r.request_id,
                    EvidenceRecord::Approval(r) => &r.request_id,
                    EvidenceRecord::ApplyIntent(r) => &r.request_id,
                    EvidenceRecord::ResultReceipt(r) => &r.request_id,
                };
                if !device_request_ids.contains(request_id) {
                    violations.push(Violation::OrphanedAuditRecord {
                        server_id: server_id.clone(),
                        request_id: request_id.clone(),
                    });
                }
            }
        }
    }

    Ok(device_commits.len())
}

fn print_result(result: &VerificationResult) {
    if result.passed {
        println!("✓ Verification PASSED");
        println!();
        println!("Summary:");
        println!(
            "  Servers verified:        {}",
            result.summary.servers_verified
        );
        println!(
            "  Segments verified:       {}",
            result.summary.segments_verified
        );
        println!(
            "  Records verified:        {}",
            result.summary.records_verified
        );
        println!(
            "  Device commits checked:  {}",
            result.summary.device_commits_checked
        );
    } else {
        println!("✗ Verification FAILED");
        println!();
        println!("Violations ({}):", result.violations.len());
        for (i, violation) in result.violations.iter().enumerate() {
            println!("  {}. {}", i + 1, format_violation(violation));
        }
        println!();
        println!("Summary:");
        println!(
            "  Servers verified:        {}",
            result.summary.servers_verified
        );
        println!(
            "  Segments verified:       {}",
            result.summary.segments_verified
        );
        println!(
            "  Records verified:        {}",
            result.summary.records_verified
        );
        println!(
            "  Device commits checked:  {}",
            result.summary.device_commits_checked
        );
    }
}

fn format_violation(v: &Violation) -> String {
    match v {
        Violation::MissingServerChain { server_id } => {
            format!("Missing server chain: {}", server_id)
        }
        Violation::MissingSegment {
            server_id,
            segment_seq,
        } => {
            format!("Missing segment: {} seg{}", server_id, segment_seq)
        }
        Violation::RecordHashMismatch {
            server_id,
            segment_seq,
            record_index,
            expected,
            actual,
        } => {
            format!(
                "Record hash mismatch: {} seg{} record#{} (expected {}, got {})",
                server_id, segment_seq, record_index, expected, actual
            )
        }
        Violation::SegmentChainBreak {
            server_id,
            segment_seq,
            expected_prev,
            actual_prev,
        } => {
            format!(
                "Segment chain break: {} seg{} prev_hash mismatch (expected {}, got {})",
                server_id, segment_seq, expected_prev, actual_prev
            )
        }
        Violation::HeadHashMismatch {
            server_id,
            segment_seq,
            expected,
            actual,
        } => {
            format!(
                "Head hash mismatch: {} seg{} (expected {}, got {})",
                server_id, segment_seq, expected, actual
            )
        }
        Violation::SignatureVerificationFailed {
            server_id,
            segment_seq,
            pubkey_name,
            error,
        } => {
            format!(
                "Signature verification failed: {} seg{} with key {} ({})",
                server_id, segment_seq, pubkey_name, error
            )
        }
        Violation::OrphanedDeviceCommit {
            device_id,
            commit_sha,
            request_id,
        } => {
            format!(
                "Orphaned device commit: {} commit {} request_id {} (not in audit)",
                device_id, commit_sha, request_id
            )
        }
        Violation::OrphanedAuditRecord {
            server_id,
            request_id,
        } => {
            format!(
                "Orphaned audit record: {} request_id {} (not in device commits)",
                server_id, request_id
            )
        }
    }
}

// Add a type alias to fix the Summary issue
type VerificationSummary = Summary;
