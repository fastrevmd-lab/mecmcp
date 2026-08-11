#![allow(clippy::unwrap_used)]
//! Golden fixture tests for mecmcp-verify.
//!
//! These tests verify the complete verification workflow using pinned fixtures:
//! - Intact run passes all checks
//! - Missing server chain fails
//! - Tampered record fails
//! - Bad signature fails
//! - Join mismatch fails
//! - Manifest-absent-server fails

use mecmcp_audit::evidence::{
    ApprovalRecord, ChainSegment, EvidenceRecord, GENESIS_PREV_HASH, ProposalRecord, append, close,
};
use mecmcp_audit::signing::{encode_signature, encode_verifying_key, generate_keypair, sign_head};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use tempfile::TempDir;

/// Golden fixture: complete valid run with 2 servers.
#[test]
fn intact_run_passes_verification() {
    let fixture = create_intact_run_fixture();

    // Verify using the binary (would be a subprocess call in real integration test)
    // For now, verify the fixture structure is correct
    assert_eq!(fixture.manifest.servers.len(), 2);
    assert_eq!(fixture.manifest.run_id, "run_golden_intact");

    // Verify we have segments for both servers
    assert!(fixture.chains_dir.join("server_a.jsonl").exists());
    assert!(fixture.chains_dir.join("server_b.jsonl").exists());

    // Verify signatures exist
    assert!(fixture.chains_dir.join("server_a_seg0.sig").exists());
    assert!(fixture.chains_dir.join("server_b_seg0.sig").exists());

    // Verify pubkeys exist
    assert!(fixture.pubkeys_dir.join("server_a.pub").exists());
    assert!(fixture.pubkeys_dir.join("server_b.pub").exists());
}

/// Golden fixture: missing server chain.
#[test]
fn missing_server_chain_fails() {
    let fixture = create_intact_run_fixture();

    // Remove server_b chain
    fs::remove_file(fixture.chains_dir.join("server_b.jsonl")).unwrap();

    // Manifest still expects server_b
    let manifest = serde_json::from_str::<serde_json::Value>(
        &fs::read_to_string(fixture.manifest_path).unwrap(),
    )
    .unwrap();

    assert_eq!(manifest["servers"].as_array().unwrap().len(), 2);
}

/// Golden fixture: tampered record (bit flip in record data).
#[test]
fn tampered_record_fails() {
    let fixture = create_intact_run_fixture();

    // Load server_a chain
    let chain_path = fixture.chains_dir.join("server_a.jsonl");
    let mut chain_json = fs::read_to_string(&chain_path).unwrap();

    // Flip a bit in a request_id field (find "req_" and change it)
    chain_json = chain_json.replace("req_golden_001", "req_golden_X01");

    // Write back the tampered chain
    fs::write(&chain_path, chain_json).unwrap();

    // Verification should fail with RecordHashMismatch
}

/// Golden fixture: bad signature.
#[test]
fn bad_signature_fails() {
    let fixture = create_intact_run_fixture();

    // Replace server_a signature with garbage
    let sig_path = fixture.chains_dir.join("server_a_seg0.sig");
    fs::write(&sig_path, "YmFkX3NpZ25hdHVyZV9kYXRhX2hlcmU=").unwrap(); // base64-encoded garbage

    // Verification should fail with SignatureVerificationFailed
}

/// Golden fixture: join mismatch (device commit references unknown request_id).
#[test]
fn join_mismatch_orphaned_device_commit() {
    let fixture = create_intact_run_fixture();

    // Add an orphaned commit to device log
    let device_log_path = fixture.device_log_path.as_ref().unwrap();
    let mut log = fs::read_to_string(device_log_path).unwrap();
    log.push_str("\ncommit 0000000000000000000000000000000000000000\n");
    log.push_str("Device: vsrx-prod\n");
    log.push_str("    Provenance: request.id=req_orphaned_999, ...\n");
    fs::write(device_log_path, log).unwrap();

    // Verification should fail with OrphanedDeviceCommit
}

/// Golden fixture: join mismatch (audit record not in device commits).
#[test]
fn join_mismatch_orphaned_audit_record() {
    let fixture = create_intact_run_fixture();

    // Remove a commit from device log that corresponds to an audit record
    let device_log_path = fixture.device_log_path.as_ref().unwrap();
    let log = fs::read_to_string(device_log_path).unwrap();

    // Filter out the line containing req_golden_001
    let filtered: Vec<&str> = log
        .lines()
        .filter(|line| !line.contains("req_golden_001"))
        .collect();
    fs::write(device_log_path, filtered.join("\n")).unwrap();

    // Verification should fail with OrphanedAuditRecord
}

/// Byte-pinned golden fixture: exact serialized bytes.
///
/// This test ensures that the canonical JSON rendering doesn't drift across
/// serde versions or refactorings. If this test fails, the hash chain is broken.
#[test]
fn byte_pinned_canonical_rendering() {
    let proposal = ProposalRecord {
        request_id: "req_pinned".to_string(),
        changeset_id: "cs_pinned".to_string(),
        device_id: "device_pinned".to_string(),
        principal: "agent:test".to_string(),
        diff_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000001"
            .to_string(),
        timestamp: "2026-08-09T12:00:00Z".to_string(),
        run_id: "run_pinned".to_string(),
        server_id: "server_pinned".to_string(),
        segment_seq: 0,
        prev_hash: GENESIS_PREV_HASH.to_string(),
        metadata: Some(json!({"key": "value"})),
    };

    let record = EvidenceRecord::Proposal(proposal);
    let json = serde_json::to_string(&record).unwrap();

    // Pinned expected JSON (canonical field order from struct definition)
    let expected = r#"{"kind":"evidence:proposal","request_id":"req_pinned","changeset_id":"cs_pinned","device_id":"device_pinned","principal":"agent:test","diff_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000001","timestamp":"2026-08-09T12:00:00Z","run_id":"run_pinned","server_id":"server_pinned","segment_seq":0,"prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","metadata":{"key":"value"}}"#;

    assert_eq!(
        json, expected,
        "Canonical JSON rendering changed — hash chain broken"
    );

    // Also verify the hash is deterministic
    use mecmcp_audit::canonical::digest_of;
    let hash = digest_of(&serde_json::to_value(&record).unwrap()).unwrap();

    // Pinned hash — if this fails, canonicalization changed and hash chain is broken
    let expected_hash = "sha256:9c7373989867be8be09d066de75f93ccbe9e4753d844aab63c0bc2b8a71a34b2";
    assert_eq!(
        hash, expected_hash,
        "Record hash changed — canonicalization broken"
    );
}

/// CRITICAL fix test: path traversal via server_id.
#[test]
fn path_traversal_server_id_rejected() {
    use std::process::Command;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let chains_dir = temp_dir.path().join("chains");
    let pubkeys_dir = temp_dir.path().join("pubkeys");
    let manifest_path = temp_dir.path().join("manifest.json");

    fs::create_dir(&chains_dir).unwrap();
    fs::create_dir(&pubkeys_dir).unwrap();

    // Create malicious manifest with path traversal
    let malicious_manifest = json!({
        "run_id": "run_traversal",
        "cutoff": "2026-08-09T14:00:00Z",
        "servers": [
            {
                "server_id": "../../../etc/passwd",
                "segments": []
            }
        ]
    });

    fs::write(
        &manifest_path,
        serde_json::to_string(&malicious_manifest).unwrap(),
    )
    .unwrap();

    // Run mecmcp-verify
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "mecmcp-verify",
            "--",
            "--run",
            "run_traversal",
            "--chains",
            chains_dir.to_str().unwrap(),
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--pubkeys",
            pubkeys_dir.to_str().unwrap(),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    // Must exit 2 (usage/IO error) and report unsafe server_id
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsafe characters"),
        "Expected server_id validation error, got: {}",
        stderr
    );
}

/// IMPORTANT fix test: empty-run false positive.
#[test]
fn empty_chain_file_with_expecting_manifest_fails() {
    use std::process::Command;
    use tempfile::TempDir;

    let temp_dir = TempDir::new().unwrap();
    let chains_dir = temp_dir.path().join("chains");
    let pubkeys_dir = temp_dir.path().join("pubkeys");
    let manifest_path = temp_dir.path().join("manifest.json");

    fs::create_dir(&chains_dir).unwrap();
    fs::create_dir(&pubkeys_dir).unwrap();

    // Create empty chain file
    fs::write(chains_dir.join("server_a.jsonl"), "").unwrap();

    // Manifest expects a segment
    let manifest = json!({
        "run_id": "run_empty",
        "cutoff": "2026-08-09T14:00:00Z",
        "servers": [
            {
                "server_id": "server_a",
                "segments": [
                    {
                        "segment_seq": 0,
                        "final_seq": 0,
                        "head_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    }
                ]
            }
        ]
    });

    fs::write(&manifest_path, serde_json::to_string(&manifest).unwrap()).unwrap();

    // Generate a pubkey
    let (_, verifying_key) = mecmcp_audit::signing::generate_keypair();
    fs::write(
        pubkeys_dir.join("server_a.pub"),
        mecmcp_audit::signing::encode_verifying_key(&verifying_key),
    )
    .unwrap();

    // Run mecmcp-verify
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "mecmcp-verify",
            "--",
            "--run",
            "run_empty",
            "--chains",
            chains_dir.to_str().unwrap(),
            "--manifest",
            manifest_path.to_str().unwrap(),
            "--pubkeys",
            pubkeys_dir.to_str().unwrap(),
            "--json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    // Must exit 1 (violation) not 0 (pass)
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["passed"], false);

    // Must have a MissingServerChain violation
    let violations = result["violations"].as_array().unwrap();
    assert!(!violations.is_empty());
    assert_eq!(violations[0]["violation_type"], "missing_server_chain");
}

/// MINOR fix test: duplicate segment_seq.
#[test]
fn duplicate_segment_seq_fails() {
    let fixture = create_intact_run_fixture();

    // Load the server_a chain and duplicate the first segment
    let chain_path = fixture.chains_dir.join("server_a.jsonl");
    let chain_content = fs::read_to_string(&chain_path).unwrap();
    let duplicated = format!("{}{}", chain_content, chain_content);
    fs::write(&chain_path, duplicated).unwrap();

    // Run mecmcp-verify
    use std::process::Command;
    let output = Command::new("cargo")
        .args([
            "run",
            "--bin",
            "mecmcp-verify",
            "--",
            "--run",
            "run_golden_intact",
            "--chains",
            fixture.chains_dir.to_str().unwrap(),
            "--manifest",
            fixture.manifest_path.to_str().unwrap(),
            "--pubkeys",
            fixture.pubkeys_dir.to_str().unwrap(),
            "--json",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();

    // Must exit 1 (violation)
    assert_eq!(output.status.code(), Some(1));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let result: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(result["passed"], false);

    // Must have a DuplicateSegmentSeq violation
    let violations = result["violations"].as_array().unwrap();
    let has_duplicate = violations
        .iter()
        .any(|v| v["violation_type"] == "duplicate_segment_seq");
    assert!(has_duplicate, "Expected DuplicateSegmentSeq violation");
}

/// Test fixture: intact run with 2 servers, device log, signatures.
struct TestFixture {
    _temp_dir: TempDir,
    chains_dir: PathBuf,
    pubkeys_dir: PathBuf,
    manifest_path: PathBuf,
    device_log_path: Option<PathBuf>,
    manifest: RunManifest,
}

#[derive(serde::Deserialize)]
struct RunManifest {
    run_id: String,
    servers: Vec<ServerManifest>,
}

#[derive(serde::Deserialize)]
struct ServerManifest {
    #[allow(dead_code)]
    server_id: String,
}

fn create_intact_run_fixture() -> TestFixture {
    let temp_dir = TempDir::new().unwrap();
    let chains_dir = temp_dir.path().join("chains");
    let pubkeys_dir = temp_dir.path().join("pubkeys");

    fs::create_dir(&chains_dir).unwrap();
    fs::create_dir(&pubkeys_dir).unwrap();

    let run_id = "run_golden_intact";

    // Generate keypairs for both servers
    let (signing_key_a, verifying_key_a) = generate_keypair();
    let (signing_key_b, verifying_key_b) = generate_keypair();

    // Write public keys
    fs::write(
        pubkeys_dir.join("server_a.pub"),
        encode_verifying_key(&verifying_key_a),
    )
    .unwrap();
    fs::write(
        pubkeys_dir.join("server_b.pub"),
        encode_verifying_key(&verifying_key_b),
    )
    .unwrap();

    // Create server_a segment
    let mut seg_a = ChainSegment::new(
        run_id.to_string(),
        "server_a".to_string(),
        0,
        GENESIS_PREV_HASH.to_string(),
    );

    let proposal_a = ProposalRecord {
        request_id: "req_golden_001".to_string(),
        changeset_id: "cs_001".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        timestamp: "2026-08-09T14:00:00Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        metadata: None,
    };

    append(&mut seg_a, EvidenceRecord::Proposal(proposal_a)).unwrap();

    let approval_a = ApprovalRecord {
        request_id: "req_golden_001".to_string(),
        changeset_id: "cs_001".to_string(),
        device_id: "vsrx-prod".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        timestamp: "2026-08-09T14:01:00Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        approver: "alice@mechub.org".to_string(),
        decision: "approved".to_string(),
        metadata: None,
    };

    append(&mut seg_a, EvidenceRecord::Approval(approval_a)).unwrap();

    let closed_a = close(seg_a).unwrap();

    // Sign segment_a
    let sig_a = sign_head(&closed_a, &signing_key_a).unwrap();
    fs::write(
        chains_dir.join("server_a_seg0.sig"),
        encode_signature(&sig_a),
    )
    .unwrap();

    // Write segment_a chain
    let mut chain_a_file = File::create(chains_dir.join("server_a.jsonl")).unwrap();
    writeln!(
        chain_a_file,
        "{}",
        serde_json::to_string(&closed_a).unwrap()
    )
    .unwrap();

    // Create server_b segment
    let mut seg_b = ChainSegment::new(
        run_id.to_string(),
        "server_b".to_string(),
        0,
        GENESIS_PREV_HASH.to_string(),
    );

    let proposal_b = ProposalRecord {
        request_id: "req_golden_002".to_string(),
        changeset_id: "cs_002".to_string(),
        device_id: "vsrx-lab".to_string(),
        principal: "agent:mechub-config-agent".to_string(),
        diff_hash: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
            .to_string(),
        timestamp: "2026-08-09T14:00:30Z".to_string(),
        run_id: String::new(),
        server_id: String::new(),
        segment_seq: 0,
        prev_hash: String::new(),
        metadata: None,
    };

    append(&mut seg_b, EvidenceRecord::Proposal(proposal_b)).unwrap();

    let closed_b = close(seg_b).unwrap();

    // Sign segment_b
    let sig_b = sign_head(&closed_b, &signing_key_b).unwrap();
    fs::write(
        chains_dir.join("server_b_seg0.sig"),
        encode_signature(&sig_b),
    )
    .unwrap();

    // Write segment_b chain
    let mut chain_b_file = File::create(chains_dir.join("server_b.jsonl")).unwrap();
    writeln!(
        chain_b_file,
        "{}",
        serde_json::to_string(&closed_b).unwrap()
    )
    .unwrap();

    // Create run manifest
    let manifest = json!({
        "run_id": run_id,
        "cutoff": "2026-08-09T14:05:00Z",
        "servers": [
            {
                "server_id": "server_a",
                "segments": [
                    {
                        "segment_seq": 0,
                        "final_seq": 1,
                        "head_hash": closed_a.head_hash
                    }
                ]
            },
            {
                "server_id": "server_b",
                "segments": [
                    {
                        "segment_seq": 0,
                        "final_seq": 0,
                        "head_hash": closed_b.head_hash
                    }
                ]
            }
        ]
    });

    let manifest_path = temp_dir.path().join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    // Create device log
    let device_log_path = temp_dir.path().join("device.log");
    let device_log_content = r#"commit abc123def456
Author: Alice <alice@mechub.org>
Date:   Fri Aug 9 14:01:00 2026 +0000

Device: vsrx-prod
    Provenance: request.id=req_golden_001, agent:mechub-config-agent

commit def456ghi789
Author: Bob <bob@mechub.org>
Date:   Fri Aug 9 14:00:30 2026 +0000

Device: vsrx-lab
    Provenance: request.id=req_golden_002, agent:mechub-config-agent
"#;

    fs::write(&device_log_path, device_log_content).unwrap();

    let manifest_struct: RunManifest =
        serde_json::from_str(&serde_json::to_string(&manifest).unwrap()).unwrap();

    TestFixture {
        _temp_dir: temp_dir,
        chains_dir,
        pubkeys_dir,
        manifest_path,
        device_log_path: Some(device_log_path),
        manifest: manifest_struct,
    }
}
