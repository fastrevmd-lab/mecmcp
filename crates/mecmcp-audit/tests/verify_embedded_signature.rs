//! End-to-end: a server configured with a signing key produces a segment
//! whose signature is embedded automatically (MEC-457's `with_signing_key`),
//! and `mecmcp-verify` accepts that embedded signature without a separate
//! `.sig` file. Tampering the embedded signature must be caught.
//!
//! This drives the real `mecmcp-verify` binary as a subprocess rather than
//! calling its internals directly, so it also proves the CLI wiring (finding
//! 4 of the MEC-457 review: nothing previously read `ClosedSegment.signature`
//! at all).

#![allow(clippy::unwrap_used)]

use mecmcp_audit::recorder::{EvidenceRecorder, RecorderConfig};
use mecmcp_audit::signing::{encode_verifying_key, generate_keypair};
use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::TempDir;

const SERVER_ID: &str = "verify-e2e";
const RUN_ID: &str = "run-verify-e2e";

/// Produces a real, auto-signed `ClosedSegment` the way a deployed server
/// would: append a record, close the segment, and let `roll` sign it because
/// a key was configured — no manual `sign_head` call.
fn signed_segment(
    signing_key: mecmcp_audit::signing::SigningKey,
) -> mecmcp_audit::evidence::ClosedSegment {
    let recorder = EvidenceRecorder::new(RecorderConfig {
        server_id: SERVER_ID.to_string(),
        run_id: RUN_ID.to_string(),
        resume_from: None,
        records_per_segment: 8,
    })
    .with_signing_key(signing_key);

    recorder.proposal(
        "req-e2e-1",
        "cs-e2e-1",
        "vsrx-e2e",
        "agent:e2e-test",
        "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    );

    recorder
        .close_current()
        .expect("a non-empty segment closes")
}

/// Lays out a `--chains`/`--pubkeys`/`--manifest` directory tree around one
/// already-closed segment, embedding its signature in the chain file rather
/// than writing a `<server>_seg<N>.sig` file.
struct Fixture {
    _dir: TempDir,
    chains_dir: std::path::PathBuf,
    pubkeys_dir: std::path::PathBuf,
    manifest_path: std::path::PathBuf,
}

fn build_fixture(
    segment: &mecmcp_audit::evidence::ClosedSegment,
    verifying_key: &mecmcp_audit::signing::VerifyingKey,
) -> Fixture {
    let dir = TempDir::new().unwrap();
    let chains_dir = dir.path().join("chains");
    let pubkeys_dir = dir.path().join("pubkeys");
    fs::create_dir(&chains_dir).unwrap();
    fs::create_dir(&pubkeys_dir).unwrap();

    fs::write(
        pubkeys_dir.join(format!("{SERVER_ID}.pub")),
        encode_verifying_key(verifying_key),
    )
    .unwrap();

    let mut chain_file = fs::File::create(chains_dir.join(format!("{SERVER_ID}.jsonl"))).unwrap();
    writeln!(chain_file, "{}", serde_json::to_string(segment).unwrap()).unwrap();

    let manifest_path = dir.path().join("manifest.json");
    let manifest = serde_json::json!({
        "run_id": RUN_ID,
        "cutoff": "2026-09-28T00:00:00Z",
        "servers": [{
            "server_id": SERVER_ID,
            "segments": [{
                "segment_seq": segment.segment_seq,
                "final_seq": 0,
                "head_hash": segment.head_hash,
            }],
        }],
    });
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .unwrap();

    Fixture {
        _dir: dir,
        chains_dir,
        pubkeys_dir,
        manifest_path,
    }
}

fn run_verify(fixture: &Fixture) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_mecmcp-verify"))
        .arg("--run")
        .arg(RUN_ID)
        .arg("--chains")
        .arg(&fixture.chains_dir)
        .arg("--manifest")
        .arg(&fixture.manifest_path)
        .arg("--pubkeys")
        .arg(&fixture.pubkeys_dir)
        .output()
        .expect("mecmcp-verify runs")
}

#[test]
fn auto_signed_segment_verifies_with_no_sig_file() {
    let (signing_key, verifying_key) = generate_keypair();
    let segment = signed_segment(signing_key);
    assert!(
        segment.signature.is_some(),
        "roll() must sign the segment automatically when a key is configured"
    );

    let fixture = build_fixture(&segment, &verifying_key);
    assert!(
        !fixture
            .chains_dir
            .join(format!("{SERVER_ID}_seg0.sig"))
            .exists(),
        "this test's whole point is that no detached .sig file exists"
    );

    let output = run_verify(&fixture);
    assert!(
        output.status.success(),
        "verification of an embedded, auto-signed segment must pass with exit 0: \
         stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tampered_embedded_signature_is_rejected() {
    let (signing_key, verifying_key) = generate_keypair();
    let mut segment = signed_segment(signing_key);

    // Flip one byte of the base64-encoded embedded signature.
    let sig = segment.signature.as_mut().expect("segment is signed");
    let mut bytes = sig.clone().into_bytes();
    let flip_at = bytes.len() / 2;
    bytes[flip_at] = if bytes[flip_at] == b'A' { b'B' } else { b'A' };
    *sig = String::from_utf8(bytes).unwrap();

    let fixture = build_fixture(&segment, &verifying_key);
    let output = run_verify(&fixture);

    assert_eq!(
        output.status.code(),
        Some(1),
        "a tampered embedded signature must fail verification (exit 1), not pass or error out: \
         stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Signature") || stdout.contains("signature"),
        "the report should name the signature as the problem: {stdout}"
    );
}
