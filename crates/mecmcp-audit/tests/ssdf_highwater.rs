//! The evidence sink must not send an INSERT its own identity cannot execute.
//!
//! `ssdf_audit` is granted INSERT and nothing else, deliberately — SSDF's
//! `007_audit.sql` gives it away at the grant so a stolen writer credential can
//! append but not enumerate. The sink previously guarded every insert with
//! `WHERE NOT EXISTS (SELECT …)`, which ClickHouse runs as the *inserting*
//! identity: every delivery would have been refused for missing SELECT.
//!
//! Dedup instead comes from the high-water mark the sink must read anyway to
//! seed its chain, using the separate `ssdf_audit_verify` identity that SSDF
//! provisions for exactly that (`009_audit_hash_chain.sql`). Resolved in
//! ssdf#47; consumed here for mecmcp#292.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::evidence::{
    ChainSegment, ClosedSegment, EvidenceRecord, GENESIS_PREV_HASH, ProposalRecord, append, close,
};
use mecmcp_audit::sinks::ssdf::{
    HttpRequest, HttpTransport, SsdfSink, SsdfSinkConfig, SsdfSinkError,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Default)]
struct RecordingTransport {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    high_water: Arc<Mutex<String>>,
}

impl HttpTransport for RecordingTransport {
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
        let decoded = urlencoding::decode(&request.url)
            .unwrap_or_default()
            .into_owned();
        self.requests.lock().unwrap().push(request.clone());
        if decoded.contains("SELECT") {
            return Ok(self.high_water.lock().unwrap().clone());
        }
        Ok(String::new())
    }
}

fn config(dir: &std::path::Path, transport_user: &str) -> SsdfSinkConfig {
    SsdfSinkConfig {
        endpoint: "http://ch.example:8123".to_string(),
        database: "ssdf".to_string(),
        username: "ssdf_audit".to_string(),
        password: "write-pw".to_string(),
        verify_username: transport_user.to_string(),
        verify_password: "verify-pw".to_string(),
        outbox_path: dir.join("outbox.ndjson"),
        ledger_path: dir.join("ledger.json"),
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
    }
}

fn segment(seq: u64) -> ClosedSegment {
    let mut seg = ChainSegment::new(
        "run-1".to_string(),
        "server-a".to_string(),
        seq,
        GENESIS_PREV_HASH.to_string(),
    );
    append(
        &mut seg,
        EvidenceRecord::Proposal(ProposalRecord {
            request_id: format!("req-{seq}"),
            changeset_id: "cs-1".to_string(),
            device_id: "vsrx-ci".to_string(),
            principal: "agent:test".to_string(),
            diff_hash: "sha256:0".to_string(),
            timestamp: "2026-08-20T00:00:00Z".to_string(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            metadata: None,
        }),
    )
    .unwrap();
    close(seg).unwrap()
}

/// The insert must be a plain INSERT. A guard clause here is not a style
/// preference: it is a statement the writer identity cannot execute.
#[test]
fn the_insert_carries_no_select_guard() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    sink.spool(segment(0)).unwrap();
    sink.attempt_delivery().unwrap();

    let requests = transport.requests.lock().unwrap();
    let insert = requests
        .iter()
        .find(|r| r.url.contains("INSERT") || r.url.contains("INSERT%20"))
        .expect("an insert was sent");
    let decoded = urlencoding::decode(&insert.url).unwrap().into_owned();
    assert!(
        !decoded.contains("NOT EXISTS"),
        "the writer identity has no SELECT; a guarded insert is refused outright: {decoded}"
    );
}

/// The dedup read runs as the verify identity, not the writer.
#[test]
fn the_high_water_read_uses_the_verify_identity() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    sink.spool(segment(0)).unwrap();
    sink.attempt_delivery().unwrap();

    let requests = transport.requests.lock().unwrap();
    let select = requests
        .iter()
        .find(|r| urlencoding::decode(&r.url).unwrap().contains("SELECT"))
        .expect("a high-water read was sent");
    let (_, auth) = select
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Authorization"))
        .expect("the read is authenticated");
    let encoded = auth.trim_start_matches("Basic ");
    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap(),
    )
    .unwrap();
    assert!(
        decoded.starts_with("ssdf_audit_verify:"),
        "the read must not use the INSERT-only identity: {decoded}"
    );
}

/// A segment at or below the high-water mark was already delivered — a lost ack,
/// not new work. Re-sending it would append a duplicate row to a hash chain.
#[test]
fn a_segment_at_or_below_the_high_water_mark_is_not_resent() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    *transport.high_water.lock().unwrap() = "3\n".to_string();
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    sink.spool(segment(2)).unwrap();
    sink.attempt_delivery().unwrap();

    let requests = transport.requests.lock().unwrap();
    let inserts = requests
        .iter()
        .filter(|r| urlencoding::decode(&r.url).unwrap().contains("INSERT"))
        .count();
    assert_eq!(inserts, 0, "segment 2 is below the high-water mark of 3");
}

/// Above the mark is genuinely new and must be sent.
#[test]
fn a_segment_above_the_high_water_mark_is_delivered() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    *transport.high_water.lock().unwrap() = "3\n".to_string();
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    sink.spool(segment(4)).unwrap();
    sink.attempt_delivery().unwrap();

    let requests = transport.requests.lock().unwrap();
    let inserts = requests
        .iter()
        .filter(|r| urlencoding::decode(&r.url).unwrap().contains("INSERT"))
        .count();
    assert_eq!(inserts, 1, "segment 4 is above the high-water mark of 3");
}
