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

struct RecordingTransport {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    /// `count\tmax` as ClickHouse renders it. Default: no rows for this run.
    high_water: Arc<Mutex<String>>,
}

impl Default for RecordingTransport {
    fn default() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            high_water: Arc::new(Mutex::new("0\t0\n".to_string())),
        }
    }
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
    *transport.high_water.lock().unwrap() = "4\t3\n".to_string();
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
    *transport.high_water.lock().unwrap() = "4\t3\n".to_string();
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

/// A high-water **maximum** only describes what landed if segments go in
/// ascending order and none is skipped. If N fails and N+1 is delivered anyway,
/// the next pass sees a mark of N+1 and treats N as landed — leaving a hole in
/// a chain that still verifies as a chain, which is the exact failure this sink
/// exists to prevent.
#[test]
fn a_failed_segment_holds_back_the_rest_of_its_run() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(FailingInsertTransport::default());
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    // Three segments of one run, spooled out of order for good measure.
    sink.spool(segment(2)).unwrap();
    sink.spool(segment(0)).unwrap();
    sink.spool(segment(1)).unwrap();

    // Segment 0's insert fails; 1 and 2 must not be attempted.
    *transport.fail_seq.lock().unwrap() = Some(0);
    let delivered = sink.attempt_delivery().unwrap().delivered;

    assert_eq!(delivered, 0, "nothing may be delivered past the failure");
    let attempted = transport.inserted_seqs.lock().unwrap().clone();
    assert_eq!(
        attempted,
        vec![0],
        "only the failing segment was attempted; later ones must not overtake it"
    );
}

/// A read that fails is not evidence that nothing landed. Treating it as such
/// green-lights a plain INSERT and appends a duplicate on a lost-ack replay.
#[test]
fn an_unreadable_high_water_mark_keeps_the_segment_spooled() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(FailingReadTransport);
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport,
        Arc::new(|_| {}),
    )
    .unwrap();
    sink.spool(segment(0)).unwrap();

    let delivered = sink.attempt_delivery().unwrap().delivered;

    assert_eq!(
        delivered, 0,
        "an unreadable mark must not be read as 'nothing landed'"
    );
}

/// `max()` over no rows and `max()` over a run whose only landed segment is
/// sequence 0 both render as `0`. Confusing them re-inserts segment 0 after a
/// crash between its insert and the ledger write.
#[test]
fn a_high_water_mark_of_zero_is_not_an_empty_result() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    // count=1, max=0 — segment 0 has landed.
    *transport.high_water.lock().unwrap() = "1\t0\n".to_string();
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();
    sink.spool(segment(0)).unwrap();

    sink.attempt_delivery().unwrap();

    let requests = transport.requests.lock().unwrap();
    let inserts = requests
        .iter()
        .filter(|r| urlencoding::decode(&r.url).unwrap().contains("INSERT"))
        .count();
    assert_eq!(
        inserts, 0,
        "segment 0 already landed and must not be resent"
    );
}

#[derive(Default)]
struct FailingInsertTransport {
    fail_seq: Arc<Mutex<Option<u64>>>,
    inserted_seqs: Arc<Mutex<Vec<u64>>>,
}

impl HttpTransport for FailingInsertTransport {
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
        let decoded = urlencoding::decode(&request.url)
            .unwrap_or_default()
            .into_owned();
        if decoded.contains("SELECT") {
            // Nothing landed yet for this run.
            return Ok("0\t0\n".to_string());
        }
        let body = String::from_utf8_lossy(&request.body).into_owned();
        // `segment_seq` is inside the escaped `args` JSON, so the key appears
        // as \"segment_seq\" in the raw body.
        let seq = body
            .split("segment_seq")
            .nth(1)
            .and_then(|rest| {
                let digits: String = rest
                    .chars()
                    .skip_while(|c| !c.is_ascii_digit())
                    .take_while(char::is_ascii_digit)
                    .collect();
                digits.parse::<u64>().ok()
            })
            .unwrap_or(u64::MAX);
        self.inserted_seqs.lock().unwrap().push(seq);
        if *self.fail_seq.lock().unwrap() == Some(seq) {
            return Err(SsdfSinkError::Http("insert refused".to_string()));
        }
        Ok(String::new())
    }
}

struct FailingReadTransport;

impl HttpTransport for FailingReadTransport {
    fn send(&self, request: &HttpRequest) -> Result<String, SsdfSinkError> {
        let decoded = urlencoding::decode(&request.url)
            .unwrap_or_default()
            .into_owned();
        if decoded.contains("SELECT") {
            return Err(SsdfSinkError::Http(
                "verify credentials expired".to_string(),
            ));
        }
        panic!("an insert must not be attempted when the high-water read failed");
    }
}

/// A restarting writer must seed from its own chain tail, read as the verify
/// identity.
///
/// This is the query the contract specifies and nothing implemented: the tail
/// is the row **nothing else points at**, found by following links rather than
/// by sorting. Ordering by `ts` and `segment_seq` looks equivalent and is not —
/// `segment_seq` restarts per run, so an older run's segment 40 outranks the
/// real tail's segment 0, and a writer seeded from an interior hash forks its
/// own chain (ssdf#47).
#[test]
fn the_remote_head_is_the_unreferenced_tail_for_this_writer() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    *transport.high_water.lock().unwrap() = "sha256:tail\n".to_string();
    let requests = Arc::clone(&transport.requests);
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    let head = sink.remote_head("server-a").unwrap();

    assert_eq!(head.as_deref(), Some("sha256:tail"));
    let sent = requests.lock().unwrap();
    let url = urlencoding::decode(&sent[0].url).unwrap().into_owned();
    assert!(
        url.contains("DISTINCT"),
        "two rows can share one unreferenced hash — a duplicated tail is one \
         head, not a fork: {url}"
    );
    assert!(
        url.contains("NOT IN"),
        "the tail must be found by following links, not by sorting: {url}"
    );
    assert!(
        !url.contains("ORDER BY"),
        "sorting by ts/segment_seq picks an interior row across runs: {url}"
    );
    let auth = sent[0]
        .headers
        .iter()
        .find(|(k, _)| k == "Authorization")
        .map(|(_, v)| v.clone())
        .expect("the read must authenticate");
    let encoded = auth.trim_start_matches("Basic ");
    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded).unwrap(),
    )
    .unwrap();
    assert!(
        decoded.starts_with("ssdf_audit_verify:"),
        "the write identity has no SELECT; this read is the verify identity's: {decoded}"
    );
}

/// A writer with no rows yet starts a root rather than inventing one.
#[test]
fn a_writer_with_no_rows_has_no_remote_head() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    *transport.high_water.lock().unwrap() = String::new();
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    assert_eq!(sink.remote_head("server-a").unwrap(), None);
}

/// Two distinct tails mean the chain has already forked, and a new run must
/// not attach to either branch.
///
/// Picking one deepens the fork, and a fork verifies as two valid chains — so
/// guessing here would bury the exact condition the design exists to make
/// impossible. Refusing surfaces it while it is still one operator decision.
#[test]
fn two_tails_are_refused_rather_than_guessed_between() {
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(RecordingTransport::default());
    *transport.high_water.lock().unwrap() = "sha256:branch-a\nsha256:branch-b\n".to_string();
    let sink = SsdfSink::new_with_transport(
        config(dir.path(), "ssdf_audit_verify"),
        transport.clone(),
        Arc::new(|_| {}),
    )
    .unwrap();

    let error = sink
        .remote_head("server-a")
        .expect_err("a forked chain must not silently pick a branch");

    assert!(
        format!("{error}").contains("forked"),
        "the error must name the condition an operator has to act on: {error}"
    );
}
