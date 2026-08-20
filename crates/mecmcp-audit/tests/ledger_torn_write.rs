//! A crash mid-append must not lock the sink out of its own outbox.
//!
//! `DeliveryLedger::write_entry` writes one line per entry. A process killed —
//! or a disk filled — partway through that write leaves a line with no
//! terminating newline. `open` rejected any unparseable line, so `SsdfSink::new`
//! failed on every subsequent start, and the durable outbox it exists to replay
//! was never read. The spool treats a ledger failure as non-fatal precisely
//! because the record is already safe in the outbox; that reasoning only holds
//! if the next start can still get at it.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::sinks::delivery_ledger::DeliveryLedger;
use std::io::Write;

fn entry(seq: u64) -> String {
    format!(
        "{{\"server_id\":\"srv-a\",\"run_id\":\"run-1\",\"segment_seq\":{seq},\"status\":\"pending\"}}\n"
    )
}

/// A torn final line is a crash, not corruption: drop it and carry on.
#[test]
fn a_torn_final_entry_does_not_block_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    {
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(entry(0).as_bytes()).unwrap();
        // Killed mid-write: no closing brace, no newline.
        file.write_all(b"{\"server_id\":\"srv-a\",\"run_id\":\"run-1\",\"segm")
            .unwrap();
    }

    let Ok(mut ledger) = DeliveryLedger::open(&path) else {
        panic!("a torn tail must not be fatal")
    };

    // The truncation must be durable, or the next append lands on the stump and
    // welds two records into one unparseable line.
    ledger
        .mark_pending(mecmcp_audit::sinks::delivery_ledger::SegmentId {
            server_id: "srv-a".to_owned(),
            run_id: "run-1".to_owned(),
            segment_seq: 1,
        })
        .unwrap();
    drop(ledger);

    let reopened = std::fs::read_to_string(&path).unwrap();
    for line in reopened.lines().filter(|line| !line.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|error| panic!("ledger line is not valid JSON ({error}): {line}"));
    }
    assert!(
        DeliveryLedger::open(&path).is_ok(),
        "the repaired ledger must reopen"
    );
}

/// A bad line in the *middle* is corruption, and must still be refused.
///
/// Only the final line can be explained by an interrupted append. Anything
/// earlier means something rewrote history, which is the one thing this whole
/// subsystem exists to detect.
#[test]
fn corruption_before_the_end_is_still_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(entry(0).as_bytes()).unwrap();
    file.write_all(b"not json at all\n").unwrap();
    file.write_all(entry(2).as_bytes()).unwrap();
    drop(file);

    assert!(
        DeliveryLedger::open(&path).is_err(),
        "a malformed line that is not the last one is corruption"
    );
}

/// A torn tail that splits a multibyte character is still just a torn tail.
///
/// Device and server identifiers are free-form strings, so a short write can
/// land in the middle of a UTF-8 sequence. Decoding the file before locating
/// the last newline fails on that with `InvalidData` — before any repair gets a
/// chance to run — so the ledger stays unopenable and the outbox stays
/// unreplayed, which is the exact failure the repair exists to prevent.
#[test]
fn a_torn_tail_split_mid_character_is_still_recoverable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    {
        let mut file = std::fs::File::create(&path).unwrap();
        file.write_all(entry(0).as_bytes()).unwrap();
        // "café" cut between the two bytes of 'é' (0xC3 0xA9).
        file.write_all(b"{\"server_id\":\"caf\xc3").unwrap();
    }

    let Ok(mut ledger) = DeliveryLedger::open(&path) else {
        panic!("a tail split mid-character is a crash, not corruption")
    };
    ledger
        .mark_pending(mecmcp_audit::sinks::delivery_ledger::SegmentId {
            server_id: "srv-a".to_owned(),
            run_id: "run-1".to_owned(),
            segment_seq: 1,
        })
        .unwrap();
    drop(ledger);

    let bytes = std::fs::read(&path).unwrap();
    let text = String::from_utf8(bytes).expect("the repaired ledger must be valid UTF-8");
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|error| panic!("ledger line is not valid JSON ({error}): {line}"));
    }
}
