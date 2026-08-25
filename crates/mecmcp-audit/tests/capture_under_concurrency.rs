//! `run_with_capture` must survive another thread using the same callsites.
//!
//! **This must stay its own integration binary.** As a unit test inside
//! `mecmcp-audit` it passes even with the fix removed, because a sibling test
//! has already registered the `audit` callsite under a capture subscriber by
//! the time it runs. The bug needs a *fresh process* in which a thread with no
//! subscriber is the first to reach the callsite — which is exactly the shape
//! that broke `bearer_boundary.rs` (mecmcp#305).
//!
//! **One test per binary.** Two of these in one process is not a reproduction —
//! whichever runs first registers the callsite under a capture subscriber and
//! immunises the second.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::AuditScope;
use mecmcp_audit::testutil::run_with_capture;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

fn emit(tool: &'static str) {
    let mut scope = AuditScope::stdio(tool, "read", Vec::new());
    scope.succeed();
}

/// The case that cost a debugging session: another thread hammering the same
/// callsites for the duration of the capture.
#[test]
fn concurrent_emission_does_not_empty_the_capture() {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = Arc::clone(&stop);
    let noisy = std::thread::spawn(move || {
        while !stop_for_thread.load(Ordering::Relaxed) {
            emit("concurrent_noise");
        }
    });

    let captured = run_with_capture(|| {
        for _ in 0..50 {
            emit("under_capture");
            std::thread::yield_now();
        }
    });

    stop.store(true, Ordering::Relaxed);
    noisy.join().expect("noisy thread");

    assert!(
        captured.contains("tool=under_capture"),
        "capture lost its own events while another thread emitted: {:?}",
        &captured[..captured.len().min(200)]
    );
}
/// Many concurrent captures must each see their own event.
///
/// `run_with_capture` rebuilds the process-global callsite interest cache. Two
/// threads doing that at once can re-evaluate a callsite against a thread whose
/// subscriber does not capture, dropping the event — so a capture comes back
/// empty even though the audit code ran correctly.
#[test]
fn many_concurrent_captures_each_see_their_own_event() {
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|i| {
                scope.spawn(move || {
                    let tool: &'static str = if i % 2 == 0 { "alpha" } else { "beta" };
                    let out = mecmcp_audit::testutil::run_with_capture(|| {
                        let mut scope = mecmcp_audit::AuditScope::stdio(tool, "read", Vec::new());
                        scope.succeed();
                    });
                    if out.contains(tool) {
                        None
                    } else {
                        Some(format!("thread {i} ({tool}) captured: {out:?}"))
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().expect("capture thread panicked"))
            .collect()
    });

    assert!(
        failures.is_empty(),
        "{} of 16 concurrent captures lost their event:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
