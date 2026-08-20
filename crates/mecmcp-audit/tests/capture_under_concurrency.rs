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
