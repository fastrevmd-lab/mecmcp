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

use mecmcp_audit::testutil::run_with_capture;
use std::sync::mpsc;

/// The harder case: a callsite whose **first** registration happens on another
/// thread while the capture is already running. A pre-emptive cache rebuild
/// cannot help here — the callsite does not exist yet when it runs.
#[test]
fn a_callsite_first_registered_mid_capture_is_still_captured() {
    let (ready_tx, ready_rx) = mpsc::channel::<()>();
    let (done_tx, done_rx) = mpsc::channel::<()>();

    let noisy = std::thread::spawn(move || {
        ready_rx.recv().expect("ready");
        tracing::info!(target: "audit", marker = "from_noisy_thread", "shared callsite");
        done_tx.send(()).expect("done");
    });

    let captured = run_with_capture(|| {
        ready_tx.send(()).expect("ready");
        done_rx.recv().expect("done");
        tracing::info!(target: "audit", marker = "from_capturing_thread", "shared callsite");
    });

    noisy.join().expect("noisy thread");

    assert!(
        captured.contains("from_capturing_thread"),
        "the capture skipped its own event, so the callsite was cached as \
         uninteresting by a thread with no subscriber: {captured:?}"
    );
}
