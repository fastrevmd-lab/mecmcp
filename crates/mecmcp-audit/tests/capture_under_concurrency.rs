//! `run_with_capture` must survive another thread emitting the same callsites.
//!
//! `tracing` caches an `Interest` per callsite, process-wide, while this
//! capture's subscriber is thread-local. When a second thread exercises the same
//! callsites with no subscriber of its own, the capture can come back **empty** —
//! including of the events its own closure emitted — which reads at the
//! assertion as "the field was empty" rather than "the capture broke".
//!
//! That cost real time once: two tests added to `bearer_boundary.rs` made an
//! unrelated capture-based test in the same binary fail deterministically, and
//! the failure looked like a regression in the change under review (mecmcp#305).
//!
//! `run_with_capture` now rebuilds the interest cache before installing its
//! subscriber. This test fails without that line.
use mecmcp_audit::{AuditScope, testutil::run_with_capture};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn emit(tool: &'static str) {
    let mut scope = AuditScope::stdio(tool, "read", Vec::new());
    scope.succeed();
}

#[test]
fn concurrent_emission_on_another_thread_does_not_empty_the_capture() {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    // A second test in the same binary, emitting with no subscriber of its own.
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
        "capture was empty or lost its own events while another thread emitted: {}",
        &captured[..captured.len().min(200)]
    );
    assert!(
        !captured.contains("concurrent_noise"),
        "the thread-local capture must not pick up another thread's events"
    );
}
