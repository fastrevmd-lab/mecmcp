//! Many concurrent captures must each see their own event.
//!
//! **This must stay its own integration binary.** The callsite interest cache is
//! process-global but the subscriber is thread-local. Two threads rebuilding
//! the cache at once can re-evaluate a callsite against a thread whose
//! subscriber does not capture, dropping the event — so a capture comes back
//! empty even though the audit code ran correctly (mecmcp#324).
//!
//! **Exactly one test in this binary.** A second test would be immunised by the
//! first test's callsite registration and would prove less than it claims. This
//! is the sibling to `capture_under_concurrency.rs`, which tests a different
//! concurrency failure mode (noisy neighbour thread).

#![allow(clippy::unwrap_used)]

use mecmcp_audit::AuditScope;
use mecmcp_audit::testutil::run_with_capture;

/// Many concurrent captures must each see their own event.
#[test]
fn many_concurrent_captures_each_see_their_own_event() {
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|i| {
                scope.spawn(move || {
                    let tool: &'static str = if i % 2 == 0 { "alpha" } else { "beta" };
                    let out = run_with_capture(|| {
                        let mut scope = AuditScope::stdio(tool, "read", Vec::new());
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
