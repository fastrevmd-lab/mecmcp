//! Tracing-capture helper for asserting on `audit`-target output in tests.
#![cfg(any(test, feature = "test-util"))]
#![allow(clippy::unwrap_used)]

use std::cell::RefCell;
use std::io::Write;
use std::sync::{Arc, Mutex, Once};
use tracing_subscriber::fmt::MakeWriter;

thread_local! {
    /// The buffer the *current thread* is capturing into, if any.
    ///
    /// `None` means this thread is not capturing, so its audit events are
    /// discarded. That is what makes a noisy neighbour harmless: it emits into
    /// its own absent buffer instead of racing the capturing thread.
    static CAPTURE_BUF: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

/// A cloneable in-memory writer collecting everything written to it.
///
/// Public because downstream servers build their own capture subscribers with
/// it. [`run_with_capture`] does **not** use it — see [`ThreadLocalWriter`].
#[derive(Clone, Default)]
pub struct CapturingWriter(pub Arc<Mutex<Vec<u8>>>);

impl Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturingWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// Writer that appends to whatever buffer the *current thread* is capturing into.
///
/// This is what makes one always-on subscriber able to serve per-thread
/// captures: routing happens at write time, by thread, rather than by swapping
/// subscribers. A thread that is not capturing has no buffer, so its events are
/// discarded instead of racing a thread that is.
#[derive(Clone, Copy, Default)]
struct ThreadLocalWriter;

impl Write for ThreadLocalWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CAPTURE_BUF.with(|cell| {
            if let Ok(mut slot) = cell.try_borrow_mut()
                && let Some(active) = slot.as_mut()
            {
                active.extend_from_slice(buf);
            }
        });
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for ThreadLocalWriter {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        *self
    }
}

/// Names from `registry` that produced no audit event when exercised.
///
/// Audit coverage is currently a property of whether whoever added a tool
/// remembered to open an [`AuditScope`](crate::AuditScope), and the failure is
/// silent in both directions: a new tool is simply absent from the trail, and
/// nothing in the log says so. A partial trail that presents as complete is
/// worse to reason about than no trail (mecmcp#32).
///
/// Nothing tied the tool registry to the audit output, so this ties them.
/// `exercise` is called once per tool name and should drive that tool's handler
/// path; any name whose run emits no `tool=<name>` audit field is returned.
///
/// Returning the gaps rather than panicking lets the caller name all of them in
/// one failure instead of one per run:
///
/// ```ignore
/// let missing = tools_without_audit_events(KNOWN_TOOLS, |tool| dispatch(tool));
/// assert!(missing.is_empty(), "tools with no audit event: {missing:?}");
/// ```
///
/// Each tool is captured independently, so one noisy tool cannot mask a silent
/// neighbour.
pub fn tools_without_audit_events<F>(registry: &[&str], mut exercise: F) -> Vec<String>
where
    F: FnMut(&str),
{
    registry
        .iter()
        .filter(|tool| {
            let captured = run_with_capture(|| exercise(tool));
            !emits_audit_for_tool(&captured, tool)
        })
        .map(|tool| (*tool).to_owned())
        .collect()
}

/// Whether `captured` contains an audit event for exactly this tool.
///
/// Matches the `tool=<name>` field with its terminator, so `get_config` is not
/// satisfied by an event for `get_config_diff`. A substring test would let a
/// tool with a longer name vouch for one that was never audited, which is the
/// exact failure this is meant to detect.
fn emits_audit_for_tool(captured: &str, tool: &str) -> bool {
    let needle = format!("tool={tool}");
    captured.match_indices(&needle).any(|(index, _)| {
        captured[index + needle.len()..]
            .chars()
            .next()
            .is_none_or(|next| !matches!(next, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-'))
    })
}

/// Installs the process-wide capture subscriber exactly once.
static INSTALL_SUBSCRIBER: Once = Once::new();

/// Serialises [`run_with_capture`].
///
/// Not needed for buffer safety any more — each capture owns a thread-local
/// buffer, so two captures cannot see each other's events. It is kept because
/// the helper is also used to assert on *absence* (see
/// [`tools_without_audit_events`]), and overlapping captures would make a
/// "nothing was emitted" result depend on scheduling.
static CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Sentinel proving the capture mechanism itself is alive.
///
/// Emitted from *this* module, so it only proves the subscriber and writer are
/// working. It deliberately does **not** prove the `audit` callsite in
/// `scope.rs` is enabled — see [`run_with_capture`].
const SENTINEL_MARKER: &str = "__CAPTURE_SENTINEL_3c7f8a2b__";

/// Run `f` with audit output captured for this thread only; return the text.
///
/// # Why a global subscriber and a thread-local buffer
///
/// The obvious implementation — build a subscriber, install it with
/// `with_default`, read the buffer — is subtly broken, and it broke twice
/// (mecmcp#305, mecmcp#324, rustjunosmcp#339).
///
/// `with_default` installs a subscriber **per thread**, but `tracing` caches
/// each callsite's `Interest` **per process**. A thread with no subscriber that
/// reaches the same callsite can get `Interest::never` cached for it, and the
/// capturing thread then skips its own events. The capture comes back empty,
/// which reads at the assertion as "the audit field was missing" rather than
/// "the capture broke" — so people debug audit code that was fine all along.
///
/// A mutex around the capture does not fix this: the offending thread is not
/// capturing, it is merely *emitting*, so it never takes the lock. That is
/// exactly the case `capture_under_concurrency.rs` reproduces, and it failed
/// about half the time with the serialising fix in place.
///
/// So the subscriber is installed **once, globally, and is always enabled**.
/// Interest is therefore computed once against a subscriber that always says
/// yes, and no thread can flip it. Routing is done by the writer instead: it
/// appends to the calling thread's buffer if that thread is capturing, and
/// discards otherwise. A noisy neighbour writes into its own absent buffer.
///
/// # Panics
///
/// If the sentinel does not survive the round trip, meaning something else has
/// already claimed the process's global subscriber and this capture cannot
/// work. Returning an empty string there would masquerade as "`f` emitted
/// nothing", and [`tools_without_audit_events`] would report every tool as
/// un-audited.
pub fn run_with_capture<F: FnOnce()>(f: F) -> String {
    // Recover from poisoning rather than propagating it: a panicking test inside
    // the closure would otherwise turn one real failure into a cascade of
    // unrelated ones in every later capture test.
    let _guard = CAPTURE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // A process-wide "floor" subscriber, installed once and always enabled.
    //
    // Its only job is to keep every audit callsite's `Interest` alive. Without
    // it, a thread that has no subscriber can reach the callsite first and get
    // `Interest::never` cached for it process-wide, after which the capturing
    // thread silently skips its own events.
    //
    // Installing it is best-effort: `mecmcp_audit::init` legitimately claims the
    // global subscriber in its own tests. Either subscriber keeps interest
    // alive, which is all this needs, so losing the race is harmless.
    INSTALL_SUBSCRIBER.call_once(|| {
        let floor = tracing_subscriber::fmt()
            .with_writer(ThreadLocalWriter)
            .with_ansi(false)
            .with_target(true)
            .with_max_level(tracing::Level::INFO)
            .finish();
        let _ = tracing::subscriber::set_global_default(floor);
    });

    // Capture through a thread-local subscriber as well, so this works whether
    // or not we won the global. Both write through `CapturingWriter`, which
    // routes by thread-local buffer, so events land in this capture exactly
    // once regardless of which subscriber handled them.
    let local = tracing_subscriber::fmt()
        .with_writer(ThreadLocalWriter)
        .with_ansi(false)
        .with_target(true)
        .with_max_level(tracing::Level::INFO)
        .finish();

    CAPTURE_BUF.with(|cell| *cell.borrow_mut() = Some(Vec::new()));
    tracing::subscriber::with_default(local, || {
        tracing::info!(target: "audit", "{}", SENTINEL_MARKER);
        f();
    });
    let bytes = CAPTURE_BUF
        .with(|cell| cell.borrow_mut().take())
        .unwrap_or_default();

    let captured = String::from_utf8(bytes).unwrap();
    assert!(
        captured.contains(SENTINEL_MARKER),
        "tracing capture never observed its own sentinel event — the capture \
         mechanism is broken. This is NOT a missing audit field; do not go \
         looking for one (mecmcp#324). Likely causes: another global subscriber \
         owns this process and filters the `audit` target, or the writer is not \
         reaching this thread's buffer."
    );

    // Strip the sentinel so callers — and `tools_without_audit_events`, which
    // treats an empty result as "this tool emitted nothing" — see only `f`'s
    // output.
    captured
        .lines()
        .filter(|line| !line.contains(SENTINEL_MARKER))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditScope;

    fn audit(tool: &'static str) {
        let mut scope = AuditScope::stdio(tool, "read", Vec::new());
        scope.succeed();
    }

    #[test]
    fn tools_that_audit_are_not_reported() {
        let missing = tools_without_audit_events(&["alpha", "beta"], |tool| match tool {
            "alpha" => audit("alpha"),
            "beta" => audit("beta"),
            other => panic!("unexpected tool {other}"),
        });

        assert!(missing.is_empty(), "expected no gaps, got {missing:?}");
    }

    /// The case the issue is about: a tool nobody remembered to audit.
    #[test]
    fn a_tool_with_no_audit_event_is_reported() {
        let missing = tools_without_audit_events(&["alpha", "forgotten"], |tool| {
            if tool == "alpha" {
                audit("alpha");
            }
            // "forgotten" does nothing, exactly like a handler that never opened
            // a scope.
        });

        assert_eq!(missing, vec!["forgotten".to_owned()]);
    }

    /// A tool must not be vouched for by a different tool that merely shares its
    /// prefix. Without the terminator check, `get_config` would look audited
    /// because `get_config_diff` emitted an event.
    #[test]
    fn a_prefix_of_another_tool_is_not_counted_as_audited() {
        let missing = tools_without_audit_events(&["get_config"], |_| audit("get_config_diff"));

        assert_eq!(
            missing,
            vec!["get_config".to_owned()],
            "a longer tool name must not satisfy a shorter one"
        );
    }

    /// Each tool is captured on its own, so a chatty tool cannot mask a silent
    /// one that ran earlier or later.
    #[test]
    fn each_tool_is_captured_independently() {
        let missing = tools_without_audit_events(&["silent", "chatty"], |tool| {
            if tool == "chatty" {
                audit("chatty");
                audit("silent"); // emitted during the wrong tool's run
            }
        });

        assert_eq!(
            missing,
            vec!["silent".to_owned()],
            "an event emitted while exercising another tool must not count"
        );
    }
}
