//! F9: `install` must not claim redaction was disabled when the call had no
//! effect because the policy was already locked in.
//!
//! Own process, same reasoning as the other `policy_*` integration tests:
//! `POLICY` is a process-global `OnceLock`.

#![allow(clippy::unwrap_used)]

use mecmcp_redact::{RedactionPolicy, active, install};
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
    type Writer = CapturedLog;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn a_disable_install_that_loses_the_race_does_not_log_disabled() {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .json()
            .with_writer(CapturedLog(buffer.clone())),
    );

    tracing::subscriber::with_default(subscriber, || {
        // Locks in `Enabled` first, exactly like the first `active()` call a
        // server makes before ever reaching its own `install`.
        assert_eq!(active(), RedactionPolicy::Enabled);

        // A later, ignored `install(DisabledByOperator)` must not claim
        // redaction was disabled — the policy is still `Enabled` and stays
        // that way.
        install(RedactionPolicy::DisabledByOperator {
            flag: "--no-redact",
        });
    });

    assert_eq!(
        active(),
        RedactionPolicy::Enabled,
        "the ignored install() must not have changed the locked-in policy"
    );

    let log = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
    assert!(
        !log.contains("tool_output_redaction_disabled"),
        "an ignored install() must not log the 'disabled' event: {log}"
    );
    assert!(
        log.contains("tool_output_redaction_install_ignored"),
        "an ignored install() must still say so: {log}"
    );
}
