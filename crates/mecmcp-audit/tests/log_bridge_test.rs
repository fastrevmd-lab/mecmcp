//! A pre-existing `log` logger must not cost the rotation handle (#200).
//!
//! Its own test binary on purpose: `set_global_default` and `log`'s logger are
//! both process-global and can each be set once, so this scenario cannot be
//! staged alongside any other test.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::{AuditConfig, AuditFormat, init_tracing};

struct SilentLogger;

impl log::Log for SilentLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        false
    }
    fn log(&self, _record: &log::Record<'_>) {}
    fn flush(&self) {}
}

/// `try_init` installs the subscriber and *then* the `log` bridge, and returns
/// the bridge's error as its own. A consumer holding a `log` logger but no
/// tracing subscriber therefore got an error from a call that had installed the
/// subscriber globally — and `init_tracing` read that as "not installed" and
/// dropped the only rotation handle, while audit records went on being written
/// through the layer it had just installed. After a rotation nothing could
/// reopen the live sink.
#[test]
fn a_pre_existing_log_logger_does_not_cost_the_rotation_handle() {
    // Exactly the state that broke it: a `log` logger, no tracing subscriber.
    log::set_boxed_logger(Box::new(SilentLogger)).expect("no logger set yet");

    let dir = tempfile::tempdir().unwrap();
    let audit_log = dir.path().join("audit.log");
    let sink = init_tracing(&AuditConfig {
        format: AuditFormat::Json,
        audit_log_file: Some(audit_log.clone()),
        redaction: None,
        journald: false,
    })
    .expect("installation must succeed");

    let sink = sink.expect("the rotation handle must survive a pre-existing log logger");
    assert_eq!(sink.path(), audit_log);

    // And it is a working handle, not just a returned value.
    std::fs::rename(&audit_log, dir.path().join("audit.log.1")).unwrap();
    sink.reopen()
        .expect("the returned handle must be able to reopen");
    assert!(audit_log.exists(), "reopen must recreate the live file");
}
