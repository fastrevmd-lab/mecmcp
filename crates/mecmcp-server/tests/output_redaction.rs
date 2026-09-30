//! `OutputRedaction::SkipForInternalRead` must be audited, not just quiet.
//!
//! Its own test binary: the capture installs a global tracing subscriber,
//! which can only be set once per process — the same reason
//! `tests/audit_scope.rs` is split out.

#![allow(clippy::unwrap_used)]

use mecmcp_audit::testutil::CapturingWriter;
use mecmcp_server::{OutputRedaction, ResultFormat, ResultLimits, tool_result};
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[test]
fn skip_for_internal_read_emits_an_audit_event_naming_the_tool_and_reason() {
    let writer = CapturingWriter::default();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false),
        )
        .init();

    let _ = tool_result::<_, std::convert::Infallible>(
        Ok(serde_json::json!({"entries": []})),
        ResultFormat::PrettyJson,
        ResultLimits {
            max_text_bytes: 1024,
            max_json_bytes: 1024,
        },
        OutputRedaction::SkipForInternalRead {
            tool: "get_audit_log",
            reason: "reads this process's own audit log entries, not vendor secrets",
        },
    );

    let captured = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    let audit_lines: Vec<&str> = captured
        .lines()
        .filter(|line| line.contains("tool_output_redaction_skipped"))
        .collect();
    assert_eq!(
        audit_lines.len(),
        1,
        "expected exactly one skip event:\n{captured}"
    );
    assert!(
        audit_lines[0].contains("tool=get_audit_log"),
        "got {captured}"
    );
    assert!(
        audit_lines[0].contains("reason=reads this process's own audit log entries"),
        "got {captured}"
    );

    // The default path must not emit the same event.
    let _ = tool_result::<_, std::convert::Infallible>(
        Ok(serde_json::json!({"hostname": "fw-01"})),
        ResultFormat::PrettyJson,
        ResultLimits {
            max_text_bytes: 1024,
            max_json_bytes: 1024,
        },
        OutputRedaction::Apply,
    );
    let captured = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        captured
            .lines()
            .filter(|line| line.contains("tool_output_redaction_skipped"))
            .count(),
        1,
        "OutputRedaction::Apply must not emit a skip event:\n{captured}"
    );
}
