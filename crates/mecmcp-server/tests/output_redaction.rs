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

    // `AlreadyRedacted` is the case this test file exists to add coverage
    // for (MEC-1168): the value really was redacted, just by the caller
    // rather than by `tool_result`, so it must stay just as quiet at `WARN`
    // as `Apply`, not join `SkipForInternalRead` in logging a false
    // "skipped" event that names the wrong function. It still logs its own
    // `DEBUG`-level event naming the tool and what redacted the value
    // (MEC-1181 / Percy's review of MEC-1168), so an operator can list every
    // call site that bypassed central redaction even though none of them
    // need a warning.
    let _ = tool_result::<_, std::convert::Infallible>(
        Ok(serde_json::json!({"continuation_token": "page-2"})),
        ResultFormat::PrettyJson,
        ResultLimits {
            max_text_bytes: 1024,
            max_json_bytes: 1024,
        },
        OutputRedaction::AlreadyRedacted {
            tool: "list_continuations",
            redacted_by: "redact_json_value at the call site, to keep continuation_token",
        },
    );
    let captured = String::from_utf8(writer.0.lock().unwrap().clone()).unwrap();
    assert_eq!(
        captured
            .lines()
            .filter(|line| line.contains("tool_output_redaction_skipped"))
            .count(),
        1,
        "OutputRedaction::AlreadyRedacted must not emit a skip event:\n{captured}"
    );
    let redacted_by_caller_lines: Vec<&str> = captured
        .lines()
        .filter(|line| line.contains("tool_output_redacted_by_caller"))
        .collect();
    assert_eq!(
        redacted_by_caller_lines.len(),
        1,
        "expected exactly one redacted-by-caller event:\n{captured}"
    );
    assert!(
        redacted_by_caller_lines[0].contains("tool=list_continuations"),
        "got {captured}"
    );
    assert!(
        redacted_by_caller_lines[0].contains("redacted_by=redact_json_value at the call site"),
        "got {captured}"
    );
}
