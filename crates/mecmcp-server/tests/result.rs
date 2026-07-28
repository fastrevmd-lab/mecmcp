//! MCP result formatting and output-bound contract tests.

use mecmcp_server::{
    BoundedText, ResultFormat, ResultLimits, bounded_text, tool_error, tool_result,
};
use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;
use serde_json::json;

fn text(result: &CallToolResult) -> &str {
    match result.content.first().expect("one content block") {
        ContentBlock::Text(content) => &content.text,
        other => panic!("expected text content, got {other:?}"),
    }
}

fn limits(max_text_bytes: usize, max_json_bytes: usize) -> ResultLimits {
    ResultLimits {
        max_text_bytes,
        max_json_bytes,
    }
}

#[test]
fn pretty_json_formats_structured_values() {
    let result = tool_result::<_, &str>(
        Ok(json!({"name": "edge", "healthy": true})),
        ResultFormat::PrettyJson,
        limits(1024, 1024),
    );

    assert_eq!(result.is_error, Some(false));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(text(&result)).expect("valid JSON"),
        json!({"name": "edge", "healthy": true})
    );
    assert!(text(&result).contains('\n'), "result must be pretty JSON");
}

#[test]
fn string_or_pretty_json_preserves_raw_strings() {
    let result = tool_result::<_, &str>(
        Ok(json!("plain operational output")),
        ResultFormat::StringOrPrettyJson,
        limits(1024, 1024),
    );

    assert_eq!(text(&result), "plain operational output");
}

#[test]
fn ordinary_errors_become_mcp_tool_errors() {
    let result = tool_result::<serde_json::Value, _>(
        Err("device unavailable"),
        ResultFormat::PrettyJson,
        limits(1024, 1024),
    );

    assert_eq!(result.is_error, Some(true));
    assert_eq!(text(&result), "device unavailable");
}

struct BrokenSerialize;

impl Serialize for BrokenSerialize {
    fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Err(serde::ser::Error::custom(
            "intentional serialization failure",
        ))
    }
}

#[test]
fn serialization_failure_becomes_a_tool_error() {
    let result = tool_result::<_, &str>(
        Ok(BrokenSerialize),
        ResultFormat::PrettyJson,
        limits(1024, 1024),
    );

    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("failed to serialize tool result"));
    assert!(text(&result).contains("intentional serialization failure"));
}

#[test]
fn exact_output_limits_are_accepted() {
    let result = tool_result::<_, &str>(
        Ok(json!("four")),
        ResultFormat::StringOrPrettyJson,
        limits(4, 6),
    );

    assert_eq!(result.is_error, Some(false));
    assert_eq!(text(&result), "four");
}

#[test]
fn oversized_json_is_refused_without_partial_output() {
    let result = tool_result::<_, &str>(
        Ok(json!({"value": "too large"})),
        ResultFormat::PrettyJson,
        limits(1024, 8),
    );

    assert_eq!(result.is_error, Some(true));
    assert!(text(&result).contains("serialized JSON exceeds the 8-byte limit"));
    assert!(!text(&result).contains("too large"));
}

#[test]
fn oversized_raw_text_is_refused_without_partial_output() {
    let result = tool_result::<_, &str>(
        Ok(json!("five!")),
        ResultFormat::StringOrPrettyJson,
        limits(4, 1024),
    );

    assert_eq!(result.is_error, Some(true));
    assert_eq!(text(&result), "tool result text exceeds the 4-byte limit");
}

#[test]
fn tool_error_has_the_protocol_error_marker() {
    let result = tool_error("denied");

    assert_eq!(result.is_error, Some(true));
    assert_eq!(text(&result), "denied");
}

#[test]
fn bounded_text_truncates_ascii_and_reports_omitted_bytes() {
    assert_eq!(
        bounded_text("abcdefgh", 5),
        BoundedText {
            text: "abcde".to_owned(),
            truncated: true,
            original_bytes: 8,
            omitted_bytes: 3,
        }
    );
}

#[test]
fn bounded_text_never_splits_multibyte_utf8() {
    assert_eq!(
        bounded_text("aé日z", 4),
        BoundedText {
            text: "aé".to_owned(),
            truncated: true,
            original_bytes: 7,
            omitted_bytes: 4,
        }
    );
}
