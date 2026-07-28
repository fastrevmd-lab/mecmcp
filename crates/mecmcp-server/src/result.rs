//! Safe conversion of domain results into MCP tool results.

use rmcp::model::{CallToolResult, ContentBlock};
use serde::Serialize;
use std::fmt::Display;

/// How successful serializable values are rendered into text content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultFormat {
    /// Render every value as indented JSON.
    PrettyJson,
    /// Preserve a JSON string as raw text; render every other value as
    /// indented JSON.
    StringOrPrettyJson,
}

/// Hard byte limits applied before a successful MCP result is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultLimits {
    /// Maximum bytes in the final text content.
    pub max_text_bytes: usize,
    /// Maximum bytes in the serialized JSON representation.
    pub max_json_bytes: usize,
}

/// A UTF-8-safe bounded text value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BoundedText {
    /// Prefix ending on a UTF-8 character boundary.
    pub text: String,
    /// Whether bytes were omitted.
    pub truncated: bool,
    /// Original UTF-8 byte length.
    pub original_bytes: usize,
    /// Number of bytes omitted from the returned prefix.
    pub omitted_bytes: usize,
}

/// Bound text to at most `max_bytes` without splitting a UTF-8 code point.
#[must_use]
pub fn bounded_text(input: &str, max_bytes: usize) -> BoundedText {
    let original_bytes = input.len();
    if original_bytes <= max_bytes {
        return BoundedText {
            text: input.to_owned(),
            truncated: false,
            original_bytes,
            omitted_bytes: 0,
        };
    }

    let mut end = max_bytes.min(original_bytes);
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    BoundedText {
        text: input[..end].to_owned(),
        truncated: true,
        original_bytes,
        omitted_bytes: original_bytes - end,
    }
}

/// Build an MCP tool error containing one safe text block.
#[must_use]
pub fn tool_error(error: impl Display) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(error.to_string())])
}

/// Convert a domain result into a bounded MCP tool result.
///
/// Domain and serialization failures are represented as MCP tool errors. An
/// oversized success is refused in full rather than returned as partial JSON.
#[must_use]
pub fn tool_result<T, E>(
    result: Result<T, E>,
    format: ResultFormat,
    limits: ResultLimits,
) -> CallToolResult
where
    T: Serialize,
    E: Display,
{
    let value = match result {
        Ok(value) => value,
        Err(error) => return tool_error(error),
    };

    let serialized = match serialize_value(&value, format) {
        Ok(serialized) => serialized,
        Err(error) => return tool_error(format!("failed to serialize tool result: {error}")),
    };

    if serialized.json_bytes > limits.max_json_bytes {
        return tool_error(format!(
            "serialized JSON exceeds the {}-byte limit",
            limits.max_json_bytes
        ));
    }
    if serialized.text.len() > limits.max_text_bytes {
        return tool_error(format!(
            "tool result text exceeds the {}-byte limit",
            limits.max_text_bytes
        ));
    }

    CallToolResult::success(vec![ContentBlock::text(serialized.text)])
}

struct SerializedValue {
    text: String,
    json_bytes: usize,
}

fn serialize_value<T: Serialize>(
    value: &T,
    format: ResultFormat,
) -> Result<SerializedValue, serde_json::Error> {
    match format {
        ResultFormat::PrettyJson => {
            let text = serde_json::to_string_pretty(value)?;
            Ok(SerializedValue {
                json_bytes: text.len(),
                text,
            })
        }
        ResultFormat::StringOrPrettyJson => {
            let value = serde_json::to_value(value)?;
            match value {
                serde_json::Value::String(text) => {
                    let json_bytes = serde_json::to_string(&text)?.len();
                    Ok(SerializedValue { text, json_bytes })
                }
                value => {
                    let text = serde_json::to_string_pretty(&value)?;
                    Ok(SerializedValue {
                        json_bytes: text.len(),
                        text,
                    })
                }
            }
        }
    }
}
