//! Vendor-neutral helpers every MCP tool handler in this family needs.
//!
//! Two concerns, deliberately kept apart:
//!
//! - **Rendering a result** — [`tool_result`], [`tool_error`], [`bounded_text`].
//!   A handler's return value is caller-visible and vendor-sized, so it is
//!   bounded before it leaves.
//! - **Authorizing a call** — the scope checks, added separately.
//!
//! Nothing here knows a vendor's names, paths, headers, models, or statuses.
//! That is the whole point: three servers were carrying their own copy of this
//! logic, and a copy is a place for two of them to disagree about what a limit
//! or a scope means.
//!
//! ## Limits are refusals, not truncation
//!
//! [`tool_result`] returns an MCP **error** when a successful value exceeds its
//! limits; it does not send a shortened value. A caller handed a silently
//! truncated result cannot tell it from a complete one, and a handler's job is
//! to be trustworthy about what it returns rather than to always return
//! something.
//!
//! [`bounded_text`] is the other half, for the places that genuinely want a
//! prefix — a log line, a preview — and it says so in its return value.

use serde::Serialize;
use std::fmt::Display;

/// How a successful serializable value is rendered into text content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultFormat {
    /// Render every value as indented JSON.
    PrettyJson,
    /// Preserve a JSON string as raw text; render every other value as indented
    /// JSON.
    ///
    /// The distinction matters for a tool whose result *is* text — a device's
    /// CLI output, say. `PrettyJson` would hand the caller a quoted, escaped
    /// blob; this hands them the text.
    StringOrPrettyJson,
}

/// Hard byte limits applied before a successful MCP result is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResultLimits {
    /// Maximum bytes in the final text content.
    pub max_text_bytes: usize,
    /// Maximum bytes in the serialized JSON representation.
    ///
    /// Separate from `max_text_bytes` because the two differ under
    /// [`ResultFormat::StringOrPrettyJson`]: a string is returned raw but
    /// measured as JSON, so escaping can make the JSON substantially larger than
    /// the text the caller receives.
    pub max_json_bytes: usize,
}

/// A UTF-8-safe bounded text value.
///
/// The three fields beyond `text` exist so a caller can tell a complete value
/// from a prefix, and by how much. A bare truncated `String` cannot be told from
/// a short one.
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
///
/// Walks back to the nearest character boundary rather than cutting at
/// `max_bytes`, so the result is always valid UTF-8. That means the returned
/// text can be shorter than `max_bytes` — up to three bytes shorter — and
/// `omitted_bytes` reports what actually went.
///
/// # Examples
/// ```
/// use mecmcp_server::bounded_text;
///
/// // `é` is two bytes, so a three-byte budget cannot include it.
/// let bounded = bounded_text("abé", 3);
/// assert_eq!(bounded.text, "ab");
/// assert!(bounded.truncated);
/// assert_eq!(bounded.original_bytes, 4);
/// assert_eq!(bounded.omitted_bytes, 2);
/// ```
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
///
/// The message is whatever `error` renders, so an error type reaching this must
/// already be safe to show a caller. This crate cannot make an unsafe message
/// safe; a type that might carry a credential or an internal path should be
/// redacted at its own boundary, not here.
///
/// The text is **not** bounded. Every caller in this family builds these from
/// its own short, fixed-shape messages, and silently shortening a diagnostic is
/// how an operator loses the part that mattered. A handler formatting a
/// vendor-supplied string into an error should pass it through [`bounded_text`]
/// first.
#[must_use]
pub fn tool_error(error: impl Display) -> rmcp::model::CallToolResult {
    rmcp::model::CallToolResult::error(vec![rmcp::model::ContentBlock::text(error.to_string())])
}

/// Convert a domain result into a bounded MCP tool result.
///
/// A failure becomes [`tool_error`]. A success is serialized per `format`, then
/// checked against both limits, and **refused** rather than truncated if it
/// exceeds either — see the note on limits in the crate documentation.
///
/// # Examples
/// ```
/// use mecmcp_server::{ResultFormat, ResultLimits, tool_result};
///
/// let over = tool_result::<_, std::convert::Infallible>(
///     Ok("0123456789"),
///     ResultFormat::StringOrPrettyJson,
///     ResultLimits { max_text_bytes: 4, max_json_bytes: 32 },
/// );
/// assert_eq!(over.is_error, Some(true));
/// ```
#[must_use]
pub fn tool_result<T, E>(
    result: Result<T, E>,
    format: ResultFormat,
    limits: ResultLimits,
) -> rmcp::model::CallToolResult
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
    rmcp::model::CallToolResult::success(vec![rmcp::model::ContentBlock::text(serialized.text)])
}

/// A rendered value and the size of its JSON form.
///
/// Both are carried because they differ under
/// [`ResultFormat::StringOrPrettyJson`], and measuring the text twice would
/// apply the JSON limit to something that is not JSON.
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
                    // Measured as JSON, returned as text: escaping means the two
                    // sizes genuinely differ, which is why `ResultLimits` has
                    // two fields rather than one.
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The only content a result carries, so a test can assert on it.
    fn text_of(result: &rmcp::model::CallToolResult) -> String {
        result
            .content
            .iter()
            .filter_map(|block| block.as_text().map(|text| text.text.clone()))
            .collect()
    }

    #[test]
    fn a_value_within_both_limits_is_a_success() {
        let result = tool_result::<_, std::convert::Infallible>(
            Ok(serde_json::json!({"device": "fw-01"})),
            ResultFormat::PrettyJson,
            ResultLimits {
                max_text_bytes: 1024,
                max_json_bytes: 1024,
            },
        );
        assert_ne!(result.is_error, Some(true));
        assert!(text_of(&result).contains("fw-01"));
    }

    /// Refused, not shortened. A caller cannot tell a truncated result from a
    /// complete one, so the limit has to be an error.
    #[test]
    fn an_oversized_success_is_refused_rather_than_truncated() {
        let result = tool_result::<_, std::convert::Infallible>(
            Ok("0123456789"),
            ResultFormat::StringOrPrettyJson,
            ResultLimits {
                max_text_bytes: 4,
                max_json_bytes: 32,
            },
        );
        assert_eq!(result.is_error, Some(true));
        let text = text_of(&result);
        assert!(text.contains("exceeds"), "got {text}");
        assert!(
            !text.contains("0123"),
            "the refusal must not carry a prefix of the value: {text}"
        );
    }

    /// The JSON limit is checked against the JSON form even when the text
    /// returned is the raw string, which is the case the two-field
    /// `ResultLimits` exists for.
    #[test]
    fn the_json_limit_is_measured_on_the_json_form() {
        // Ten quote characters: two bytes each once escaped, plus the pair of
        // enclosing quotes — 22 bytes of JSON for 10 bytes of text.
        let quotes = "\"".repeat(10);
        let result = tool_result::<_, std::convert::Infallible>(
            Ok(quotes),
            ResultFormat::StringOrPrettyJson,
            ResultLimits {
                max_text_bytes: 16,
                max_json_bytes: 16,
            },
        );
        assert_eq!(
            result.is_error,
            Some(true),
            "10 bytes of text is inside the text limit but its JSON form is not"
        );
        assert!(
            text_of(&result).contains("JSON"),
            "the JSON limit should be the one that fired"
        );
    }

    /// A string comes back as text, not as a quoted JSON blob. This is the
    /// entire difference between the two formats and the reason a device's CLI
    /// output is readable.
    #[test]
    fn a_string_is_returned_raw_under_string_or_pretty_json() {
        let limits = ResultLimits {
            max_text_bytes: 1024,
            max_json_bytes: 1024,
        };
        let raw = tool_result::<_, std::convert::Infallible>(
            Ok("show version"),
            ResultFormat::StringOrPrettyJson,
            limits,
        );
        assert_eq!(text_of(&raw), "show version");

        let quoted = tool_result::<_, std::convert::Infallible>(
            Ok("show version"),
            ResultFormat::PrettyJson,
            limits,
        );
        assert_eq!(
            text_of(&quoted),
            "\"show version\"",
            "PrettyJson must keep the quotes — that is what makes it JSON"
        );
    }

    #[test]
    fn a_failure_becomes_a_tool_error_carrying_its_message() {
        let result = tool_result::<serde_json::Value, _>(
            Err("device unreachable"),
            ResultFormat::PrettyJson,
            ResultLimits {
                max_text_bytes: 1024,
                max_json_bytes: 1024,
            },
        );
        assert_eq!(result.is_error, Some(true));
        assert_eq!(text_of(&result), "device unreachable");
    }

    #[test]
    fn text_within_the_budget_is_returned_whole_and_not_marked_truncated() {
        let bounded = bounded_text("abé", 4);
        assert_eq!(bounded.text, "abé");
        assert!(!bounded.truncated);
        assert_eq!(bounded.original_bytes, 4);
        assert_eq!(bounded.omitted_bytes, 0);
    }

    /// The reason this is not `&input[..max_bytes]`: that panics mid-code-point.
    #[test]
    fn bounding_never_splits_a_utf8_code_point() {
        let bounded = bounded_text("abé", 3);
        assert_eq!(bounded.text, "ab");
        assert!(bounded.truncated);
        assert_eq!(bounded.original_bytes, 4);
        assert_eq!(bounded.omitted_bytes, 2);

        // A four-byte code point walked back over three interior boundaries.
        let emoji = bounded_text("🦀", 3);
        assert_eq!(emoji.text, "");
        assert!(emoji.truncated);
        assert_eq!(emoji.omitted_bytes, 4);
    }

    #[test]
    fn a_zero_budget_yields_empty_text_rather_than_panicking() {
        let bounded = bounded_text("anything", 0);
        assert_eq!(bounded.text, "");
        assert!(bounded.truncated);
        assert_eq!(bounded.omitted_bytes, 8);
    }
}
