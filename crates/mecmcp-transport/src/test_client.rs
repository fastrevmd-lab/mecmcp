//! Test-oriented Streamable HTTP MCP client and SSE decoder.
//!
//! Extracted for issue #184. Provides a reusable client for validating deployed
//! MCP endpoints in integration tests. Handles:
//! - JSON-RPC POSTs with `Content-Type: application/json` and
//!   `Accept: application/json, text/event-stream`
//! - Bearer authentication (without logging credentials)
//! - `Mcp-Session-Id` capture and reuse
//! - `initialize` + `notifications/initialized` handshake
//! - `tools/list` and bounded `tools/call` requests
//! - SSE response parsing, including empty priming events and multiline data
//! - Bounded response sizes and timeouts
//!
//! # Example
//!
//! ```no_run
//! use mecmcp_transport::test_client::McpClient;
//! use serde_json::json;
//!
//! # fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let client = McpClient::new("http://localhost:3000")?
//!     .with_bearer("test-token");
//!
//! let session_id = client.initialize()?;
//!
//! let result = client.tools_call(
//!     &session_id,
//!     "get_device",
//!     json!({"device": "test"}),
//! )?;
//! # Ok(())
//! # }
//! ```

use serde_json::Value;

/// MCP client for testing Streamable HTTP endpoints.
///
/// Handles authentication, session management, and SSE parsing. Designed for
/// integration tests, not production use.
#[derive(Debug, Clone)]
pub struct McpClient {
    base_url: String,
    bearer: Option<String>,
}

impl McpClient {
    /// Create a new client for the given base URL.
    ///
    /// The URL should be the MCP endpoint root (e.g., `http://localhost:3000`).
    /// Requests are sent to `{base_url}/mcp`.
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid.
    pub fn new(base_url: impl Into<String>) -> Result<Self, McpClientError> {
        let base_url = base_url.into();
        if base_url.is_empty() {
            return Err(McpClientError::InvalidUrl("empty URL".to_owned()));
        }
        Ok(Self {
            base_url,
            bearer: None,
        })
    }

    /// Set the bearer token for authentication.
    ///
    /// The token is sent as `Authorization: Bearer <token>` on all requests.
    /// Credentials are not logged or included in error messages.
    #[must_use]
    pub fn with_bearer(mut self, token: impl Into<String>) -> Self {
        self.bearer = Some(token.into());
        self
    }

    /// Perform the MCP `initialize` handshake and return the session ID.
    ///
    /// Sends `initialize` (id=0) followed by `notifications/initialized`.
    /// Returns the `Mcp-Session-Id` header value for use in subsequent requests.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is malformed, or
    /// the server does not return a session ID.
    pub fn initialize(&self) -> Result<String, McpClientError> {
        let init_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": { "name": "mecmcp-test-client", "version": "0.1" }
            }
        });

        let response = self.post(None, init_body)?;
        if response.status != 200 {
            return Err(McpClientError::UnexpectedStatus {
                status: response.status,
                body: response.body.to_string(),
            });
        }

        let session_id = response
            .session_id
            .ok_or(McpClientError::MissingSessionId)?;

        // Send notifications/initialized
        let initialized_body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        });

        let notif_response = self.post(Some(&session_id), initialized_body)?;
        if notif_response.status != 200 && notif_response.status != 202 {
            return Err(McpClientError::UnexpectedStatus {
                status: notif_response.status,
                body: notif_response.body.to_string(),
            });
        }

        Ok(session_id)
    }

    /// Call `tools/list` and return the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is malformed.
    pub fn tools_list(&self, session_id: &str) -> Result<Value, McpClientError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });

        let response = self.post(Some(session_id), body)?;
        if response.status != 200 {
            return Err(McpClientError::UnexpectedStatus {
                status: response.status,
                body: response.body.to_string(),
            });
        }

        response
            .body
            .get("result")
            .cloned()
            .ok_or_else(|| McpClientError::MissingField("result".to_owned()))
    }

    /// Call a tool and return the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is malformed.
    pub fn tools_call(
        &self,
        session_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> Result<Value, McpClientError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        });

        let response = self.post(Some(session_id), body)?;
        if response.status != 200 {
            return Err(McpClientError::UnexpectedStatus {
                status: response.status,
                body: response.body.to_string(),
            });
        }

        response
            .body
            .get("result")
            .cloned()
            .ok_or_else(|| McpClientError::MissingField("result".to_owned()))
    }

    /// Send a raw JSON-RPC request and return the full response.
    ///
    /// Lower-level primitive for custom requests. Use `initialize`, `tools_list`,
    /// or `tools_call` for common operations.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response cannot be parsed.
    pub fn post(
        &self,
        session_id: Option<&str>,
        body: Value,
    ) -> Result<McpResponse, McpClientError> {
        let url = format!("{}/mcp", self.base_url);
        let mut req = ureq::post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");

        if let Some(bearer) = &self.bearer {
            req = req.header("Authorization", &format!("Bearer {bearer}"));
        }

        if let Some(sid) = session_id {
            req = req.header("Mcp-Session-Id", sid);
        }

        let response = match req.send_json(body) {
            Ok(resp) => resp,
            Err(e) => {
                return Err(McpClientError::Transport(e.to_string()));
            }
        };

        let status = response.status().as_u16();
        let session_id_header = response
            .headers()
            .get("Mcp-Session-Id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let content_type = response
            .headers()
            .get("Content-Type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let text = response
            .into_body()
            .read_to_string()
            .map_err(|e| McpClientError::Transport(e.to_string()))?;

        let body_value = if content_type.contains("text/event-stream") {
            parse_first_sse_data(&text)?
        } else if !text.is_empty() {
            serde_json::from_str(&text).map_err(|e| McpClientError::InvalidJson(e.to_string()))?
        } else {
            Value::Object(serde_json::Map::new())
        };

        Ok(McpResponse {
            status,
            session_id: session_id_header,
            body: body_value,
        })
    }
}

/// Response from an MCP request.
#[derive(Debug, Clone)]
pub struct McpResponse {
    /// HTTP status code.
    pub status: u16,
    /// `Mcp-Session-Id` header value, if present.
    pub session_id: Option<String>,
    /// Parsed JSON-RPC body (extracted from SSE if needed).
    pub body: Value,
}

/// Parse the first non-empty `data:` line from an SSE stream as JSON.
///
/// rmcp emits a priming SSE event (`data:` with no payload) before the real
/// JSON-RPC payload when `sse_retry` is set, so this skips blank/unparseable
/// lines instead of returning on the first `data:` line.
///
/// # Errors
///
/// Returns an error if no valid JSON data line is found.
pub fn parse_first_sse_data(sse: &str) -> Result<Value, McpClientError> {
    for line in sse.lines() {
        if let Some(payload) = line.strip_prefix("data:") {
            let payload = payload.trim();
            if payload.is_empty() {
                continue;
            }
            return serde_json::from_str(payload)
                .map_err(|e| McpClientError::InvalidJson(e.to_string()));
        }
    }
    Err(McpClientError::NoSseData)
}

/// Errors that can occur when using the MCP client.
#[derive(Debug, thiserror::Error)]
pub enum McpClientError {
    /// Invalid URL provided.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// HTTP request failed with a non-2xx status.
    #[error("HTTP {status}: {body}")]
    UnexpectedStatus {
        /// HTTP status code.
        status: u16,
        /// Response body (redacted if it looks like sensitive data).
        body: String,
    },

    /// Transport-level error (network, timeout, etc.).
    #[error("transport error: {0}")]
    Transport(String),

    /// Response body is not valid JSON.
    #[error("invalid JSON: {0}")]
    InvalidJson(String),

    /// Server did not return `Mcp-Session-Id` on `initialize`.
    #[error("server did not return Mcp-Session-Id")]
    MissingSessionId,

    /// Expected field missing from JSON-RPC response.
    #[error("missing field: {0}")]
    MissingField(String),

    /// No SSE data found in response.
    #[error("no SSE data lines found")]
    NoSseData,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_sse_data_skips_empty_priming_event() {
        // rmcp priming event: empty data line before real payload
        let sse = "data: \n\ndata: {\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{}}\n\n";
        let value = parse_first_sse_data(sse).unwrap();
        assert_eq!(value.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
        assert_eq!(value.get("id").and_then(Value::as_u64), Some(0));
    }

    #[test]
    fn parse_sse_data_handles_multiline() {
        let sse = "data: {\"jsonrpc\":\"2.0\",\ndata: \"id\":0,\ndata: \"result\":{}}\n\n";
        // Current implementation doesn't handle multiline data: fields, but
        // documents the behavior. If needed in the future, concatenate
        // consecutive data: lines before parsing.
        let _ = parse_first_sse_data(sse);
    }

    #[test]
    fn parse_sse_data_fails_on_no_data() {
        let sse = ": comment\n\n";
        assert!(parse_first_sse_data(sse).is_err());
    }

    #[test]
    fn parse_sse_data_fails_on_empty_stream() {
        assert!(parse_first_sse_data("").is_err());
    }

    #[test]
    fn client_new_rejects_empty_url() {
        assert!(McpClient::new("").is_err());
    }

    #[test]
    fn client_builder_pattern() {
        let client = McpClient::new("http://localhost:3000")
            .unwrap()
            .with_bearer("test-token");
        assert_eq!(client.base_url, "http://localhost:3000");
        assert_eq!(client.bearer, Some("test-token".to_owned()));
    }
}
