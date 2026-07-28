# `mecmcp-server` Design

## Purpose

`mecmcp-server` owns the vendor-neutral adapter code between `rmcp` tool
handlers and the existing `mecmcp-auth` and `mecmcp-audit` boundaries. Both
`rustjunosmcp` and `rustpanosmcp` currently implement the same caller
extraction, tool/target authorization, tool-list filtering, audit-scope
construction, and result conversion locally.

The crate does not own tool declarations, tool registries, write-tool names,
vendor errors, protocol clients, or HTTP middleware. Those remain consumer
parameters or responsibilities.

## Public API

The crate exposes four focused modules:

- `caller`: recover a typed `CallerCtx<G>` from `rmcp::Extensions` without
  treating stdio as an authenticated caller.
- `authorize`: check tool and optional target scope using a consumer-supplied
  write-tool registry, and return a typed, safe `AuthorizationError`.
- `tools`: filter an advertised `Vec<rmcp::model::Tool>` with the same
  authorization predicate used for calls.
- `result`: create successful or error `CallToolResult` values, supporting
  pretty JSON, raw strings for Junos compatibility, UTF-8-safe text bounds, and
  a hard serialized JSON byte limit.
- `audit`: construct `mecmcp_audit::AuditScope` from an optional caller.

`mecmcp-audit::Attribution` remains the only request-ID generator. The new crate
must not add a timestamp-based request ID.

## Security and Compatibility

- Wildcard tool scopes continue to exclude the consumer-supplied write tools.
- Target denials do not disclose whether the target exists.
- Malformed serialization becomes an MCP tool error, never a protocol-level
  failure or panic.
- Text bounds operate on UTF-8 character boundaries.
- An oversized JSON value is rejected rather than serialized partially.
- Junos can select raw-string formatting; PAN-OS can retain pretty-JSON
  formatting.
- Existing `mecmcp` crates do not gain a dependency on `mecmcp-server`.

## Consumer Migration

After publishing one shared release tag:

1. `rustpanosmcp` replaces its local caller, authorization, and result helpers.
2. `rustjunosmcp` replaces its local caller, tool-list filtering, audit-scope,
   authorization, and result helpers.
3. Both consumer tool-schema and authorization suites must remain unchanged.
4. Local helpers are deleted rather than retained as wrappers.

