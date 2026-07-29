# Shared HTTP Server Composition Design

## Goal

Finish the vendor-neutral Streamable HTTP extraction before adding another
consumer. `mecmcp` must own the HTTP bearer boundary, scope preflight parser,
rmcp router assembly, resource-limit layering, metrics mounting, and plain/TLS
listener bootstrap. Junos, PAN-OS, and SDC should supply configuration and
vendor services, not reimplement this stack.

## Findings

The first transport extraction moved the individual limiters into
`mecmcp-transport`, but left each consumer to compose them. That left three
shared implementations downstream:

1. bearer header parsing and token authentication;
2. JSON-RPC `tools/call` scope preflight parsing;
3. session-manager, middleware, metrics, rmcp service, and listener assembly.

The downstream implementations are not byte-for-byte identical. Their
differences are public compatibility choices and must be parameters:

- Junos accepts trimmed legacy bearer whitespace and returns its established
  RFC 6750 error bodies; PAN-OS uses strict bearer syntax and compact errors.
- Junos target arguments use scalar `router`/`router_name` and non-empty array
  `routers`/`router_names`; PAN-OS uses scalar `device`.
- Junos can explicitly disable Host checking; PAN-OS cannot.
- Host and Origin additions, metric identity, write-tool registry, body and
  concurrency limits remain consumer-owned values.

## Ownership

### `mecmcp-auth`

- Parse a bearer credential from a string without depending on an HTTP stack.
- Export the stable parse error and syntax policy.
- Existing consumer auth crates may re-export this API for source
  compatibility, but must not retain an implementation.

### `mecmcp-transport`

- Authenticate HTTP requests through a generic closure returning
  `CallerCtx<G>`.
- Insert the grant-bearing caller for handlers and a separate non-generic token
  identity for rate/concurrency/session accounting.
- Buffer once, enforce the configured cap, and run optional scope preflight.
- Provide a reusable preflight configured by write-tool registry and typed
  target fields.
- Build the rmcp router with the one correct middleware order:
  body limit → bearer/preflight → rate → concurrency → rmcp.
- Build Host/Origin policy, optional metrics, session limits, and plain/TLS
  listeners.

### Consumers

- Construct the authenticator closure from their atomically reloadable store.
- Choose bearer compatibility profile, target fields, write tools, identity,
  Host/Origin policy, and limits.
- Retain only vendor-specific runtime loading, reload behavior, CLI additions,
  and MCP service construction.

## Caller identity

`CallerCtx<G>` is generic because grants are vendor-specific. The current
transport limiters look up `CallerCtx<NoGrant>`, forcing PAN-OS to insert both
its real `CallerCtx<MutationGrant>` and a lossy `CallerCtx<NoGrant>`.

The shared boundary will instead insert:

- `CallerCtx<G>` for handler authorization and attribution;
- `AuthenticatedToken`, containing only the non-secret token name, for
  transport accounting.

Limiters will read `AuthenticatedToken`. During migration they also accept the
old `CallerCtx<NoGrant>` extension so existing embedders do not break.

## Preflight model

`ScopePreflight` receives a grant-neutral borrowed view of the caller scopes.
`ToolScopePreflight` parses single or batch JSON-RPC requests and checks:

- exact tool authorization using the consumer write-tool registry;
- configured target fields using either scalar-string or non-empty
  string-array shape;
- consumer-selected handling of a present non-object `arguments` value.

Invalid JSON and protocol shapes that do not identify a tool call remain for
rmcp to diagnose. Once a configured target field is present, an invalid value
follows the field's explicit malformed-value policy.

## Compatibility and safety

- Existing tool schemas, token files, token digests, grants, metrics names,
  listener flags, status codes, and tested error codes remain unchanged.
- No vendor name, target key, write tool, realm, or metric name is hardcoded in
  a shared implementation.
- The shared crate selects no rustls crypto provider.
- TLS files continue through the existing hardened loader.
- Real-device integration tests remain opt-in and are not part of this
  extraction.
