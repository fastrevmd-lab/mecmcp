# Shared HTTP Server Composition Implementation Plan

**Goal:** Remove the remaining vendor-neutral HTTP server implementations from
Junos and PAN-OS and make the resulting foundation directly reusable by SDC.

**Architecture:** `mecmcp-auth` owns bearer syntax. `mecmcp-transport` owns the
generic authenticated request boundary, configured scope preflight, rmcp router
composition, and listener bootstrap. Consumers provide closures and parameter
objects.

**Verification discipline:** Each API is introduced by a focused test observed
failing for the intended missing behavior, then implemented. Every repository
must pass format, strict clippy, locked workspace tests, dependency/security
checks, and its documented offline release gates before integration.

## Task 1: Shared bearer syntax

- Add failing public API tests for strict and trimmed bearer syntax, duplicate
  credentials being handled at the HTTP boundary, empty credentials, and
  non-Bearer schemes.
- Implement `BearerSyntax`, `BearerHeaderError`, and `parse_bearer_header` in
  `mecmcp-auth`.
- Delete PAN-OS's parser implementation and re-export the shared API.

## Task 2: Grant-neutral transport caller identity

- Add failing limiter tests using a grant-bearing caller plus
  `AuthenticatedToken`, proving per-token rate, concurrency, and session caps
  do not depend on `CallerCtx<NoGrant>`.
- Add `AuthenticatedToken` and migrate limiter lookups, retaining a temporary
  fallback to the old extension for source compatibility.

## Task 3: Configured tool/target preflight

- Change `ScopePreflight` to receive a grant-neutral scope view.
- Add failing tests for Junos scalar/array target fields, PAN-OS scalar target
  fields, batches, write tools, malformed arguments, malformed target values,
  empty arrays, and absent arguments.
- Implement `ToolScopePreflight`, `TargetField`, `TargetValueShape`, and the
  malformed-arguments policy.

## Task 4: Shared bearer boundary

- Add failing router tests for missing, malformed, invalid, and valid tokens;
  grant-bearing caller propagation; preflight denial; oversized requests; and
  both compatibility response profiles.
- Implement generic `BearerAuthenticator<G>` and authenticated middleware.
- Ensure the request body is buffered once and replayed unchanged.

## Task 5: Router and listener composition

- Add failing tests for Host/Origin policy, disabled Host checks, middleware
  ordering, metrics mounting, and validation errors.
- Implement `HttpTransportConfig<G>`,
  `build_streamable_http_router`, and `serve_router`.
- Add `axum-server` without selecting a rustls crypto provider.

## Task 6: Adopt in PAN-OS

- Pin all mecmcp crates to the new immutable revision.
- Replace the local bearer boundary, preflight parser, router assembly, and
  listener with shared configuration.
- Delete the local implementations while preserving its public wrapper used by
  integration tests.
- Run the full PAN-OS release and security gates, integrate locally, and clean
  the issue worktree.

## Task 7: Adopt in Junos/SRX

- Pin all mecmcp crates to the same immutable revision.
- Replace `rust-junosmcp-auth::tower`, local preflight parsing, HTTP config,
  router assembly, and listener with shared configuration.
- Re-export only compatibility names that still have downstream callers;
  otherwise delete the local implementations.
- Run all offline Junos gates. Do not run real-device ignored tests without the
  explicit confirmation required by that repository.
- Integrate locally and clean the issue worktree.

## Task 8: Shared runtime validation completion

- Extract the strict common serve-validation data model from PAN-OS into
  `mecmcp-runtime`: numeric bind host, exact auth mode, absolute sensitive
  paths, Host/Origin syntax, off-loopback policy, body bounds, and rate bounds.
- Make both consumers call it and retain only genuinely vendor-specific rules.
- Add a reusable reload-handler adapter where the callback semantics match.

## Task 9: Final verification

- Run workspace format, strict clippy, tests, cargo-deny, Trivy, and dependency
  tree inspection in `mecmcp`.
- Confirm transport/runtime contain no vendor strings except examples and
  compatibility documentation.
- Confirm downstream source no longer defines bearer, preflight, router
  composition, or listener implementations.
- Publish an immutable dependent branch/PR so consumer revisions are
  fetchable.
