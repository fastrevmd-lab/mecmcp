# Architecture

How `mecmcp` is put together and how a vendor server sits on top of it.

`mecmcp` is a **library workspace, not a server.** It ships no binary and opens
no socket. Everything in it is consumed by the per-vendor MCP servers, which are
the things that actually run.

The organising rule: *everything that is not NETCONF or a vendor's XML/REST API
lives here once.* Authentication, attribution, audit, transport hardening,
policy, inventory, change control. A vendor server is then only the part that is
genuinely vendor-specific — which is much smaller than it looks before the
extraction.

---

## 1. The crates

Fourteen crates, versioned together. The workspace version is the release unit;
a consumer pins one tag and gets a coherent set.

### Foundation

| Crate | What it owns |
|---|---|
| `mecmcp-secret` | Zeroizing outbound-credential type and a hardened loader that rejects symlinks, oversized values, and group/world-readable files. Unix-only, deliberately. |
| `mecmcp-auth` | Bearer tokens, digests, `ScopeSet`, `Grant`, `CallerCtx`. Free of vendor concepts — it knows names and opaque subjects, not what a subject *means*. |
| `mecmcp-audit` | `Attribution`, `Principal`, `AuditOutcome`, redaction, sinks. Also free of vendor concepts: it knows principals, not devices. |

### Boundary

| Crate | What it owns |
|---|---|
| `mecmcp-transport` | The whole protected `/mcp` endpoint: `build_streamable_http_router`, `serve_router`, `HostOriginPolicy`, bearer middleware, rate and concurrency limits, session caps, TLS, `ToolScopePreflight`. Also `test_client::McpClient` for integration tests. |
| `mecmcp-server` | The handler side: `authorize_call`, `authorize_tool`, `authorize_target`, `caller_from_extensions`, `filter_tools_for_scope`, and bounded result rendering (`tool_result`, `bounded_text`). |

### Domain

| Crate | What it owns |
|---|---|
| `mecmcp-inventory` | The `Inventory<D, P>` trait and a file-backed implementation that reads three on-disk schemas without forcing a migration. |
| `mecmcp-policy` | Generic glob rule engine for blocklist guardrails, generic over the action type so Junos and PAN-OS share it. Specificity-scored, with `Defaults` vs `Device` as the tiebreak. |
| `mecmcp-changeset` | Fingerprint-bound two-person change control: stage → digest → approve → apply, with indeterminate-outcome recovery and atomic persistence. |
| `mecmcp-device` | Cross-process device leases over `flock`, plus cancellation. |

### Outbound and process

| Crate | What it owns |
|---|---|
| `mecmcp-http` | Hardened outbound client: HTTPS-only, no redirects, no proxy autodiscovery, bounded concurrency, whole-request deadlines. |
| `mecmcp-scp` | SCP1 over SSH exec channels, for devices like Junos that disable SFTP. |
| `mecmcp-job` | Polling for async management-plane jobs: immediate first probe, capped backoff, cooperative cancellation, whole-operation deadline. |
| `mecmcp-openapi` | Bounded pagination and URL path expansion that rejects rather than repairs. |
| `mecmcp-runtime` | CLI parsing and provenance, validation, TLS bootstrap, signals, graceful shutdown, token subcommands. |

### Dependency shape

```
mecmcp-secret ─┬─> mecmcp-auth ─┬─> mecmcp-audit ──> mecmcp-transport ──> mecmcp-server
               │                └────────────────────────────────────────>┘
               ├─> mecmcp-inventory
               ├─> mecmcp-http
               ├─> mecmcp-scp
               └─> mecmcp-changeset (also depends on mecmcp-audit)

mecmcp-device ──> mecmcp-job
mecmcp-policy, mecmcp-openapi, mecmcp-runtime  — near-standalone
```

`mecmcp-secret` is the floor and `mecmcp-server` is the ceiling. Nothing in the
tree knows a vendor's names, paths, headers, or status codes.

---

## 2. The request lifecycle

This is the architecture. Everything else is support for it.

A `tools/call` arriving over streamable HTTP passes through, in this order:

```
TLS ─> Host/Origin ─> IP rate limit ─> auth ─> token rate ─> token concurrency
    ─> body limit ─> preflight ─> target concurrency ─> transport audit ─> handler
```

The inner segment is not assembled by hand in each consumer. `apply_bearer_boundary`
in `crates/mecmcp-transport/src/auth.rs` installs it and **enforces the order**:

```text
auth → token_rate → token_concurrency → body_limit → preflight → target_concurrency → handler
```

Each position is load-bearing, and the rationale is recorded next to the function:

- **Auth is outermost** so an anonymous request cannot charge a token's budget.
- **Token rate and concurrency are non-buffering**, so they decide before the
  body is read.
- **The body limit precedes anything that buffers**, so preflight and target
  concurrency cannot be made to allocate without bound.
- **Preflight runs after token accounting**, so an out-of-scope request still
  consumes budget rather than being a free retry channel.
- **Target concurrency is innermost**, so an unauthorized request never acquires
  a per-device permit.

### Preflight

`ToolScopePreflight` (`crates/mecmcp-transport/src/preflight.rs`) parses the
JSON-RPC body, extracts the tool name and the configured target fields, and
denies with 403 before dispatch. It is generic over the argument shape because
the four consumers differ only in field naming — Junos uses `router`/`routers`,
PAN-OS `device`, SDC `tenant`, Mist an org/site subject. Each configures
`TargetField`s rather than writing its own preflight.

### Audit by construction

Since 0.8.1 the bearer boundary emits a transport audit event for **every**
`tools/call` before dispatch. The point is the quantifier: a call is audited
because it crossed the transport, not because a handler author remembered to log
it.

The handler still emits its own, richer event — action, resolved device targets,
outcome — correlated by request id. The transport cannot know any of those, so
the two events are complementary rather than redundant.

One subtlety worth carrying forward: the tool name is read from an
attacker-controlled body, and it is parsed *before* preflight has decided whether
the caller may call anything at all. It is interned into a table capped at 256
entries of ≤128 bytes, restricted to `[A-Za-z0-9_-]`; anything else records as
`unregistered`. An earlier revision interned every parsed name for process
lifetime on the reasoning that tool names are "a finite, small set" — true of the
registry, false of a request field, and both a memory-exhaustion and an
unbounded-cardinality path.

### Handler-side authorization

The transport's decision is not the last word. A handler recovers its caller with
`caller_from_extensions` and re-checks via `authorize_call`.

Three rules in `crates/mecmcp-server/src/authorize.rs` are easy to get wrong and
are therefore encoded rather than documented elsewhere:

1. **A `None` caller is the stdio path and is authorized.** So a handler must
   pass the caller it actually recovered, never `None` on a lookup miss.
   `caller_from_extensions` reads two levels deep — the MCP layer carries
   `http::request::Parts` in its own extensions, and the bearer middleware put
   the caller in *those*. Reading only the outer map finds nothing, and under
   this rule that would authorize every call.
2. **Tool scope is checked before target scope.** A token with no right to
   `apply_change_set` is told exactly that, rather than being told which targets
   it may not touch. The narrower failure leaks less.
3. **A wildcard tool scope permits everything except the server's registered
   write tools.** `authorize_tool` takes that registry as a parameter because
   only the server knows it — and passing an empty slice silently turns every
   wildcard token into a writer.

`authorize_target` deliberately does **no** inventory lookup. It answers "is this
name inside the caller's scope", which is a question about the token. Whether the
name exists is a question about the inventory. Merging them would make an
out-of-scope target indistinguishable from an unknown one, which tells an
unauthorized caller which device names are real.

### Results are bounded, and a limit is a refusal

`tool_result` returns an MCP **error** when a successful value exceeds its
limits. It does not send a shortened value: a caller handed a silently truncated
result cannot tell it from a complete one. `bounded_text` is the other half, for
places that genuinely want a prefix — a log line, a preview — and it says so in
its return type.

---

## 3. The consumers

Four servers sit on this foundation. They are at very different maturity, and
that difference matters more than the feature tables.

| | rustjunosmcp | rustpanosmcp | rustsdcmcp | rustmistmcp |
|---|---|---|---|---|
| Target | Juniper Junos / SRX **devices** | Palo Alto **PAN-OS** | Security Director **Cloud** | Juniper **Mist** cloud |
| Outbound transport | NETCONF over SSH + SCP1 | HTTPS XML-API | HTTPS REST | HTTPS REST |
| Credential to upstream | SSH key or password | API key | `x-api-key` or `x-oauth2-token` | `Authorization: Token …` |
| Version | 0.17.0 | 0.8.0 | 0.1.0 | 0.1.0 |
| Maturity | **production** | **production** | lab only | scaffold |
| Scope axes | device glob × tool | device × tool | tenant × tool | org/site UUID × operation × capability |
| mecmcp pin | `v0.7.3` | `v0.7.3` | `v0.8.0` | git rev (0.7.x) |

**rustjunosmcp** is the runtime-hardening reference — session pooling, device
leases, rate limits, audit redaction. Repo layout is flat: `rust-junosmcp`
(binary, MCP handler), `-core` (device manager, tools), `-auth`, `-srx-core`
(SRX workflows, behind the default `srx` feature).

**rustpanosmcp** is the change-control reference — the plan → digest → approve →
apply state machine that became `mecmcp-changeset`.

**rustsdcmcp** fronts the SASE management plane rather than a device, so one
action can touch a whole fleet; every mutation is therefore change-set gated. It
is lab-only pending replacement of its remaining compatibility shims with
upstream APIs shipped in one coherent release.

**rustmistmcp** carries an audited catalog of 1,059 Mist operations derived from
the upstream OpenAPI spec, classified by capability (ordinary read, privileged
read, create, update, delete, execute). Mutating tools are deliberately absent
until the change-set work lands. Treat it as a scaffold.

### Why the pins differ

A consumer upgrades on its own schedule, so the fleet runs a spread of `mecmcp`
versions at any time. That is expected. What is *not* optional is reading the
upgrade notes for the versions being skipped — the 0.7.0 → 0.7.2 sequence in
particular shipped a graceful-drain fix whose first two attempts were both
inert, and both passed CI.

---

## 4. Conventions a consumer is expected to follow

- **Vendor logic only.** If a thing could be written the same way for another
  vendor, it belongs in `mecmcp`, not in the server.
- **Configure, don't reimplement.** Preflight, transport assembly, token
  subcommands and shutdown are parameterised precisely so a consumer passes
  arguments instead of forking behaviour.
- **Reads are direct; writes go through the change set.** Stage, digest, approve
  as a *distinct* principal, apply — refusing if the target drifted since it was
  planned.
- **Mutating tools are named explicitly in a scope.** Never reachable by
  wildcard.
- **Secrets are files with enforced modes**, loaded through `mecmcp-secret`, and
  never round-tripped through configuration JSON.

Packaging and installed layout are specified separately in
[`PACKAGING.md`](PACKAGING.md). Operating the servers is in
[`ONBOARDING.md`](ONBOARDING.md). Where the family is going is in
[`../ROADMAP.md`](../ROADMAP.md).
