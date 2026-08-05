<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">mecmcp</h1>

<p align="center"><strong>Vendor-neutral Rust foundation for enterprise network-security MCP servers</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

---

`mecmcp` is the shared crate family underneath mechub's per-vendor MCP servers.
Authentication, attribution, audit, transport hardening, policy, inventory,
change control — everything that is *not* NETCONF or XML-API — lives here once
and is consumed by every vendor server.

Today two servers independently reimplement all of it:

| | [rustjunosmcp](https://github.com/fastrevmd-lab/rustjunosmcp) | [rustpanosmcp](https://github.com/fastrevmd-lab/rustpanosmcp) |
|---|---|---|
| Vendor | Juniper Junos / SRX | Palo Alto PAN-OS |
| Device transport | NETCONF over SSH (`rustnetconf`) | HTTPS XML-API (`reqwest`) |
| Shared-by-accident | token auth, scopes, TLS, CLI, HTTP transport, inventory | same, written separately |

The duplication is not the main cost. The main cost is that **each repo is the
reference implementation for something the other lacks** — rustjunosmcp has the
runtime hardening (concurrency, rate limits, session caps, audit redaction),
rustpanosmcp has the change-control state machine (plan → digest → approve →
apply) and the modern crate hygiene. Neither benefits from the other.

`mecmcp` makes both the union instead of the intersection.

## Status

**0.3.8 — eleven crates, extraction complete.** Both the original extraction and
the cloud-foundations programme (#90) have landed: `mecmcp-secret`,
`mecmcp-http`, `mecmcp-job` and `mecmcp-openapi` are new, and `mecmcp-changeset`
gained multi-target change sets.

Not published to crates.io. Consumers depend on this repository directly and pin
an exact version.

### Upgrading to 0.5.0

**Breaking for consumers only because of the rmcp major: `rmcp 2` → `rmcp 3.1.1`.**
Nothing in this workspace's own API changed shape. A consumer must bump its own
`rmcp` dependency in the same commit — cargo will not unify a 2.x and a 3.x rmcp,
so a partial upgrade is a build failure rather than a subtle one.

**What the rmcp major actually is.** rmcp 3.x implements the 2026-07-28 MCP
revision, but it is not the forced cutover the spec summaries suggest. The
`initialize` handshake and `Mcp-Session-Id` are *not* removed: rmcp runs both
protocols side by side and `StreamableHttpServerConfig::legacy_session_mode`
defaults to `true`, which is the pre-2026-07-28 flow. Statelessness is opt-in,
per request, keyed on the version the client declares.

Consumer-visible changes:

| Change | Action |
|---|---|
| `StreamableHttpServerConfig::stateful_mode` renamed to `legacy_session_mode` | Rename the field; same default (`true`), same behaviour |
| `SessionManager` gained `event_store()` | Defaulted, so nothing breaks — but see below if you wrap a manager |
| `Mcp-Method` / `Mcp-Name` header validation | Now enforced **by the SDK** for clients declaring `>= 2026-07-28`. No middleware needed |
| **`StreamableHttpServerConfig::max_request_body_bytes` is new, and defaults to 4 MiB** | **Stop calling `StreamableHttpServerConfig::default()`. Call `mecmcp_transport::streamable_http_server_config(&limits)` instead.** |

Everything else is source-compatible. MSRV stays 1.88 and the edition stays 2024,
both of which this workspace already required.

**The body limit is the one that bites silently.** rmcp 3 enforces its own 4 MiB
request-body cap *inside* the service, after this crate's `apply_body_limit`
layer has already accepted the request. `LimitsConfig::max_request_body_bytes`
defaults to 10 MiB here, so on a plain `default()` every request between 4 and
10 MiB starts failing with a 413 from a limit the operator never set and cannot
see in their own config. `streamable_http_server_config` derives it from
`LimitsConfig` and maps `0` (unlimited) to `usize::MAX`.

**Session capacity is now protocol-aware.** rmcp computes
`use_session = legacy_session_mode && is_legacy_request(..)`, so a client
declaring `2026-07-28` is routed statelessly *even though `legacy_session_mode`
is `true`* — and a stateless POST carries no `Mcp-Session-Id` because there is no
session. The old classifier (`POST` without that header) would therefore have
charged every ordinary `tools/call` from a modern client against
`--max-sessions` and `--max-sessions-per-token`, handing out 503s after
`max_sessions` calls. `is_session_creating` now also requires the absence of an
`MCP-Protocol-Version` at or above `2026-07-28`. No consumer action needed.

**One security note on the new header validation.** rmcp only enforces
`Mcp-Method`/`Mcp-Name` when the request declares protocol `>= 2026-07-28`; a
client declaring an older version simply omits them. So the headers are an
optimisation, not a control. **The scope preflight remains the authorization
boundary** — do not move an authorization decision up to a header a client can
decline to send by claiming to be old.

### Fixed in 0.5.0: `LimitedSessionManager` answered for the manager it wraps

`LimitedSessionManager` overrode 8 of the 10 `SessionManager` methods and
inherited the defaults for `restore_session` (`NotSupported`) and, as of rmcp 3,
`event_store` (`None`). Because it is a *wrapper*, inheriting those defaults meant
reporting "restore unsupported, no event store" **on behalf of the inner
manager**, discarding whatever that manager actually provided.

Latent until now — both current consumers wrap `LocalSessionManager`, which
supplies neither — and it would have stayed silent when it did bite: the symptom
is SSE resumability quietly not working, not a compile error or a log line.

`event_store` is now forwarded. `restore_session` is now an **explicit refusal**
rather than an inherited one — same answer, stated on purpose.

That asymmetry is deliberate. Forwarding `event_store` touches no limit and
undoes a real rmcp 3 regression. Forwarding `restore_session` looked like the
same two-line change and is not: every limit this wrapper enforces is applied on
the *create* path, and a restore arrives by a different route.

- **Per-token cap.** The concurrency middleware classifies a request as
  session-creating with `POST && !contains("mcp-session-id")`. A restore
  necessarily carries that header, so no token slot is reserved. A restored
  session would raise only the global count — letting one token restore its old
  sessions *and* create a full `max_sessions_per_token` on top.
- **Idle and lifetime timeouts.** The reaper closes the inner in-memory session
  but cannot delete an entry from an rmcp `session_store` it does not own. A
  reaped id could be restored with fresh timestamps, repeatedly, which does not
  weaken the timeouts so much as remove them.
- **Overload response.** A cap rejection on the restore path would surface as a
  generic 500 rather than the stable 503 + `Retry-After`.

Refusing costs nothing today — `LocalSessionManager`, which both consumers wrap,
returns `NotSupported` anyway. Doing it properly needs reaper tombstoning, a
token reservation on the restore path, generation-safe registration and
cancellation-safe cleanup; that is tracked separately. Until then an honest
refusal beats a cap that quietly does not hold.

### Upgrading to 0.4.0

**Additive: one new crate, `mecmcp-server`, and nothing else changed.** The minor
bump is because a new crate is new API, not because anything broke — a consumer
that does not want it can stay pinned at `v0.3.9` indefinitely.

`mecmcp-server` is #199's milestone 1: the vendor-neutral helpers every MCP tool
handler in this family needs, which three servers were each carrying their own
copy of.

| Group | Items |
|---|---|
| Rendering a result | `tool_result`, `tool_error`, `ResultFormat`, `ResultLimits`, `BoundedText`, `bounded_text` |
| Authorizing a call | `authorize_call`, `authorize_tool`, `authorize_target`, `AuthorizationError`, `caller_from_extensions`, `filter_tools_for_scope`, `audit_scope` |

Two behaviours to know before adopting, both documented at the call site:

- **`tool_result` refuses an oversized success rather than truncating it.** A
  caller handed a shortened value cannot tell it from a complete one.
  `bounded_text` is for the places that genuinely want a prefix.
- **A `None` caller is authorized for everything**, because that is the stdio
  path, which has no bearer token. On an authenticated path a handler must pass
  the caller it recovered — passing `None` on a lookup miss authorizes the call.

This lets `rustsdcmcp` delete `compat/server.rs` and `rustsdcmcp-core/src/compat.rs`,
332 of its 1,162 compat lines. The remaining groups — bearer boundary, HTTP
transport assembly, preflight — are tracked in #199.

### Upgrading to 0.3.9

A correctness release: every finding from the codex review of 0.3.8's unreviewed
window, nine P1 and twelve P2. Four changes need a consumer's attention.

| Change | What a consumer must do |
|---|---|
| `TokenStoreFile::set_scopes` gained a `grant: Option<G>` parameter | pass `None` to leave the stored grant alone — a `NoGrant` consumer always wants `None`. This is a plain arity change, so the compiler will find every call site |
| `TargetError` gained `MissingPrimary` | nothing unless you match the enum exhaustively; a target set must now contain the record's own `device` |
| `try_parse_from`, `parse_with_provenance` and `ParsedCli` are generic over the consumer's parser | nothing if you use `parse_for`; `ParsedCli` defaults to `Cli`. **Servers with flags of their own should now flatten `Cli` into their own struct and pass that** — the previous API could not parse a vendor flag at all |
| `ChangeSetRecord::validate_target_set` and `validate_preview` are enforced at insert and load | a preview's `digest` must be built with the new `preview_digest`; a hand-written value is refused |

Behaviour changes worth knowing about, none of which need code:

- A **multi-target change set now survives a restart.** It was written with the
  five-tuple digest and re-verified with the four-tuple, so every one was
  rejected on the next load. Single-target digests are unchanged, byte for byte.
- `max_targets_per_set` and `max_preview_bytes` are enforced. They were read by
  nothing before, so a deployment relying on the old non-enforcement would now
  see refusals.
- `set-scopes` asks for `--yes` in two more cases: any grant replacement, and a
  tool scope moving from `*` to an allowlist. Both are escalations — the tool
  wildcard deliberately withholds the server's write tools, so naming one grants
  what the wildcard withheld.
- An expiry sweep no longer retires a change set whose apply is in flight, and it
  is persisted even when the insert that triggered it is refused.
- `init_tracing` no longer drops the rotation handle when the consumer already
  installed a `log` logger.

On-disk state is unchanged from 0.3.8 in both directions.

### Upgrading to 0.3.8

This release is **breaking at the source level**, and needs a deliberate upgrade
rather than a version-string change:

| Change | What a consumer must do |
|---|---|
| `OperationLimits` gained public fields | struct-literal construction needs `..OperationLimits::default()` |
| `ChangeSetRecord` gained required `targets` and `preview` fields | it has no `Default`, so `..Default::default()` does not compile — add `targets: Vec::new(), preview: None` to every literal |
| `mecmcp-secret` is now Unix-only | nothing on Linux; the crate refuses to compile elsewhere by design |
| `mecmcp-auth` and `mecmcp-inventory` read their files through the shared hardened loader | `tokens.json` and `devices.json` **must** be mode 0600, a regular file, and owned by the service user — inventory had no such check before |

On-disk state is compatible in both directions **only while no change set holds
targets or a preview**. Either one gates the file to version 2, and 0.3.7's
`ChangeSetRecord` is `deny_unknown_fields`, so it rejects the whole file — the
absence of multi-target sets alone is not enough, because `preview` does it too.
A 0.3.8 deployment using neither still writes version-1 files that the previous
binary reads.

**Verify the deployed files before rolling out.** A `tokens.json` or
`devices.json` that has drifted to 0644 loaded fine under 0.3.7 and will be
refused at startup by 0.3.8.

## Documents

| Document | What it is |
|---|---|
| [`ANALYSIS.md`](ANALYSIS.md) | Side-by-side teardown of both repos — what is duplicated, what is asymmetric, what stays vendor-specific |
| [`PLAN.md`](PLAN.md) | Program-level extraction plan: crate map, phase sequencing, decisions, exit criteria (historical — the plan is delivered) |
| [`ROADMAP.md`](ROADMAP.md) | What "enterprise grade" means at 150 engineers and 4,000 multi-vendor firewalls |
| [`docs/PACKAGING.md`](docs/PACKAGING.md) | How a mechub MCP server is delivered and installed — container base, LXC, README requirements |
| [`docs/superpowers/plans/`](docs/superpowers/plans/) | Executable per-phase implementation plans |

## The crate family

| Crate | Responsibility | Extracted from |
|---|---|---|
| `mecmcp-auth` | Token mint/digest/verify, `tokens.json` load + hot-reload, scopes, grants, caller context | both (union) |
| `mecmcp-audit` | Attribution, audit events, redaction, pluggable sinks | rustjunosmcp |
| `mecmcp-transport` | Streamable-HTTP: host/Origin checks, bearer middleware, rate limits, concurrency + session caps, metrics | rustjunosmcp `limits/` + rustpanosmcp scope preflight |
| `mecmcp-runtime` | CLI skeleton, TLS bootstrap, signals, graceful shutdown | both (union) |
| `mecmcp-policy` | Compiled allow/deny rule engine over command and config subjects | rustjunosmcp `policy.rs` |
| `mecmcp-inventory` | Device registry as a trait — file today, database and NetBox later | both (generalized) |
| `mecmcp-device` | Connection lease/pool, per-device concurrency, cancellation, timeouts | rustjunosmcp |
| `mecmcp-changeset` | Plan → digest → approve → apply → verify, two-principal enforcement, indeterminate recovery | rustpanosmcp `mutation.rs` |
| `mecmcp-secret` | Outbound credential type (zeroizing, unprintable) and hardened env/file loader | new — see #90 |
| `mecmcp-job` | Cancellable job polling: immediate first probe, capped backoff, whole-operation deadline | new — see #90 |
| `mecmcp-http` | Outbound HTTP client: HTTPS-only, no redirects, no proxy, bounded concurrency, whole-request deadline, sensitive headers | new — see #90 |
| `mecmcp-openapi` | Whole-segment path expansion and bounded pagination — rejects, never clamps | new — see #90 |
| `mecmcp-intent` | Vendor-neutral policy/object model with per-vendor rendering | new — see ROADMAP |

### Remote listeners fail closed

A Streamable HTTP listener bound off-loopback must supply `--allowed-host`, and
an allowlist of blank strings does not count. An empty Host allowlist is not
"accept whatever the operator forgot to configure" — it is a DNS-rebinding and
Host-confusion surface.

`--allowed-origin` is required only by consumers whose transport actually
applies browser-Origin policy, via `validate_with_origin_policy`. Requiring it
everywhere refused a deployed server whose transport applies only `allowed_host`
— and any dummy value would have satisfied it while enabling nothing. That is
the failure `docs/PACKAGING.md` names: a flag that is present but ignored is
worse than one that is absent, because the operator cannot tell.

Loopback binds are exempt. A listener on `127.0.0.1` or `::1` is already bounded
by the host, and requiring the flags there would break every stdio and
local-HTTP deployment for nothing.

Vendor servers keep their protocol adapters, XML parsers, and vendor workflows.
For `mecmcp-http` specifically, that means endpoint catalogs, header names, payload
schemas, terminal job states, and retry policy stay in the product repository —
the shared crate owns only the transport posture.

## License

Licensed under [MIT](LICENSE).
