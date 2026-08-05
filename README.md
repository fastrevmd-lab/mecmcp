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
