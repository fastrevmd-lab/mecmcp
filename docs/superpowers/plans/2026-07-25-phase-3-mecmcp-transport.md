# Phase 3a — `mecmcp-transport` Implementation Plan

> **Scope note.** [`PLAN.md`](../../../PLAN.md) §Phase 3 covers
> `mecmcp-transport` **and** `mecmcp-runtime`. At ~4,000 lines the transport
> half is a plan on its own, so Phase 3 is split: this is **3a**, and
> `mecmcp-runtime` (CLI skeleton, signals, graceful shutdown) is **3b** in its
> own plan. Read the handoff at the end before assuming this plan closes
> Phase 3 — it does not.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One streamable-HTTP hardening layer — host/Origin validation, bearer
middleware, rate limits, concurrency and session caps, overload responses,
metrics, TLS loading — consumed by both vendor servers, with every
consumer-owned choice passed in rather than baked in.

**Architecture:** Extract `rust-junosmcp-core/src/limits/` (3,835 lines) as the
base, because it is the only hardened implementation. Fold in the two things
`rustpanosmcp` does better: its TLS key loader and its middleware-layer scope
preflight. Every vendor string — metric names, target argument keys, realm,
server label — becomes a constructor parameter.

**Tech Stack:** axum, tower, rmcp streamable-HTTP, rustls (`ring`), metrics +
metrics-exporter-prometheus, tokio.

---

## Global Constraints

Inherited from [`PLAN.md`](../../../PLAN.md). Repeated here because a task
implementer sees only their task:

- **Edition 2024, MSRV 1.88.**
- **Workspace lints:** `missing_docs = "warn"`, `unsafe_code = "forbid"`,
  `clippy::all = "warn"` (priority -1), `dbg_macro = "deny"`, `todo = "deny"`,
  `unwrap_used = "warn"`.
- **`unsafe_code` stays at `deny` for this plan.** Raising it to `forbid` is a
  Phase 3b criterion — the two remaining `#[allow]`s guard `libc::kill(SIGHUP)`
  calls that belong to `mecmcp-runtime`. See the handoff at the end.
- **No breaking change to on-disk `tokens.json` or `devices.json`.**
- **No breaking change to the MCP tool surface** of either server.
- **The deployed systemd override on LXC 609 must keep working unchanged:**
  `0.0.0.0:30031`, `--allow-insecure-bind`, `--allowed-host <lan-ip>`, no
  `--inventory-readonly`.
- **LXC 608 terminates TLS itself** with `--tls-cert`/`--tls-key`, and its unit
  file carries those paths directly rather than in a drop-in. Nothing in this
  phase may change TLS behaviour or the CLI flags that configure it.
- **Licence:** MIT. **Naming:** `mecmcp-` crate prefix.

### The rule that governs every decision below

**Anything that belongs to the consuming server must be a parameter, not baked
into the shared crate.** This phase is where that rule is most load-bearing: the
audit crate already shipped a defect where a hardcoded metric name silently
renamed a consumer's public Prometheus series, and the transport layer holds
*four* more such names plus a hardcoded device vocabulary.

---

## What each repo actually has

Measured, not assumed — from a read of both trees on 2026-07-25.

| Concern | rustjunosmcp | rustpanosmcp |
|---|---|---|
| Rate limiting | token bucket, ns precision, per-token (434 ln) | **fixed window**, 60s, per-IP *and* per-token |
| Concurrency caps | global + per-token + per-device (1,144 ln) | **absent** |
| Session caps + reaper | `SessionTracker`, `LimitedSessionManager` (1,453 ln) | **absent** |
| Prometheus metrics | 4 metrics, `/metrics` route (229 ln) | **absent** — `tracing::info!` only |
| Overload responses | 503/429 + `Retry-After`, typed limit kinds (141 ln) | inline 401/403/413 |
| Body limit | via `LimitsConfig` | `to_bytes(body, limit)`, 1 MiB |
| Host/Origin | rmcp `StreamableHttpServerConfig` | same, plus auto-generated loopback origins |
| Scope preflight | **absent** — deferred to handler | **present** at middleware layer |
| TLS key loading | 89-line plain PEM loader | **hardened**: `O_NOFOLLOW`, mode ≤0600, owner check, size caps, `Zeroizing` |

The extraction is genuinely bidirectional. Junos supplies the hardening;
PAN-OS supplies the TLS loader and the preflight.

---

## Decisions

**D1 — Rate limiting: token bucket wins, and PAN-OS's behaviour changes.**
The two algorithms are not reconcilable by configuration; they differ in
observable behaviour at the boundary. A fixed window admits up to 2× the
nominal rate across a window edge, which is exactly the burst a limiter exists
to prevent. The token bucket is also the one already carrying per-token
accounting in production. PAN-OS moves to it. **This is a behaviour change on a
deployed server** and must be called out in that repo's CHANGELOG, not slipped
in — a client that currently survives a burst at a window boundary may start
seeing 429.

**D2 — TLS loader comes from PAN-OS, not Junos.** It is strictly stronger:
`O_NOFOLLOW` defeats a symlink swap, the mode and owner checks refuse a
world-readable key, and `Zeroizing` clears the key bytes. Junos gains all of
this. Note the consequence: **a Junos deployment whose key file is looser than
0600 will stop starting.** That is the correct outcome, but it is an upgrade
note, and the error must name the file, its mode, and the remedy.

**D3 — Scope preflight is optional and takes a callback.** PAN-OS extracts
`params.arguments.device`; Junos has no equivalent and defers to the handler.
Baking either in would force the other. The shared crate takes an
`Option<Arc<dyn ScopePreflight>>`; passing `None` reproduces Junos's behaviour
exactly.

**D4 — The crypto provider is never selected by the shared crate.** Both repos
pin `ring`, and PAN-OS already uses `*-no-provider` features on `axum-server`
and `reqwest` precisely to avoid a second provider being linked. `mecmcp-transport`
sets `default-features = false` on every rustls-adjacent dependency and selects
no provider. This is not a style preference: a default-featured dependency
pulled `aws-lc-rs` into this workspace once already and broke TLS.

**D5 — Vendor vocabulary is a parameter, everywhere.** Concretely:

| Baked in today | Becomes |
|---|---|
| `ROUTER_KEYS = ["router", "router_name", "routers", "router_names"]` (`router.rs:10`) | `target_keys: &[&str]` — PAN-OS passes `["device", "devices"]` |
| `junosmcp_active_sessions`, `junosmcp_limit_hits_total`, `junosmcp_tool_duration_seconds`, `junosmcp_sessions_reaped_total` (`prometheus.rs:11-14`) | a required `metric_prefix` constructor argument |
| `PrometheusRuntime::install("junos")` (`http_transport.rs:65`) | already a parameter; plumb from config |
| `Bearer realm="rust-panosmcp"` (`http_transport.rs:335,347`) | `realm` parameter |
| `"router_concurrency"` limit kind (`overload.rs:32`) | `"target_concurrency"`, with the old string kept as a documented alias so existing alert rules keep firing |

**D6 — `max_inflight_requests_per_router` keeps its name in `LimitsConfig`.**
Renaming it to `_per_device` would break the deployed config on 609. It gets a
serde alias for the new spelling and documentation saying it means "per target
device"; the rename is not worth an outage.

---

## File Structure

New crate `crates/mecmcp-transport/`:

| File | Responsibility |
|---|---|
| `config.rs` | `LimitsConfig` — capacities and timeouts, no vendor strings |
| `identity.rs` | `TransportIdentity` — metric prefix, server label, realm, target keys. The parameter object that D5 hangs on |
| `rate_limit.rs` | token-bucket limiter, per-token and per-IP |
| `concurrency.rs` | global / per-token / per-target in-flight caps |
| `target.rs` | `TargetLimiter`, `extract_targets(body, keys)` — was `router.rs` |
| `session.rs` | `SessionTracker`, `LimitedSessionManager`, reaper |
| `metrics.rs` | `PrometheusRuntime`, metric names derived from the prefix |
| `overload.rs` | 503/429 responses, typed limit kinds |
| `preflight.rs` | `ScopePreflight` trait, `None` = disabled |
| `tls.rs` | hardened key/cert loader, ported from PAN-OS |
| `lib.rs` | re-exports, `build_router`, middleware assembly |

---

## Task sequence

Each task ends green and independently reviewable.

- **Task 1** — Scaffold the crate; port `config.rs` and `overload.rs` (the two
  with no vendor coupling). Introduce `TransportIdentity`. Add the
  `"router_concurrency"` → `"target_concurrency"` alias with a test asserting
  *both* strings appear in the documented set.
- **Task 2** — Port `metrics.rs` with `metric_prefix` required. Test: two
  runtimes with different prefixes emit disjoint metric names, and neither
  emits a `junosmcp_`-prefixed series unless asked. This is the regression test
  for the defect that shipped in `mecmcp-audit`.
- **Task 3** — Port `target.rs` with `target_keys` as a parameter. Test with
  the Junos key set and the PAN-OS key set over the same request body, and
  assert each extracts only its own.
- **Task 4** — Port `rate_limit.rs` (token bucket), adding the per-IP dimension
  PAN-OS needs. Property test: sustained rate never exceeds the configured
  ceiling across a window boundary — the fixed-window bug D1 describes.
- **Task 5** — Port `concurrency.rs` and `session.rs`. Largest task; no
  interface changes beyond the `target_keys` threading from Task 3.
- **Task 6** — Port PAN-OS's hardened `tls.rs`. Tests: refuse a key at 0644,
  refuse a symlink, accept 0600. Assert the error message names the file, the
  mode, and the remedy.
- **Task 7** — `preflight.rs`. `None` must be byte-identical in behaviour to
  today's Junos path.
- **Task 8** — Wire `rustjunosmcp`. Exit: 924 tests pass, `/metrics` still
  exposes `junosmcp_*` names unchanged, deployed override still valid.
- **Task 9** — Wire `rustpanosmcp`. Exit: 62 tests pass, TLS still terminates,
  scope preflight still returns 403 `insufficient_scope`, CHANGELOG documents
  the D1 rate-limit behaviour change.
Task 10 — raising `unsafe_code` to `forbid` — **is not in this plan.** See the
handoff below.

---

## Handoff to Phase 3b (`mecmcp-runtime`)

Phase 0 left `unsafe_code = "deny"` in `rustjunosmcp` rather than `forbid`,
with two `#[allow]`s naming Phase 3 as the phase that removes them. Neither is
reachable from this plan:

| Site | What it is |
|---|---|
| `rust-junosmcp/src/token_cmd.rs:160` | `libc::kill(pid, SIGHUP)` to trigger hot reload |
| `rust-junosmcp/tests/http_reload.rs:4` | the same call, in the SIGHUP smoke test |

Both are **signal handling**, which `PLAN.md`'s crate map assigns to
`mecmcp-runtime`, not `mecmcp-transport`. The source comments say so directly:
*"moves to `mecmcp-runtime` in mecmcp Phase 3, where the signal is sent safely
through `rustix`."*

So the `forbid` bump is a **3b exit criterion**, gated on `mecmcp-runtime`
landing. Phase 3 as a whole is not complete until 3b raises it and both
`#[allow]`s are gone. Do not raise the lint from this plan — it will not
compile, because the unsafe calls are still there.

---

## Exit criteria

- Both servers build, and their full suites pass at their current baselines
  (junos 924, panos 62) with `EXIT=0` — verified by exit status, never by
  summing per-target `test result:` lines.
- `rustjunosmcp` `/metrics` exposes exactly the four `junosmcp_*` series it
  does today. A dashboard querying `junosmcp_tool_duration_seconds_bucket`
  must not need editing.
- `rustpanosmcp` still terminates TLS and still enforces scope preflight.
- `cargo tree -e normal` from each consumer shows exactly one rustls crypto
  provider, and it is `ring`.
- Neither deployed unit file needs an edit.
