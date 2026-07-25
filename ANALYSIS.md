# Analysis — rustjunosmcp and rustpanosmcp

Teardown performed 2026-07-24 against `rustjunosmcp` 0.9.1 (commit `a485901`) and
`rustpanosmcp` 0.2.2. Purpose: identify what can be factored into vendor-neutral
Rust crates, and what must stay vendor-specific.

## 1. Both repos already agree on the architecture

Independently written, same shape:

```
<name>            binary: CLI, TLS, HTTP transport, MCP server wiring, token subcommands
<name>-core       device client, inventory, tool handlers, errors
<name>-auth       token mint/verify, tokens.json, scopes
<name>-audit      (rustjunosmcp only) audit events, redaction, sinks
<name>-srx-core   (rustjunosmcp only) SRX workflow crate behind a `srx` feature
```

This convergence is the strongest argument for extraction: there is no
architectural disagreement to reconcile, only two implementations of one design.

## 2. Size and posture

| | rustjunosmcp 0.9.1 | rustpanosmcp 0.2.2 |
|---|---|---|
| Total Rust LOC (src) | ~37,150 | ~8,290 |
| Workspace crates | 5 | 3 |
| Edition / MSRV | 2021 / not pinned | **2024 / 1.88** |
| Workspace lints | none | `missing_docs` warn, `unsafe_code` **forbid**, `clippy::all` warn, `dbg_macro`/`todo` deny, `unwrap_used` warn |
| Supply chain | `trivy.yaml` | `deny.toml`, `fuzz/`, `THREAT_MODEL.md`, `SECURITY.md` |
| Release profile | default | `lto="thin"`, `codegen-units=1`, `panic="abort"`, `strip="symbols"` |

rustpanosmcp is the younger repo but carries the stricter engineering posture.
Any shared crate family should adopt **its** baseline, not rustjunosmcp's.

Note the direct consequence: rustjunosmcp's `rust-junosmcp-auth/src/token.rs`
hand-rolls secret zeroing with `unsafe { std::ptr::write_volatile }`, which
would not compile under rustpanosmcp's `unsafe_code = "forbid"`. rustpanosmcp
uses the `zeroize` crate for the same job. That is a concrete, mechanical
improvement rustjunosmcp gets for free from extraction.

## 3. Straight duplication — same job, two implementations

| Concern | rustjunosmcp | rustpanosmcp | Verdict |
|---|---|---|---|
| Token mint / hash / constant-time verify | `-auth/src/token.rs` (`Secret`, `TokenHash`, `unsafe` zeroing, `rand::OsRng`) | `-auth/src/token.rs` (`TokenSecret`, `TokenDigest`, `zeroize`, `getrandom`) | Same design. Take rustpanosmcp's. |
| `tokens.json` load, perms, atomic write | `-auth/src/file.rs` (884 LOC, `cfg(unix)` EACCES diagnostics with uid + mode) | `-auth/src/file.rs` (539 LOC) | Take rustjunosmcp's diagnostics onto rustpanosmcp's structure. |
| `TokenStore` + `ScopeSet` | `-auth/src/store.rs` (230 LOC) | `-auth/src/store.rs` (414 LOC, bounded, validated) | Take rustpanosmcp's. |
| Bearer middleware | `-auth/src/tower.rs` | `-auth/src/bearer.rs` + `http_transport.rs` | Merge. |
| TLS bootstrap | `src/tls.rs` | `src/tls.rs` (162 LOC) | Near-identical. |
| CLI + arg validation | `src/cli.rs` (407) + `src/cli_validate.rs` (212) | `src/cli.rs` (271) + `src/cli_validate.rs` (315) | Merge. |
| `token add/revoke/rotate/list` | `src/token_cmd.rs` | `src/token_cmd.rs` (241) | Merge. |
| Streamable-HTTP serve | `src/http_transport.rs` | `src/http_transport.rs` (453) | Merge; see §5. |
| Inventory load / validate / atomic write | `-core/src/inventory.rs` (995) | `-core/src/inventory.rs` (871) | Generalize; see §6. |

Roughly 1,100 lines of CLI/TLS/token-command code and the entire auth crate are
duplicated with divergent behavior. Divergent duplication is worse than
duplication: a fix applied to one server silently does not reach the other.

### Concrete divergences in the auth layer

These matter because both servers have **deployed `tokens.json` files in
production** (`/etc/jmcp/tokens.json` on the deployment container), so extraction must preserve
on-disk compatibility:

| Field | rustjunosmcp | rustpanosmcp |
|---|---|---|
| digest field name | `hash` | `digest` |
| device scope field | `routers` | `devices` |
| creation time | `created_at` (RFC 3339 via `chrono`) | `created_at_unix` (u64) |
| expiry | **none** | `expires_at_unix: Option<u64>` |
| bounds | none | `MAX_TOKENS=1024`, `MAX_SCOPE_NAMES=256` |
| name validation | none | `validate_name()` |
| wildcard tool scope | permits everything | **excludes write tools** (`allows_tool`) |
| write grants | none | `MutationGrant { allowed_xpath_roots, actions }` |

rustjunosmcp has no token expiry and no bounds, and its wildcard tool scope
grants write tools. All three are real gaps that extraction closes.

## 4. Asymmetric capability — each repo is the other's missing half

### rustjunosmcp has, rustpanosmcp lacks

- **`rust-junosmcp-audit`** — a dedicated crate: `AuditScope` (RAII span with
  `succeed`/`fail`/`fail_kind`/`deny`), `AuditOutcome`, bounded error rendering,
  HMAC-keyed field redaction over a declared `REDACTABLE_FIELDS` list, and
  journald + JSON sinks with rotation. rustpanosmcp has a single
  `AUDIT_TARGET: &str` constant and an `audited()` helper in `http_transport.rs`.
- **`-core/src/limits/`** — real runtime hardening: `concurrency.rs` (1,144),
  `session.rs` (1,447, per-token session caps with overshoot-race fix),
  `rate_limit.rs` (434, per-token RPS), `overload.rs` (503 responses),
  `prometheus.rs` (`/metrics`). rustpanosmcp has a 100-line in-file fixed-window
  limiter and nothing else.
- **`policy.rs`** (754) — a compiled rule engine: `RuleSource`, `CompiledRule`,
  `Decision<'a>`, glob + regex matching over commands, PFE commands, and config
  paths, with per-device rules layered over inventory defaults.
- **`device_lease.rs`** / `device_manager.rs` / `cancel.rs` — connection
  leasing, pooling, and cancellation.
- **`output.rs`** (547) — output shaping and truncation.
- Jinja templating via `minijinja` (`tools/template.rs`).

### rustpanosmcp has, rustjunosmcp lacks

- **`-core/src/mutation.rs` (2,166 LOC)** — the change-control state machine,
  and the single most valuable thing in either repo:
  - `create_panos_change_set` → plan actions, compute an exact digest
  - `approve_panos_change_set` → a **different principal** approves that digest
  - `apply_panos_change_set` → apply only the reviewed, approved actions
  - `LifecycleState` / `ChangeSetState` persisted across restarts
  - `resolve_persisted_operation()` — operator-confirmed recovery for
    *indeterminate* operations (the apply whose outcome was never observed)
  - `get_candidate_fingerprint` — stable pre-change state digest
  - `CommitDisposition` and detached-commit acknowledgement for long commits

  rustjunosmcp has no equivalent. `load_and_commit_config` is one-shot: no plan,
  no digest, no second principal. There is a `rollback_config` tool but no
  change-set identity to roll back *to*.
- **Scope preflight at the HTTP boundary** — `request_exceeds_scope()` and
  `tool_call_exceeds_scope()` parse the JSON-RPC body and reject out-of-scope
  tool/device combinations *before* dispatch. rustjunosmcp authorizes inside
  handlers instead, which is a larger trusted surface.
- **`MutationGrant`** — per-token write authority (action set + XPath subtree
  roots), finer-grained than rustjunosmcp's router/tool `ScopeSet`.
- Fuzz targets, threat model, `deny.toml`.

## 5. Transport: the merge is not symmetric

rustjunosmcp's `http_transport.rs` is thin (~80 lines) because the work lives in
`-core/src/limits/`, wired as tower middleware. rustpanosmcp's is 453 lines
carrying its own limiter, security boundary, and scope preflight inline.

The shared crate should take **rustjunosmcp's `limits/` module wholesale** as
the structural base, and fold in **rustpanosmcp's `security_boundary` scope
preflight** as an additional layer. That produces a transport strictly stronger
than either: bounded body, per-IP and per-token rate limits, concurrency caps,
session caps, host/Origin/DNS-rebind checks, scope preflight before dispatch,
overload 503, and Prometheus metrics.

## 6. Inventory: both hardcode a JSON file

`Inventory` is a concrete struct in both repos, loading a single JSON file.
rustjunosmcp's carries `DeviceEntry`, `AuthConfig`, `BlocklistRules`, name and
address validators, `insert_device`, `hash_file`, `write_atomic`.
rustpanosmcp's carries `DeviceConfig`, `DeviceMetadata`, `LoadedTlsTrust`,
`MutationPolicy`, and environment-injected credentials.

At the target scale in [`ROADMAP.md`](ROADMAP.md) — 4,000 devices — a JSON file
is the wrong backing store. `Inventory` must become a **trait** with a
file-backed implementation today and database / NetBox / Nautobot
implementations later, generic over a vendor-specific device payload.

## 7. What stays vendor-specific

Not candidates for extraction, and should not be forced into the shared crates:

- **rustjunosmcp:** `rustez` / `rustnetconf` NETCONF adapters; `upgrade_junos.rs`
  (1,725); `transfer_file.rs` (2,520); the whole `rust-junosmcp-srx-core` crate —
  IDP package (2,008), AppID package (1,627), support bundle (973 + staging +
  redaction), cluster health/status, VPN lifecycle, license checks; Junos
  candidate/commit semantics.
- **rustpanosmcp:** `client.rs` XML-API transport; `xml.rs` (811) PAN-OS XML
  handling; XPath semantics; PAN-OS commit/validate behaviour; vsys and Panorama
  concepts.

## 8. Estimated effect

| | Before | After extraction |
|---|---|---|
| rustjunosmcp | ~37,150 LOC | ~22,000 vendor-specific |
| rustpanosmcp | ~8,290 LOC | ~3,000 vendor-specific |
| `mecmcp` shared | — | ~12,000, one implementation, one test suite |

The LOC reduction is secondary. The primary effects are:

1. rustjunosmcp gains change control, token expiry, scope bounds, scope
   preflight, and `unsafe`-free secret handling.
2. rustpanosmcp gains real concurrency/session/rate limiting, the audit crate
   with redaction, the compiled policy engine, and connection pooling.
3. A third vendor (FortiGate, ASA/FTD, Panorama, FortiManager) costs a protocol
   adapter and a tool surface — not a fourth reimplementation of authentication.

## 9. Constraints extraction must respect

1. **On-disk `tokens.json` compatibility.** Both servers have live deployments.
   Field renames require serde aliases and a documented migration, not a break.
2. **Independent release cadence.** rustjunosmcp is at 0.9.1 and rustpanosmcp at
   0.2.2 with separate release processes. A monorepo would couple them; `mecmcp`
   is therefore a separate repo consumed as a tagged git dependency.
3. **Edition/MSRV alignment.** rustjunosmcp must move to edition 2024 / MSRV
   1.88 and adopt the workspace lint set before it can consume the crates.
4. **`--inventory-readonly` and the deployed systemd override** on the deployment container must
   keep working unchanged through every phase.
