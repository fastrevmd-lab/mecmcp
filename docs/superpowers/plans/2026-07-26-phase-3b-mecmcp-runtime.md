# Phase 3b — `mecmcp-runtime` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the CLI skeleton (`serve`, token subcommands), TLS bootstrap, signal handling, and graceful shutdown from both servers into one shared `mecmcp-runtime` crate. Complete the two remaining unsafe-code eliminations that Phase 3a could not reach — `libc::kill(SIGHUP)` replaced with `rustix::process::kill` — and raise the workspace lint from `unsafe_code = "deny"` to `unsafe_code = "forbid"`.

**Scope:** This plan bundles three GitHub issues, not just the crate move:

- **mecmcp #35** — replace `libc::kill` with `rustix::process::kill` and raise the lint to `forbid`.
- **mecmcp #29** — standardise CLI flags on `--devices` (with `--routers` retained as a hidden alias in junos).
- **mecmcp #28, CLI half only** — default *values* for `--tokens-file`, `-f/--device-mapping`, `--state-file` move with the CLI. Standardise on the full service name and put `tokens.json` under `/var/lib/<service>/` since the server writes it. **Installer, systemd units, and service-user names explicitly NOT in scope** — that is packaging work with migration risk against four live deployments. The issue stays open.

**Architecture:** `rustjunosmcp` carries the larger CLI (430 lines) with more flags, so it becomes the base. `rustpanosmcp` contributes its hardened TLS loader (162 lines with `Zeroizing`, `O_NOFOLLOW`, mode ≤0600 enforcement), its `state` subcommand for indeterminate-operation recovery, and its `SetScope` token action. Both carry the same four token subcommands (`add`, `list`, `revoke`, `rotate`); the implementations merge.

---

## Global Constraints

Inherited from [`PLAN.md`](../../../PLAN.md). Repeated here because a task implementer sees only their task:

- **Edition 2024, MSRV 1.88.**
- **Workspace lints:** `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"` (priority -1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`.
- **Raising `unsafe_code` to `forbid` is an exit criterion of this phase.** The two remaining `#[allow(unsafe_code)]` sites guard `libc::kill(pid, SIGHUP)` calls that move into this crate and become safe calls through `rustix::process::kill`. Phase 3a left the lint at `deny` precisely because these unsafe calls were still present.
- **No breaking change to CLI flags.** They are a public interface consumed by deployed systemd unit files, runbooks, and the operators who type them. New spellings ship as aliases; existing ones keep working.
- **`max_inflight_requests_per_router` keeps its name** — it is in the deployed config on LXC 609. A serde alias for the new spelling is added; the field name is not renamed.
- **The SIGHUP hot-reload behaviour must not regress.** It is how `devices.json` and `tokens.json` reload without a restart on deployed containers (LXCs 608, 609, 600, 601), and `rustjunosmcp/tests/http_reload.rs` is its only coverage. The test must pass unmodified after this phase.
- **Live deployments:** LXC 608, 609 (production), 600, 601 (clean-room reference). LXC 608 carries TLS paths in its unit file rather than a drop-in, so nothing may assume the shipped unit is what is installed.
- **Licence:** MIT. **Naming:** `mecmcp-` crate prefix.

### The rule that governs every decision below

**Anything that belongs to the consuming server must be a parameter, not baked into the shared crate.** Four defects shipped by violating it; Phase 3a documents them all. This phase is where it matters for flag defaults: `staging_dir`, `device_lease_dir`, `support_bundle_staging_dir`, and the new state-file path all contain vendor-specific directory names today, and the shared crate must not choose them.

---

## What each repo actually has

Measured from `RustJunosMCP/rust-junosmcp/` and `rust-panosmcp/rust-panosmcp/` on 2026-07-26.

| File | rustjunosmcp | rustpanosmcp |
|---|---|---|
| `main.rs` | 268 lines | 140 lines |
| `cli.rs` | 430 lines, 19 serve flags, 5 token actions | 321 lines, 26 serve flags, 4 token actions + `state` subcommand |
| `cli_validate.rs` | 214 lines | 315 lines |
| `token_cmd.rs` | 179 lines, `sighup_if_requested` w/ `libc::kill` | 248 lines, no signal handling |
| `tls.rs` | 135 lines, plain PEM loader | 162 lines, hardened: `Zeroizing`, `O_NOFOLLOW`, mode ≤0600 |
| `http_transport.rs` | (not moving — Phase 3a extracted this to `mecmcp-transport`) | (same) |

**Key divergences:**

| Concern | rustjunosmcp | rustpanosmcp |
|---|---|---|
| TLS loader | Plain `fs::read`, no mode check | **Hardened**: `rustix::fs::open(...NOFOLLOW)`, refuses mode >0600, `Zeroizing` |
| Token actions | `add`, `list`, `revoke`, `rotate`, `set_scope` | `add`, `list`, `revoke`, `rotate` (no `set_scope`) |
| State recovery | **absent** | `state resolve` subcommand for indeterminate PAN-OS operations |
| `--routers` vs `--devices` | `--routers` in CLI, `devices`/`device_count` in audit since v0.11.0 | `--devices` everywhere |
| `--server-pid` for SIGHUP | present in junos token actions | **absent** in panos |
| Default paths | `/var/lib/jmcp/`, `/etc/jmcp/` | `/var/lib/rust-panosmcp/`, `/etc/rust-panosmcp/` |
| Signal handling | `libc::kill(pid, SIGHUP)` in `token_cmd.rs:165` and `tests/http_reload.rs:88,179` | **absent** |

---

## Decisions

**D1 — the hardened TLS loader is already done. This phase inherits it; it does not port it.**

Phase 3a delivered this. `rust-junosmcp/src/tls.rs` is already a thin shim:

```rust
//! This is a thin shim over `mecmcp_transport::tls::load` that installs the
//! ...
    mecmcp_transport::tls::load(cert, key, provider)
```

Task 6 ported the loader from `rustpanosmcp` into `mecmcp-transport`, and Task 8
wired junos onto it. The evidence is in junos's own tests: `http_tls.rs` and
`srx_http_tls.rs` both gained `set_permissions(0o600)` during Task 8, because the
hardened loader began refusing the 0644 keys `fs::write` creates.

**Do not put a TLS port in the task list.** An earlier draft of this decision did,
which would have sent an implementer to redo finished work.

Recorded here because the *next* server to adopt `mecmcp-runtime` meets the same
requirement and should not rediscover it: the loader enforces `O_NOFOLLOW` on open,
a size cap, a mode of 0600 or stricter, and an owner matching the effective uid or
root, with `Zeroizing` on the key bytes.

**The operator impact already shipped, in v0.11.1.** A junos deployment whose key
file is looser than 0600 stops starting. That was omitted from the original
release notes — found while reviewing this plan — and has since been corrected in
both the published notes and the CHANGELOG. `mecmcp-runtime` inherits the
behaviour unchanged; there is nothing further to announce.

**D2 — `--devices` everywhere, with `--routers` retained as a hidden alias in junos.** Matches mecmcp #29's decision comment. `devices` is the universal term — the fleet includes PAN-OS firewalls and the Proxmox/UniFi servers being built next, none of them routers. Junos is already internally inconsistent: v0.11.0 renamed the *audit* fields `routers` → `devices` and `router_count` → `device_count`, so the emitted events use the new term while the token CLI still takes `--routers`. The alias is hidden rather than deprecated-with-a-warning: `token add` is a one-shot admin command, and a warning on a box touched twice a year is noise.

**D3 — SIGHUP signalling moves to `rustix::process::kill`.** This is the point of the phase. `rustix` is already a dependency of `rustpanosmcp` (with `features = ["process", "fs"]`), and `mecmcp-transport` already calls `rustix::process::geteuid()`. The safe wrapper replaces the two `#[allow(unsafe_code)]` sites in junos, and the lint rises to `forbid`. `deny` means "we agreed not to"; `forbid` means the compiler will not permit it.

**D4 — The `state resolve` subcommand stays panos-only.** It is specific to PAN-OS indeterminate-operation recovery and has no junos equivalent. `mecmcp-runtime` will expose the CLI skeleton and an `enum StateSubcommand` extension point, but only panos will populate it in this phase. When junos needs its own state subcommand, it can use the same extension point.

**D5 — Default path values standardise on the full service name, with `tokens.json` under `/var/lib/`.** Per mecmcp #28's scope comment: the CLI defaults are in scope, but the installer, systemd units, and service-user names are not. `tokens.json` is server-written state (the server rewrites it on `add`, `rotate`, `revoke`), so it belongs under `/var/lib/<service>/`, not `/etc/`. This also removes a real footgun — the atomic write needs the *directory* writable, which surfaced as a confusing `Permission denied ... at path "/etc/jmcp/.tokens-KNnZkm.tmp"` when only the files had been chowned. New repos (`rustproxmoxmcp`, `rustunifimcp`) adopt the standard from day one.

**D6 — Vendor-specific flag defaults are constructor parameters.** The shared crate cannot know that junos needs `--staging-dir`, `--known-hosts-file`, `--device-lease-dir`, and `--support-bundle-staging-dir`, or that panos needs `--state-file`. Those flags stay in the consuming servers' CLI definitions. Only the flags *every* vendor needs — `--device-mapping`, `--tokens-file`, `--transport`, `--host`, `--port`, `--tls-cert`, `--tls-key` — move to the shared `Cli` struct.

**D7 — The `set_scope` token action is junos-only.** Panos does not have it. Like `state`, it stays server-specific for now and can move to the shared crate when the second consumer needs it.

**D8 — The shared CLI takes a `service_name: &str` parameter** used to construct default paths (`/var/lib/{service_name}/tokens.json`), the server version banner, and the clap `about` string. This is what makes D5 and D6 work without hardcoding vendor names.

---

## File Structure

New crate `crates/mecmcp-runtime/`:

| File | Responsibility |
|---|---|
| `cli.rs` | Shared `Cli` struct with `serve` flags and `token` subcommand. Extension points for vendor-specific subcommands (e.g., panos `state`, junos-only flags) via a generic parameter |
| `cli_validate.rs` | CLI validation: TLS pair, `--allow-no-auth` vs `--allow-insecure-bind` refusal matrix, token-file requirement |
| `token_cmd.rs` | Token subcommands: `add`, `list`, `revoke`, `rotate`. SIGHUP signalling via `rustix::process::kill` |
| `tls.rs` | Hardened TLS loader from panos: `O_NOFOLLOW`, mode ≤0600, `Zeroizing` |
| `signals.rs` | Unix signal handling setup for SIGHUP hot-reload |
| `shutdown.rs` | Graceful shutdown coordinator |
| `lib.rs` | Re-exports, public API |

---

## Task sequence

Each task ends green and independently reviewable.

### Task 1 — Scaffold the crate

Create `crates/mecmcp-runtime/` with `Cargo.toml` declaring: `clap`, `rustix`
(features = `["process", "fs"]`), `thiserror`, `anyhow`. Add it to the workspace.

**Do NOT port a TLS loader.** An earlier draft of this task said to port
`rustpanosmcp/src/tls.rs` here, which contradicts D1 and would create a *third*
copy: panos's original, `mecmcp-transport::tls` (where Phase 3a put it), and a new
one here. Both servers already consume the transport crate's loader —
`rust-junosmcp/src/tls.rs` is a thin shim over `mecmcp_transport::tls::load`.

`PLAN.md`'s crate map assigns "TLS bootstrap" to this crate, and that remains
right, but bootstrap means the **CLI plumbing**: parsing `--tls-cert`/`--tls-key`,
validating that they are supplied as a pair, and installing the consumer's crypto
provider before handing paths to `mecmcp_transport::tls::load`. That work belongs
to Task 2 with the rest of the CLI. The loader itself does not move.

If this crate ends up needing a `tls` module at all, it re-exports from
`mecmcp-transport` rather than reimplementing. Per D4 of the Phase 3a plan the
crypto provider stays a parameter, so nothing here selects `ring` or `aws-lc-rs`.

**Test:** `cargo build -p mecmcp-runtime` succeeds and the crate is in the
workspace. There is nothing behavioural to test yet — resist adding a placeholder
test that asserts nothing.

**Exit:** the crate exists, builds, and `cargo tree -e normal -p mecmcp-runtime`
pulls no rustls crypto provider.

### Task 2 — Port CLI structure and validation

Create `cli.rs` with a `Cli` struct holding only the flags *every* vendor needs:
- `device_mapping: PathBuf` (default determined by caller)
- `transport: Transport` (stdio | streamable-http)
- `host: String`, `port: u16`
- `tokens_file: Option<PathBuf>` (default determined by caller)
- `tls_cert: Option<PathBuf>`, `tls_key: Option<PathBuf>`
- `allow_no_auth: bool`, `allow_insecure_bind: bool`
- `allowed_host: Vec<String>`, `allowed_origin: Vec<String>`
- Audit flags: `audit_format`, `audit_log_file`, `audit_journald`, `audit_redact`, `audit_hmac_key_file`

Add a `command: Option<Command>` field where `Command` is an enum with `Token { action: TokenAction }` and a generic extension variant for vendor-specific subcommands.

Port the validation logic from both servers into `cli_validate.rs`: TLS pair must both be present or both absent; `--allow-no-auth` refuses to bind off-loopback; `--allow-insecure-bind` is required for non-loopback plaintext; `--tokens-file` is required for streamable-http unless `--allow-no-auth`.

**Test:** Unit tests asserting the refusal matrix: `allow_no_auth + host=0.0.0.0` is rejected; `host=0.0.0.0 + no tls + no allow_insecure_bind` is rejected; `tls_cert` without `tls_key` is rejected.

**Exit:** `cargo test -p mecmcp-runtime` passes; the CLI parses and validates.

### Task 3 — Port token subcommands with `rustix` signalling

Create `token_cmd.rs` porting the four shared actions: `add`, `list`, `revoke`, `rotate`. Merge the implementations from both servers:
- junos's `add` takes `--routers` (now aliased to `--devices`), panos's takes `--devices` — standardise on `--devices` with `#[arg(long, alias = "routers", hide = true)]` for the alias.
- Both `add` implementations validate device names against the inventory; the shared version takes `known_devices: &[String]` as a parameter.
- junos's actions take `--server-pid: Option<i32>`; panos's do not. Retain it in the shared version.

Replace the two `libc::kill` sites with `rustix::process::kill(Pid::from_raw(pid).unwrap(), Signal::Hup)`. This is the `deny` → `forbid` transition. Remove the `#[allow(unsafe_code)]` annotations from the ported code.

**Test:** Port `rustjunosmcp/tests/token_subcommand.rs` to exercise `add`, `list`, `revoke`, `rotate` through the shared implementation. Add a test that asserts `--routers` still works and produces the same output as `--devices`.

**Exit:** All token subcommands work; the signalling is safe; no `#[allow(unsafe_code)]` remains in `mecmcp-runtime`.

### Task 4 — Signal handling and graceful shutdown

Create `signals.rs` with a Unix-only signal handler that listens for SIGHUP and triggers a reload callback. On non-Unix, the module is a no-op.

Create `shutdown.rs` with a `GracefulShutdown` coordinator that aggregates `tokio::signal::ctrl_c()`, the SIGHUP handler, and a manual shutdown trigger.

**Test:** A test that spawns a dummy server, sends it SIGHUP via `rustix::process::kill`, and asserts the reload callback fires. Another test for Ctrl-C (if testable in this environment).

**Exit:** The signal plumbing compiles and is tested.

### Task 5 — Wire `rustjunosmcp`

Update `rustjunosmcp/Cargo.toml` to depend on `mecmcp-runtime`. Replace `cli.rs`, `cli_validate.rs`, `token_cmd.rs`, and `tls.rs` with imports from `mecmcp-runtime`. Vendor-specific flags (`--staging-dir`, `--known-hosts-file`, `--device-lease-dir`, `--support-bundle-staging-dir`, `--ssh-accept-new-host-keys`, `--enable-metrics`, rate-limit flags) stay in the server's own extended `Cli` struct.

Add `#[arg(long, alias = "routers", hide = true)]` to the `--devices` flag in the shared CLI. Update `token_cmd::run` call sites to pass the inventory's device names.

Delete `src/cli.rs`, `src/cli_validate.rs`, `src/token_cmd.rs`, `src/tls.rs` from the server. Remove `libc` from `Cargo.toml` if it is no longer needed.

**Test:** Run the full `rustjunosmcp` test suite. The SIGHUP reload test `tests/http_reload.rs` must pass unmodified — it is the only coverage of the hot-reload behaviour. The suite baseline is 924 tests; all must pass.

**Exit:** All 924 tests pass; no `#[allow(unsafe_code)]` remains in `rustjunosmcp`; the binary still starts and serves MCP.

### Task 6 — Wire `rustpanosmcp`

Update `rustpanosmcp/Cargo.toml` to depend on `mecmcp-runtime`. Replace `cli.rs` (partially — the `state` subcommand stays server-specific), `cli_validate.rs`, `token_cmd.rs`, and `tls.rs` with imports from `mecmcp-runtime`.

The `state` subcommand and its `StateAction` enum stay in `rustpanosmcp/src/cli.rs`. The server's `Cli` struct extends the shared one with `--state-file` and the vendor-specific rate-limit and session flags.

Update the default path for `--tokens-file` from `/etc/rust-panosmcp/tokens.json` to `/var/lib/rust-panosmcp/tokens.json` per D5. Document the migration in the server's CHANGELOG: existing deployments honour the path in the unit file; fresh installs use the new default.

Delete `src/token_cmd.rs` and `src/tls.rs` from the server.

**Test:** Run the full `rustpanosmcp` test suite. The suite baseline is 62 tests; all must pass.

**Exit:** All 62 tests pass; the binary still starts and serves MCP; the `state resolve` subcommand still works.

### Task 7 — Raise `unsafe_code` to `forbid`

In `mecmcp/Cargo.toml` (the workspace root), raise the workspace lint from `unsafe_code = "deny"` to `unsafe_code = "forbid"`. Verify that both servers and all `mecmcp-*` crates compile.

**Test:** `cargo clippy --workspace --all-targets -- -D warnings` must pass.

**Exit:** The lint is `forbid`; no crate in the workspace contains unsafe code or an `#[allow(unsafe_code)]` annotation.

### Task 8 — Update CHANGELOGs and documentation

Update `rustjunosmcp/CHANGELOG.md`:
- Document the TLS loader change: keys looser than mode 0600 now refuse to load.
- Document `--devices` as the new spelling, with `--routers` retained as a hidden alias.
- Document the `unsafe_code = "forbid"` milestone.

Update `rustpanosmcp/CHANGELOG.md`:
- Document the default path change for `--tokens-file`: `/var/lib/rust-panosmcp/tokens.json` on fresh installs, existing deployments honour the unit file path.

Update `mecmcp/PLAN.md` to mark Phase 3b complete.

**Exit:** All documentation is updated; the changes are user-facing and noted.

---

## Open Questions

**Q1:** Should `set_scope` move to the shared crate now, even though only junos uses it? **Recommendation:** No. Move it when the second consumer needs it, not before — that is when the interface can be validated. Leave it in junos for this phase.

**Q2:** Should the `state` subcommand extension point be a trait or an enum variant? **Recommendation:** Enum variant with a generic parameter, e.g., `Command::VendorSpecific(V)` where `V: Subcommand`. Simpler than a trait and matches clap's model.

**Q3:** Should the signal-handling tests run on CI, or are they Unix-only and therefore gated? **Recommendation:** Gate them with `#[cfg(unix)]` and `#[cfg(not(unix))]` no-op stubs, same as the implementation. CI runs on Linux, so they will execute.

---

## Exit criteria

- Both servers build, and their full suites pass at their current baselines (junos 924, panos 62) with `EXIT=0` — verified by exit status, never by summing per-target `test result:` lines.
- `rustjunosmcp/tests/http_reload.rs` passes unmodified — the SIGHUP hot-reload behaviour is unchanged.
- `cargo clippy --workspace --all-targets -- -D warnings` passes in both server repos and the `mecmcp` workspace.
- The workspace lint is `unsafe_code = "forbid"`, and no crate contains unsafe code or an `#[allow(unsafe_code)]` annotation.
- `--routers` still works in junos as a hidden alias; `--devices` is accepted everywhere.
- A junos deployment whose TLS key is mode 0644 fails to start with an error naming the file, its mode, and the remedy.
- `rustpanosmcp` fresh installs default `--tokens-file` to `/var/lib/rust-panosmcp/tokens.json`; existing deployments (608, 609, 600, 601) continue to work with their unit file paths.
- Neither deployed unit file needs an edit.
- `mecmcp/PLAN.md` marks Phase 3b complete, and both servers' CHANGELOGs document the user-facing changes.
