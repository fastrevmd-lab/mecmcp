# Phase 4 — `mecmcp-policy`, `mecmcp-inventory`, `mecmcp-device` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract the Junos policy engine, generalize the inventory abstraction, and lift device connection management into three shared crates. This phase unblocks database-backed inventory for large fleets and gives PAN-OS the command/config guardrail capability Junos has today.

**Scope:** Three crates, bundling GitHub issues mecmcp #6 (trait abstraction only, not schema convergence — that is explicitly deferred to #27), and the inventory/device-management portions of the extraction program.

- **mecmcp #6, Phase 4 subset only** — `Inventory` trait abstracting over the two existing on-disk schemas. Schema convergence (mecmcp #27) is **explicitly out of scope** and tracked separately.
- **Policy and device concurrency lifts** — extract Junos's 754-line rule engine and its device-lease cross-process exclusion mechanism, with decisions on what PAN-OS adopts and what stays vendor-specific.

**Architecture:** This phase delivers **the trait abstraction over two existing, incompatible schemas** — junos's flat map with `_blocklist_defaults` and panos's versioned envelope with a device array. Both schemas continue to load through `Inventory::load()` unchanged. mecmcp #27 (schema convergence) is deferred because attempting it now means a migration against four live deployments in the same change that introduces the abstraction. The trait is what makes #27 tractable later: a converged schema can then be a second `Inventory` implementation rather than a flag day.

---

## Global Constraints

Inherited from [`PLAN.md`](../../../PLAN.md). Repeated here because a task implementer sees only their task:

- **Edition 2024, MSRV 1.88.**
- **Workspace lints:** `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"` (priority -1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`.
- **No breaking change to on-disk `devices.json`** in either server. Live deployments exist on LXC 608, 609, 600, 601.
- **Anything that belongs to the consuming server must be a parameter, not baked into the shared crate.** Four defects shipped by violating this in Phase 3; see PLAN.md's "The rule these phases keep learning the hard way."
- **Do not hand a consumer something older than it already has.** Check dependency versions in both servers before pinning anything in a shared crate.
- **One git ref for all `mecmcp-*` deps.** Two refs produce two `CallerCtx` types with different `TypeId`s and per-token limits silently stop enforcing. `grep -c '^name = "mecmcp-auth"' Cargo.lock` must print 1 in each consuming server.
- **Licence:** MIT. **Naming:** `mecmcp-` crate prefix.
- **Never `thread_local!` for anything request-handling code reads.** Phase 3a shipped metrics in thread-local storage that tokio workers never saw; the counters silently stopped recording.

---

## What each repo actually has

Measured from `RustJunosMCP` and `rust-panosmcp` on 2026-07-26.

| File | rustjunosmcp | rustpanosmcp |
|---|---|---|
| `policy.rs` | **754 lines** (`rust-junosmcp-core/src/`) | **does not exist** |
| `inventory.rs` | 995 lines (`rust-junosmcp-core/src/`) | 961 lines (`rust-panosmcp-core/src/`), different schema |
| `device_lease.rs` | 419 lines (`rust-junosmcp-core/src/`) | — |
| `device_manager.rs` | 668 lines (`rust-junosmcp-core/src/`) | — |
| `cancel.rs` | 124 lines (`rust-junosmcp-core/src/`) | — |

**Key divergences:**

| Concern | rustjunosmcp | rustpanosmcp |
|---|---|---|
| Inventory schema | Flat map with magic `_blocklist_defaults` key | Versioned envelope (`version: 1`) with device array |
| Policy enforcement | 754-line `Policy` engine: glob matchers, specificity scoring, `Decision::Allow\|Deny` | XPath prefix validation in `validate_write_xpath()` against `MutationPolicy.allowed_xpath_roots` — simpler, no glob engine |
| Device concurrency | **File locks** — `flock` via `OpenOptions`, kernel-owned, survives process death | `Arc<Semaphore>` inside `PanosClient` (in-process only) |
| Connection pooling | — | **Already present**: `Client::builder().pool_max_idle_per_host(config.max_concurrency)` at `rust-panosmcp-core/src/client.rs:251` |
| Cross-process exclusion | `device_lease.rs` — "the open file descriptor and kernel lock are authoritative... the kernel provides crash recovery without stale-lock deletion" | **absent** |

---

## Decisions

**D1 — Schema convergence (mecmcp #27) is explicitly out of scope for Phase 4.**

`PLAN.md`'s exit criterion says "both servers load their existing `devices.json` unchanged through the trait." This phase delivers the **trait abstraction** over the two existing schemas, not schema convergence. Attempting both at once means a migration against four live deployments (LXC 608, 609, 600, 601) in the same change that introduces the abstraction.

mecmcp #27 documents the problem thoroughly: junos uses a flat map with a magic `_blocklist_defaults` entry sharing the namespace with devices; panos uses a versioned envelope with a device array. They differ in every structural decision available. #27 proposes a converged shape and notes the hard constraint: both servers have live deployments, so this lands as "read both shapes, write the new one, with the legacy reader kept and tested until every deployment has migrated."

**The trait is what makes #27 tractable.** Once `Inventory` is a trait, the converged schema becomes a second implementation (`InventoryV2` or `StandardInventory`) consumed through the same interface. Doing it now produces a flag day; doing it after this phase is a controlled migration.

**D2 — `mecmcp-policy` extracts Junos's rule engine as-is, with PAN-OS adopting it for read-only tools only.**

Junos has a 754-line rule engine with glob matchers, specificity scoring, and three rule domains (`commands`, `config`, `pfe_commands`). PAN-OS has none — it validates XPath prefixes against `allowed_xpath_roots` for mutations, and does **no authorization of read-only operational commands or XPath reads** beyond checking that the caller has a valid token.

`mecmcp-policy` extracts the Junos engine verbatim. PAN-OS gains the capability for **read-only operational commands** (`execute_panos_op`) and **XPath reads** (`get_panos_config`), giving operators the same blocklist guardrails Junos has. PAN-OS mutations **continue to use `validate_write_xpath`** — XPath prefix validation against inventory-defined roots — because that is a materially different authorization model (prefix allowlist) than the rule engine (most-specific glob match).

**Operator-visible behaviour change:** PAN-OS `execute_panos_op` currently accepts any `<show>` command if the caller has a valid token. After adopting the engine, a blocklist can deny specific commands. This is an **additive capability** — an empty blocklist produces today's behaviour (allow everything). Existing deployments with no blocklist in inventory see no change; new deployments can add one.

**Why not also use the engine for PAN-OS mutations?** The engine evaluates `Decision::Allow | Deny` by matching a single string (a command, a config line) against glob rules. PAN-OS mutations operate on XPath trees (`/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/hostname`), where authorization is "inside one of these subtrees or not." Prefix matching is the right model, and `validate_write_xpath` already does it correctly. Forcing mutations through a glob engine would require either flattening XPaths to strings and writing glob patterns that mimic prefix semantics, or extending the engine with an XPath matcher — both worse than what exists.

**D3 — The `Inventory` trait is generic over device and policy payloads.**

Junos's `DeviceEntry` carries SSH connection parameters, port, credentials, and an optional per-device blocklist. PAN-OS's `DeviceConfig` carries HTTPS endpoint, API key, TLS trust strategy, concurrency caps, and an optional `MutationPolicy` (XPath roots, admin, delete permission, lock requirement). They have nothing in common beyond a name.

The trait is therefore generic over `Device` and `Policy`:

```rust
pub trait Inventory<D, P>: Send + Sync {
    fn names(&self) -> Vec<String>;
    fn get(&self, name: &str) -> Result<&D, InventoryError>;
    fn policy(&self) -> Option<&P>;
}
```

Junos's policy is the compiled `Policy` (the rule engine); PAN-OS has none today and can either leave `P = ()` or define a `PanosGlobalPolicy` holding defaults for read-only command blocklists when it adopts the engine in Task 6.

**D4 — Device concurrency: two separate mechanisms, not one merged abstraction.**

`PLAN.md` Phase 4's description says "lift connection leasing," but this conflates two different mechanisms with different purposes:

- **Junos `device_lease.rs`** — cross-process exclusion using kernel file locks (`flock`), so a long-running upgrade cannot be raced by a second process. Its own docs say "the open file descriptor and kernel lock are authoritative... the kernel provides crash recovery without stale-lock deletion." This is a **distributed lock** using the kernel as the authority.

- **PAN-OS `Arc<Semaphore>`** — in-process concurrency limiting inside `PanosClient`, capping parallel API calls to one device. This is a **rate limiter / connection pool**, not a lock.

Merging them into one `mecmcp-device` abstraction without distinguishing them produces something that is wrong for both. `mecmcp-device` will offer **both**, not a single unified "device lease":

- A `DeviceLock` trait for cross-process exclusion, with a file-lock implementation (`FlockDeviceLock`) as the first and only impl in this phase. Junos uses it; PAN-OS does not (yet — it may want it for upgrades or HA failover workflows later).
- A `ConnectionPool` or `ConcurrencyLimit` trait for in-process connection management. PAN-OS already has this via `reqwest::Client` and `Arc<Semaphore>`; Junos does not use HTTP pooling but does limit SSH connections via `device_manager.rs`.

**Recommendation for this phase:** extract `device_lease.rs` into `mecmcp-device` as `FlockDeviceLock` and wire it into Junos unchanged. PAN-OS does not adopt it yet. Extract the connection-management parts of `device_manager.rs` and PAN-OS's semaphore logic into a shared abstraction only if the interface is identical — if not, defer until both servers need the same thing.

**D5 — Connection pooling is already done in PAN-OS and not applicable to Junos.**

`PLAN.md`'s Phase 4 exit says "rustpanosmcp gains connection pooling and per-device in-flight caps." This is **already satisfied**. `rust-panosmcp-core/src/client.rs:251` configures `Client::builder().pool_max_idle_per_host(config.max_concurrency)`, and `PanosClient` holds `concurrency: Arc<Semaphore>` capping in-flight requests. The client is documented as "Pooled PAN-OS API client for exactly one validated inventory device."

Junos does not use HTTP and therefore has no connection pooling — it opens ephemeral SSH sessions via rustnetconf. So there is nothing to "lift" here; the two vendors use different transports.

**Corrected exit criterion:** "Both servers load their existing `devices.json` through the `Inventory` trait; PAN-OS adopts the policy engine for read-only tools; Junos's cross-process device locking is extracted to `mecmcp-device::FlockDeviceLock` and wired unchanged."

**D6 — Vendor-specific device payloads stay in the consuming servers.**

The shared `Inventory` trait takes `Device` and `Policy` as generic parameters. Junos's `DeviceEntry` (SSH/port/username/auth/blocklist) and PAN-OS's `DeviceConfig` (HTTPS/apikey/TLS/concurrency/mutation) do not move into `mecmcp-inventory`. They stay in `rust-junosmcp-core` and `rust-panosmcp-core`, respectively, and are passed as type parameters when constructing the file-backed inventory implementation.

This keeps vendor connection details out of the shared crate and preserves the rule: "anything that belongs to the consuming server must be a parameter."

**D7 — The file-backed inventory implementation ships with both legacy loaders.**

To meet the "no breaking change to on-disk `devices.json`" constraint, `mecmcp-inventory`'s file-backed impl must read **both** schemas — junos's flat map and panos's versioned envelope — and detect which one it sees. Serde's untagged enum can handle this:

```rust
#[derive(Deserialize)]
#[serde(untagged)]
enum RawInventory<D> {
    JunosFlat(HashMap<String, D>),
    PanosEnvelope { version: u32, devices: Vec<D> },
}
```

Both servers then load their existing files unchanged. When mecmcp #27 converges the schema, a third variant is added and the old ones remain loadable.

**D8 — Atomic write and hot-reload move with the inventory.**

Both servers already have these. Junos's `inventory.rs:74-109` is `write_atomic` with `tempfile` and `fs::rename`. PAN-OS's is `rust-panosmcp-core/src/inventory.rs:945-969`, nearly identical. The logic is not vendor-specific and belongs in the shared file-backed impl.

Hot-reload (triggered by SIGHUP) is already in `mecmcp-runtime` as of Phase 3b. The inventory's `reload()` method is what the signal handler calls.

---

## File Structure

Three new crates under `crates/`:

### `mecmcp-policy/`

| File | Responsibility |
|---|---|
| `lib.rs` | `RuleSource`, `CompiledRule`, `Decision`, `Policy`, `compile_rules`, `evaluate` — the engine extracted from junos |
| `matchers.rs` | Pluggable matchers: `GlobMatcher` (the only one in this phase); extension point for regex, xpath-prefix, config-path |
| `normalize.rs` | `normalize_input` — trim and collapse whitespace for config-line matching |

### `mecmcp-inventory/`

| File | Responsibility |
|---|---|
| `lib.rs` | `Inventory` trait, `InventoryError`, `validate_device_name` |
| `file.rs` | File-backed implementation: `FileInventory<D, P>`, reads both legacy schemas, atomic write, hot-reload |
| `loaders.rs` | Schema detection and parsing for junos flat-map vs panos envelope |

### `mecmcp-device/`

| File | Responsibility |
|---|---|
| `lib.rs` | `DeviceLock` trait, `DeviceLockError` |
| `flock.rs` | `FlockDeviceLock` — cross-process exclusion via kernel file locks, extracted from junos `device_lease.rs` |
| `cancel.rs` | `Cancellable` trait, token plumbing — extracted from junos `cancel.rs` |

---

## Task sequence

Each task ends green and independently reviewable.

### Task 1 — Scaffold `mecmcp-policy` and port the rule engine

Create `crates/mecmcp-policy/` with `Cargo.toml` declaring `globset`, `serde`, `thiserror`. Add to workspace.

Port `rust-junosmcp-core/src/policy.rs:1-143` (everything up to `struct Policy`) into `mecmcp-policy/lib.rs`:
- `RuleSource`, `CompiledRule`, `Decision`, `count_literal_chars`, `compile_rules`, `evaluate`, `normalize_input`.
- Keep `Action` as a dependency — it comes from the inventory, not the policy crate.

Do NOT port `struct Policy` yet — it is built from Junos's `Inventory` and will be constructed differently after the trait exists. Task 2 handles that.

**Test:** Port the unit tests from `rust-junosmcp-core/src/policy.rs:493-end` that cover `count_literal_chars`, `normalize_input`, `compile_rules`, and `evaluate`. All must pass.

**Files:**
- `crates/mecmcp-policy/Cargo.toml`
- `crates/mecmcp-policy/src/lib.rs`
- `crates/mecmcp-policy/src/normalize.rs` (if you split it; optional)

**Exit:** `cargo test -p mecmcp-policy` passes; the rule engine primitives are extracted and tested.

### Task 2 — Port `Policy` builder and decision methods

Port `struct Policy` and its `build()`, `check_command()`, `check_pfe_command()`, `check_config()` methods from `rust-junosmcp-core/src/policy.rs:145-335`.

`Policy::build()` currently takes `&crate::Inventory` — change the signature to take iterators or pre-compiled rule sets as parameters, so the policy crate does not depend on any specific inventory implementation. Example:

```rust
impl Policy {
    pub fn build<I>(
        default_rules: DefaultRules,
        device_rules: I,
    ) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = (String, DeviceRules)>,
    { ... }
}

pub struct DefaultRules {
    pub commands: Vec<RuleSpec>,
    pub config: Vec<RuleSpec>,
    pub pfe_commands: Vec<RuleSpec>,
}

pub struct DeviceRules {
    pub commands: Vec<RuleSpec>,
    pub config: Vec<RuleSpec>,
    pub pfe_commands: Vec<RuleSpec>,
}
```

The consuming server (Junos) will extract these from its inventory and pass them in.

**Test:** Port the decision tests from `rust-junosmcp-core/src/policy.rs` that exercise `check_command`, `check_config`, `check_pfe_command`. All must pass.

**Exit:** `Policy` is buildable and testable without depending on Junos's inventory; the decision logic is extracted.

### Task 3 — Scaffold `mecmcp-inventory` with the trait

Create `crates/mecmcp-inventory/` with `Cargo.toml` declaring `serde`, `thiserror`, `tokio` (for `RwLock` in hot-reload). Add to workspace.

Define the `Inventory` trait in `lib.rs`:

```rust
use std::error::Error;

pub trait Inventory<D, P>: Send + Sync {
    fn names(&self) -> Vec<String>;
    fn get(&self, name: &str) -> Result<&D, Box<dyn Error + Send + Sync>>;
    fn policy(&self) -> Option<&P>;
}
```

Add `validate_device_name` as a free function (both servers have nearly identical validation — max length, allowed characters).

**Test:** A trivial `impl Inventory<(), ()>` for a `HashMap<String, ()>` that can satisfy the trait. No file I/O yet.

**Exit:** The trait compiles and a trivial implementation passes `cargo test -p mecmcp-inventory`.

### Task 4 — Port file-backed inventory with dual-schema loader

Create `file.rs` with `FileInventory<D, P>` implementing `Inventory<D, P>`. Port the atomic write and hot-reload logic from both servers (they are nearly identical).

Create `loaders.rs` with schema detection:

```rust
#[derive(Deserialize)]
#[serde(untagged)]
enum RawInventory<D> {
    JunosFlat(HashMap<String, D>),
    PanosEnvelope { version: u32, devices: Vec<D> },
}
```

The loader detects which schema it sees and normalizes both into a name-indexed map. `FileInventory::load()` takes a `Path` and returns `Self` after validation (no duplicate names, names pass `validate_device_name`, version is supported).

Add a `reload()` method that re-reads the file and atomically swaps the internal map if validation succeeds.

**Test:**
- Load a junos-shaped file: a flat map with magic `_blocklist_defaults`.
- Load a panos-shaped file: `{ "version": 1, "devices": [...] }`.
- Assert both produce the same `Inventory` interface.
- Assert `reload()` picks up changes to the file.

**Exit:** `FileInventory` reads both legacy schemas and hot-reloads; tests pass.

### Task 5 — Wire `rustjunosmcp` to `mecmcp-policy` and `mecmcp-inventory`

Update `rust-junosmcp-core/Cargo.toml` to depend on `mecmcp-policy` and `mecmcp-inventory`.

Replace `rust-junosmcp-core/src/policy.rs` with a thin shim that:
- Defines `RuleSpec` and `Action` (Junos-specific serde types from inventory).
- Re-exports from `mecmcp_policy`.
- Implements a builder that extracts `DefaultRules` and per-device `DeviceRules` from the Junos inventory and calls `Policy::build()`.

Update `rust-junosmcp-core/src/inventory.rs` to implement `Inventory<DeviceEntry, BlocklistDefaults>` instead of being a standalone type. Device loading logic (SSH parameters, credential resolution) stays in the server; only the `names()`, `get()`, `policy()` interface changes.

Delete the old `policy.rs` and the duplicated atomic-write logic from `inventory.rs` once the migration is complete.

**Test:** Run the full `rustjunosmcp` test suite. Baseline is 924 tests (as of Phase 3b completion); all must pass. The policy decisions and inventory loading must work identically to before.

**Exit:** Junos uses the shared policy and inventory crates; the existing test suite passes; no behaviour change.

### Task 6 — Wire `rustpanosmcp` to `mecmcp-policy` and `mecmcp-inventory`

Update `rust-panosmcp-core/Cargo.toml` to depend on `mecmcp-policy` and `mecmcp-inventory`.

Update `rust-panosmcp-core/src/inventory.rs` to implement `Inventory<DeviceConfig, ()>` (no global policy yet — PAN-OS has none). Device loading logic (HTTPS endpoint, API key resolution, TLS trust, concurrency) stays in the server.

**Adopt the policy engine for read-only tools only:**
- Define a blocklist schema for PAN-OS inventory (optional, per-device and/or global) covering `commands` (for `execute_panos_op`) and `xpath` (for `get_panos_config`).
- Wire `execute_panos_op` to check `Policy::check_command()` before sending the command to the device.
- Wire `get_panos_config` to check `Policy::check_config()` (treating the XPath as a "config line") before sending the request.

**Do NOT wire mutations.** PAN-OS mutations continue to use `validate_write_xpath` — that is D2's decision.

Delete the duplicated atomic-write logic from `inventory.rs` once the migration is complete.

**Test:** Run the full `rustpanosmcp` test suite. Baseline is 62 tests; all must pass. Add a test that asserts a blocklist rule denies a specific `<show>` command or XPath read.

**Exit:** PAN-OS uses the shared inventory crate; read-only tools enforce blocklist rules; mutations are unchanged; the existing test suite passes.

### Task 7 — Scaffold `mecmcp-device` and extract `FlockDeviceLock`

Create `crates/mecmcp-device/` with `Cargo.toml` declaring `rustix` (features = `["fs"]`), `thiserror`, `tokio`. Add to workspace.

Define the `DeviceLock` trait in `lib.rs`:

```rust
#[async_trait]
pub trait DeviceLock: Send + Sync {
    async fn acquire(&self, device: &str) -> Result<DeviceLockGuard, DeviceLockError>;
}

pub struct DeviceLockGuard {
    // RAII guard; drop releases the lock
}
```

Port `rust-junosmcp-core/src/device_lease.rs` into `flock.rs` as `FlockDeviceLock`, implementing `DeviceLock`. The implementation is unchanged — kernel file locks via `rustix::fs::flock`, with the lock held until the guard drops.

**Test:** Port the unit tests from `rust-junosmcp-core/src/device_lease.rs`. Assert that two tasks racing for the same device name serialize correctly.

**Exit:** `FlockDeviceLock` works and is tested; the trait is usable.

### Task 8 — Extract cancellation plumbing

Port `rust-junosmcp-core/src/cancel.rs` into `mecmcp-device/src/cancel.rs`. This is the `Cancellable` trait and token plumbing used by device operations to respect cancellation.

**Test:** Port the unit tests from `rust-junosmcp-core/src/cancel.rs`.

**Exit:** Cancellation logic is extracted and tested.

### Task 9 — Wire `rustjunosmcp` to `mecmcp-device`

Update `rust-junosmcp-core/Cargo.toml` to depend on `mecmcp-device`.

Replace `rust-junosmcp-core/src/device_lease.rs` and `rust-junosmcp-core/src/cancel.rs` with imports from `mecmcp-device`.

Delete the old files.

**Test:** Run the full `rustjunosmcp` test suite. All 924 tests must pass; device locking behaviour is unchanged.

**Exit:** Junos uses the shared device-lock crate; the existing test suite passes.

### Task 10 — Update CHANGELOGs and documentation

Update `rustjunosmcp/CHANGELOG.md`:
- Document that policy and inventory are now shared crates.
- Note that device locking is extracted to `mecmcp-device::FlockDeviceLock`.

Update `rustpanosmcp/CHANGELOG.md`:
- Document that inventory is now a shared crate.
- **Document the new capability**: read-only operational commands and XPath reads can now be blocked via inventory blocklist rules. This is an **additive capability** — existing deployments with no blocklist see no change.
- Note that mutations continue to use XPath prefix validation (unchanged behaviour).

Update `mecmcp/PLAN.md` to mark Phase 4 complete and note the #27 deferral.

**Exit:** All documentation is updated; the user-facing changes are noted.

---

## Open Questions

**Q1:** Should PAN-OS adopt `FlockDeviceLock` for long-running operations like upgrades in this phase? **Recommendation:** No. It does not have those workflows yet, and adding the lock without a consumer would be speculative. Defer until PAN-OS needs it.

**Q2:** Should the connection-management parts of `device_manager.rs` move to `mecmcp-device` now? **Recommendation:** Only if the interface is identical between Junos (SSH connection pool) and PAN-OS (HTTP pool + semaphore). If not, defer until both servers need the same abstraction. This plan leaves `device_manager.rs` in Junos for now.

**Q3:** Should `mecmcp-policy` support regex or XPath matchers in addition to globs? **Recommendation:** Not in this phase. Glob is what Junos uses, and it is sufficient for the two consumers. Add other matchers when a consumer needs them.

---

## Exit criteria

- All three new crates (`mecmcp-policy`, `mecmcp-inventory`, `mecmcp-device`) build and pass their own test suites.
- Both servers build, and their full suites pass at their current baselines (junos 924, panos 62) with `EXIT=0`.
- **Both servers load their existing `devices.json` unchanged through the `Inventory` trait.** No on-disk file format changes.
- PAN-OS's `execute_panos_op` and `get_panos_config` enforce blocklist rules when present in inventory. An empty blocklist produces the same behaviour as before (allow everything).
- PAN-OS mutations use `validate_write_xpath` unchanged — XPath prefix validation, not the glob engine.
- Junos's cross-process device locking works identically through `mecmcp-device::FlockDeviceLock`.
- `cargo clippy --workspace --all-targets -- -D warnings` passes in the mecmcp workspace and both server repos.
- `grep -c '^name = "mecmcp-' Cargo.lock` in each server shows all mecmcp crates at one git ref.
- `mecmcp/PLAN.md` marks Phase 4 complete and documents the #27 deferral.
- CHANGELOGs in both servers document the extraction and the new PAN-OS blocklist capability.

---

## Findings from verification against the tree

Three claims in `PLAN.md` Phase 4 did not match the code:

1. **"rustpanosmcp gains connection pooling and per-device in-flight caps"** — already done. `rust-panosmcp-core/src/client.rs:251` configures `pool_max_idle_per_host`, and `PanosClient` holds `concurrency: Arc<Semaphore>`. Exit criterion corrected to focus on the trait abstraction.

2. **"Lift connection leasing" conflates two mechanisms.** Junos's `device_lease.rs` is cross-process exclusion (kernel file locks); PAN-OS's semaphore is in-process concurrency limiting. They serve different purposes. This plan separates them into `DeviceLock` (cross-process) and connection-pool logic (deferred until both servers need the same interface).

3. **PAN-OS has no policy engine, but does have XPath prefix validation.** `validate_write_xpath` checks that a mutation XPath is inside one of the operator-configured `allowed_xpath_roots`. This is a prefix allowlist, not a glob-matching rule engine. The plan adopts the glob engine for read-only tools only; mutations stay on prefix validation.
