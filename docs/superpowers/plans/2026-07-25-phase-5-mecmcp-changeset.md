# Phase 5 — `mecmcp-changeset` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extract two-person change control from `rustpanosmcp` into a shared crate so both servers get fingerprint-bound planning, independent approval, and indeterminate recovery. The extraction must preserve `/var/lib/rust-panosmcp/mutation-state.json` on LXC 608 without data loss or schema breakage, and it must fit Junos NETCONF candidate/commit as naturally as it fits PAN-OS XPath set/delete + commit.

**Architecture:** Generalize `rust-panosmcp-core/src/mutation.rs` (2,234 lines) behind a `DeviceTransaction` trait. PAN-OS and Junos each implement the trait over their native protocols. The shared crate manages lifecycle state, two-principal enforcement, approval TTLs, indeterminate recovery, and atomic persistence. Every vendor-specific concern — device vocabulary, metric names, commit comment format, admin scope revert — is a trait method or a constructor parameter, never baked into the crate.

**Tech Stack:** serde, serde_json, sha2, getrandom, tokio (for async trait and Mutex), tempfile (for atomic writes).

---

## Global Constraints

Inherited from [`PLAN.md`](../../../PLAN.md):

- **Edition 2024, MSRV 1.88.**
- **Workspace lints:** `missing_docs = "warn"`, `unsafe_code = "forbid"`, `clippy::all = "warn"` (priority -1), `dbg_macro = "deny"`, `todo = "deny"`, `unwrap_used = "warn"`.
- **No breaking change to on-disk `tokens.json` or `devices.json`.**
- **No breaking change to the MCP tool surface** of either server.
- **Licence:** MIT. **Naming:** `mecmcp-` crate prefix.

### Phase 5 critical constraints

- **The production state file on LXC 608 must not be corrupted, truncated, or replaced with an empty file.** `/var/lib/rust-panosmcp/mutation-state.json` holds approval evidence and indeterminate recovery state. Any migration ships with a compatible read path that accepts both the old and new schema. Field renames use serde aliases; the old spelling keeps working and stays tested.
- **Approval evidence is the product.** The approve event captures `change_set_id`, `digest`, `owner`, and `approver` as independent principals. A schema change that loses any of these is wrong. The digest binds `(owner, device, pre-fingerprint, ordered-actions)` — that exact tuple must remain the digest input across any refactor.
- **Two principals must be genuinely distinct.** The approver-is-owner check (`record.owner == approver`) enforces separation of duties. `Principal` is an enum in `mecmcp-audit` specifically to prevent token-name forgery. The changeset crate must compare principals by that type, never by string, and it must document the requirement that the consumer pass typed principals.
- **Indeterminate outcomes are recoverable but never silently resolved.** A commit RPC that times out mid-flight leaves unknown remote state. The current code marks it `indeterminate`, persists recovery instructions, and exposes `resolve_persisted_operation(confirmation: "RESOLVED {id} AS COMMITTED|DISCARDED")` for manual reconciliation. This must carry forward unchanged — no automatic resolution, no best-effort inference.
- **The trait must fit Junos as naturally as PAN-OS.** Junos uses NETCONF `<lock-configuration/>`, `<load-configuration/>`, `<commit/>`, `<rollback/>`, and `<unlock-configuration/>`. PAN-OS uses XPath `set`/`delete`, `<validate>`, and `<commit>` with an admin-scoped partial revert. If the trait as sketched in `PLAN.md` forces awkward adapters, the trait is wrong — adjust it and document the rationale.
- **Consumer-owned choices are parameters.** Device vocabulary ("device" vs "router"), metric names, tool names, admin scope logic, commit comment format — all are owned by the consuming server and must not be hardcoded into the shared crate. The rule: if two consumers would spell it differently, it is a parameter.

---

## What each repo actually has

Measured from source on 2026-07-25. Line counts via `tokei`, excluding tests.

| Concern | rustjunosmcp | rustpanosmcp |
|---|---|---|
| Two-person change control | **absent** | 2,234 lines: plan → approve → apply (mutation.rs) |
| Approval gate | **absent** | digest-bound, separate principals, 15-min TTL |
| Indeterminate recovery | **absent** | `resolve_persisted_operation`, persisted across restarts |
| Lifecycle state | **absent** | 9 states: staging → staged → validating → validated → committing → committed/discarded/failed/indeterminate |
| Fingerprinting | **absent** | SHA-256 over candidate subtrees, bound into digest |
| Persistence | **absent** | `/var/lib/rust-panosmcp/mutation-state.json`, atomic write + fsync |
| Single-action stage | **absent** | `stage_config`, fingerprint-guarded, config lock |
| Change-set apply | **absent** | multi-action, all-or-nothing with auto-revert |
| Commit | `load_and_commit_config`, one-shot | detached worker, job polling, lock release tracking |
| Commit-check | `commit_check_config` | validate step in lifecycle |
| Rollback | `rollback_config`, load archive N + commit | admin-scoped partial revert |
| Discard | **candidate_transaction.rs** rollback-0 | admin-scoped partial revert, lock-aware |
| Audit | attributed via `mecmcp-audit` | inline `tracing::info!(target: "audit")` |

The extraction is heavily asymmetric. PAN-OS contributes the full lifecycle machinery; Junos contributes only the observation that NETCONF candidate/commit is also a guarded transaction and must fit the same trait.

---

## Decisions

**D1 — The trait is `DeviceTransaction`, not `MutationManager`.** The name must telegraph what implementers provide (a way to transact on a device) rather than what the shared crate does (manage mutation state). The Junos and PAN-OS implementers will read the trait signature, not the crate internals.

**D2 — `DeviceTransaction::Action` is an associated type, not a trait.** PAN-OS actions are `{action: Set|Delete, xpath: String, element: Option<String>, confirmation: Option<String>}`. Junos actions are `{payload: ConfigPayload, rollback_source: Option<u32>}`. The two have no common interface beyond serde; forcing a shared trait would abstract nothing and couple the vendors. The crate requires only `Serialize + DeserializeOwned + Send + Sync`.

**D3 — The fingerprint is opaque to the shared crate.** PAN-OS fingerprints SHA-256 candidate subtrees listed in inventory policy. Junos would fingerprint what? The entire candidate? A stanza? The mechanism is vendor-specific. The crate stores it as `String`, validates the `sha256:<64-hex>` format, and compares for equality. Implementations decide what to hash.

**D4 — `stage()` returns a vendor-defined `Staged` type, not the fingerprint alone.** PAN-OS needs to communicate `config_lock_held: bool` and `operation_id` back to the tool for later lifecycle calls. Junos may need different metadata. The trait returns `Staged` as an associated type. The shared crate passes it back opaque to `diff`/`validate`/`commit`.

**D5 — `commit()` takes `Attribution`, not a principal string.** The crate depends on `mecmcp-audit` for `Attribution`, which carries `principal: Principal`, `actor_type`, `agent`, `on_behalf_of`, `change_ref`, and `request_id`. This makes `Attribution` available to the device so Junos can write `commit comment "CHG0012345 by alice via claude-opus-5"` and PAN-OS can write `<commit><description>...</description></commit>`. The crate serializes the attribution into the persisted operation record for audit.

**D6 — The state file schema is already versioned. Adopt it unchanged; do not migrate.**

Verified against `rust-panosmcp-core/src/mutation.rs` on `main`, not inferred:

```rust
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OnDiskMutationState {   // mutation.rs:499
    version: u32,
    state: MutationState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationState {          // mutation.rs:490
    #[serde(default)]
    operations: BTreeMap<String, OperationRecord>,
    #[serde(default)]
    change_sets: BTreeMap<String, ChangeSetRecord>,
}
```

and the loader already rejects anything else (`mutation.rs:1977`):

```rust
if on_disk.version != 1 {
    return Err(PanosMcpError::Configuration(format!(
        "unsupported mutation state version {}", on_disk.version)));
}
```

So the wrapper exists, `version: 1` is enforced, and the file on LXC 608 is
already in this shape. **There is no bare `{"operations": ...}` format in the
field and no migration to write.** An earlier draft of this decision proposed
adding the wrapper via `#[serde(alias = "state")]`; that would have been a
no-op at best and a regression of a working version gate at worst. The shared
crate adopts this layout as-is and keeps `version: 1`.

**The real hazard is `deny_unknown_fields`, on *both* structs.** It makes the
schema strictly closed in both directions:

- Adding any field to the shared `ChangesetState` produces a file that an
  **older** binary cannot read at all — it fails the whole load, not just the
  new field. On a server holding approval history, a failed load is an outage.
- So a field addition is a **version bump**, not an additive change. Bumping to
  `version: 2` is the honest signal, and the loader must then accept 1 and 2
  and upgrade 1 on read.

Any task in this plan that adds a field to the persisted state must say which
version it lands in and how a v1 file is read. Rollback matters as much as
upgrade here: 608 has no standby, so the recovery path is a Proxmox snapshot
restore, and a state file the previous binary cannot parse defeats it.

**D7 — `rollback()` is a trait method, not a tool-level concern.** Junos `rollback_config` loads archive N and commits it as a single action. PAN-OS has no archive-based rollback; it reverts candidate changes attributed to an admin. Both are vendor-specific, but both are part of the transaction lifecycle. The trait exposes `async fn rollback(&self, to: RollbackRef) -> Result<Outcome, Self::Error>` where `RollbackRef` is an enum: `RollbackRef::Archive(u32)` for Junos, `RollbackRef::CandidateRevert` for PAN-OS. The shared crate does not call it directly; the consuming server's `rollback_*` tool invokes it.

**D8 — Indeterminate recovery is a free function, not a trait method.** `resolve_persisted_operation(path, operation_id, disposition, confirmation)` operates on the state file directly and does not talk to a device. It is a manual recovery tool, not part of the device transaction. It stays a crate-level function, not a method on `ChangesetCoordinator`.

**D9 — Approval TTL is a constructor parameter, not a constant.** PAN-OS uses 15 minutes. A future consumer may want 5 or 60. The shared crate takes `approval_ttl: Duration` in `ChangesetCoordinator::load()`.

**D10 — Operation and change-set capacities are constructor parameters.** PAN-OS uses `MAX_OPERATIONS = 1024`, `MAX_CHANGE_SETS = 1024`, `MAX_CHANGE_SET_ACTIONS = 64`. These are operational policy, not crate constants. The coordinator takes `OperationLimits { max_operations, max_change_sets, max_actions_per_set, max_state_bytes }`.

**D11 — The crate does not validate XPaths, config payloads, or admin names.** Those are vendor concerns. PAN-OS validates XPath roots against inventory policy; Junos validates config format. The shared crate validates only the lifecycle invariants (digest match, fingerprint match, state transitions, expiry). Payload validation is the trait implementation's job.

**D12 — Metrics are not baked into the changeset crate.** PAN-OS has no Prometheus metrics for mutation; Junos will add them when it gains the lifecycle. Metric names would be consumer-specific (`junosmcp_change_set_approvals_total` vs `panosmcp_...`). The crate exposes no metrics; consumers instrument their own tool handlers.

---

## File Structure

New crate `crates/mecmcp-changeset/`:

| File | Responsibility |
|---|---|
| `lib.rs` | Public API: `DeviceTransaction` trait, `ChangesetCoordinator`, `resolve_persisted_operation`, input/output types |
| `transaction.rs` | `DeviceTransaction` trait definition and associated types (`Staged`, `Diff`, `Validation`, `CommitOutcome`, `RollbackRef`) |
| `coordinator.rs` | `ChangesetCoordinator` — in-memory state, endpoint locks, insert/update/persist |
| `lifecycle.rs` | State machines: `LifecycleState`, `ChangeSetState`, transition rules |
| `persistence.rs` | `read_state()`, `write_state()`, `validate_state()` — atomic write, mode checks, schema versioning |
| `changeset.rs` | Change-set CRUD: `create()`, `approve()`, `apply()`, `get()` |
| `operation.rs` | Operation state: `OperationRecord`, fingerprint guards, policy signature |
| `digest.rs` | Digest computation: `change_set_digest()`, `fingerprint_from_parts()`, `validate_digest()` |
| `recovery.rs` | `resolve_persisted_operation()` — manual reconciliation for indeterminate state |
| `types.rs` | Input/output DTOs, limits config |

---

## Task sequence

Each task ends green and independently reviewable.

### Task 1 — Scaffold and persistence

- [ ] Create `crates/mecmcp-changeset/` with `Cargo.toml` (edition 2024, MSRV 1.88, workspace lints, MIT license, depends on `mecmcp-audit`, `serde`, `serde_json`, `sha2`, `getrandom`, `tokio`, `tempfile`).
- [ ] Port `persistence.rs`: `read_state()`, `write_state()`, `validate_state()` from mutation.rs lines 1929-2086. Port `OnDiskChangesetState` as `{ version: u32, state: ChangesetState }` with `#[serde(deny_unknown_fields)]` — this is the shape already on disk (see D6). Keep the `version != 1` rejection. Add no alias and no migration: there is no older format in the field.
- [ ] Port `digest.rs`: `change_set_digest()`, `validate_digest()`, `validate_fingerprint()`, `bytes_hex()`, `digest_hex()` from mutation.rs lines 1719-2109.
- [ ] Test: write a `{"version": 1, "state": {...}}` file, read it back, assert it round-trips byte-identically. Assert `{"version": 2, ...}` is **rejected** with a message naming the version. Assert a bare `{"operations": {}}` file is **rejected** — it is not a legacy format to support, and `deny_unknown_fields` plus the missing `version` field means accepting it would require deliberately weakening the schema. Verify `sha256:<64 lowercase hex>` validation rejects uppercase, rejects 63 chars, rejects `sha512:`.

### Task 2 — Lifecycle state machines

- [ ] Port `lifecycle.rs`: `LifecycleState`, `ChangeSetState` enums from mutation.rs lines 377-454. Add `#[must_use]` to state-transition methods.
- [ ] Port `types.rs`: `OperationLimits`, `Fingerprint` (newtype over `String` with validation), `OperationId` (newtype over `String`, 64 hex chars).
- [ ] Test: round-trip every `LifecycleState` and `ChangeSetState` through serde as `"staging"`, `"planned"`, etc. Assert `terminal()` returns true only for `Committed`/`Discarded`.

### Task 3 — `DeviceTransaction` trait

- [ ] Define `transaction.rs`: `DeviceTransaction` trait with associated types `Action`, `Staged`, `Diff`, `Validation`, `CommitOutcome`, `Error`. Methods: `async fn fingerprint()`, `async fn stage(actions: &[Action])`, `async fn diff(&self, staged: &Staged)`, `async fn validate(&self, staged: &Staged)`, `async fn commit(&self, staged: &Staged, attribution: &Attribution)`, `async fn rollback(&self, to: RollbackRef)`.
- [ ] Define `RollbackRef` enum: `Archive(u32)`, `CandidateRevert`, `Custom(String)`.
- [ ] Define `CommitOutcome` enum: `Reconciled { succeeded: bool, job_id: Option<String>, details: Option<String> }`, `Detached { job_id: Option<String> }`, `Indeterminate { reason: String }`.
- [ ] Document the trait contract: implementations must guarantee fingerprint stability (no background changes), stage must be atomic (all actions or none), commit must return `Indeterminate` on timeout/cancel rather than guess.

### Task 4 — Operation and change-set records

- [ ] Port `operation.rs`: `OperationRecord`, `require_operation_fingerprint()`, `require_operation_policy()`, `mutation_policy_signature()` from mutation.rs lines 411-1668. Replace PAN-OS `MutationPolicy` with a generic `PolicySignature: AsRef<str>` so implementations can pass any stable policy identifier.
- [ ] Port `changeset.rs`: `ChangeSetRecord`, `change_set_digest()`, `validate_change_set_actions()` from mutation.rs lines 456-1716. Remove XPath validation; that stays in the PAN-OS implementation. The shared crate validates only: non-empty actions, `<= max_actions_per_set`, serialized size `<= max_change_set_bytes`.
- [ ] Test: compute a digest for `(owner, device, fingerprint, actions)`, assert changing any one component changes the digest. Verify a change set with 0 actions is rejected, and one with 65 actions (over the 64 limit) is rejected.

### Task 5 — Coordinator and endpoint locking

- [ ] Port `coordinator.rs`: `ChangesetCoordinator`, `device_guard()`, `insert()`, `update()`, `remove()`, `insert_change_set()`, `update_change_set()`, `change_set()` from mutation.rs lines 505-736.
- [ ] Take `OperationLimits` and `approval_ttl: Duration` as constructor parameters in `ChangesetCoordinator::load(path, limits, approval_ttl)`.
- [ ] On load, mark in-flight operations (`Staging`, `Validating`, `Committing`) as `Indeterminate` and in-flight change sets (`Applying`) as `Failed`, then persist the recovery. This is the restart-recovery logic from lines 537-559.
- [ ] Test: insert an operation, restart the coordinator (drop and reload from disk), assert the operation persists. Insert an operation in `Staging`, restart, assert it becomes `Indeterminate`. Verify `device_guard()` serializes concurrent access to the same endpoint.

### Task 6 — Change-set lifecycle tools

- [ ] Implement `ChangesetCoordinator::create_change_set(device, actions, owner, expected_fingerprint, policy_signature)` from mutation.rs lines 754-819. Returns `ChangeSetOutput`.
- [ ] Implement `ChangesetCoordinator::approve_change_set(change_set_id, device, approver, expected_digest)` from mutation.rs lines 821-895. Enforces `record.owner != approver`, `state == Planned`, `now < expires_at`, `digest == expected`. Returns `ChangeSetOutput`.
- [ ] Implement `ChangesetCoordinator::change_set_status(change_set_id, device)` from mutation.rs lines 899-913. Auto-expires if `now >= expires_at`.
- [ ] Test the approval gate: create a change set as "alice", attempt approve as "alice" (must fail), approve as "bob" (succeeds), attempt second approval (must fail). Verify expired change sets transition to `Expired` on status poll.

### Task 7 — Change-set apply

- [ ] Implement `ChangesetCoordinator::apply_change_set<T: DeviceTransaction>(change_set_id, device, owner, expected_digest, expected_fingerprint, transaction: &T, attribution: &Attribution)` from mutation.rs lines 916-1155. This is the largest method: acquires device guard, validates the approval is fresh, stages all actions via `transaction.stage()`, handles partial failure with auto-revert, persists `Applying` → `Applied` or `Failed`.
- [ ] Return `ApplyOutput { operation_id, before_fingerprint, after_fingerprint, staged: T::Staged }` on success.
- [ ] Test (requires a mock `DeviceTransaction`): create, approve, apply a 2-action change set. Verify `operation_id` is recorded in the change-set record. Apply the same change set again concurrently (must fail). Stage a change set where the second action fails; verify the state transitions to `Failed` and the change set is not marked `Applied`.

### Task 8 — Single-operation lifecycle (stage/diff/validate/commit/discard)

- [ ] Implement `ChangesetCoordinator::stage_operation<T: DeviceTransaction>(device, owner, expected_fingerprint, transaction: &T, policy_signature)` wrapping `transaction.stage()`. Returns `StageOutput { operation_id, staged, before_fingerprint, after_fingerprint }`.
- [ ] Implement `ChangesetCoordinator::diff_operation<T: DeviceTransaction>(operation_id, device, owner, expected_fingerprint, transaction: &T)`. Validates the operation fingerprint matches, calls `transaction.diff(staged)`.
- [ ] Implement `ChangesetCoordinator::validate_operation<T: DeviceTransaction>(operation_id, device, owner, expected_fingerprint, transaction: &T)`. Validates fingerprint, calls `transaction.validate(staged)`, transitions `Staged` → `Validating` → `Validated` or `Failed`.
- [ ] Implement `ChangesetCoordinator::commit_operation<T: DeviceTransaction>(operation_id, device, owner, expected_fingerprint, transaction: &T, attribution: &Attribution)`. Spawns a detached worker (or runs to completion if not cancelled), polls the commit job, handles `Indeterminate` on lock-release failure.
- [ ] Implement `ChangesetCoordinator::discard_operation<T: DeviceTransaction>(operation_id, device, owner, expected_fingerprint, transaction: &T)`. Calls `transaction.rollback(RollbackRef::CandidateRevert)`, releases lock if held, transitions to `Discarded`.
- [ ] Test: stage, diff, validate, commit a single operation. Verify a commit timeout leaves the operation `Indeterminate`. Verify discard after a failed validation succeeds and releases the lock.

### Task 9 — Indeterminate recovery

- [ ] Port `recovery.rs`: `resolve_persisted_operation(path, operation_id, disposition, confirmation)` from mutation.rs lines 323-375. The confirmation must be `"RESOLVED {operation_id} AS COMMITTED"` or `"RESOLVED {operation_id} AS DISCARDED"` exactly.
- [ ] Test: stage an operation, mark it `Indeterminate` manually, resolve it with the wrong confirmation (must fail), resolve it with the correct confirmation (succeeds), attempt to resolve it again (must fail because it is no longer `Indeterminate`).

### Task 10 — PAN-OS migration to shared crate

- [ ] In `rustpanosmcp`, implement `DeviceTransaction` for `PanosClient`. `Action` is the existing `ChangeSetAction`. `fingerprint()` is the existing `candidate_fingerprint()` function. `stage()` wraps the XPath set/delete loop. `diff()` calls `<show><config><list><change-summary/></list></config></show>`. `validate()` runs `<validate>` and polls the job. `commit()` runs the partial commit and polls the job, returns `Indeterminate` on lock-release failure. `rollback()` runs `<revert><config><partial><admin>...</admin></partial></revert>`.
- [ ] Replace `rust-panosmcp-core/src/mutation.rs` with thin wrappers over `mecmcp-changeset`. The tool handlers (`create_panos_change_set`, `approve_panos_change_set`, `apply_panos_change_set`, `stage_panos_config`, `diff_panos_candidate`, `validate_panos_candidate`, `commit_panos_candidate`, `discard_panos_candidate`, `get_panos_operation`) become 10-50 line functions calling the coordinator.
- [ ] Migrate the state file on first run: if `mutation-state.json` exists and has no `version` key, wrap it in `{"version": 1, "state": <contents>}` atomically before loading. Log the migration.
- [ ] Exit: all 62 PAN-OS tests pass, the mutation lifecycle test in `mutation_lifecycle.rs` still validates the approval audit event, and `/var/lib/rust-panosmcp/mutation-state.json` on LXC 608 loads successfully after a restart.

### Task 11 — Junos implementation

- [ ] In `rustjunosmcp`, implement `DeviceTransaction` for the Junos session. `Action` is `{payload: ConfigPayload, rollback_source: Option<u32>}`. `fingerprint()` returns a SHA-256 of the entire candidate via `<get-configuration database="candidate"/>`. `stage()` locks, loads the payload or rollback archive, diffs. `validate()` runs `<commit-check/>`. `commit()` runs `<commit><log>attribution</log></commit>`, waits for the operation to complete (Junos commits are synchronous). `rollback()` loads `<load-configuration rollback="N"/>` and commits.
- [ ] Add four new tools: `create_junos_change_set`, `approve_junos_change_set`, `apply_junos_change_set`, `get_junos_change_set_status`. These mirror the PAN-OS tools but use Junos `Action` types.
- [ ] Add `discard_junos_candidate` wrapping `rollback(RollbackRef::CandidateRevert)`.
- [ ] Exit: create a 2-action change set on a vSRX lab device, approve it with a second token, apply it, verify `show system commit` on the device names the attribution. Verify `discard_junos_candidate` reverts uncommitted changes.

### Task 12 — Documentation and changelog

- [ ] Write `crates/mecmcp-changeset/README.md` documenting the trait contract, the state-file schema, the approval workflow, and the indeterminate recovery procedure.
- [ ] Document the PAN-OS → Junos asymmetry: PAN-OS contributed the lifecycle, Junos consumed it. Future vendors implement the trait and get the workflow for free.
- [ ] Add `CHANGELOG.md` entries to `mecmcp-changeset` (initial 0.1.0 release), `rustpanosmcp` (migration to shared crate, state file schema upgrade), and `rustjunosmcp` (two-person change control added).
- [ ] Update `mecmcp/PLAN.md` to mark Phase 5 complete.

---

## The `DeviceTransaction` trait (detailed)

This is the interface both vendors must implement. The sketch in `PLAN.md` is a starting point; the exact signature follows from the above decisions.

```rust
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use serde::{Deserialize, Serialize};

/// Fingerprint-bound change transaction on a vendor device.
#[async_trait]
pub trait DeviceTransaction: Send + Sync {
    /// Vendor-specific action type. PAN-OS: XPath set/delete. Junos: config payload.
    type Action: Serialize + for<'de> Deserialize<'de> + Send + Sync;

    /// Opaque staged-transaction handle returned by `stage()` and passed to later steps.
    type Staged: Send + Sync;

    /// Diff output. Vendor-specific format (XML, text, JSON).
    type Diff: Serialize + Send + Sync;

    /// Validation result. Must report success, job ID, and details.
    type Validation: Serialize + Send + Sync;

    /// Transaction-specific error. Must be `std::error::Error + Send + Sync + 'static`.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Compute a stable fingerprint over the configuration state this transaction will mutate.
    /// PAN-OS: SHA-256 over candidate subtrees. Junos: SHA-256 over entire candidate.
    /// Must be stable: calling twice without intervening mutation returns the same value.
    async fn fingerprint(&self) -> Result<String, Self::Error>;

    /// Stage one or more actions atomically. All succeed or all fail.
    /// Returns a vendor-specific staged handle the coordinator passes back to later steps.
    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error>;

    /// Compute a diff of the staged changes.
    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error>;

    /// Validate the staged transaction. PAN-OS: `<validate>`. Junos: `<commit-check/>`.
    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error>;

    /// Commit the validated transaction. Must wait for the operation to complete or return
    /// `CommitOutcome::Indeterminate` if the outcome is unknown (timeout, cancel, lock-release failure).
    /// `attribution` carries the principal, change reference, agent identity, and request ID for
    /// on-device commit logs and audit.
    async fn commit(
        &self,
        staged: &Self::Staged,
        attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error>;

    /// Rollback. Junos: load archive N. PAN-OS: admin-scoped candidate revert.
    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error>;
}

/// Rollback target.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackRef {
    /// Junos: load rollback archive N and commit.
    Archive(u32),
    /// PAN-OS: revert candidate changes attributed to the configured admin.
    CandidateRevert,
    /// Vendor-specific: implementation-defined rollback (e.g., named checkpoint).
    Custom(String),
}

/// Commit outcome or detached/indeterminate acknowledgement.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case", tag = "disposition")]
pub enum CommitOutcome {
    /// Commit reached a known terminal state.
    Reconciled {
        succeeded: bool,
        job_id: Option<String>,
        details: Option<String>,
    },
    /// Caller cancelled; worker continues in background. Poll operation status.
    Detached { job_id: Option<String> },
    /// Outcome is unknown (timeout, cancel, lock-release failure). Manual reconciliation required.
    Indeterminate { reason: String },
}

/// Rollback outcome.
#[derive(Debug, Clone, Serialize)]
pub struct RollbackOutcome {
    pub succeeded: bool,
    pub details: Option<String>,
}
```

Junos fit check:

- `fingerprint()`: `<get-configuration database="candidate"/>`, SHA-256 the XML.
- `stage()`: `<lock-configuration/>`, `<load-configuration/>`, `<get-configuration/>` (for diff), return an opaque struct holding the session and the diff.
- `diff()`: return the diff captured during stage.
- `validate()`: `<commit-check/>`, wait for the operation to complete (synchronous on Junos).
- `commit()`: `<commit><log>{attribution}</log></commit>`, wait for completion. Junos commits are synchronous; `Detached` is not used. If the commit RPC times out, return `Indeterminate`.
- `rollback()`: `<load-configuration rollback="{N}"/>`, `<commit/>`.

PAN-OS fit check:

- `fingerprint()`: SHA-256 over `<show><config>running</config></show>` for each `allowed_xpath_root`.
- `stage()`: acquire config lock, loop over actions calling `type=config&action=set|delete&xpath=...`, capture fingerprint before/after.
- `diff()`: `<show><config><list><change-summary/></list></config></show>`.
- `validate()`: `<validate><full/></validate>`, poll job.
- `commit()`: `<commit><partial><admin>...</admin></partial></commit>`, poll job, release lock, return `Indeterminate` if lock release fails.
- `rollback()`: `<revert><config><partial><admin>...</admin></partial></config></revert>`.

Both fit naturally. The trait does not force either into an awkward adapter.

---

## Exit criteria

- `mecmcp-changeset` compiles clean, passes `cargo clippy -- -D warnings`, and has 100% of its public API documented.
- `rustpanosmcp` test suite (62 tests) passes. The `mutation_lifecycle.rs` test still validates the approval audit event contains `change_set_id`, `digest`, `owner`, and `action_count`.
- `rustjunosmcp` test suite (987 tests) passes. Four new tests cover Junos change-set create/approve/apply/status.
- Lab verification: create a 2-action change set on vSRX `srx-01` as token "writer", approve it as token "reviewer", apply it, run `show system commit`, verify the commit log names the attribution. Verify `discard_junos_candidate` reverts uncommitted changes and releases the lock.
- PAN-OS lab verification: `/var/lib/rust-panosmcp/mutation-state.json` on LXC 608 loads successfully after the server restarts with the new crate. An existing approved change set created before the migration remains approved and applyable.
- `cargo deny check` passes in all three repos.
- Snapshot LXC 608 before deploying the PAN-OS migration. If the migration fails, roll back to the snapshot. Document the rollback procedure in the phase CHANGELOG.

---

## Risk mitigation

| Risk | Mitigation |
|---|---|
| Corrupting `/var/lib/rust-panosmcp/mutation-state.json` on LXC 608 | Snapshot 608 before deploying. The format does not change — the shared crate adopts the existing `{"version": 1, "state": {...}}` layout unchanged (D6). Write a property test asserting any valid v1 file round-trips through read+write byte-identically. Because `deny_unknown_fields` makes the schema closed in both directions, a rollback to the previous binary must also be tested: restore the snapshot and confirm the older build still loads a file the newer build wrote. |
| Losing approval evidence in the migration | The `ChangeSetRecord` fields `{id, owner, device, digest, approver, actions}` are load-bearing and must survive the migration byte-for-byte. Write a test loading a v1 state file with an approved change set, assert every field matches after deserialization. |
| The trait does not fit Junos candidate/commit | Task 11 implements the Junos side and validates the fit. If `DeviceTransaction` needs adjustment (e.g., an additional method for Junos-specific ephemeral configuration), adjust the trait in Task 3 and document the rationale. Do not ship a forced adapter. |
| Breaking the two-principal check | The crate must compare principals by `mecmcp_audit::Principal`, not by string. Write a test where two tokens with the same name but different `Principal` variants (e.g., `Principal::Token("alice")` vs `Principal::Oidc("alice")`) are treated as distinct. |
| Indeterminate recovery silently auto-resolving | `resolve_persisted_operation()` requires exact confirmation: `"RESOLVED {id} AS COMMITTED"` or `"... AS DISCARDED"`. Write a test asserting partial matches ("RESOLVED", "AS COMMITTED") are rejected. |

---

## What Junos gains

Before Phase 5, `rustjunosmcp` has:

- `load_and_commit_config`: load + commit in one shot, no review.
- `commit_check_config`: validate-only, no persistence.
- `rollback_config`: load archive N + commit in one shot, no review.

After Phase 5, `rustjunosmcp` gains:

- `create_junos_change_set`: plan a multi-action change, bind it to a fingerprint and digest, persist it.
- `approve_junos_change_set`: independent principal approves the exact digest.
- `apply_junos_change_set`: the owner applies the approved plan as a single atomic operation.
- `get_junos_change_set_status`: poll lifecycle state, check expiry.
- `discard_junos_candidate`: revert uncommitted changes, release lock.

This is the two-person change control that does not exist on Junos today. The workflow:

1. Alice (writer token) runs `create_junos_change_set` with a 2-stanza config. Gets back `{change_set_id, digest}`.
2. Bob (reviewer token) runs `approve_junos_change_set` with the `change_set_id` and `digest`. Approval persists.
3. Alice runs `apply_junos_change_set`. The config stages atomically, validates, commits with Alice's attribution in the commit log.
4. `show system commit` on the vSRX shows `"CHG0012345 by alice via claude-opus-5"`.

If Alice's apply times out during commit, the operation is marked `Indeterminate`, and an operator runs `resolve_persisted_operation` after checking `show system commit` and `show configuration` on the device.
