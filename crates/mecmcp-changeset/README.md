# mecmcp-changeset

Fingerprint-bound change-set lifecycle for multi-vendor device automation.

This crate provides vendor-neutral change control with two-person approval, digest-bound approval gates, and indeterminate recovery. It generalizes the PAN-OS mutation lifecycle behind a `DeviceTransaction` trait so both PAN-OS and Junos can use the same workflow without adapters.

## What this crate is for

Device configuration changes require two patterns of change control:

1. **Change-set flow** — a multi-action plan is created, independently approved by a second principal, and then applied atomically. The approval is bound to the exact plan via a SHA-256 digest. This is two-person change control.

2. **Single-operation flow** — one action is staged, diffed, validated, and then either committed or discarded. No approval gate, but the operation is fingerprint-guarded: if the device state changes underneath, the operation is rejected.

Both flows use the same underlying `DeviceTransaction` trait, which abstracts vendor-specific staging, diffing, validation, and commit primitives. The crate coordinates the lifecycles, manages per-device mutual exclusion, and persists state atomically so restart recovery can resolve in-flight operations.

## The two flows

### Change-set flow

Three steps, three principals (owner, approver, owner):

1. **Plan** — the owner calls `create_change_set(device, actions, expected_fingerprint)`. The coordinator computes a digest over `(owner, device, expected_fingerprint, actions)` and persists the plan as `Planned`. The digest is the approval target.

2. **Approve** — a *different* principal calls `approve_change_set(change_set_id, expected_digest)`. The coordinator validates the approver is not the owner, the digest matches exactly, and the approval window has not expired. On success, the change set transitions to `Approved`, and an approval digest is computed over `(change_set_id, plan_digest, owner, approver, approved_at)` and stored for tamper detection.

3. **Apply** — the owner calls `apply_change_set(change_set_id, expected_digest, expected_fingerprint, transaction)`. The coordinator acquires the device guard, validates the approval is fresh, stages all actions through the `DeviceTransaction`, and records the operation. The staged handle is returned to the caller, who then calls `commit_operation()` to finalize.

Lab mode allows single-operator application: `waive_approval(change_set_id, expected_digest)` transitions directly from `Planned` to `Approved`, recording a **waiver** rather than fabricating an approver. The waiver is visible in the JSON: `"approver"` is absent and a `"waived"` object is present, so a waiver can never be mistaken for a genuine two-person approval.

### Single-operation flow

Stage → diff → validate → commit/discard:

```rust
use mecmcp_changeset::{ChangesetCoordinator, DeviceTransaction};
use mecmcp_audit::Attribution;
use tokio_util::sync::CancellationToken;

async fn example<T: DeviceTransaction>(
    coordinator: &ChangesetCoordinator,
    device: &str,
    owner: &str,
    expected_fingerprint: &str,
    endpoint: &str,
    transaction: &T,
    actions: &[T::Action],
    attribution: &Attribution,
    cancellation: &CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    // Stage the operation
    let output = coordinator.stage_operation(
        device,
        owner,
        expected_fingerprint,
        endpoint,
        transaction,
        actions,
        "set",                    // primary action discriminator (vendor-specific)
        Some("/config/example"),  // primary target (vendor-specific)
        "policy-v1",              // policy signature
        cancellation,
    ).await?;

    // Diff (optional)
    let diff = coordinator.diff_operation(
        &output.operation_id,
        device,
        owner,
        &output.after_fingerprint,
        transaction,
        &output.staged,
        cancellation,
    ).await?;

    // Validate
    coordinator.validate_operation(
        &output.operation_id,
        device,
        owner,
        &output.after_fingerprint,
        transaction,
        &output.staged,
        cancellation,
    ).await?;

    // Commit
    use mecmcp_changeset::CommitOptions;
    coordinator.commit_operation(
        &output.operation_id,
        device,
        owner,
        &output.after_fingerprint,
        "policy-v1",  // current policy signature
        transaction,
        &output.staged,
        attribution,
        &CommitOptions::default(),
        cancellation,
    ).await?;

    Ok(())
}
```

## The `DeviceTransaction` contract

Implementers of `DeviceTransaction` must guarantee three things:

### 1. Stage atomicity

`stage(actions)` applies all actions or none. A partial failure (e.g., the second action fails after the first succeeds) must revert the first action before returning an error. A failed revert taints the session — the implementation must mark the session tainted and refuse to pool it.

The coordinator does **not** revert on partial failure. Doing so would be redundant and dangerous: a candidate revert clears *all* uncommitted changes, including pre-existing operator work. The `stage()` contract requires the implementation to clean up its own mess.

### 2. Unlock is separate from rollback

`rollback(CandidateRevert)` reverts the candidate but does **not** release the configuration lock. On PAN-OS the commit lock survives a revert. If the coordinator cleared its `config_lock_held` flag after a rollback, it would be recording something it never verified, and the device would stay locked against every later change while the state file said otherwise.

The trait has an explicit `unlock()` method. The default returns `UnlockOutcome::Unsupported`, which tells the coordinator to leave the lock state alone. PAN-OS implements `unlock()` and issues an explicit unlock RPC; Junos does not need to (the rollback releases the candidate lock).

### 3. Indeterminate honesty

`commit()` must return `CommitOutcome::Indeterminate` rather than guess when the outcome cannot be established. Two cases force this:

- The commit RPC times out. The device may or may not have committed.
- The commit succeeds but the unlock RPC fails. The commit landed, but the lock state is unknown.

An implementation must never silently resolve an unknown outcome as success or failure. The caller persists the indeterminate state and exposes manual reconciliation.

## Lifecycle states

### Operation states

| State | Description | Terminal? |
|-------|-------------|-----------|
| `Staging` | Operation is being staged on the device | No |
| `Staged` | Operation has been staged successfully | No |
| `Validating` | Validation is in progress | No |
| `Validated` | Validation succeeded; ready to commit | No |
| `Committing` | Commit is in progress | No |
| `Committed` | Commit succeeded | **Yes** |
| `Discarded` | Operation was discarded without commit | **Yes** |
| `Failed` | Staging, validation, or commit failed | No |
| `Indeterminate` | Commit outcome unknown; manual reconciliation required | No |

Terminal states (`Committed`, `Discarded`) are evictable from the operation store once capacity is reached. Non-terminal states block the endpoint until resolved.

### Change-set states

| State | Description | Terminal? |
|-------|-------------|-----------|
| `Planned` | Created, awaiting approval | No |
| `Approved` | Approved by a second principal | No |
| `Applying` | Being applied to the device | No |
| `Applied` | Successfully applied | **Yes** |
| `Expired` | Approval window expired | **Yes** |
| `Failed` | Apply failed | **Yes** |

## Restart recovery

On restart, the coordinator marks in-flight operations as `Indeterminate` and in-flight change sets as `Failed`. This is conservative: an operation interrupted mid-commit cannot be resumed (the `T::Staged` handle only existed in memory), so it requires manual reconciliation.

An interrupted `Staged` operation also converts to `Indeterminate` because the staged handle is lost. The operator must check the device state and call `resolve_persisted_operation()` with the correct disposition.

## Operator-facing behaviors

### Interrupted operations require manual resolution

An operation that reaches `Staged` but the process exits before `commit_operation()` or `discard_operation()` completes will convert to `Indeterminate` on restart. The operator must:

1. Check the device state (show candidate, show commit log, show locks).
2. Determine whether the commit succeeded or the candidate was discarded.
3. Call `resolve_persisted_operation(operation_id, disposition, confirmation)`.

The confirmation string must be **exactly** `RESOLVED <operation-id> AS COMMITTED` or `RESOLVED <operation-id> AS DISCARDED`. No trimming, no case-folding. This prevents accidental resolution.

### Lab mode records a waiver, never an approver

When lab mode is enabled, `waive_approval()` transitions a change set from `Planned` to `Approved`, but the approval is recorded as **waived**, not as obtained. In the JSON:

```json
{
  "approver": null,
  "approval": {
    "approver": null,
    "approved_at_unix": 1700000000,
    "digest": "sha256:...",
    "waived": {
      "reason": "lab-mode"
    }
  }
}
```

A waiver can never be mistaken for a genuine two-person approval: the `"approver"` field is absent (or `null`), and a `"waived"` object is present. The waiver digest covers `(change_set_id, plan_digest, owner, waived_at, "lab-mode-waived")`, making it tamper-evident but distinct from genuine approvals.

### Policy signature drift rejects commits

Operations carry a `policy_signature` field that captures the policy version at staging time. Before commit, `commit_operation()` validates the current policy signature matches the staged operation's signature. If they differ, the commit is rejected: the device's authorization policy has changed, and the operation must be re-evaluated.

This prevents a staged operation from committing under a policy that no longer allows it.

## The state file

The state file is versioned JSON with a `{ "version": N, "state": { ... } }` envelope. Two versions exist:

- **Version 1** — the original format. No `attribution` or `rollback_deadline_unix` fields on operation records, no `policy_signature` on change-set records.
- **Version 2** — adds those fields. Written only when a record actually carries a field the version 1 reader does not know.

Both record types are `#[serde(deny_unknown_fields)]`, so an unexpected key makes an older binary reject the entire file. Rolling a release back is a documented deploy step, so version 2 is written **only when necessary** to preserve rollback compatibility.

A deployment that uses none of the version 2 fields keeps producing files the older binary can read.

## Operation record fields

Two fields are vendor-shaped and caller-supplied because a vendor-neutral crate cannot derive them:

- `action` — the vendor's discriminator string (PAN-OS: `"set"` or `"delete"`, Junos: could be `"merge"` or `"replace"`). The deployed PAN-OS reader expects a string here, not the full action object.
- `xpath` — the vendor's primary target (PAN-OS: the XPath being mutated, Junos: `None`). Optional, skipped on serialization if absent.

Writing anything else produces a file the deployed PAN-OS reader cannot parse. These fields are passed to `stage_operation()` and `apply_change_set()` as parameters, and the coordinator writes them verbatim.

## License

MIT

