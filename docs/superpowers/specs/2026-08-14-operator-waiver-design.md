# Operator waivers: a waiver record that can say what kind it is

**Issue:** mecmcp#275 · **Date:** 2026-08-14 · **Target release:** 0.10.0 (breaking)

## Problem

`WaiverRecord` carries one field:

```rust
pub struct WaiverRecord {
    pub reason: String,
}
```

and the waived-approval digest binds the literal string `"lab-mode-waived"`
(`digest.rs:215`). So **every waiver is a lab-mode waiver by construction.** The
`reason` field is free text that nothing verifies and nothing binds.

Two different things need recording, and today they are indistinguishable:

- **`--lab-mode`** — a process-start flag for disposable rigs. The guardrail is
  switched **off**. Every override is expected.
- **A time-boxed operator waiver** — a deliberate, ticketed exception naming
  specific targets with an expiry, granted out of band. The guardrail is **on**;
  this is one authorised exception to it.

Recording the second as `lab-mode-waived` tells an auditor that someone turned
the control off, when in fact someone granted a bounded exception under it.
Those are different events and they must not share a representation.

`rustproxmoxmcp` needs both paths for its 0.3 (destructive operations); this
blocks that milestone, not its 0.1 or 0.2.

## What the fleet actually contains

Surveyed 2026-08-14 across LXC 950, 960, 601, 606 and 600:

| Host | State file | Schema | Change sets | Waivers |
|---|---|---|---|---|
| 950 | `/var/lib/jmcp/changeset-state.json` | v2 | **28** | **0** |
| 960 | `/var/lib/rust-panosmcp/mutation-state.json` | v1 | live | **0** |
| 601 | `/var/lib/rust-panosmcp/mutation-state.json` | v1 | live | **0** |
| 606 | `/var/lib/rustsdcmcp/changeset-state.json` | v2 | live | **0** |
| 600 | `/var/lib/jmcp/changeset-state.json` | v2 | live | **0** |

**There is not one waiver record in the estate.** That is the fact that makes
this change cheap: altering the waiver digest invalidates nothing that exists.
It is also the reason the neighbouring approval digest is explicitly *not*
touched here — 950 alone holds 28 change sets whose approval digests are
verified on every load.

## Approach

### §1 The record gains three digest-bound fields

```rust
pub enum WaiverKind {
    /// `--lab-mode`: the control is switched off for this process.
    LabMode,
    /// A waiver granted out of band, in a file the service cannot write.
    OperatorFile,
    /// A waiver granted in band, through a tool call by a second principal.
    OperatorTool,
}

pub struct WaiverRecord {
    pub kind: WaiverKind,
    pub reason: String,
    pub expires_at_unix: Option<u64>,
    pub ticket: Option<String>,
}
```

**Both operator channels are represented, and stay distinguishable.** A waiver
granted by editing a root-owned file is a different claim from one granted by a
second principal calling a tool: the first cannot be reached by the calling
agent at all, the second can if that agent holds two credentials. An auditor
must be able to tell which happened without inferring it from context.

mecmcp supplies the **vocabulary and the verification**, not the granting
mechanism. Reading a waiver file, hot-reloading it on SIGHUP, and deciding which
targets it covers all belong to the consumer — `rustproxmoxmcp` describes its
own file format in its 0.3 design. This crate's job is to make the resulting
record unforgeable and self-describing.

### §2 Bind all three fields, not just `kind`

The issue argues for binding `kind`. That is necessary and not sufficient.

- **`expires_at_unix` must be bound.** An expiry that can be edited after the
  fact is not a time box. This is the field that turns "an exception" into "a
  bounded exception", and unbound it does neither.
- **`ticket` must be bound.** Its only purpose is to point an auditor at the
  change-control record that authorised this. A pointer that can be rewritten
  afterwards misleads precisely the reader it exists for.

### §3 A new digest function with an unambiguous encoding

```rust
pub fn compute_waiver_digest_v3(
    change_set_id: &str,
    plan_digest: &str,
    owner: &str,
    waived_at_unix: u64,
    waiver: &WaiverRecord,
) -> String
```

It hashes `serde_json::to_vec` of a tuple, matching what `change_set_digest`
already does (`digest.rs:41`), rather than the `|`-joined string the current
waiver digest uses. A serialized tuple encodes lengths, so no field value can
shift a boundary.

The tuple leads with a domain-separation marker (`"mecmcp-waiver-v3"`) so a
waiver digest can never collide with an approval digest — the role the literal
`"lab-mode-waived"` plays today.

`compute_waiver_digest` is **kept, not removed.** It is the only thing that can
verify a v1 or v2 record. It gains documentation saying so, and that new code
must not call it.

**This also closes the separator ambiguity for waivers.** The same weakness in
`compute_approval_digest` is filed as **mecmcp#283** and deliberately left
alone: waivers have zero records to migrate, approvals have thirty.

### §4 Schema v3, with v1 and v2 still readable

`persistence.rs` currently accepts `version` 1 and 2. It gains 3:

- **Write:** always v3.
- **Read v3:** verify waivers with `compute_waiver_digest_v3`.
- **Read v1/v2:** verify waivers with `compute_waiver_digest`, and deserialize a
  bare `{ "reason": ... }` into `WaiverRecord { kind: LabMode, reason, expires_at_unix: None, ticket: None }`.

The v1/v2 waiver path is, on today's evidence, unreachable — no such record
exists. It is implemented anyway, because "no waiver exists in the fleet I
surveyed" is a statement about five hosts on one afternoon, not a property of
the format.

### §5 An expired waiver is not an approval

This is the part that makes the feature real rather than decorative.

`apply.rs` gates on `state != ChangeSetState::Approved` at lines 178 and 241.
A change set approved by a waiver whose `expires_at_unix` has passed must be
refused there, with a distinct error naming expiry — not a generic "not
approved", which would send an operator looking for the wrong problem.

The clock is the same one that stamps `waived_at_unix`. An expiry in the past
at the moment of waiving is a validation error, not a waiver that is instantly
dead.

### §6 The existing lab-mode path keeps working

`waive_approval` keeps its signature and produces
`WaiverKind::LabMode` with `expires_at_unix: None` and `ticket: None`. No
consumer changes to keep lab mode working; the operator paths are new API a
consumer opts into.

## Consequences

- **Breaking:** `WaiverRecord` gains public fields, so struct-literal
  construction breaks. Consumers that only call `waive_approval` are unaffected.
- **0.10.0**, not 0.9.2 — a public type changes shape and the persisted schema
  moves.
- **No data migration.** Zero waiver records exist; v1/v2 files keep loading.
- **Unblocks `rustproxmoxmcp` 0.3.** It can stop keeping a private waiver record
  alongside the change set, which today loses the link between the approval and
  the reason it was waived.

## Testing

1. **Digest binding, per field.** Change `kind`, then `expires_at_unix`, then
   `ticket`, and assert the digest changes each time. A record whose `kind` can
   be edited without invalidating the digest is the exact defect being fixed.
2. **Encoding ambiguity.** Assert that a `reason` or `ticket` containing `|`
   cannot produce the digest of a different field arrangement — the property the
   old encoding lacked.
3. **Domain separation.** Assert a waiver digest never equals an approval digest
   over the same inputs.
4. **v1/v2 read path.** Load a fixture file at each version carrying a bare
   `{"reason": ...}` waiver and assert it verifies and deserializes to
   `LabMode`. Write fixtures by hand; do not generate them with the new code, or
   the test proves only that the new code agrees with itself.
5. **Expiry refuses apply.** A change set waived with a past expiry must be
   refused at `apply`, with the expiry-specific error. **Sabotage-verify this
   one**: remove the expiry check and confirm the test fails. An expiry that
   does not block an apply is worse than no expiry, because the record claims a
   bound that is not enforced.
6. **Lab-mode compatibility.** `waive_approval` still produces a valid,
   verifiable waiver and still refuses when lab mode is off.

## Out of scope

- **The approval digest's separator ambiguity** — mecmcp#283. Thirty live
  records; needs its own migration.
- **The waiver file format, its reload, and target matching** — consumer-side,
  `rustproxmoxmcp` 0.3.
- **Who may call a tool-granted waiver.** The record can express
  `OperatorTool`; enforcing a different-principal rule for it is a consumer
  authorization decision, and this crate should not assume one.

## Open question for implementation

Whether `WaiverKind` should be `#[non_exhaustive]`. It makes adding a fourth
channel later non-breaking, at the cost of forcing a wildcard arm on every
consumer match today. Recommend **yes** — the set of ways an exception can be
granted is exactly the kind of list that grows, and this change exists because
the previous version of it was implicitly a set of one.
