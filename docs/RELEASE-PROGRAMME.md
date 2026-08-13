# Release programme

**Opened 2026-08-13.** The plan to get `mecmcp` and its consumer servers to a
consistent released state, and the standing decisions that shape it.

## Scope

**In:** `mecmcp` and the six servers that consume it — `rustjunosmcp`,
`rustsdcmcp`, `rustmistmcp`, `rustproxmoxmcp`, `rustsdonpremmcp`,
`rustpanosmcp`.

**Out, and deliberately so:**

| Repo | Why it is out |
|---|---|
| `mechub`, `entsafemcp` | A superset of this programme. Their roadmap governs them; this document does not. |
| `rustunifimcp` | A design document, not a codebase — 59 lines of Rust, one commit, a binary that prints "not implemented". Its `PLAN.md` says it is gated on `mecmcp` crates that now exist, so that gate is stale. Revisit when implementation starts. |
| `rustnetconf` | A NETCONF client library, not an MCP server. Consumed by `rustjunosmcp` at `0.13`. Clean at v0.13.3 with no unreleased commits and no open issues — **verified not a blocker** for the Junos release. Monitor its cadence during that release only. |

---

## Decision: Security Director unifies into one server

**Decided 2026-08-13. Supersedes the earlier "keep separate" analysis.**

`rustsdcmcp` grows multi-instance support and absorbs SD On-Prem as a backend
variant. The unified server is eventually renamed `rustsdmcp`.

### What was decided

1. **Build multi-instance/multi-tenant support in `rustsdcmcp` first.** An
   inventory of Security Director targets, per-instance authentication, and
   per-instance capability flags. This ships value on its own: today the server
   validates against a single `expected_tenant_id`, so it is one tenant per
   process.
2. **Add SD On-Prem as a backend variant** behind that abstraction — not as a
   repository merge.
3. **Rename to `rustsdmcp` last**, when the second backend actually lands.
   Renaming earlier is churn across the repo, crate names, systemd units, the
   LXC 606 deployment, token files, docs, and the registry.

### Why, and what changed

An initial pair of surveys split: the On-Prem survey recommended merging, the
Cloud survey recommended separating. A third review that read both codebases
recommended keeping them separate, citing 946 core lines versus 9,106, four
read-only tools versus forty-eight, stubbed writes, and `PollSettings` left as
dead code marked TODO.

**That analysis was rejected because it measured maturity, not architecture.**
SD On-Prem is early. An early repo lacking features is evidence that it is
early — not evidence that its architecture differs. A `TODO` marking intent to
implement async job polling is not proof of a divergent lifecycle.

Stripping the maturity arguments out leaves the product-level facts:

**Toward unification**
- Both share the same `/api/v1/...` paths for devices, certificates and
  subscriptions, and the same `atom_portal` backend
  (`rustsdonpremmcp-core/src/catalog.rs:22-34`).
- Both already define `JobStatus` / `JobState` with **identical shapes** — the
  On-Prem scaffold was written expecting the same async job lifecycle.

**Genuinely different, and deployment-level rather than architectural**
- Credential issuance: `x-api-key` / `x-oauth2-token` versus `x-iam-token`.
- TLS trust: public CA versus self-signed appliance certificate.
- Tenancy: multi-tenant cloud versus single instance.

Those three are exactly what a per-instance configuration model exists to hold.

The 2.2%-shared-code figure that anchored the separate verdict was never an
argument against this plan, because the goal is a capability — one endpoint
fronting a fleet of Security Director deployments — not code reuse.

### Design constraints this creates

- **Per-instance capability flags, not a lowest common denominator.** If a
  mutation returns a job handle against one target and completes synchronously
  against another, the calling agent must be able to tell which it got. The
  abstraction models the difference; it does not hide it.
- **Credential lifecycle — resolved 2026-08-13.** SD On-Prem *can* mint a
  credential programmatically: a `curl` exchange of username and password
  returns a key. The earlier concern — that the inventory would have to express
  "this target's credential expires and a human must refresh it" — **does not
  apply**. Both backends can self-refresh, so no other server in this family
  gains a new operational property.

  This trades one problem for a smaller but real one: **On-Prem targets require
  the server to hold a username and password, where Cloud targets hold an API
  key.** A password is a higher-value secret than a scoped token — it is
  reusable outside this server and typically grants more than the API surface.
  The inventory design must therefore treat On-Prem credentials as a distinct
  sensitivity class: never logged, never echoed into audit attribution, stored
  the way `mecmcp-secret` handles material rather than as ordinary config, and
  ideally exchanged for a key once at startup so the password is not held in
  memory for the process lifetime. Verify against the On-Prem key's TTL and
  whether re-minting requires the password each time or supports refresh.

### What would overturn this decision

Evidence that the two products' `/api/v1` responses differ in *shape* rather
than only in path, or that On-Prem mutations are permanently synchronous
(`200 {result}`) rather than async (`202 {job_id}`) once its writes are
implemented. Neither has been demonstrated.

### Family precedent

One server fronting many targets is the established idiom here, and Security
Director is the outlier: `rustjunosmcp` serves 36 devices from one process,
`rustpanosmcp` has a `devices.json`, `rustproxmoxmcp` is multi-cluster.
`mecmcp#48` (canonical inventory envelope) is the shared groundwork.

---

## The structural problem: pin drift

Six consumers sit on five different `mecmcp` pins. `mecmcp` itself has 29
unreleased commits carrying four breaking changes, so **every consumer must
re-pin regardless** — which makes this the moment to collapse them to one.

| Consumer | Pin | Missing since its pin |
|---|---|---|
| `rustsdcmcp` | v0.8.0 | audit-by-construction (0.8.1), `client_name` (0.8.2/0.8.3), preflight-denial fix (0.8.8) |
| `rustsdonpremmcp` | v0.8.0 | same |
| `rustpanosmcp` | v0.8.6 | `client_name` wiring, preflight-denial fix |
| `rustjunosmcp` | v0.8.7 | preflight-denial fix |
| `rustmistmcp` | v0.8.8 (rev) | current |
| `rustproxmoxmcp` | v0.8.8 (tag) | current |

### Migration surface

Mechanical everywhere — no design judgement required. Roughly one day in total.

| Consumer | Call sites | Test literals | Notes |
|---|---|---|---|
| `rustjunosmcp` | 4 | 12 | ~40 lines across 3 files |
| `rustpanosmcp` | 4 | 1 | |
| `rustsdcmcp` | 4 | 2 | |
| `rustmistmcp` | 6 | 11 | **also delete its hand-rolled `validate_runtime_serve`** |
| `rustproxmoxmcp` | 4 | 1 | ~10 lines |
| `rustsdonpremmcp` | 5 | several | |

The 0.9.0 migration steps themselves are in the README's *Upgrading to 0.9.0*.

`rustmistmcp` gets a defect closed for free: its `load_http_token_store` has a
permissive `_ => Ok(None)` arm that serves with no token store when neither
`--tokens-file` nor `--allow-no-auth` is given. Adopting 0.9.0 makes that
unrepresentable; **no local patch is needed**.

---

## Phases

### Phase 0 — Unblock — **COMPLETE 2026-08-13**

Nothing releases until these clear. Independent of each other.

| # | Action | Repo |
|---|---|---|
| 0.1 | **Done.** Merged PR #300 and get off `fix/provenance-request-id`. Without it, `parse_device_log` has no `request.id` to join on. | `rustjunosmcp` |
| 0.2 | **Done.** Added `--allowed-origin http://192.168.1.127` and `http://192.168.1.108` (this host and `strix`) to LXC 950's drop-in override; snapshot `pre-allowed-origin` taken first; verified by a live MCP call returning all 36 devices. 0.9.0 refuses an off-loopback listener with no Origin allowlist, so the service will not start. Tagged `protected` — snapshot first. | fleet |
| 0.3 | **Done.** Tagged `v0.1.0` at 26fbad0 and `v0.1.1` at d5b3e7b retroactively and pushed. It links to release URLs for tags that do not exist. | `rustproxmoxmcp` |

### Phase 1 — `mecmcp` 0.9.0 — **COMPLETE 2026-08-13**

**Released: `v0.9.0` tagged and pushed** (PR #279). #266 shipped with it.

Ruling on #266's shape: a loud stderr warning on `revoke` and `rotate`, not
auto-discover-and-SIGHUP. This estate runs the same binary as a
production/rehearsal pair (950 and 600, 960 and 601), and a revoke that
signalled the wrong process would be worse than one that signalled none. Exit
stays 0 because the revoke did succeed.

Original plan follows. Fold **#266** in first — `token revoke` reports success while the running
server keeps accepting the credential. Consumers re-pin once for both.

Deferred, not blockers: **#275** (blocks `rustproxmoxmcp` 0.3 only), **#222**,
**#91**, **#48**, and the four MCP-spec issues (#164/#167/#168/#169), which are
their own programme.

### Phase 2 — Converge every consumer onto 0.9.1 — **COMPLETE 2026-08-13**

All six merged, all six pinned to `v0.9.1`. The drift is closed.

(Originally written as 0.9.0; 0.9.1 shipped mid-phase and the family moved to it
so the result would be one pin rather than two.)

The phase that pays: five pins collapse to one, and the two servers on v0.8.0
pick up eight releases of fixes. Deployed servers first:

`rustjunosmcp` → `rustpanosmcp` → `rustsdcmcp` → `rustmistmcp` →
`rustproxmoxmcp` → `rustsdonpremmcp`

### Phase 2 findings — recorded because they cost real time

**`ServePlan`'s opacity needed an upstream affordance, and did not have one.**
0.9.0 sealed the `Router` so a consumer cannot serve it directly and skip the
admission checks. Correct — but four consumer repositories migrating on the same
day each worked around it in a worse way: two **deleted** their HTTP boundary
tests, one disabled four test files **and relaxed `unsafe_code` from `forbid` to
`warn`**, and one wrote an `unsafe` helper that assumed the struct's field layout
and **segfaulted**. Four independent attempts reaching for something bad means
the affordance was missing upstream, not that four engineers erred. Fixed in
**0.9.1** as `test_harness::serve_on_loopback`, which serves the plan on a
loopback port and never exposes the `Router`.

Design rule this leaves behind: when sealing an API for safety, ship the
supported replacement path in the same release. A seal without an affordance
exports the cost to every consumer, and they will pay it in the cheapest way
available.

**The family converges on ONE pin, deliberately.** All six repositories moved to
`v0.9.1`, including the four that had already landed on `v0.9.0`. Stopping at two
pins would have restarted precisely the drift this phase existed to end.

**Gates that exist but do not run keep turning up.** Four more this phase, on top
of the `cli_validate` case that opened the programme:

- `rustsdcmcp`'s `scripts/verify-packaging.sh` invoked `rg`, absent on the CI
  runner. Both `if rg …; then fail` branches never fired, so the checks that
  production Rust must not spawn processes and that the installer must not start
  the service had **never run**. Switched to `grep`.
- `cargo fmt --check` and `cargo doc` are CI gates that `cargo test` and
  `cargo clippy` do not cover — each was missed for a full branch.
- `cargo clippy` without `--all-targets` misses test-target warnings entirely.
- CI runs `cargo test --locked`; a plain `cargo test` does not exercise the same
  lockfile path, so a stale dependency-contract constant passed locally and
  failed on CI.

The verification list for any change in this family is therefore: `build
--all-targets`, `test --locked`, `clippy --all-targets`, `fmt --check`, `doc`,
plus whatever repo-local policy script exists.

### Phase 3 — Release what is deployed — **COMPLETE 2026-08-13** (deployment pending)

`rustpanosmcp` **v0.9.0** and `rustjunosmcp` **v0.20.0** are tagged. The change-set
risk cleared: `ChangesetState`, `OperationRecord` and `ChangeSetRecord` serialize
identically between mecmcp v0.8.6 and v0.9.1, so LXC 960's `mutation-state.json`
survives and in-flight change sets are not orphaned.

**Not yet done: installing these on LXC 950 and 960.** Both are `protected`.
Snapshot each, rehearse on the disposable rigs 600 and 601, then production.
950's `--allowed-origin` is already in place and verified by a live MCP call.


- **`rustpanosmcp`** — 9 unreleased commits including a breaking fail-closed
  HTTP change; LXC 960 is 9 behind. **Before upgrading 960:** confirm 0.9.0 does
  not orphan in-flight change-sets. `mutation-state.json` is **unversioned** and
  `mecmcp` owns its schema.
- **`rustjunosmcp`** — 0.20.0 with PR #300 plus 0.9.0 adoption. Note `main` is
  exactly at v0.19.0; there is no hidden unreleased work.

Both hosts are `protected`: snapshot, then rehearse on 601/600 before 960/950.

### Phase 4 — First releases — **PARTIALLY COMPLETE 2026-08-13**

Released: `rustmistmcp` **v0.1.0** (first ever), `rustsdcmcp` **v0.1.0-lab.8**,
`rustproxmoxmcp` **v0.1.2**, `rustsdonpremmcp` **v0.1.0-alpha.1**.

**Scoping correction.** This phase originally listed "proxmox 0.2 (low-tier
mutations)" and "sdc 0.2 (multi-instance)". Those are development projects, not
releases: proxmox 0.2 means implementing 23 write tools against an authorization
spine that has never run a real mutation, and sdc's multi-instance work is the
subsystem that needs its own spec then plan. Neither is a version bump. They stay
open as development, and the releases above are what was genuinely releasable.

**Ruling:** mist's four WAN edge branches (two carrying 13 commits) were deferred
past v0.1.0 rather than landed. They have no PRs and were never proposed for
merge; landing unreviewed feature work as part of a tagging exercise would be
reckless. v0.1.0 is the stable base they build on.

Original plan follows.


- **`rustmistmcp` 0.1.0** — never tagged; 19 commits, 6 unmerged WAN branches to
  land or close.
- **`rustproxmoxmcp` 0.2** — low-tier mutations. Its authorization spine is
  enforced by types and covered by tests, but **no mutating tool calls it yet**,
  so the gate is unproven against a real destroy. Highest blast radius in the
  fleet until 0.2/0.3 exercise it.
- **`rustsdcmcp` 0.2** — plus the multi-instance work from the decision above.
- **`rustsdonpremmcp`** — per that decision, folded in as a backend rather than
  released separately.

### Phase 5 — Issue burn-down — **STARTED 2026-08-13**

Closed today: **#274** (README supersession), **#273** (unskippable listener
validation), **#269** (request_id correlation), **#266** (revoke propagation),
**#267** (`--lab-mode` is CLI-only). Eight remain.

What is left is not burn-down. **#275** changes a digest-bound field, so it alters
verification of existing records — a 0.10.0 change needing its own design.
**#222**, **#91** and **#48** are each substantial design work. **#164/#167/#168/
#169** are the 2026-07-28 MCP spec migration, a programme in its own right and
explicitly out of this one's scope.

Original plan follows.


`mecmcp` #275 (unblocks `rustproxmoxmcp` 0.3) → #222 → #91 → #48;
`rustsdcmcp` #55, #21, #33, #34, #31; `rustjunosmcp` #267, #299, #203.

---

## Standing housekeeping

- **Done 2026-08-13:** `rustjunosmcp` pruned from 20+ remote refs to 3;
  `rustpanosmcp` from 4 to 2. Nothing unmerged was deleted.
- Two branches survive with one real commit each and need a decision:
  `rustjunosmcp` `triage/issue-267-110`, and `rustpanosmcp`
  `sha-pin-docker-actions` (superseded by the `-v2` branch that actually shipped
  as PR #101).
- `rustsdonpremmcp` has **no CI at all** and uses `master` while every sibling
  uses `main`.

## A note on surveys

Two of the repository surveys behind this document were wrong about merge state
— one claimed a branch was merged when its `-v2` successor was, another placed a
commit on `main` that never left its branch. Both were caught by direct `git`
checks. Treat survey claims about code structure as reliable and claims about
merge state as needing verification.
