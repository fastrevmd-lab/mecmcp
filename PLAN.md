# mecmcp program plan

Extraction of vendor-neutral logic from `rustjunosmcp` and `rustpanosmcp` into a
shared Rust crate family. Written 2026-07-24 against the teardown in
[`ANALYSIS.md`](ANALYSIS.md).

This is the **program-level** plan: crate boundaries, phase sequencing,
decisions, and exit criteria. Each phase gets its own executable implementation
plan under [`docs/superpowers/plans/`](docs/superpowers/plans/) when it starts —
one subsystem per plan, each producing working, testable software on its own.

## Goal

One implementation of authentication, attribution, audit, transport hardening,
policy, inventory, and change control, consumed by every mechub vendor MCP
server, so that adding a vendor costs a protocol adapter and a tool surface
rather than a reimplementation of the security layer.

## Non-goals

- Merging the two servers into one binary. They stay separate products with
  separate release cadences.
- Rewriting vendor workflows (`rust-junosmcp-srx-core`, PAN-OS XML handling).
- Publishing to crates.io in the initial phases. Consumed as a tagged git
  dependency until the interfaces stabilise.

## Global constraints

Every phase inherits these. Copied verbatim into each per-phase plan.

- **Edition 2024, MSRV 1.88.** Matches `rustpanosmcp`.
- **Workspace lints, adopted from `rustpanosmcp`:**
  `missing_docs = "warn"`, `unsafe_code = "forbid"`,
  `clippy::all = "warn"` (priority -1), `dbg_macro = "deny"`, `todo = "deny"`,
  `unwrap_used = "warn"`.
- **`unsafe_code = "forbid"` is load-bearing**, not aspirational: it is the
  reason `rustjunosmcp`'s hand-rolled `write_volatile` secret zeroing must be
  replaced with `zeroize`.
- **No breaking change to on-disk `tokens.json` or `devices.json`.** Live
  deployments exist (the deployment container, `/etc/jmcp/tokens.json`). Field renames ship as
  serde aliases; the old spelling keeps working and stays tested.
- **No breaking change to the MCP tool surface** of either server. Tool names,
  input schemas, and output shapes are a public API.
- **The deployed systemd override on the deployment container must keep working** unchanged
  through every phase: `0.0.0.0:30031`, `--allow-insecure-bind`,
  `--allowed-host <server-lan-ip>`, no `--inventory-readonly`.
- **Licence:** MIT, single. Every crate carries `license = "MIT"`.
- **Naming:** product name `mecmcp` (lowercase, no dashes, per the mechub brand
  standard). Crate names take the `mecmcp-` prefix; Rust crate names keep
  dashes, which the naming rule does not govern.
- **Consumed as a git dependency pinned by tag**, e.g.
  `mecmcp-auth = { git = "https://github.com/fastrevmd-lab/mecmcp", tag = "auth-v0.1.0" }`.

### The rule these phases keep learning the hard way

**Anything that belongs to the consuming server must be a parameter, not baked
into a shared crate.** Metric names, tool registries, TLS backends, device
vocabularies, log field names — these are part of a *server's* public interface.
A shared crate that decides them forces every consumer to accept its choice, and
the breakage lands on operators rather than on compilation.

Four instances so far, each found only after it reached a consumer:

| What was baked in | What it broke |
|---|---|
| `metrics-exporter-prometheus` as a normal dependency with default features | Pulled `hyper-rustls` → `aws-lc-rs`, colliding with a consumer pinning `ring`. Broke two-person change control in tests and would have killed a production TLS listener on deploy |
| The tool-duration metric name | Renamed a consumer's public metric, silently breaking every `histogram_quantile` dashboard querying its `_bucket` series |
| `G: Default` inferred on the grant type | Forced every consumer to define a "default write authority" — a concept with no safe answer |
| `principal` flattened to `String`, with `"stdio"` as a sentinel | Let a token *named* `stdio` be logged as unauthenticated, forging caller identity in the audit trail |

`mecmcp-auth` got this right once, deliberately: `allows_tool` takes the
write-tool registry as a `&[&str]` **parameter** because each server has its own
tool surface. That is the shape to copy.

Practical test when adding anything to a shared crate: *if two consumers could
reasonably want different values, it is a parameter.* If it reaches
`Cargo.toml`, also ask whether default features drag in a TLS or async backend a
consumer may already have pinned — `cargo tree -e normal` from the consumer's
side is the check.

This is why `Principal` is an enum rather than a `String`: the variant *is* the
authorization fact, so a token cannot forge `Unauthenticated` by being named
`stdio`. Where a type in this plan carries a security or correctness invariant
that a primitive would lose, that choice is normative and a phase may not
quietly flatten it.

That is narrower than "every non-primitive in a code block is mandatory." The
struct sketches below are illustrative: a field holding free text — an external
ticket ID, a human's name — is correctly a `String`, and wrapping it buys
nothing. Phase 2's `Attribution` shipped exactly this way, and the shipped API
is the contract once a phase is released.

---

## Crate map

| Crate | Responsibility | Primary source | Depends on |
|---|---|---|---|
| `mecmcp-auth` | Token mint/digest/verify, `tokens.json` load + hot-reload, `ScopeSet`, generic grants, `CallerCtx` | union of both `-auth` crates | — |
| `mecmcp-audit` | `Attribution`, audit events, outcomes, HMAC redaction, journald/JSON sinks | `rust-junosmcp-audit` | `mecmcp-auth` |
| `mecmcp-transport` | Streamable-HTTP: host/Origin/DNS-rebind, bearer middleware, scope preflight, body limits, per-IP + per-token rate limits, concurrency + session caps, overload 503, `/metrics`, `/healthz` | `rust-junosmcp-core/limits/` + `rustpanosmcp` `security_boundary` | `mecmcp-auth`, `mecmcp-audit` |
| `mecmcp-runtime` | CLI skeleton (`serve`, `token add\|revoke\|rotate\|list`, `validate-config`), TLS bootstrap, signals, graceful shutdown | union of both binaries | `mecmcp-auth`, `mecmcp-transport` |
| `mecmcp-policy` | `RuleSource`, `CompiledRule`, `Decision`, pluggable matchers (glob, regex, xpath-prefix, config-path) | `rust-junosmcp-core/policy.rs` | — |
| `mecmcp-inventory` | `Inventory` trait, file-backed impl, name/address validators, atomic write, hot-reload; generic over a vendor device payload | generalised from both | `mecmcp-policy` |
| `mecmcp-device` | `Transport` trait, connection lease/pool, per-device in-flight cap, cancellation, timeouts | `rust-junosmcp-core` `device_lease`/`device_manager`/`cancel` | `mecmcp-inventory` |
| `mecmcp-changeset` | `DeviceTransaction` trait; plan → digest → approve → apply → verify; two-principal enforcement; persisted lifecycle; indeterminate recovery; idempotency keys | `rust-panosmcp-core/mutation.rs` | `mecmcp-auth`, `mecmcp-audit` |
| `mecmcp-server` | `rmcp` caller extraction, tool/target authorization, scope-filtered tool advertisement, bounded result conversion, audit-scope construction | both server binaries | `mecmcp-auth`, `mecmcp-audit` |
| `mecmcp-intent` | Vendor-neutral policy/object model, per-vendor rendering | new — see [`ROADMAP.md`](ROADMAP.md) | — |

### The two load-bearing traits

Everything above the vendor line is shared; these traits are the line.

```rust
// mecmcp-device — how a vendor talks to a box
#[async_trait]
pub trait Transport: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn connect(&self, device: &DeviceRef) -> Result<Self::Session, Self::Error>;
}

// mecmcp-changeset — how a vendor performs a reviewed change
#[async_trait]
pub trait DeviceTransaction: Send + Sync {
    type Action: Serialize + DeserializeOwned + Send + Sync;
    type Error: std::error::Error + Send + Sync + 'static;

    async fn fingerprint(&self) -> Result<Fingerprint, Self::Error>;
    async fn stage(&self, actions: &[Self::Action]) -> Result<Staged, Self::Error>;
    async fn diff(&self) -> Result<Diff, Self::Error>;
    async fn validate(&self) -> Result<Validation, Self::Error>;
    async fn commit(&self, attribution: &Attribution) -> Result<CommitOutcome, Self::Error>;
    async fn rollback(&self, to: RollbackRef) -> Result<Outcome, Self::Error>;
}
```

`rustjunosmcp` implements `DeviceTransaction` over NETCONF candidate/commit;
`rustpanosmcp` implements it over XPath set/delete plus PAN-OS commit. Both then
get plan/approve/apply, two-person enforcement, and indeterminate recovery from
the shared crate without writing any of it.

## Phase sequence

Ordered by risk, lowest first. Each phase ends with both servers building,
passing their existing test suites, and deployed to the lab before the next
phase starts.

### Phase 0 — Align the consumers *(prerequisite, no shared code)*

`rustjunosmcp` moves to edition 2024 / MSRV 1.88 and adopts the workspace lint
set. Adopt `deny.toml` in both.

**Completed 2026-07-24** on branch `chore/phase0-edition-2024-lints`. Findings
worth carrying forward:

- `cargo fix --edition` produced **zero** source changes across 37k LOC, and all
  987 tests passed unmodified. The tree was already edition-2024 clean.
- `unsafe_code` landed as **`deny`, not `forbid`**. There are **four** unsafe
  sites, not the one predicted: `token.rs` `write_volatile` and `file.rs`
  `getuid` (removed in Phase 1), plus `token_cmd.rs` and the `http_reload` test
  using `kill(SIGHUP)` (removed in Phase 3). `forbid` cannot be locally
  overridden, so `deny` plus targeted `#[allow]`s naming the removing phase is
  the only workable intermediate. Phase 1 and Phase 3 each delete their allows;
  Phase 3 raises the lint to `forbid`.
- `cargo-deny` needed two fixes to pass: allow `Zlib` (`foldhash`, transitive
  via `hashbrown`) and pin `version` alongside `path` on the intra-workspace
  dependencies, which cargo-deny reads as wildcards.
- Adopting the lint set surfaced ~1,700 findings, of which the material subset
  is **13** — the shipping-code `unwrap_used` hits. All 13 were reviewed and
  every one is guarded by an earlier return or a loop invariant the lint cannot
  see. 946 of the 959 are in tests. `missing_docs` and `unwrap_used` are
  therefore set to `allow` and tracked in rustjunosmcp issue #193, rather than
  left at `warn` where they would bury genuinely new warnings.

**Exit (met):** `cargo clippy --workspace --all-targets --all-features -D warnings`
clean in both repos, with `missing_docs` and `unwrap_used` explicitly deferred
under issue #193 and every other lint active; `cargo deny check` reporting
`advisories ok, bans ok, licenses ok, sources ok`; all 987 tests passing.

### Phase 1 — `mecmcp-auth` *(the proving spike)*

The smallest self-contained subsystem that both servers depend on, with the
highest duplication and real on-disk compatibility constraints. If the extraction
model works here, it works everywhere.

Design = `rustpanosmcp`'s store/token (bounded, validated, `zeroize`, expiry)
+ `rustjunosmcp`'s `file.rs` diagnostics, plus:

- generic `Grant` so PAN-OS `MutationGrant` (XPath) and a future Junos
  config-path grant both fit without the crate knowing either vendor;
- `devices` as the canonical scope field with `#[serde(alias = "routers")]`;
- `digest` canonical with `#[serde(alias = "hash")]`;
- both `created_at` (RFC 3339) and `created_at_unix` accepted;
- token expiry for both servers (`rustjunosmcp` gains it);
- wildcard tool scope excludes write tools, with the write-tool registry
  supplied by the consumer rather than hardcoded.

Detailed plan: [`docs/superpowers/plans/2026-07-24-mecmcp-auth.md`](docs/superpowers/plans/2026-07-24-mecmcp-auth.md)

**Exit:** both servers authenticate against their *existing, unmodified*
production `tokens.json` files; `rustjunosmcp` contains no `unsafe`; round-trip
tests prove old and new field spellings both load.

### Phase 2 — `mecmcp-audit` + `Attribution`

Lift `rust-junosmcp-audit` and add the `Attribution` type as a first-class
value threaded through every mutating path. `rustpanosmcp` replaces its
`AUDIT_TARGET` constant with the real crate.

`Attribution` is the piece neither repo has and both need:

```rust
pub struct Attribution {
    pub principal: Principal,          // token name today; OIDC subject later
    pub actor_type: ActorType,         // Human | Agent
    pub agent: Option<AgentIdentity>,  // model id, session id, MCP client
    pub on_behalf_of: Option<String>,  // the human whose authority an agent used
    pub change_ref: Option<String>,    // CHG0012345 — free text, no newtype
    pub request_id: Uuid,
}
```

It lands in three places, not one:

1. the audit event,
2. **the device itself** — Junos `commit comment`, PAN-OS commit description, so
   `show system commit` names a human and a ticket,
3. the change-set record, so plan and approve carry *separate* principals.

**Exit:** every mutating tool in both servers emits an attributed audit event;
a lab commit on a vSRX and on the PAN-OS VM both show the requesting principal
in on-box commit history.

### Phase 3 — `mecmcp-transport` + `mecmcp-runtime`

`rustjunosmcp`'s `limits/` becomes the shared transport; `rustpanosmcp`'s scope
preflight becomes an additional layer in it. CLI, TLS, and token subcommands
move to `mecmcp-runtime`. Largest mechanical diff, lowest conceptual risk.

**Exit:** `rustpanosmcp` gains per-token session caps, per-token RPS limits, and
`/metrics`; `rustjunosmcp` gains pre-dispatch scope preflight; the deployed
systemd override still works verbatim.

**Completed 2026-07-26**, split into 3a (`mecmcp-transport`, `transport-v0.1.6`)
and 3b (`mecmcp-runtime`, `runtime-v0.1.6`). Findings worth carrying forward:

- **The extraction was bidirectional**, which this plan did not anticipate.
  `rustjunosmcp` supplied the hardening `rustpanosmcp` lacked entirely —
  concurrency caps, session caps and reaper, Prometheus metrics, typed overload
  responses. `rustpanosmcp` supplied a materially stronger TLS loader
  (`O_NOFOLLOW`, mode and owner checks, size caps, `Zeroizing`) and the scope
  preflight concept. Neither repo was simply the source.

- **Four defects reached review in the shared crate, every one a silent
  degradation.** Metric names in `thread_local!` storage, invisible to tokio
  workers so `<prefix>_limit_hits_total` stopped recording with no panic and no
  log. `rmcp` pinned to 0.2.1, carrying RUSTSEC-2026-0189 — DNS rebinding in the
  Streamable HTTP transport, the very component the crate exists to harden.
  `rustls` 0.22 pulling three certificate-validation advisories. `ConnectInfo`
  as a required extractor, returning **500 on every request** when the router is
  mounted without `into_make_service_with_connect_info`.

  None were caught by the crate's own 202 tests. Each surfaced only from a
  *second* consumer or a differently-shaped test. **A shared crate verified
  against one consumer is not verified.**

- **Two of those share a root cause worth naming: the shared crate was older
  than its consumers.** Both servers already ran `rmcp` 2.x and `rustls` 0.23.
  So the rule this program keeps relearning has a second half — not only "do not
  bake in a consumer's choice", but "do not hand a consumer something worse than
  what it already has".

- **One git ref, always.** Two refs for `mecmcp-auth` produce two `CallerCtx`
  types with different `TypeId`s; `Extensions::get` then silently returns `None`
  and per-token limits stop enforcing while startup still logs them as
  configured. `grep -c '^name = "mecmcp-auth"' Cargo.lock` must print `1`, and
  it is worth checking on every dependency change.

- **Plans drifted from the tree three times.** Phase 5's D6 specified a
  state-file migration that already existed; Phase 3b's D1 specified a TLS port
  Phase 3a had already done, and its Task 1 still said to port the loader even
  after D1 was corrected — which would have made a third copy. Chasing the D1
  discrepancy also surfaced that v0.11.1 shipped a breaking TLS key-mode
  requirement with nothing in the release notes. **Verify each decision against
  `main` before implementing.**

### Phase 4 — `mecmcp-policy` + `mecmcp-inventory` + `mecmcp-device`

Generalise the rule engine, turn `Inventory` into a trait with the file-backed
impl as the first implementation, and lift connection leasing. This phase
unblocks the database-backed inventory that 4,000 devices requires.

**Exit:** both servers load their existing `devices.json` unchanged through the
trait; `rustpanosmcp` gains connection pooling and per-device in-flight caps.

**Completed 2026-07-26**, released as `phase4-v0.1.7`. Findings worth carrying
forward:

- **Two of this plan's premises did not match the tree**, found by measuring
  before writing. The stated exit — "`rustpanosmcp` gains connection pooling and
  per-device in-flight caps" — was **already satisfied**: `PanosClient` is a
  pooled per-device client holding an `Arc<Semaphore>`, with
  `pool_max_idle_per_host` configured. And "lift connection leasing" conflated
  two mechanisms: junos's `device_lease.rs` is *cross-process* kernel file
  locking so a long-running upgrade cannot be raced by another process, while
  panos's semaphore is *in-process* concurrency limiting. Only the file lock was
  extracted.

- **The authorisation models are not interchangeable, and nearly were.**
  `mecmcp-policy` is a fail-open glob blocklist: unmatched input is allowed.
  `rustpanosmcp`'s `validate_write_xpath` is a fail-closed prefix allowlist: an
  XPath must sit under a configured root. Adopting the engine for mutations
  would have silently widened what a mutation token reaches. It is used for
  read-only tools only, additively.

- **The `Inventory` trait shipped unimplementable.** `FileInventory::get`
  returned `Err` unconditionally and `policy` returned `None`, because
  `-> Result<&D, _>` cannot be honoured by anything with interior mutability —
  which hot reload requires. Every test used the concrete type, so nothing
  caught it. Fixed in v0.1.7 by returning owned values, plus a test that calls
  through `&dyn Inventory`.

  The same area hid a latent panic: the sync trait called
  `tokio::RwLock::blocking_read()`, which panics inside an async context, while
  the inherent accessors awaited the same lock. Now `std::sync::RwLock`
  throughout.

- **"Wired" is not the same as "used".** Both server tasks declared a new
  dependency without consuming it, and both reported success with green CI —
  junos never imported `mecmcp-inventory`, panos never called `mecmcp-policy`.
  A later attempt "used" the loader by calling it, discarding the result, and
  parsing the file a second time locally. **Dead code is the signal:** if
  replacing an implementation leaves nothing for clippy to flag as unused, it
  was added alongside rather than substituted.

- **Schema convergence (#27) stayed out of scope deliberately**, and should stay
  out until the trait has consumers. A converged schema is now a second
  `Inventory` implementation rather than a flag day against four live
  deployments.

### Phase 5 — `mecmcp-changeset`

Generalise `mutation.rs` behind `DeviceTransaction` and implement the trait for
Junos NETCONF candidate/commit. This is the phase that delivers the headline
capability: **two-person change control on Junos**, which does not exist today.

**Exit:** a Junos change set can be planned by one token, approved by a second,
applied, and verified; an interrupted apply resolves through
`resolve_persisted_operation` rather than leaving unknown state.

**Completed 2026-07-28**, released through `changeset-v0.3.5`. Both halves of
verification standard item 4 are met: Junos below, PAN-OS further down. The
Junos exit criterion was demonstrated on a live vSRX 24.4R1.9 (`vsrx-ci`) from a
throwaway container, LXC 610, built from merged `main`:

```
0   2026-07-28 18:33:02 UTC by netconf via netconf
    no-change-ref by phase5-owner (agent) on-behalf-of=mharman via anthropic-private
```

An earlier revision of this file quoted the 17:52 entry from the same log as the
evidence. That line reads `by lab-change-writer (unknown) on-behalf-of=self`,
which is the *defect*, not the demonstration: `token add` discarded the
provenance flags (rustjunosmcp#233). The line above is the same flow after the
fix, on the same device.

Fingerprint read from the real candidate, change set planned by one token,
**self-approval refused at the transport with `insufficient_scope`**, approved
by a second token, applied, committed, and the attribution present in
`show system commit`.

The failed run before it was worth as much as the success. An invalid Junos
payload produced `state: failed` rather than applied, `operations: 0` so no
stranded reservation blocking the device, an unchanged candidate fingerprint —
the all-or-none staging contract holding against real hardware — and
`version: 2` on disk, the rollback-safety escalation firing correctly.

Done and merged:

- `mecmcp-changeset` in full — records, `DeviceTransaction`, coordinator with
  restart recovery, validation, the approval gate with tamper-evident
  approvals, change-set apply, the single-operation lifecycle, indeterminate
  recovery, and the lab-mode waiver. Plus token-bound provenance (#52) and
  the crate README.
- PAN-OS: `DeviceTransaction` for `PanosClient`, and `MutationCoordinator`
  replaced by the shared `ChangesetCoordinator`.
- The device-lock primitive (#60): `requires_config_lock()` and `lock()` pairing
  with `unlock()`, with the coordinator ordering acquire → fingerprint → stage.
  **In the trait only** — neither vendor overrides it yet, so runtime behaviour
  is unchanged and the race is not closed on the wire. See #80.
- Cancellation re-checks across the lifecycle methods (#63).

Verified against the live deployment: `/var/lib/rust-panosmcp/mutation-state.json`
on LXC 608 loads with the new reader — six operations, six change sets, every
approver distinct from its owner. That is half the exit criterion, checked
read-only against the real container rather than against the fixture.

Since resolved:

- The rest of the PAN-OS `mutation.rs` migration. A first attempt migrated all
  seven single-operation methods at once, compiled clean, passed every unit
  test, and broke four of the five integration tests — including one it was
  scoped not to touch. Reverted. The approach that worked was one method at a
  time with the full suite green before and after. Landed as rustpanosmcp#67
  and #68 — and #68 sat unpushed on a local branch for a day while this file
  already recorded the phase as complete, which is the failure this section now
  guards against.
- The Junos change-set tools (rustjunosmcp#228), merged after the two-person
  control defect was fixed — the authenticated identity was being discarded and
  a client-supplied `owner` persisted instead.
- The live vSRX half of the exit criterion, demonstrated above.

**PAN-OS half completed 2026-07-28**, on the live 12.1.5 lab firewall (`panosvm`,
PA-VM, serial matching its pinned leaf certificate) from LXC 610 — not 608, which
is `protected`, and whose credentials were not read.

The full criterion, in order: candidate fingerprint read from the device; change
set planned by `panos-owner`; **apply refused while unapproved** (`change set
requires independent approval before apply`); **self-approval refused at the
transport** with `insufficient_scope`; approved by `panos-approver`; applied;
validated (`Configuration is valid`, job 129686); committed and confirmed
present in the **running** config; and the resulting operation resolved through
`state resolve` to terminal `committed` with the lock released.

The verification paid for itself three times over. Every finding below is a
defect that live hardware exposed and the test suites could not:

- **rustpanosmcp#72** — restart recovery rewrote the state file after the
  coordinator had loaded, so the API answered `indeterminate` while the file said
  `staged` and the offline recovery tool refused. The operation was neither usable
  nor resolvable, with its candidate and lock still held. Fixed by making the
  policy a load-time parameter (`StagedRecovery`, `changeset-v0.3.5`) so one owner
  writes both copies.
- **rustpanosmcp#75** — PAN-OS releases the vsys config lock as part of
  committing, so the server's explicit release afterwards fails with `not
  currently locked` and marks the operation `Indeterminate`. **Every successful
  commit** lands in the manual-recovery queue and blocks the next change set.
- **rustpanosmcp#74** — a staged operation whose candidate drifts externally can
  be neither discarded (fingerprint guard) nor resolved offline (not
  indeterminate), and it blocks every later apply on that device.

#75 in particular means the happy path is not yet operationally clean, even
though the change-set semantics it exercises are correct.

Findings worth carrying forward:

- **A green suite is not evidence the thing works.** Every serious defect this
  phase surfaced — a state file the coordinator would refuse to reload, an
  `action` encoding the deployed reader cannot parse, tools that did not
  actually enforce two-person control — passed `fmt`, `clippy -D warnings` and
  the full test suite. They lived in the space the tests did not reach:
  persistence enabled, an authenticated caller, a failing commit outcome.
- **Check the pass count, not the failure count.** A workspace that fails to
  compile reports zero passes *and* zero failures, which reads as success if
  you only look for failures. This cost time twice.
- **"Pre-existing and unrelated" is worth thirty seconds of checking.** It was
  claimed three times about breakage the change itself had caused; stashing and
  re-running settled it each time.
- **Do not edit the evidence.** A required field was made to pass by adding a
  fabricated value to the six real LXC 608 change sets in the compatibility
  fixture. The suite went green over a change that would have stopped the
  coordinator starting. `production_fixture_is_unmodified` now pins its
  SHA-256, and the real file has since been confirmed to match.
- **Say `Indeterminate` when you mean it.** The recurring defect class was
  records asserting more certainty than the code established: a waiver written
  as an approver, a lock flag cleared without unlocking, a dropped commit
  future reported as `Detached`, a failed write returned as success. For a
  crate whose product is a state file an operator trusts at 3am, that is the
  failure that matters.

### Phase 6+ — scale and multi-vendor

Driven by [`ROADMAP.md`](ROADMAP.md): blast-radius guards, staged rollout, drift
detection, database inventory, OIDC, `mecmcp-intent`, additional vendors.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Repo layout | Separate `mecmcp` repo, git dependency pinned by tag | Both servers release independently; a monorepo couples their cadence |
| Baseline posture | `rustpanosmcp`'s edition/lints/profile | Stricter, and already proven in a shipping repo |
| Token design | `rustpanosmcp`'s store + token | Bounded, validated, `zeroize`, has expiry |
| File I/O design | `rustjunosmcp`'s `file.rs` | Better operator diagnostics (uid + mode on EACCES) |
| Transport base | `rustjunosmcp`'s `limits/` | Materially more capable; `rustpanosmcp` has ~100 lines to `rustjunosmcp`'s ~3,500 |
| Change control base | `rustpanosmcp`'s `mutation.rs` | The only implementation that exists |
| Scope field name | `devices` canonical, `routers` aliased | "Device" is vendor-neutral; alias preserves live `tokens.json` |
| Per-phase deployment | Lab-deploy each phase before the next | Both servers are in real use; big-bang integration is the failure mode |
| crates.io | Deferred | Interfaces will move through Phase 5 |

## Risks

| Risk | Mitigation |
|---|---|
| Breaking a live deployment mid-extraction | Every phase ends deployed to the lab and verified; serde aliases for all renames; **snapshot the deployment container before installing each release** and roll back to the snapshot if needed. There is no standby host — the former standby was retired and destroyed, so a snapshot is the only revert path |
| Trait over-abstraction — a `DeviceTransaction` that fits neither vendor well | Phase 5 implements it for *both* vendors in the same phase; if the trait needs vendor-specific escape hatches, that is a finding, not a failure |
| The generic `Grant` trait leaking vendor concepts into `mecmcp-auth` | The crate must not name XPath or Junos config paths anywhere; enforced by review and by the crate compiling with neither vendor as a dependency |
| Extraction stalls half-done, leaving three implementations | Phases are ordered so each is independently valuable; stopping after any phase leaves both servers better than before |
| MSRV/edition bump breaking `rustjunosmcp`'s dependency tree | Phase 0 is a standalone prerequisite with its own verification, before any shared code exists |

## Verification standard

Applies to every phase; a phase is not done until all four hold.

1. `cargo clippy --workspace --all-targets -- -D warnings` clean in `mecmcp` and
   both consumers.
2. Existing test suites in both consumers pass **unmodified** where the phase did
   not intentionally change behaviour.
3. Both servers start against their existing production config files with no
   edits to those files.
4. Lab deployment verified: `rustjunosmcp` on the deployment container against the vSRX fleet,
   `rustpanosmcp` against the PAN-OS 12.1.5 lab firewall.
