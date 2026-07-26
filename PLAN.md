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
`/metrics`; `rustjunosmcp` gains pre-dispatch scope preflight; the the deployment container
systemd override still works verbatim.

### Phase 4 — `mecmcp-policy` + `mecmcp-inventory` + `mecmcp-device`

Generalise the rule engine, turn `Inventory` into a trait with the file-backed
impl as the first implementation, and lift connection leasing. This phase
unblocks the database-backed inventory that 4,000 devices requires.

**Exit:** both servers load their existing `devices.json` unchanged through the
trait; `rustpanosmcp` gains connection pooling and per-device in-flight caps.

### Phase 5 — `mecmcp-changeset`

Generalise `mutation.rs` behind `DeviceTransaction` and implement the trait for
Junos NETCONF candidate/commit. This is the phase that delivers the headline
capability: **two-person change control on Junos**, which does not exist today.

**Exit:** a Junos change set can be planned by one token, approved by a second,
applied, and verified; an interrupted apply resolves through
`resolve_persisted_operation` rather than leaving unknown state.

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
