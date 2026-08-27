# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **How to read the entries below 0.21.0.** This file was added on 2026-08-26,
> after 0.20.0 shipped. Those entries are reconstructed from commit *subjects*,
> so they are accurate about *what changed* and terse about *why it mattered* —
> unlike the hand-written notes in the sibling servers' changelogs. Where an
> entry is not enough, the commit range in the matching GitHub release is the
> source.
>
> Two exceptions, both deliberate. The **Security** entries were written by hand
> after reading the commit bodies, because classifying by subject alone missed
> them and classifying by body text mislabelled two features as security fixes.
> And the bold prefix is the commit's *scope*, which is usually a crate but is
> sometimes an area — `deps`, `plan`, `packaging`, `spec`.
>
> Release commits — the `chore(release): X.Y.Z` and `bump workspace to X.Y.Z`
> subjects that carry only a number — are omitted. Two early version bumps
> are kept, at 0.3.8, because their subjects record *why* the version moved:
> `Workspace 0.1.6 for the ConnectInfo fix` marks the release consumers had
> to pin past a broken rate limiter, and `Bump intra-workspace dependency
> pins to 0.2.0` repaired dependency resolution.
>
> Entries from 0.21.0 onward should be written by hand at release time.

## [Unreleased]

## [0.20.0] - 2026-08-25

### Added

- **changeset** — Record the vendor task handle for an in-flight apply

### Changed

- Move the pinned toolchain to 1.98.0

### Fixed

- **changeset** — Do not settle an apply that still has a task handle
- **changeset** — Drop an empty task handle at every boundary it crosses

## [0.19.0] - 2026-08-25

### Fixed

- **audit** — Add capture sentinel to detect broken tracing mechanism
- **audit** — Capture by thread-local buffer, not by swapping subscribers

### Documentation

- follow-up block A design (captures, dependency coverage, egress)
- Implementation plan for follow-up block A
- Record block A outcome — seven tasks, five issues closed

## [0.18.0] - 2026-08-24

### Fixed

- **testutil** — Serialise run_with_capture against the global interest cache

### Documentation

- Fleet cleanup sprint design (2026-08-24)
- Record the sprint outcome, including where the plan was wrong

## [0.17.0] - 2026-08-24

### Added

- mecmcp 0.17.0 - fleet-shared improvements

### Fixed

- **audit** — Tighten by bitmask, not magnitude
- **auth,audit** — Surface permission errors, accept multiple live secrets, fix umask brittleness
- **auth** — One file, one stale-secret finding

## [0.16.0] - 2026-08-23

### Fixed

- **audit** — A receipt names who executed, not who proposed (0.16.0)

## [0.15.0] - 2026-08-23

### Fixed

- **runtime** — The CA refusal explained the wrong flag (0.14.2)
- **runtime** — Mark EvidenceArgsError non_exhaustive

## [0.14.1] - 2026-08-23

### Fixed

- **runtime** — The trust anchor belongs with the evidence flags (0.14.1)

## [0.14.0] - 2026-08-23

### Added

- **auth** — Accept targets as a scope spelling and expose neutral APIs (#91)
- **transport** — Carry client_version and client_call_id to handlers (#304)
- **auth** — Refuse a wildcard target scope beside a target-scoped grant (rustmistmcp#17)
- **inventory** — Emit the canonical envelope, explicitly (#48)
- **audit** — Produce evidence records at the lifecycle points (#292)
- **changeset** — Emit evidence at the four lifecycle points (#292)
- **audit** — Join the recorder to the SSDF sink (#292)
- **audit** — Give the sink a drain, and order the startup reads
- **runtime** — Give every server the evidence-pipeline flags
- **transport** — A TLS transport for the evidence sink

### Changed

- Drop an unused Read import from the chunked-response test
- **transport** — A read-only probe for evidence TLS reachability

### Fixed

- **digest** — Give approvals an unambiguous encoding (#283)
- **transport** — Withhold the call id for a batch, and keep ClientExtras open (#304)
- **transport** — Keep the audited element's call id on the transport event (#304)
- **testutil** — Rebuild the interest cache before capturing (#305)
- **testutil** — Keep the capture from being cached away (#305)
- **auth** — Check scope agreement on the mutated token, not the whole store
- **inventory** — Make migration lossless, safe to run, and abort on drift (#48)
- **ssdf-sink** — Dedup by high-water mark, not by an insert the writer cannot run (#292)
- **ssdf-sink** — Make the high-water mark a safe statement of what landed (#292)
- **ssdf-sink** — Bound a chunk before allocating it (#292)
- **recorder** — Produce evidence SSDF can actually verify (#292)
- **recorder** — Key context by changeset, resume the tier chain, close the flush race (#292)
- **recorder** — Reconcile the resume head with the outbox, evict the oldest (#292)
- **audit** — Resume from the newest segment produced, not the newest pending
- **audit** — Fail the apply when its intent record cannot be persisted
- **audit** — Close four gaps the gate found in the lifecycle emission
- **audit** — Serialize flushes, persist receipts, and complete waiver evidence
- **audit** — Recover a torn ledger tail, omit absent waiver fields
- **audit** — Repair a torn ledger tail in bytes, and keep the load streaming
- **audit** — Send an insert deduplication token (ssdf#49)
- **audit** — Make the dedup token injective for any identifier
- **audit** — Stop the service losing segments, hiding failures, and stalling
- **runtime** — Require an explicit --ssdf-audit-server-id
- **runtime** — Four config defects the gate found in EvidenceArgs
- **audit** — Shutdown must not abandon segments on the first error
- **runtime** — Reject a blank chain identity, and order run ids again
- **transport** — Take the crypto provider rather than constructing it
- **transport** — Probe must refuse http, and record why shutdown continues
- **runtime** — Order run ids below process-start resolution

### Documentation

- Fix intra-doc link left by the digest rename (#283)
- Say plainly that a store write canonicalizes scope aliases (#91)
- **audit** — Record what the trail sits in, not just how it is emitted (rustjunosmcp#299)

## [0.13.0] - 2026-08-19

### Added

- **audit** — Capture the client version and per-call id (rustjunosmcp#267)

## [0.12.0] - 2026-08-16

### Added

- **transport** — Capture provenance from per-request _meta (#288)
- **auth,runtime** — Add `token set-provenance` (#289)
- **audit** — Carry the approver and change set on Attribution (rustjunosmcp#307)

### Fixed

- **changeset** — Retire a change set whose waiver has lapsed (#284)
- **transport** — Make interning race-free, unflaking model_id_is_interned

### Documentation

- Make ECS-over-TCP audit forwarding a family standard
- Transport is the hash-chained ClickHouse sink, not syslog

## [0.11.0] - 2026-08-16

### Added

- **transport,audit** — Carry client-asserted model_id and session_id into attribution (#267)

### Fixed

- **changeset** — Reject the digest separator in owner and approver (#283)
- **test** — Add real end-to-end provenance test, make unit tests honest

### Documentation

- **transport** — Document stateless-path provenance limitation

## [0.10.0] - 2026-08-14

### Added

- **changeset** — WaiverRecord gains a digest-bound kind, expiry and ticket (#275)  
  **Breaking change.**
- **changeset** — Add the v3 waiver digest binding kind, expiry and ticket (#275)
- **changeset** — Schema v3 for operator waivers, v1/v2 still readable (#275)  
  **Breaking change.**
- **changeset** — Refuse apply when a waiver has expired (#275)
- **changeset** — Add waive_approval_operator alongside the lab-mode path (#275)

### Changed

- **changeset** — Add v3 waiver round-trip and version-dependence test (#275)
- **changeset** — Isolate pre/post-guard waiver expiry checks
- **changeset** — Remove two tests that could never run (#275)
- **changeset** — Forge each v3-only waiver field on its own (#275)

### Fixed

- **changeset** — Correct waiver expiry boundary and extract duplicate check
- Three v1/v2 waiver defects — metadata forgery, load/save bricking, vacuous test
- **changeset** — Make waiver expiry tests provably diagonal
- **changeset** — Reject v1/v2 waivers with edited reason or both approver+waived
- **changeset** — Say "device guard", not "device lock", in the expiry errors (#275)

### Documentation

- **packaging** — --lab-mode is CLI-only, never product configuration
- Open the release programme and record the SD unification decision
- Resolve the SD On-Prem credential question
- Mark Phases 0 and 1 complete
- Record Phase 2's findings
- Mark Phase 2 complete — all six consumers on v0.9.1
- Record phases 3-5 outcomes and two scoping corrections
- Record the 950 outage and the flag-wiring defect class
- **spec** — Operator waivers with a digest-bound kind (#275)
- **plan** — Implementation plan for operator waivers (#275)
- **changeset** — Correct ApprovalRecord digest and waived field docs (#275)
- **readme** — Fix the 0.9.1 issue citation and state the upgrade shape (#275)

## [0.9.1] - 2026-08-13

### Added

- **transport** — Add a supported test harness for ServePlan

## [0.9.0] - 2026-08-13

### Added

- **audit** — Add Junos native device log parser
- **transport** — Add operator acknowledgement types (#273)
- **transport** — Add listener admission checks (#273)
- **transport** — Make authentication a constructor choice (#273)  
  **Breaking change.**
- **transport** — Refuse inadmissible listeners in serve_router (#273)  
  **Breaking change.**

### Changed

- Ignore subagent-driven-development scratch dir
- **transport** — Migrate call sites to ServePlan and serve_router (#273)
- **transport** — Guard that the pre-0.9.0 constructors stay removed (#273)
- **transport** — Document compile-fail fixture brittleness and regeneration procedure
- **runtime** — Collapse cli_validate and demote it to a pre-check (#273)  
  **Breaking change.**
- **transport** — sabotage-verify the listener refusals (#273)
- Apply rustfmt across the #273 branch

### Fixed

- **audit** — Correlate transport and handler events by request_id
- **transport** — Add compile_fail doctests to prove consent types are unconstructible (#273)
- **transport** — Migrate doctests to new constructors (#273)
- **runtime** — Warn when a revoke or rotate has not reached the server

### Documentation

- **readme** — Mark 0.6.0 manual wiring superseded by 0.7.0 assembly
- **readme** — Stop endorsing hand-assembly as a 0.7.0+ path
- **readme** — Correct the Origin and session-tracker caveats
- **readme** — Scope the Host guard to /mcp and the tracker defect to 0.8.2
- **spec** — Design for unskippable listener validation (#273)
- **plan** — Implementation plan for unskippable listener validation (#273)
- 0.9.0 upgrade notes for unskippable listener validation (#273)
- **transport** — Resolve two broken intra-doc links

## [0.8.8] - 2026-08-12

### Changed

- **transport** — Drive build_streamable_http_router end-to-end

### Fixed

- **transport** — Settle the preflight audit outcome after the check, not before

## [0.8.7] - 2026-08-11

### Added

- Expose client name through CallerCtx for handler audit events (#262)
- **changeset** — Review view — expose stored actions on request
- **runtime** — Add WebApproverArgs for server-common approver flag

## [0.8.6] - 2026-08-11

### Added

- **inventory,changeset** — vendor-neutral config authority tracking (#260)

## [0.8.5] - 2026-08-10

### Added

- **changeset** — Add cancel_change_set lifecycle operation

### Changed

- **changeset** — Add provenance round-trip integration test
- Fix clippy lints in verify_golden_fixtures test

## [0.8.4] - 2026-08-10

### Added

- **audit** — Add ssdf sink with durable outbox and delivery ledger
- **audit** — Add mecmcp-verify CLI with run-manifest completeness

### Fixed

- **audit** — Complete ssdf sink - real HTTP, wired backoff, server-side dedup
- **audit** — Fmt blocker + test improvements
- **audit** — Path traversal, empty-run false positive, duplicate segment_seq
- **changeset,audit** — Unify join format and per-record row_hash

## [0.8.3] - 2026-08-10

### Added

- **changeset** — Add commit metadata hook for device-side provenance
- **mecmcp-audit** — Evidence records and hash-chained segments
- **audit** — Add ed25519 signing over closed segment heads

### Fixed

- **mecmcp-audit** — Address 4 critical review findings
- **mecmcp-audit** — Envelope mismatch validation in append()
- **audit** — Address signing security and usability findings
- **lint** — Gate test-only unwraps so the workspace lint passes again (#249)
- **transport** — Give the bearer boundary the session tracker (#250)

## [0.8.2] - 2026-08-09

### Added

- **transport** — Capture clientInfo from MCP initialize (#53)
- **transport** — Capture clientInfo from MCP initialize (#53) (#239)
- **audit** — Propagate captured client name into audit events (#53) (#241)

### Documentation

- Standardize filesystem layout across MCP servers (#28) (#235)
- Standardize release artifacts across MCP servers (#30) (#236)
- Standardize Docker documentation across MCP servers (#31) (#237)
- Add ARCHITECTURE.md and ONBOARDING.md (#240)

## [0.8.1] - 2026-08-08

### Added

- **transport** — transport-level audit for every tools/call (#32) (#233)  
  **Breaking change.**

## [0.8.0] - 2026-08-07

### Added

- **transport** — Extraction milestone 4 — generic scope preflight + shared test client (#232)  
  **Breaking change.**

## [0.7.3] - 2026-08-07

### Changed

- **deps** — axum-server 0.8, dropping the unmaintained rustls-pemfile (#231)  
  **Breaking change.**

### Security

- **deps** — Dropped `rustls-pemfile`, which [RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134) marks unmaintained, by moving to axum-server 0.8. It was failing the supply-chain gate.

## [0.7.2] - 2026-08-07

### Fixed

- **transport** — Give rmcp its own token so the drain can deliver a response (#230)  
  **Breaking change.**

## [0.7.1] - 2026-08-07

### Fixed

- **runtime** — Hold the wait future across polls so shutdown actually fires (#229)  
  **Breaking change.**

## [0.7.0] - 2026-08-07

### Added

- **transport** — Extraction milestone 3 — HTTP transport assembly (#114-#117,#148-#154,#156) (#227)  
  **Breaking change.**

### Changed

- Ignore docs/codex.thoughts

### Security

- **transport** — The assembled transport owns Host and Origin validation ([RUSTSEC-2026-0189](https://rustsec.org/advisories/RUSTSEC-2026-0189)), so consumers inherit the DNS-rebinding guard instead of each writing one. Host validation always carries the loopback allowlist; a non-loopback listener is refused unless both allowed hosts and allowed origins are configured, while a loopback bind may leave Origin validation off.

## [0.6.1] - 2026-08-07

### Added

- **mecmcp-scp** — Add SCP1 file-transfer client for legacy SSH devices (#225)
- **mecmcp-scp** — Handle OpenSSH marker lines (@revoked, @cert-authority) and add SSH liveness deadlines (#226)

### Security

- **scp** — The SCP1 client is built on russh 0.62.5, patched against CVE-2026-68930. The workspace pins `russh >=0.62.5, <0.63` for this reason; `Cargo.lock` is gitignored, so the floor cannot be relaxed to `"0.62"` without exposing consumers.

## [0.6.0] - 2026-08-07

### Added

- Extract the bearer boundary into mecmcp-auth and mecmcp-transport (#223)

## [0.5.0] - 2026-08-05

### Added

- **transport** — Adopt rmcp 3.1.1, fix LimitedSessionManager forwarding, release 0.5.0 (#221)  
  **Breaking change.**

## [0.4.0] - 2026-08-05

### Added

- Add mecmcp-server with the bounded result helpers (#217)
- Add the scope authorization half of mecmcp-server (#219)

### Documentation

- Record the set_scopes break the 0.3.9 notes missed (#216)

## [0.3.9] - 2026-08-05

### Added

- Report the consumer's version, and make CLI provenance visible (#204)
- Expose set-scopes, and let it reach the mutation grant (#205)

### Fixed

- Fail closed on an unopenable audit file, and allow lossless rotation (#200)
- Make off-loopback Host/Origin validation fail closed (#201)
- Stop an expired change set locking a principal out of its device (#202)
- Bound the wait queue to prevent unbounded memory use (#203)
- Require Origin only where the transport enforces it (#206)
- Confirm the two scope changes that quietly widened authority (#207)
- Keep the expiry sweep off in-flight applies, and make it durable (#208)
- Parse the consumer's CLI, and walk the whole command tree (#209)
- Close the path-expansion bypass, and stop mislabelling decoded bytes (#211)
- Enforce the multi-target and preview invariants that were declared but never checked (#210)
- Stop a pre-existing log logger costing the rotation handle (#212)
- Give the saturation tests a release signal that latches (#213)

### Documentation

- Correct two upgrade claims that would strand a consumer (#214)

## [0.3.8] - 2026-07-31

### Added

- mecmcp-auth — Phase 1 of the shared crate extraction (#1)
- **mecmcp-auth** — Add token lifecycle operations (add/rotate/revoke) (#2)
- **auth** — set_scopes — change a token's scopes without touching its secret (#3)
- mecmcp-audit — Phase 2 of the shared crate extraction (#12)
- **mecmcp-inventory** — Add canonical envelope with legacy readers (#46)
- **changeset** — Define DeviceTransaction trait with confirmed-commit support (#51)
- **mecmcp-changeset** — Add operation/changeset validation (Task 4) (#55)
- **Phase 5 Task 5** — Add ChangesetCoordinator with restart recovery (#56)
- **Phase 5 Task 6** — Add change-set approval gate with tamper-evident approvals (#57)
- **changeset** — lab-mode approval waiver that records a waiver, not an approver (#54) (#58)
- **changeset** — Port indeterminate-operation recovery (Phase 5 Task 9) (#59)
- **auth,audit** — Bind provenance to the token, and mark which fields are verified (#52) (#61)
- **changeset** — single-operation lifecycle (Phase 5 Task 8) (#64)
- **changeset** — Apply an approved change set (Phase 5 Task 7) (#65)
- **changeset** — Add a device-lock primitive to DeviceTransaction (#78)
- **changeset** — Expose an operations snapshot for post-load recovery (#83)
- **changeset** — Make staged-restart recovery a load-time vendor policy (#84)
- **changeset** — Report why approval was waived (#95)
- Add mecmcp-secret crate for outbound credentials (#171) (#172)
- Add mecmcp-http hardened outbound client (#90 phase 2a) (#178)
- Stream response bodies under a hard limit (#90 phase 2b) (#180)
- Extract one hardened file reader, sized and scoped for documents (#183)
- Adopt the shared hardened reader in auth and inventory (#185)
- Make mecmcp-secret Unix-only instead of faking cross-platform support (#188)
- Harden the change-set state read, and fix two overflows it exposed (#189)
- Add mecmcp-job, cancellable polling with capped backoff (#90 phase 3) (#191)
- Add mecmcp-openapi, whole-segment paths and bounded pagination (#90 phase 4) (#194)
- multi-target change sets (#90 phase 5) (#196)

### Changed

- Gate the repo with build/lint/test, MSRV, and supply-chain checks (#9)
- Build at the declared MSRV, and widen the MSRV job to --all-targets (#10)
- Install cargo-deny directly; document the distroless spawn constraint (#13)
- Phase 5 implementation plan: mecmcp-changeset (#16)
- Phase 3a: mecmcp-transport — the vendor-neutral hardening layer (#22)
- Workspace 0.1.6 for the ConnectInfo fix (#24)
- Phase 3b: mecmcp-runtime implementation plan (#36)
- Phase 3b Tasks 1-4: mecmcp-runtime crate (#38)
- Phase 4: mecmcp-policy, mecmcp-inventory, mecmcp-device (#41)
- Standardize on device terminology (BREAKING: router→device) (#44)  
  **Breaking change.**
- Phase 5 Tasks 1-2: scaffold mecmcp-changeset crate (#49)
- Ignore the .claude worktree scratch directory
- Review each commit of a pull request with codex (#72)
- Feat/share provenance parsing (#76)
- Fix/86 flaky concurrency tests (#88)
- **audit** — Assert tool-registry audit coverage from one place (#92)
- **ci** — Drop the API-billed Codex review workflow (#161)

### Fixed

- **auth** — Preserve the on-disk envelope version — rollback safety (#4)
- **auth** — Make device validation optional, keep tool validation strict (#5)
- **audit** — Make the metrics exporter test-only; it was breaking consumer TLS (#15)
- **transport** — Missing ConnectInfo 500'd every request (#23)
- **plan** — Task 1 would have created a third copy of the TLS loader (#37)
- **inventory** — The Inventory trait could not be implemented (#42)
- Bump intra-workspace dependency pins to 0.2.0 (#45)
- **changeset** — Stop requiring an HTTPS endpoint from every vendor (#70)
- **auth** — Preserve the token file's owner across a rewrite (#74)
- **changeset** — re-check cancellation in diff, validate, and before commit (#81)
- **changeset** — Allow offline resolution of any non-terminal operation (#87)
- Keep consumer grant types through token lifecycle commands (#170)
- Bound and sanitise error causes, and correct the HTTP/2 record (#182)

### Documentation

- mecmcp analysis, program plan, roadmap, and phase-1 auth plan
- Pin the phase-1 toolchain to 1.97.0, not the 1.88 MSRV floor
- Record Phase 0 as complete with as-built findings
- State the rollback path as snapshot-based (#8)
- Add the packaging standard (#11)
- Lock Debian 13 and the logging baseline into the packaging standard (#25)
- Record the consumer-owned-choices rule in Global constraints (#34)
- Mark Phase 3 complete, with the findings worth carrying forward (#39)
- Phase 4 implementation plan — policy, inventory, device (#40)
- Mark Phase 4 complete, with the findings worth carrying forward (#43)
- **phase5** — Task 10's state-file migration is unnecessary
- **changeset** — Document the crate, weighted toward what an operator hits (#67)
- **plan** — Record Phase 5's real status and what it taught (#68)
- **plan** — Phase 5 complete, exit criterion demonstrated on hardware (#73)
- **plan** — Correct Phase 5's recorded status (#82)
- **plan** — Record the PAN-OS half of Phase 5 as verified (#85)
- **packaging** — Declare runtime dependencies and the LXC/image asymmetry (#93)
- **packaging** — Make the change-set CLI a cross-server standard (#155)

## Before 0.3.8 — the component-named tags

The workspace has always shared one version: members carry
`version.workspace = true`, and the tags below name the *component the release
was about*, not a separately versioned crate. `changeset-v0.2.2`, for example,
tags the whole workspace at version 0.2.2.

- `auth-v0.1.0` … `auth-v0.1.4`
- `audit-v0.1.0`, `audit-v0.1.5`
- `transport-v0.1.5`, `transport-v0.1.6`
- `runtime-v0.1.6`
- `devices-v0.2.0`, `inventory-v0.2.1`
- `changeset-v0.2.2` … `changeset-v0.3.7`
- `phase4-v0.1.6`, `phase4-v0.1.7` — note the tag name is a phase, not a
  version: `phase4-v0.1.7` tags workspace version **0.1.6**
- `salvage/extraction-transport-20260728` — a preservation tag for a divergent
  pre-0.3.8 lineage, not a release

They have no GitHub release attached, and consumers pin the unified `vX.Y.Z`
tags instead.

**Keep every mecmcp crate in a consumer on one ref.** Cargo keys a git
dependency on the ref, so when the *same* package arrives through two of them
the graph carries two copies and their types do not unify — the failure this
project actually hit was two `mecmcp-auth` copies and therefore two
incompatible `CallerCtx` types, pulled in because `mecmcp-audit` depends on
`mecmcp-auth`. Crates with no internal mecmcp dependency would not duplicate on
their own, so the rule is a policy rather than a law of Cargo; it is cheap to
follow and the failure it prevents is confusing to diagnose.
