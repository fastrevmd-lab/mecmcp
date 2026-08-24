# Fleet cleanup sprint — design

**Opened 2026-08-24.** A two-day sweep to clear the open backlog across
`mecmcp` and its six consumer repos, verified on the 610–619 test rigs.

## Goal and definition of done

Clear the 48 open issues across seven repos by **fixing the ones that carry
value or risk and triage-closing the rest with a written reason**. Every fix is
rehearsed on a `disposable`-tagged test rig. **No 900-series guest is touched
in this sprint** — production upgrade is a separate, snapshot-gated exercise
that this sprint only prepares.

Success is not "48 closed". Success is: every Tier 1 and Tier 2 item landed and
rehearsed, every deferred item carrying a stated reason and a label, and no
claim of green that was not observed.

## The finding that shapes the plan

The backlog is not 48 independent problems. Forty-four of the 48 were filed on
2026-08-24 as children of three `mecmcp` trackers — **#318** (Tier 1, provable
from the tree, no behaviour change), **#319** (Tier 2, behaviour change, needs a
change window), **#320** (Tier 3, spikes). The same defect recurs across
junos / sdc / panos / proxmox / mist:

| Defect class | Filed as | Tier |
|---|---|---|
| `tokens.json` under `/etc` vs `ProtectSystem=strict` | junos #333, sdc #92, mist #42, proxmox #22; panos #125 is the inverse | 2 |
| systemd hardening drift | junos #332, panos #129, proxmox #19, mist #41 | 2 |
| audit flags / HMAC key absent from the *shipped* unit | junos #334, sdc #96, panos #130, proxmox #23 | 2 |
| superseded token / TLS files left on guests | sdc #95, panos #131, proxmox #24, mist #43 | 2 |
| no `[profile.release]` | junos #330, proxmox #20 | 1 |
| `dependabot.yml` missing or incomplete | sdc #93, proxmox #21, mist #40 | 1 |
| apt cache never cleaned | sdc #94, panos #128, mist #45 | 1 |
| journald drop-in override conflict | junos #331, sdc #97, mist #44 | 1 |

So the leverage is **fix once, apply five times** — and the four recurring
Tier 2 classes each have a shared component that belongs in `mecmcp` rather
than being written five times with five different behaviours.

### The evidence-writer bug — #319's open question, answered

`mecmcp` #319 §1 asked whether the world-readable evidence files on 971 were a
proxmox defect or a shared one. They are shared:

- `crates/mecmcp-audit/src/sinks/ssdf.rs:235` — outbox opened
  `.create(true).append(true)` with **no `.mode()`**
- `crates/mecmcp-audit/src/sinks/delivery_ledger.rs:116` — ledger, same
- yet `crates/mecmcp-audit/src/signing.rs:497` and
  `crates/mecmcp-audit/src/bin/mecmcp-audit-keygen.rs:51` **do** set
  `.mode(0o600)`

The evidence files therefore inherit the process umask. On 950/951/952/960 they
land `0600` only because those units carry `UMask=0077`; 971 has no `UMask`
line, so they landed `0644`. Fixing this in `mecmcp-audit` protects all five
servers regardless of whether a unit remembers the directive, and closes the
first task of rustproxmoxmcp#18.

## Constraints that govern sequencing

1. **The `mecmcp` pin is the critical path.** All six servers pin
   `mecmcp v0.16.0` by immutable git tag. `rustsdcmcp` pins it in **five files**
   behind a tag guard *and* an SBOM guard, enforced at build, package, **and
   deploy** time (`Cargo.toml:50-55`, `scripts/verify-packaging.sh`,
   `scripts/build-lab-package.sh:267-273`, `packaging/tests/package-smoke.sh`,
   `packaging/lxc/install.sh:95,114-120`, plus `ci.yml:100`). A `mecmcp` bump is
   a coordinated seven-repo change, so it happens **exactly once**.
2. **One agent per working directory.** Subagents share the parent checkout, so
   two agents in one repo corrupt branch state silently. Waves are barriers;
   within a wave there is exactly one agent per repo.
3. **The codex gate is a real throughput limit.** Roughly ten to twelve PRs each
   need `codex exec review --commit <sha>`. Quota exhaustion presents as a
   transient error; if the gate does not produce a verdict it is reported as
   *not run*, never as a pass.
4. **Test rigs only.** 610–619 are all running and `disposable`-tagged, a
   matched two-person / lab-mode pair per server. Production (950, 951, 952,
   960, 971) is out of scope for this sprint.

## Wave structure

### Wave 0 — `mecmcp` 0.17.0 (serial; blocks Wave 2)

The shared work, done once. Four changes, then tag.

- **Evidence file mode.** Set `0600` explicitly at both open sites above. Test:
  create the sink under a permissive umask (`0022`) and assert the resulting
  mode is `0600` — the test must fail against today's code.
- **Shared token-path resolver.** Primary `/var/lib/<service>/tokens.json`,
  fallback read from `/etc/<service>/tokens.json` with a warning. **Read, never
  silently copy** — a silent copy leaves a stale credential file behind, which
  is the very defect sd/panos/proxmox/mist are filing. Serves junos#333,
  sdc#92, mist#42, proxmox#22, panos#125.
- **Stale-secret startup warning.** On start, glob the token and TLS
  directories for sibling files (`*.pre-*`, `*.bak`, retired keys) and warn,
  naming each. Serves sdc#95, panos#131, proxmox#24, mist#43. Warn only — it
  must never delete an operator's file.
- **`[profile.release]`** for `mecmcp` itself (#318 item 2).

Tag `v0.17.0`. Nothing downstream moves until this tag exists.

### Wave 1 — Tier 1, five agents in parallel (no `mecmcp` dependency)

Each repo gets one agent, one branch, one PR closing all of its Tier 1 items.
No behaviour change, so no rig rehearsal is required beyond CI.

| Repo | Issues |
|---|---|
| RustJunosMCP | #329 dead `openssh-client`, #330 `[profile.release]`, #331 journald retention conflict |
| rustsdcmcp | #93 dependabot, #94 jq requirement + apt clean, #97 journald drop-in |
| rust-panosmcp | #126 toolchain frozen at MSRV, #127 stale distroless digest, #128 apt clean |
| rustproxmoxmcp | #20 `[profile.release]`, #21 dependabot |
| rustmistmcp | #40 dependabot cargo ecosystem, #44 journald drop-in, #45 apt clean |

**Coupling to respect:** sdc#97 and mist#44 ship the *same* `mecmcp.conf`
journald drop-in. If only one repo stops shipping it, the survivor re-creates it
on the next install. They must land together, and the installer must remove the
stale file rather than merely stop writing it.

**Record before/after binary size** in the `[profile.release]` PRs (#330, #20).
Expect roughly 38.8 MB → 10–14 MB for junos. Evaluate `panic = "abort"`
separately; it changes unwinding and interacts with tests, so it does not ride
along.

Also in this wave, and currently unticketed — **file both, then fix**:

- **ssdf CI is red on all ten recent runs.** Fix or correctly disable.
- **rustmistmcp's scheduled security run failed 2026-08-24 08:10** while
  manual and PR runs pass. Diagnose the schedule-only difference.

### Wave 2 — Tier 2, five agents in parallel (after the 0.17.0 bump)

Each repo bumps its `mecmcp` pin to `v0.17.0` — for `rustsdcmcp` that means all
five guard files plus `ci.yml` — then lands its Tier 2 items.

Ordered security-first within each repo:

1. tokens.json move onto the shared resolver
2. stale-secret warning adopted
3. systemd hardening
4. audit config promoted into the shipped unit
5. Dockerfile / packaging

| Repo | Issues |
|---|---|
| RustJunosMCP | #333 tokens path, #332 hardening, #334 audit HMAC key |
| rustsdcmcp | #92 tokens path, #95 stale secrets, #96 `--audit-log-file`, #91 Dockerfile |
| rust-panosmcp | #125 tokens path mismatch, #131 stale secrets, #129 syscall denylist + IP restrictions, #130 audit config |
| rustproxmoxmcp | #25 `StateDirectory=`, #22 tokens path, #18 `UMask=0077`, #24 stale secrets, #19 hardening + bind default, #23 audit config, #26 Dockerfile |
| rustmistmcp | #42 tokens path, #43 stale secrets, #41 hardening |

**Ordering dependency:** proxmox #25 (`StateDirectory=`) must land *before* #22
(tokens move), or the token file lands in a hand-made `0750` directory.

**Two changes carry real blast radius** and are called out so they are not
treated as boilerplate:

- **junos #332** is the only server doing SSH/SCP file transfer.
  `RestrictAddressFamilies` and the syscall denylist need `transfer_file`,
  `fetch_file`, and `collect_jtac_support_bundle` exercised against a real
  device before the change is believed.
- **`IPAddressDeny`** (panos #129, mist #41, junos #332) must not blackhole the
  SSDF evidence endpoint at `192.168.1.151:8443` or any device subnet. Check the
  inventory before writing the rule, not after.
- **proxmox #19** changes the `--host` default from `0.0.0.0` to `127.0.0.1`.
  That will break any registered MCP entry relying on the old default; the
  rig test must confirm the override path still binds.

### Wave 3 — rig rehearsal

Prove each change on the matched pair, lab-mode rig first, then two-person.

| Server | Rigs | What must be exercised |
|---|---|---|
| junos | 611 → 610 | `transfer_file`, `fetch_file`, `collect_jtac_support_bundle` under the new filter; token fallback read; commit path against vsrx-ci |
| panos | 613 → 612 | stage → validate → commit; SSDF evidence drain; change-set create/approve/apply |
| sdc | 615 → 614 | prepare → approve → apply; packaging smoke with the new pin |
| proxmox | 617 → 616 | bind default, `StateDirectory` mode, evidence file mode now `0600`, change-set plan/approve/apply |
| mist | 619 → 618 | read path, plan/approve/apply, evidence outbox under the denylist |

Explicit checks, since these are the claims the sprint is making:

- evidence ledger and outbox are `0600` **with the unit's `UMask` removed**,
  proving the `mecmcp` fix rather than the directive
- the token fallback **reads** `/etc` and warns, and does **not** create a copy
- the stale-secret warning names every sibling file and deletes none
- binary size recorded before and after

A failed apply must be left reconciled, and any device residue reverted — a rig
left dirty is a finding, not an acceptable end state.

### Wave 4 — triage and close

| Item | Disposition |
|---|---|
| mecmcp #318 / #319 / #320 | Close as their children close; #320 stays open if spikes 1–2 are deferred |
| mecmcp #167 | Do it — XS, a verification task against SEP-2260 |
| mecmcp #164 | Do it if Wave 2 finishes early — S, the spike says rmcp 2→3 is cheaper than assumed |
| mecmcp #168 / #169 | Defer with reason: opt-in, no client needs them yet |
| mecmcp #222 | Defer with reason: no consumer configures `session_store` |
| junos #110 | Keep open, label `blocked-upstream` — closes when `ssh-key` 0.7.0 goes stable, tracked as rustnetconf#64. Not closeable by bumping russh; verified. |
| junos #335 | Decide and document (keep `/etc/jmcp`, record why), then close |
| junos #336 / #320 spikes 1–2 | Run the musl spike only if Wave 3 finishes early; otherwise defer with kill criteria recorded |
| rustmistmcp #39 | Defer or do if time — L; 78 MB RSS is the 4.5 MB catalog parsed to untyped `Value` and cloned in `relaxed_components()` |
| SSDF #26 | Out of sprint scope — a feature needing a new collector, schema, and MCP tool |

## Parallel workstream — publish `ssdf`

Independent of the five Rust repos, so it runs alongside Waves 1–2 without
contending for a checkout. It is roughly a day of work on its own; that cost was
raised and accepted.

Today `ssdf` is the only private repo of the seven. Its HEAD alone carries ~190
references to `pve3.mechub.org`, 105 to `192.168.1.150`, plus `panosvm`,
`prod-junosmcp`, `prod-panosmcp` and ~20 further internal hosts, across 145
commits.

1. **Back up first** — a full mirror clone kept locally. A history rewrite is
   not reversible on the remote.
2. **Real secrets before cosmetic ones.** Run gitleaks/trufflehog over all 145
   commits. A live credential in history is a rotation task, not a redaction
   task, and it outranks everything else here.
3. **Redaction mapping**, applied consistently so the docs stay coherent:
   internal hostnames to documentation names, `192.168.1.0/24` to a
   documentation range. Record the mapping in the repo.
4. **Rewrite** with `git-filter-repo` on the mirror, verify the result reads
   correctly, then force-push.
5. **Fix the red CI** (also tracked in Wave 1).
6. **Flip visibility — hard gate.** Publishing is outward-facing and effectively
   irreversible: forks and caches survive a revert. The flip happens only on
   explicit confirmation at the time, not on this document's approval.

## Risks

- **Codex quota exhaustion** mid-sprint. Presents as "Review was interrupted";
  the real cause shows only in raw `--json`. Mitigation: batch each repo's tier
  into one PR rather than one PR per issue, and report an ungated PR as ungated.
- **The `rustsdcmcp` five-file pin.** Missing one guard fails at *deploy* time,
  not build time. Mitigation: grep for the old tag across the repo before
  opening the PR.
- **junos syscall denylist breaking file transfer.** Highest blast radius in the
  sprint. Mitigation: rehearse on 611 before 610, and never on 950.
- **`IPAddressDeny` blackholing the evidence endpoint or a device subnet.**
  Mitigation: inventory check written into the PR description.
- **History rewrite invalidating clones.** Mitigation: mirror backup, and the
  rewrite is announced rather than silent.

## Explicitly out of scope

Production guests 950 / 951 / 952 / 960 / 971; LXC 970 (`notmechub`, not ours);
the MCP 2026-07-28 spec adoption beyond #167 and possibly #164; SSDF #26; the
Security Director unification described in `RELEASE-PROGRAMME.md`.
