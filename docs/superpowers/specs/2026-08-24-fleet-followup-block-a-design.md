# Fleet follow-up, block A: flaky captures, dependency coverage, egress posture

**Opened 2026-08-24**, after the fleet cleanup sprint closed 35 issues and left
13 open. This block covers five of them. The remaining eight are deliberately
out of scope and listed at the end.

## Scope

| Group | Issues | Repos touched |
|---|---|---|
| A — flaky audit capture | mecmcp #324, junos #339 | mecmcp, RustJunosMCP |
| B — dependency coverage | junos #338, panos #133 | RustJunosMCP, rustsdcmcp, rustproxmoxmcp, rust-panosmcp |
| C — egress posture | mecmcp #322 | RustJunosMCP, rust-panosmcp, rustmistmcp, rustproxmoxmcp |

Success is these five closed, each with the fix verified rather than asserted,
and no new inert controls introduced.

---

## Group A — the two flaky-test issues are one bug

### What is actually wrong

Both issues describe the cause as process-wide **stdout** capture racing under
`cargo test` parallelism. That is wrong, and it matters: it sends the next
reader to the wrong mechanism.

`run_with_capture` (`crates/mecmcp-audit/src/testutil.rs:148`) installs its
subscriber with `tracing::subscriber::with_default`, which is **thread-local**.
Two tests capturing concurrently do not share a subscriber.

What they do share is the **process-global callsite interest cache**. The helper
calls `tracing::callsite::rebuild_interest_cache()` before capturing, precisely
because a callsite may hold a verdict cached from before the subscriber existed.
When a second test rebuilds that cache mid-capture, a callsite the first test
depends on can be re-evaluated against a thread whose default subscriber does
not capture, and the event is dropped. The first test then sees an empty or
partial capture and fails.

This is also why the failure looks like "the capture went missing" rather than
"the assertion was wrong".

### The fix

A process-wide mutex held inside `run_with_capture`, spanning the interest-cache
rebuild and the capture. It goes **in the helper**, so:

- no test in any repo changes,
- junos is fixed by a `mecmcp` version bump alone,
- and a future consumer of the helper cannot reintroduce the race by forgetting
  to serialise.

Serialising is acceptable here on cost: these tests are sub-millisecond and there
are few of them. The alternative — giving `AuditScope` a caller-owned writer and
removing the global entirely — is the better end state but is a public API change
across every consumer, and is not worth coupling to a flake fix.

Use a `std::sync::Mutex` with poison recovery, because a panicking test inside
the closure would otherwise poison the lock and cascade one real failure into
every subsequent capture test.

### Verification

- `capture_under_concurrency` and junos's `srx_audit.rs` / `audit.rs` must pass
  a **50-run loop**, not a single run. The pre-fix rate was ~1 in 10, so a
  single green run proves nothing.
- Note for the runner: `capture_under_concurrency` needs
  `--features test-util`. Without it cargo **errors** rather than running, which
  in a loop is indistinguishable from a failing test. This produced a false
  "12/12 failures" reading during triage.
- Sabotage: remove the mutex, confirm the loop goes red again.
- Correct the stated mechanism in both issues when closing them.

---

## Group B — the gap is coverage, not a missing checker

### What the audit found

| Repo | Dependabot ecosystems | Dockerfile |
|---|---|---|
| **RustJunosMCP** | **none — no `.github/dependabot.yml` at all** | yes |
| rustsdcmcp | cargo, github-actions | yes (added Wave 2) |
| rustproxmoxmcp | cargo, github-actions | yes (added Wave 2) |
| rustmistmcp | cargo, github-actions, docker | yes |
| rust-panosmcp | cargo, github-actions, docker | yes |

**junos has no dependency automation of any kind.** Not cargo, not actions, not
docker. It is also the repo carrying the CVE-pinned `russh`, the `aws-lc-rs`
stack, and the only SSH/SCP surface in the fleet. Tier 1 added dependabot to
sdc, proxmox and mist — junos was skipped because it was assumed to already have
one.

sdc and proxmox were told to add the docker ecosystem "when a Dockerfile lands".
It landed in Wave 2. Nobody went back.

### Why this closes #338 without a bespoke checker

Dependabot already does registry digest resolution, and it demonstrably works
here: rustmistmcp #48 was Dependabot's own correction of the same stale
`d97bc0a9` digest, open and green, merged during the follow-up pass. junos's
digest is stale for exactly one reason — nothing is watching.

So:

1. Add `.github/dependabot.yml` to junos (cargo, github-actions, docker), copying
   mist's shape. **Do not** copy panos's historical `ignore: rust` entry — that
   was itself a filed bug that froze its toolchain at MSRV.
2. Add the docker ecosystem to sdc and proxmox now their Dockerfiles exist.
3. Let Dependabot open the junos digest PR; merge it. If it does not appear
   within a day, resolve `gcr.io/distroless/cc-debian13:nonroot` by hand and pin
   what the registry reports — never copy a sibling repo's digest, which is how
   `d97bc0a9` became "fleet consensus" in the first place.

### #133 — the drift check as a backstop

Implement it **scheduled and advisory**, not as a PR gate. A hard gate that fails
whenever upstream republishes a tag blocks every unrelated PR for something no
contributor did. A weekly workflow that resolves each pinned tag and opens or
updates a single issue on drift gives the same signal without the collateral.

It is a backstop for the case Dependabot misses, not the primary mechanism.

---

## Group C — make the inert control visible, do not pretend

`IPAddressDeny` / `IPAddressAllow` are accepted by systemd and reported by
`systemctl show`, and are **not enforced** in an unprivileged LXC — systemd
cannot attach the cgroup BPF program. Measured on rig 613: a loopback connection
succeeds identically with and without `IPAddressDeny=127.0.0.0/8`.

Every guest in this fleet is an unprivileged LXC.

Three parts, and only the first two are in scope here:

1. **Document it beside the directive** in junos, panos, mist and proxmox — unit
   comment plus operations doc — matching the wording rustsdcmcp already uses in
   `docs/operations.md`, "Enforcing it where systemd cannot".
2. **Warn at startup** when the unenforced case is detected, so an operator
   learns it from the running service rather than from reading a unit file. The
   check must be cheap and must never prevent startup.
3. **Move the control outward** — guest nftables, host nftables, or the Proxmox
   firewall. **Deferred by decision**: filed as separate ops work, because it is
   cluster configuration rather than repo code and would touch production guests.

The directive stays. It is correct and does enforce on a normal host or a
privileged container, and these units are not LXC-only artifacts. What changes is
that nobody reads it as active protection here.

---

## Sequencing

A, B and C are independent — no shared files, no ordering constraint between
groups. Within B, junos's `dependabot.yml` should land before waiting on the
digest PR, since it is the thing that produces it.

One agent per repo, as before. mecmcp's group A change lands first only because
junos's fix is a version bump that depends on it.

## Risks

- **Serialising captures hides a real concurrency bug.** If `AuditScope` itself
  were unsafe under concurrent emission, the mutex would mask it. It is not —
  the race is in the test helper's interest-cache handling, not the recorder —
  but the 50-run loop should be run against the *unserialised* production path
  too, not only the helper.
- **A new dependabot.yml on junos will open a burst of PRs.** That repo has never
  had automated updates, so expect a backlog on first run, including majors.
  Review rather than bulk-merge; the `russh` pin exists for CVE-2026-68930 and
  must not be bumped casually.
- **A scheduled drift check can become noise.** One issue updated in place, not a
  new issue per run.

## Out of scope

Eight issues are deliberately not in this block:

| Issue | Disposition |
|---|---|
| mecmcp #168, #169 | MCP 2026-07-28 spec work — real engineering, own block |
| mecmcp #222 | To be closed `wontfix`; its trigger is a consumer that does not exist |
| mecmcp #320, junos #336 | Spikes — to be **run and answered**, including "no" |
| mist #39 | 78 MB catalog perf; diagnosis recorded, own block |
| ssdf #1 | Device-native alarms ingest; check the UniFi CEF path first |
| junos #110 | Blocked upstream on `ssh-key` 0.7.0 |

## Outcome (2026-08-24)

All seven tasks shipped. Every target issue is closed: mecmcp #324 and #322,
junos #338 and #339, panos #133.

| Task | Repos | Result |
|---|---|---|
| 1 | mecmcp | `run_with_capture` serialised against the global interest cache |
| 2 | mecmcp | v0.18.0 tagged (`a0a59ad`) |
| 3 | junos | consumes mecmcp 0.18.0 |
| 4+5 | junos, sdc, proxmox | `docker` ecosystem added to dependabot |
| 6 | panos | scheduled digest-drift backstop (advisory) |
| 7 | junos, panos, mist, proxmox | egress-enforcement probe ported from sdc |

Final whole-branch review across all six repos: spec compliance PASS, quality
APPROVED, no findings.

### What the block actually taught

**The dependency fix proved itself rather than being assumed.** Task 4 added the
`docker` ecosystem to junos because nothing was watching the base image. The
prediction above — "expect a backlog on first run, including majors" — held
exactly: Dependabot's first run opened twelve PRs. One of them, #342, bumped the
precise stale digest that #338 was filed for. That is the fix demonstrating
itself end to end, not a hand-bump that would have left the blind spot intact.

The majors in that backlog (`actions/checkout` 4→7, `rustix` 0.38→1.1,
`tower-http` 0.6→0.7) are deliberately left open for review, per this spec's own
warning. The `russh` pin was not touched.

**A digest is an identity, not a magnitude.** An earlier reading called
`a77defd6` a downgrade from `d97bc0a9`. SHA-256 digests have no ordering; the
registry settles which is current, and comparison is equality only.

**`UNKNOWN` is the load-bearing verdict.** The egress probe's value is not that
it detects unenforced policy — it is that it refuses to answer when it cannot
measure. A host where the probe cannot run reports `UNKNOWN`, never
`NOT ENFORCED`. Reporting the latter would send an operator after a problem that
may not exist: the same false-assurance error this block exists to remove,
merely inverted. Verified by observation — the probe returns `UNKNOWN` on an
unprivileged workstation.

**Keeping the directive was the right call.** `IPAddressDeny` is inert only under
unprivileged LXC. Deleting it would have traded a silent false positive for a
real loss of defence everywhere the mechanism works. The fix was to stop
*implying* enforcement and start *measuring* it.
