# Package conformance check — design

Date: 2026-09-11
Closes the recurring half of: #355 (point 4), #357 (point 4)
Related: #356, #358

## Why

#6, #28 and #30 all closed COMPLETED on 2026-08-09. On 2026-09-07 every MCP
test rig was rebuilt from scratch and the divergences those issues described
were still present, now across six repos instead of two. Nothing was
continuously checking that the agreed convergence held, which is why four
repos were built afterwards that do not follow it and why nobody noticed for
a month.

#355 point 4, #356 point 3, #357 point 4 and #358 point 3 independently
propose the same remedy. This is that remedy, scoped to what can be proven
on a GitHub-hosted runner.

Two P1 fixes on 2026-09-11 are the immediate argument for it. In both
rustmistmcp#78 and rustproxmoxmcp#85 the Dockerfile fix was correct while the
documentation and, in mist's case, `scripts/verify-packaging.sh` still
described the broken world. Green CI throughout.

## What the tree actually shows, 2026-09-11

#355's table is a month old and three of its claims no longer hold. Verified
with `git ls-files -s` and `git grep` across all six repos:

| #355 said | Actual |
|---|---|
| junos's installer is at the repo root | **All six** are `packaging/lxc/install.sh`. This has already converged. |
| panos ships a 0644 installer | **panos and proxmox** both ship 0644. |
| provenance file mandatory | Not yet true anywhere. junos, proxmox and unifi reference `BUILD-INFO` zero times; only sdc recomputes a sha256. Mandatory remains the destination — see **Provenance ordering** for why the order matters. |

Confirmed unchanged: **no repo creates its own `.service.d` directory**
(0 of 6), so every install needs a manual `mkdir -p` before site config can
be placed.

These corrections are the point. A list in an issue rots; a check in CI does
not. The design assumes any hand-maintained inventory of the divergence is
already wrong.

## Decisions

Three choices were settled before design, each with the alternatives
considered.

### 1. Runs on GitHub-hosted runners, as an install-contract check

All seven repos run on `ubuntu-24.04`; the account has **zero** self-hosted
runners (`gh api repos/.../actions/runners` → `total_count=0`).

The posture #355 cares most about — `SystemCallFilter`, `ProtectSystem=strict`,
`SystemCallErrorNumber` — is systemd unit directives that only take effect
under a real systemd PID 1 on the target guest. Two alternatives were
rejected:

- **systemd inside a privileged container on the runner.** The runner's
  cgroup and seccomp environment is not an unprivileged Proxmox LXC.
  `IPAddressDeny` is the standing proof that a directive can be accepted,
  reported by `systemctl show`, and enforce nothing in that environment. A
  green result here could assert enforcement the real guests never receive,
  which is worse than no check.
- **A self-hosted runner in the lab.** Highest fidelity and the only thing
  that would truly retire "nobody has run a genuine fresh install from these
  artifacts", but it needs new infrastructure holding cluster credentials and
  able to create and destroy guests. Out of scope here; still the right answer
  for runtime enforcement, and this design must not be mistaken for it.

Every concrete failure #355 documents is an **install-time** failure:
`Permission denied` on a 0644 installer, three answers to where the binary
goes, a hand-forged `BUILD-INFO`, a missing drop-in directory, a host-proof
environment variable only one repo wants. None of them needs systemd to
detect.

### 2. Declare now, converge later

The verifier checks two classes of rule.

**Class 1 — the manifest.** Each repo commits `packaging/conformance.toml`
declaring what it claims to ship. The verifier asserts the package matches the
declaration. This is deliberately descriptive: it renders six layouts in one
schema so they are visible and diffable, without forcing a packaging migration
in five repos at once. Convergence later becomes a PR that changes values
rather than a rewrite.

Enforcing one layout immediately — what #355 literally asks for — was
rejected as a first increment. Its blast radius is every deploy path in the
fleet, and it would land before anything proves the checker itself works.

**Class 2 — universal rules**, true regardless of what a repo declares. These
are where convergence is actually enforced, and the set grows as repos are
fixed.

### 3. A SHA-pinned reusable workflow in mecmcp

mecmcp hosts `.github/workflows/package-conformance.yml` as a `workflow_call`
workflow. Each repo calls it, pinned by SHA, exactly as every other action in
these repos is already pinned.

Vendoring the script into each repo with a drift check was rejected: it is six
copies by construction, which is the shape #355 is complaining about, and the
drift check is itself something that can rot. Shipping the verifier inside the
mecmcp crate pin was rejected because a cargo dependency's binaries are not
runnable by dependents without `cargo install --git`, and the check inspects a
package tarball rather than linking Rust code.

## The manifest

`packaging/conformance.toml`, one per repo:

This example parses. `packaging/conformance/README.md` is the schema reference;
every key below is required unless marked optional.

```toml
# binary, installer and units are paths INSIDE the staging directory passed as
# --staging. An absolute value is rejected, because it would be joined onto the
# staging path anyway and report "not found" for a file that exists.
binary     = "bin/rust-proxmoxmcp"
installer  = "packaging/lxc/install.sh"
service    = "rust-proxmoxmcp"          # service name, no ".service"

# config_dir and tokens are absolute ON THE TARGET, and stay absolute.
config_dir = "/etc/proxmoxmcp"
tokens     = "/var/lib/proxmoxmcp/tokens.json"

# Provenance is MANDATORY. This key does not opt out of rule 3; it records
# whether the repo has reached it yet, and rule 3 reports warn instead of
# fatal while false. There is no configuration that makes a package legitimately
# provenance-free.
build_info = false        # -> true once the packager emits one honestly

# The packager's supported path for packaging a CI-built binary. Required
# before build_info can become true -- see "Provenance ordering" below.
# The three existing names already disagree, which is #355 in miniature.
# Optional. Either false, or a string NAMING the variable. `true` is rejected:
# it satisfies the ordering guard while naming nothing, which is what silently
# disabled rule 3's third clause.
skip_build_env = false    # panos, proxmox, unifi have none today

# Required, and the one key the earlier version of this example omitted. The
# units rule renders each of these and checks systemd can resolve the result.
# An empty list is legal and is announced, so it cannot be mistaken for the
# rule having been deleted.
units = ["packaging/systemd/rust-proxmoxmcp.service"]

# Flags that MUST survive an operator override (rule 6). Per-server knowledge:
# a generic rule cannot know that mist's audit keying is security-relevant and
# its --port is not. The mechanism is central; this list is what differs.
must_survive_override = [
  "--clusters-file",
  "--tokens-file",
]

# Optional. Test values for the @TOKEN@ placeholders the shipped units carry,
# used only to render a unit before checking it. Omit the table when the units
# carry no placeholders; an unrendered placeholder that survives rendering is a
# failure, because installing one killed rig 623.
[placeholders]
"@BIND_ADDRESS@" = "127.0.0.1:30031"
```

Unknown keys are an error, so a typo cannot silently disable a check.

## Universal rules

Each rule states its status: **fatal** now, or **warn** until the repos are
fixed. The two are chosen on one criterion — **can the adopting repo fix the
violation in the same PR that adopts the check?**

- **fatal** when the fix is trivial and local. Rule 1 is fatal even though
  panos and proxmox fail it today, because the fix is one `chmod` and lands in
  the same PR. That is deliberate: proxmox adopts first precisely so the first
  run fails, proving the rule bites before anyone relies on it.
- **warn** when the fix is neither. Rule 4 needs installer changes in all six
  repos, so it reports without failing until they are done, then flips.

No rule is introduced red in a repo that cannot go green in the same change.

| # | Rule | Status | Grounding |
|---|---|---|---|
| 1 | The installer is executable | **fatal** | panos and proxmox fail today; this is the whole reason rollout starts at proxmox |
| 2 | The declared binary exists at the declared path and is executable | **fatal** | three payload layouts; the manifest makes each one checkable |
| 3 | A `BUILD-INFO` is present, its recorded sha256 equals the real bytes, and `rustc` does not name a toolchain that did not compile the binary | **fatal where `build_info = true`, warn elsewhere** | a `BUILD-INFO` was hand-written to satisfy validation and installed on two rigs. All three clauses from day one: mandatory-but-unverified is worse than absent, because it launders a fabrication through a green check |
| 4 | The installer creates its own `.service.d` directory | **warn** | 0 of 6 today; becomes fatal once fixed |
| 5 | Shipped units resolve under `systemd-analyze verify` after placeholder substitution | **fatal** | codifies the manual check already run by hand during the 2026-09-06/07 seccomp wave, which rendered the `@PLACEHOLDER@` tokens and confirmed `EPERM=1 denylist=1 SystemCallLog=0` on all six. Doing it by hand is why it was only done once |
| 6 | Every flag in `must_survive_override` is still present in the container's argv after a typical operator override | **fatal** | rustmistmcp#78: any `--host` override silently dropped audit keying and redaction. Central mechanism, manifest-declared flag list |

Rule 6 replaces the per-repo assertions added to rustmistmcp and
rustproxmoxmcp on 2026-09-11. Standardising is the point of #355, and two
hand-written copies are two things that drift.

**They are removed only after the central rule is proven to bite in that
repo**, in the adopting PR: delete the flag from the Dockerfile, watch the
central rule fail, restore it, then delete the local assertion. Trading a
guard known to work for one merely known to be present is the failure mode
this project keeps finding.

## Provenance ordering

Provenance is mandatory. The order in which it becomes mandatory is the part
that matters, because getting it wrong recreates the bug the rule exists to
prevent.

Measured 2026-09-11:

| repo | supported skip-build path | ships `BUILD-INFO` |
|---|---|---|
| rustjunosmcp | `JMCP_PACKAGE_SKIP_BUILD` | **none** |
| rustpanosmcp | **none** | 1 file |
| rustsdcmcp | `SDCMCP_PACKAGE_SKIP_BUILD` | 4 files, **recomputes sha256** |
| rustmistmcp | `RUSTMISTMCP_SKIP_BUILD` | 5 files |
| rustproxmoxmcp | **none** | **none** |
| rustunifimcp | **none** | **none** |

Three repos cannot package a CI-built binary at all. Repackaging on a
workstation is not an alternative: glibc is forward-incompatible, so a binary
linked against the workstation's 2.44 will not start on the containers' 2.41,
and it fails at service start *after* the old binary has been replaced.

So a check that demands a `BUILD-INFO` those packagers cannot honestly produce
leaves the operator two options: do not ship, or hand-write one. That is
exactly how the forged `BUILD-INFO` of 2026-09-07 came about — #355's own
diagnosis is that "the pressure to fabricate it came directly from there being
no supported path". Making provenance mandatory before the supported path
exists would rebuild that pressure and put a passing check's name on the
result.

Therefore:

1. **A supported skip-build path lands first** in rustpanosmcp,
   rustproxmoxmcp and rustunifimcp, emitting an honest provenance file — one
   that records `rustc=unknown (binary supplied prebuilt; not compiled by this
   script)` rather than naming a local toolchain, as rustmistmcp already does.
2. **Then that repo flips `build_info = true`**, and rule 3 goes fatal for it.
3. Rule 3's three clauses — present, sha256 matches the real bytes, `rustc`
   honest — apply from day one wherever it is fatal. Mandatory-but-unverified
   is strictly worse than absent: it launders a fabrication through a green
   check, which is the precise failure #355 reports.

`build_info = false` is therefore a statement about *progress*, not an opt-out.
No value of it makes a package legitimately provenance-free, and the rule
reports on every run either way.

## Rollout

1. mecmcp: the workflow, the verifier, and its fixture tests.
2. **rustproxmoxmcp first.** It fails rule 1 today, so the first real run
   proves the check is live rather than vacuous, and the fix is one `chmod`.
3. rustpanosmcp next, the other rule 1 failure.
4. The remaining four, one PR each.
5. Separately, give rustpanosmcp, rustproxmoxmcp and rustunifimcp a
   supported skip-build path, then flip each to `build_info = true`.
6. Once rule 4 passes everywhere, flip it to fatal in mecmcp. One PR, and
   every repo that has bumped the pin inherits it. Same for rule 3 once all
   six declare `build_info = true`, at which point the key can be deleted.

## What this does not prove

Stated in the workflow's own output, not only here, because a green check is
read by people who did not read this document:

- **Nothing about runtime enforcement.** `SystemCallFilter`,
  `ProtectSystem=strict` and `SystemCallErrorNumber` are inert until a real
  systemd PID 1 on the real guest applies them. A green run must never be read
  as "the seccomp posture works."
- **Nothing about a genuine fresh install.** The package is unpacked and
  inspected, not installed. The standing caution that no fresh install has
  been performed from these artifacts survives this work unchanged.
- **Nothing about the device-facing behaviour** of any server.

## Testing the verifier

The verifier is a shell script, tested in mecmcp's own CI against fixture
packages under `packaging/conformance/fixtures/`:

- one conformant package, which must pass;
- **one deliberately broken package per rule**, each of which must fail that
  specific rule and no other.

The negative fixtures are the requirement, not a nicety. A checker whose
failure path is never exercised is indistinguishable from one that always
passes, and this project has shipped several. The fixture suite is what makes
rule 4's later promotion from warn to fatal a one-line change that is known to
bite.

## Out of scope

- Converging the six layouts onto one. This design makes the divergence
  visible; changing it is separate work.
- The credential-surface questions in #356 — config-vs-state for `tokens.json`,
  one naming rule, single-pass mode validation.
- `cli_validate` divergence in #358.
- Anything requiring lab hardware.
