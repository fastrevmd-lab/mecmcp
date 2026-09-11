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
| provenance file mandatory | junos, proxmox and unifi reference `BUILD-INFO` zero times. Only sdc recomputes a sha256. |

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

```toml
# Paths are relative to the assembled package root unless absolute.
binary     = "bin/rust-proxmoxmcp"
installer  = "packaging/lxc/install.sh"
service    = "rust-proxmoxmcp"
config_dir = "/etc/proxmoxmcp"
tokens     = "/var/lib/proxmoxmcp/tokens.json"

# Provenance. junos, proxmox and unifi ship none today; this records that
# truthfully rather than asserting an aspiration.
build_info = false

# Set when the repo's packager can package a CI-built binary, with the flag
# name it uses. The three names already disagree, which is #355 in miniature.
skip_build_env = "PROXMOXMCP_PACKAGE_SKIP_BUILD"   # or false
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
| 3 | If `build_info = true`, its sha256 equals the real bytes and `rustc` does not name a toolchain that did not compile the binary | **fatal where declared** | a `BUILD-INFO` was hand-written to satisfy validation and installed on two rigs |
| 4 | The installer creates its own `.service.d` directory | **warn** | 0 of 6 today; becomes fatal once fixed |
| 5 | Shipped units resolve under `systemd-analyze verify` after placeholder substitution | **fatal** | codifies the manual check already run by hand during the 2026-09-06/07 seccomp wave, which rendered the `@PLACEHOLDER@` tokens and confirmed `EPERM=1 denylist=1 SystemCallLog=0` on all six. Doing it by hand is why it was only done once |
| 6 | No security-relevant flag appears only in Docker `CMD` | **fatal** | rustmistmcp#78: any `--host` override silently dropped audit keying and redaction |

Rule 6 generalises the per-repo assertions added to rustmistmcp and
rustproxmoxmcp on 2026-09-11. Those stay where they are; this does not remove
them.

## Rollout

1. mecmcp: the workflow, the verifier, and its fixture tests.
2. **rustproxmoxmcp first.** It fails rule 1 today, so the first real run
   proves the check is live rather than vacuous, and the fix is one `chmod`.
3. rustpanosmcp next, the other rule 1 failure.
4. The remaining four, one PR each.
5. Once rule 4 passes everywhere, flip it to fatal in mecmcp. One PR, and
   every repo that has bumped the pin inherits it.

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
