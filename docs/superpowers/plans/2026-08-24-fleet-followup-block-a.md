# Fleet Follow-up Block A Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close five issues left by the fleet cleanup sprint — one shared test-helper race, a fleet-wide dependency-automation gap, and an egress control that reports as present but is not enforced.

**Architecture:** Three independent groups. Group A fixes one shared helper in `mecmcp-audit`, so junos is fixed by a version bump with no test changes. Group B closes a Dependabot **coverage** gap rather than building a bespoke digest checker, because Dependabot already resolves these digests correctly. Group C ports rustsdcmcp's existing, working egress-enforcement probe to the four servers that lack it, rather than inventing a new warning.

**Tech Stack:** Rust 2024 edition (MSRV 1.88), `tracing` / `tracing-subscriber`, POSIX sh and bash installers, GitHub Actions, Dependabot.

**Spec:** `docs/superpowers/specs/2026-08-24-fleet-followup-block-a-design.md`

## Global Constraints

- **Never claim a gate passed without seeing it pass.** Capture the real exit code; `cmd | tail` reports *tail's* status, not the command's. Use `cmd; echo "exit=$?"`.
- **Never `git add -A`** — `codex exec review` leaves a `.review-codex/` tree containing a ~23 MB binary. Stage files explicitly.
- **Do not touch any live guest.** No `ssh`, `pct`, `qm`, or Proxmox API. Guests 950/951/952/960/971 are production; 610–619 are rigs and are out of scope for this block.
- All five workspaces set `clippy::todo = "deny"` and `clippy::unwrap_used = "deny"`. Test modules need `#[allow(clippy::unwrap_used)]`.
- **`RustJunosMCP`'s `russh` pin exists for CVE-2026-68930.** Do not bump it.
- mecmcp version is currently **0.17.0**; consumers pin it by immutable git tag.
- Repo→path: `mecmcp`, `RustJunosMCP`, `rustsdcmcp`, `rustproxmoxmcp`, `rustmistmcp`, `rust-panosmcp` all under `/home/mharman/Projects/`.

---

## Task 1: Serialise the audit capture helper (mecmcp #324)

**Files:**
- Modify: `crates/mecmcp-audit/src/testutil.rs:148-163` (the `run_with_capture` function)
- Test: `crates/mecmcp-audit/tests/capture_under_concurrency.rs` (exists; add one test)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub fn run_with_capture<F: FnOnce()>(f: F) -> String` — signature **unchanged**. Task 3 relies on this being fixed without any caller edit.

**Background the implementer needs:** The race is *not* stdout. `tracing::subscriber::with_default` is thread-local, so concurrent tests do not share a subscriber. What they share is the process-global callsite interest cache, which `run_with_capture` rebuilds via `tracing::callsite::rebuild_interest_cache()`. A concurrent rebuild re-evaluates a callsite against a thread whose default subscriber does not capture, and the event is dropped — so the failure looks like a missing capture, not a wrong assertion.

- [ ] **Step 1: Write the failing test**

Append to `crates/mecmcp-audit/tests/capture_under_concurrency.rs`:

```rust
/// Many concurrent captures must each see their own event.
///
/// `run_with_capture` rebuilds the process-global callsite interest cache. Two
/// threads doing that at once can re-evaluate a callsite against a thread whose
/// subscriber does not capture, dropping the event — so a capture comes back
/// empty even though the audit code ran correctly.
#[test]
fn many_concurrent_captures_each_see_their_own_event() {
    let failures: Vec<String> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|i| {
                scope.spawn(move || {
                    let tool: &'static str = if i % 2 == 0 { "alpha" } else { "beta" };
                    let out = mecmcp_audit::testutil::run_with_capture(|| {
                        let mut scope = mecmcp_audit::AuditScope::stdio(tool, "read", Vec::new());
                        scope.succeed();
                    });
                    if out.contains(tool) {
                        None
                    } else {
                        Some(format!("thread {i} ({tool}) captured: {out:?}"))
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .filter_map(|h| h.join().expect("capture thread panicked"))
            .collect()
    });

    assert!(
        failures.is_empty(),
        "{} of 16 concurrent captures lost their event:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
cd /home/mharman/Projects/mecmcp
for i in $(seq 10); do
  cargo test -q -p mecmcp-audit --features test-util --test capture_under_concurrency \
    many_concurrent_captures >/dev/null 2>&1 || echo "FAIL run $i"
done
```

Expected: at least one `FAIL run N`.

**If it passes 10/10**, the test is not reproducing the race — raise the thread count to 64 and retry before proceeding. Do not continue with a test that does not fail.

**Note:** `--features test-util` is required. Without it cargo prints `target requires the features: test-util` and exits non-zero, which in a loop is indistinguishable from a failing test.

- [ ] **Step 3: Implement the fix**

Replace the body of `run_with_capture` in `crates/mecmcp-audit/src/testutil.rs`:

```rust
/// Serialises [`run_with_capture`].
///
/// The subscriber is thread-local, but the callsite interest cache this helper
/// rebuilds is process-global. Two captures running at once invalidate each
/// other's callsite verdicts and silently drop events, which presents as an
/// empty capture rather than a failed assertion (mecmcp#324, rustjunosmcp#339).
///
/// Serialising is cheap here — these captures are sub-millisecond — and putting
/// the lock inside the helper means no caller can reintroduce the race by
/// forgetting to take it.
static CAPTURE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` with a temporary subscriber capturing INFO output; return the text.
pub fn run_with_capture<F: FnOnce()>(f: F) -> String {
    // Recover from poisoning rather than propagating it: a panicking test inside
    // the closure would otherwise turn one real failure into a cascade of
    // unrelated ones in every later capture test.
    let _guard = CAPTURE_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    let cap = CapturingWriter::default();
    let subscriber = AlwaysAsk(
        tracing_subscriber::fmt()
            .with_writer(cap.clone())
            .with_ansi(false)
            .with_target(true)
            .with_max_level(tracing::Level::INFO)
            .finish(),
    );
    // Existing callsites may already hold a cached verdict from before this
    // subscriber existed; `AlwaysAsk` only governs registrations it sees.
    tracing::callsite::rebuild_interest_cache();
    tracing::subscriber::with_default(subscriber, f);
    let bytes = cap.0.lock().unwrap().clone();
    String::from_utf8(bytes).unwrap()
}
```

- [ ] **Step 4: Run the loop and confirm it now passes**

```bash
cd /home/mharman/Projects/mecmcp
fail=0
for i in $(seq 50); do
  cargo test -q -p mecmcp-audit --features test-util --test capture_under_concurrency >/dev/null 2>&1 || fail=$((fail+1))
done
echo "failures: $fail/50"
```

Expected: `failures: 0/50`. A single green run is not sufficient — the pre-fix rate was roughly 1 in 10.

- [ ] **Step 5: Sabotage-verify the fix**

Comment out the `let _guard = ...` line, re-run the 50-run loop, confirm failures return, then restore and confirm 0/50 again. Paste both numbers.

- [ ] **Step 6: Full gate**

```bash
cd /home/mharman/Projects/mecmcp
fail=0
cargo fmt --all -- --check || fail=1
cargo clippy --workspace --all-targets -- -D warnings >/dev/null 2>&1 || fail=1
cargo test --workspace >/dev/null 2>&1 || fail=1
echo "gates failed=$fail"
```

Do not commit unless `gates failed=0`.

- [ ] **Step 7: Commit**

```bash
cd /home/mharman/Projects/mecmcp
git checkout -b fix/324-serialise-capture
git add crates/mecmcp-audit/src/testutil.rs crates/mecmcp-audit/tests/capture_under_concurrency.rs
git commit -m "fix(testutil): serialise run_with_capture against the global interest cache

The race is not process-wide stdout — with_default is thread-local. It is
tracing::callsite::rebuild_interest_cache(), which is process-global: a
concurrent rebuild re-evaluates a callsite against a thread whose subscriber
does not capture, and the event is dropped. That is why the failure presents
as an empty capture rather than a wrong assertion.

A mutex inside the helper fixes every consumer without a caller change,
including rustjunosmcp#339 which imports this same function. Poison is
recovered rather than propagated so one panicking test does not cascade.

Sabotage-verified: without the guard the 50-run loop fails; with it, 0/50.

Closes #324"
```

---

## Task 2: Release mecmcp 0.18.0

**Files:**
- Modify: `Cargo.toml:6` (workspace `version`)

**Interfaces:**
- Consumes: Task 1's fix on the same branch.
- Produces: git tag **`v0.18.0`**, pushed. Task 3 pins this exact tag.

- [ ] **Step 1: Bump the workspace version**

In `/home/mharman/Projects/mecmcp/Cargo.toml`, change `version      = "0.17.0"` to `version      = "0.18.0"`. All 14 member crates inherit it.

- [ ] **Step 2: Confirm nothing still says 0.17.0**

```bash
cd /home/mharman/Projects/mecmcp
rg -n '0\.17\.0' Cargo.toml crates/*/Cargo.toml
```

Expected: no output.

- [ ] **Step 3: Gate**

```bash
cd /home/mharman/Projects/mecmcp
fail=0
cargo fmt --all -- --check || fail=1
cargo clippy --workspace --all-targets -- -D warnings >/dev/null 2>&1 || fail=1
cargo test --workspace >/dev/null 2>&1 || fail=1
echo "gates failed=$fail"
```

- [ ] **Step 4: Commit, open the PR, and merge once CI is green**

```bash
cd /home/mharman/Projects/mecmcp
git add Cargo.toml
git commit -m "chore: release 0.18.0"
git push -u origin fix/324-serialise-capture
gh pr create --repo fastrevmd-lab/mecmcp --base main --head fix/324-serialise-capture \
  --title "fix(testutil): serialise run_with_capture; release 0.18.0" \
  --body "Fixes the shared capture race behind #324 and rustjunosmcp#339. Closes #324."
```

Wait for all checks to report SUCCESS, then merge with `gh pr merge <n> --merge --delete-branch`.

**If `capture_under_concurrency` fails in CI**, that is the very flake being fixed — but do not assume. Re-run the job once; if it fails twice, the fix is incomplete and Task 1 must be revisited.

- [ ] **Step 5: Tag and push**

```bash
cd /home/mharman/Projects/mecmcp
git checkout main && git pull --ff-only
git tag -a v0.18.0 -m "mecmcp 0.18.0

run_with_capture is serialised against the process-global callsite interest
cache. Fixes intermittent empty captures in mecmcp-audit and in every consumer
that imports the helper (rustjunosmcp#339)."
git push origin v0.18.0
```

---

## Task 3: Fix junos's flaky audit tests via the mecmcp bump (junos #339)

**Files:**
- Modify: `/home/mharman/Projects/RustJunosMCP/Cargo.toml` — every `mecmcp-*` dependency, tag `v0.17.0` → `v0.18.0`

**Interfaces:**
- Consumes: tag `v0.18.0` from Task 2, and the unchanged `run_with_capture` signature from Task 1.
- Produces: nothing later tasks depend on.

**No test file changes.** `rust-junosmcp/tests/audit.rs` and `tests/srx_audit.rs` import `mecmcp_audit::testutil::run_with_capture`; the fix arrives with the dependency.

- [ ] **Step 1: Bump every mecmcp pin**

```bash
cd /home/mharman/Projects/RustJunosMCP
git checkout main && git pull --ff-only
git checkout -b fix/339-mecmcp-018
sed -i 's/tag = "v0\.17\.0"/tag = "v0.18.0"/g; s/version = "0\.17\.0"/version = "0.18.0"/g' Cargo.toml
rg -n '0\.17\.0' Cargo.toml
```

Expected from the final `rg`: no output.

- [ ] **Step 2: Update the lockfile**

```bash
cd /home/mharman/Projects/RustJunosMCP
cargo update -w
grep -A1 'name = "mecmcp-audit"' Cargo.lock | head -2
```

Expected: `version = "0.18.0"`.

- [ ] **Step 3: Prove the flake is gone**

```bash
cd /home/mharman/Projects/RustJunosMCP
fail=0
for i in $(seq 50); do
  cargo test -q -p rust-junosmcp --test audit >/dev/null 2>&1 || fail=$((fail+1))
done
echo "audit.rs failures: $fail/50"
fail=0
for i in $(seq 50); do
  cargo test -q -p rust-junosmcp --test srx_audit >/dev/null 2>&1 || fail=$((fail+1))
done
echo "srx_audit.rs failures: $fail/50"
```

Expected: `0/50` for both. Before this change the rate was roughly 1 in 10.

- [ ] **Step 4: Full gate**

```bash
cd /home/mharman/Projects/RustJunosMCP
fail=0
cargo fmt --all -- --check || fail=1
cargo clippy --workspace --all-targets -- -D warnings >/dev/null 2>&1 || fail=1
cargo test --workspace >/dev/null 2>&1 || fail=1
shellcheck packaging/tests/*.sh packaging/lxc/install.sh scripts/*.sh >/dev/null 2>&1 || fail=1
echo "gates failed=$fail"
```

Note: `cargo test --workspace` may now be run without `--test-threads=1`, which was previously needed to dodge this flake. If it passes, say so in the PR — that is the observable proof.

- [ ] **Step 5: Commit, PR, merge**

```bash
cd /home/mharman/Projects/RustJunosMCP
git add Cargo.toml Cargo.lock
git commit -m "chore(deps): mecmcp 0.18.0, fixing the flaky audit captures

The race was in mecmcp-audit's run_with_capture, which this repo imports:
the callsite interest cache it rebuilds is process-global while the
subscriber is thread-local, so concurrent captures dropped each other's
events. Fixed upstream; no test changes needed here.

audit.rs and srx_audit.rs now pass 50/50 each, and the workspace suite no
longer needs --test-threads=1.

Closes #339"
git push -u origin fix/339-mecmcp-018
gh pr create --repo fastrevmd-lab/RustJunosMCP --base main --head fix/339-mecmcp-018 \
  --title "chore(deps): mecmcp 0.18.0 — fixes flaky audit captures (#339)" \
  --body "Closes #339. No test changes; the fix is in the shared helper."
```

Merge once green.

---

## Task 4: Give RustJunosMCP its first Dependabot config (junos #338)

**Files:**
- Create: `/home/mharman/Projects/RustJunosMCP/.github/dependabot.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing later tasks depend on. Independent of Tasks 1–3.

**Why this exists:** junos has **no** `.github/dependabot.yml` at all — no cargo, no github-actions, no docker — in the repo carrying the CVE-pinned `russh`, the `aws-lc-rs` stack, and the fleet's only SSH/SCP surface. That is the sole reason its distroless digest went stale with no PR while mist's was corrected automatically.

- [ ] **Step 1: Create the config**

```yaml
version: 2
updates:
  - package-ecosystem: "cargo"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 5
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

Do **not** add an `ignore:` entry for `rust`. rust-panosmcp carried one and it silently froze its builder toolchain at the MSRV floor for months (rustpanosmcp#126).

- [ ] **Step 2: Verify it parses as YAML**

```bash
cd /home/mharman/Projects/RustJunosMCP
python3 -c "import sys,yaml;yaml.safe_load(open('.github/dependabot.yml'));print('valid YAML')" 2>/dev/null \
  || python3 -c "
import re,sys
s=open('.github/dependabot.yml').read()
assert s.startswith('version: 2'), 'must start with version: 2'
assert s.count('- package-ecosystem:')==3, 'expected 3 ecosystems'
for e in ('cargo','github-actions','docker'):
    assert f'\"{e}\"' in s, f'missing {e}'
print('structure OK')"
```

- [ ] **Step 3: Commit, PR, merge**

```bash
cd /home/mharman/Projects/RustJunosMCP
git checkout main && git pull --ff-only
git checkout -b fix/338-dependabot
git add .github/dependabot.yml
git commit -m "ci: add Dependabot — this repo had none at all

No cargo, no github-actions, no docker. That is why the distroless digest
went stale with no PR: nothing was watching. Tier 1 added Dependabot to sdc,
proxmox and mist and skipped this repo on the assumption it already had one.

This is also the repo with the CVE-2026-68930 russh pin and the fleet's only
SSH/SCP surface, so it is the worst place to have no automated advisories.

No ignore: rust entry — that pattern froze rust-panosmcp's builder at the
MSRV floor (rustpanosmcp#126).

Refs #338"
git push -u origin fix/338-dependabot
gh pr create --repo fastrevmd-lab/RustJunosMCP --base main --head fix/338-dependabot \
  --title "ci: add Dependabot (repo had none)" --body "Refs #338."
```

- [ ] **Step 4: Let Dependabot open the digest PR, then close #338**

After merge, wait for Dependabot's first run (up to ~24h). It should open a docker PR moving `gcr.io/distroless/cc-debian13:nonroot` off the stale `d97bc0a9`. Review and merge it, then close #338 referencing that PR.

**If no PR appears within a day**, resolve the digest by hand and pin exactly what the registry reports:

```bash
TOKEN=$(curl -s "https://gcr.io/v2/token?scope=repository:distroless/cc-debian13:pull&service=gcr.io" \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
curl -sI -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
  https://gcr.io/v2/distroless/cc-debian13/manifests/nonroot | grep -i docker-content-digest
```

Never copy a digest from a sibling repo. Comparing repos to each other rather than to the registry is exactly how the stale `d97bc0a9` became "fleet consensus".

**Expect a burst of PRs on first run**, including majors — this repo has never had automated updates. Review them; do not bulk-merge. The `russh` pin must not move.

---

## Task 5: Add the docker ecosystem to rustsdcmcp and rustproxmoxmcp

**Files:**
- Modify: `/home/mharman/Projects/rustsdcmcp/.github/dependabot.yml`
- Modify: `/home/mharman/Projects/rustproxmoxmcp/.github/dependabot.yml`

**Interfaces:**
- Consumes: nothing. Independent of all other tasks.
- Produces: nothing.

**Why:** both were told to add the docker ecosystem "when a Dockerfile lands" (rustsdcmcp#93, rustproxmoxmcp#21). It landed in Wave 2 (rustsdcmcp#91, rustproxmoxmcp#26). Nobody went back, so both now ship a distroless image with no digest automation.

- [ ] **Step 1: Append the ecosystem to both files**

Add to the end of `updates:` in each:

```yaml
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

- [ ] **Step 2: Confirm each repo actually has a Dockerfile at that directory**

```bash
for d in rustsdcmcp rustproxmoxmcp; do
  printf "%-16s " "$d"
  ls "/home/mharman/Projects/$d/Dockerfile" >/dev/null 2>&1 && echo "Dockerfile present" || echo "MISSING — do not add the ecosystem"
done
```

Both must print `Dockerfile present`. If either does not, stop and report — the ecosystem would watch nothing.

- [ ] **Step 3: Commit both, PR each, merge**

```bash
for d in rustsdcmcp rustproxmoxmcp; do
  cd "/home/mharman/Projects/$d"
  git checkout main && git pull --ff-only
  git checkout -b ci/dependabot-docker
  git add .github/dependabot.yml
  git commit -m "ci: watch the Dockerfile with Dependabot

The docker ecosystem was deferred until a Dockerfile existed. One landed in
Wave 2, so the image has been shipping with no digest automation since.

Without this, a stale base digest goes unnoticed until someone compares
repos by hand — which is how rustjunosmcp#338 happened."
  git push -u origin ci/dependabot-docker
done
```

Open a PR in each with `gh pr create`, and merge once green.

---

## Task 6: Scheduled digest-drift backstop (panos #133)

**Files:**
- Create: `/home/mharman/Projects/rust-panosmcp/.github/workflows/digest-drift.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing.

**Design constraint from the spec:** this is **scheduled and advisory**, never a PR gate. A hard gate would fail every unrelated PR the moment Google republishes a tag — punishing a contributor for someone else's release. It is a backstop for what Dependabot misses, not the primary mechanism.

- [ ] **Step 1: Create the workflow**

```yaml
name: digest drift

# Advisory only, and deliberately not a PR gate: upstream republishing a tag
# must not fail an unrelated contributor's build. Dependabot is the primary
# mechanism; this catches the case where it does not fire.
on:
  schedule:
    - cron: "17 6 * * 1"
  workflow_dispatch:

permissions:
  contents: read
  issues: write

jobs:
  check:
    name: pinned digest vs registry
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Resolve the pinned tag and compare
        id: drift
        run: |
          set -euo pipefail
          line=$(grep -m1 '^FROM gcr.io/distroless/cc-debian13' Dockerfile)
          pinned=$(printf '%s' "$line" | sed -n 's/.*@\(sha256:[0-9a-f]*\).*/\1/p')
          tag=$(printf '%s' "$line" | sed -n 's|^FROM gcr.io/distroless/cc-debian13:\([^@]*\)@.*|\1|p')
          [ -n "$pinned" ] && [ -n "$tag" ] || { echo "could not parse Dockerfile FROM line"; exit 1; }

          token=$(curl -sf "https://gcr.io/v2/token?scope=repository:distroless/cc-debian13:pull&service=gcr.io" \
            | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
          current=$(curl -sfI -H "Authorization: Bearer $token" \
            -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
            "https://gcr.io/v2/distroless/cc-debian13/manifests/$tag" \
            | tr -d '\r' | sed -n 's/^docker-content-digest: //Ip')
          [ -n "$current" ] || { echo "registry did not return a digest"; exit 1; }

          echo "tag=$tag"; echo "pinned=$pinned"; echo "current=$current"
          {
            echo "tag=$tag"
            echo "pinned=$pinned"
            echo "current=$current"
            if [ "$pinned" = "$current" ]; then echo "drifted=false"; else echo "drifted=true"; fi
          } >> "$GITHUB_OUTPUT"

      - name: Open or update the drift issue
        if: steps.drift.outputs.drifted == 'true'
        env:
          GH_TOKEN: ${{ github.token }}
          TAG: ${{ steps.drift.outputs.tag }}
          PINNED: ${{ steps.drift.outputs.pinned }}
          CURRENT: ${{ steps.drift.outputs.current }}
        run: |
          set -euo pipefail
          title="Pinned distroless digest has drifted from the registry"
          body=$(printf '%s\n' \
            "\`gcr.io/distroless/cc-debian13:$TAG\` no longer resolves to the pinned digest." \
            "" \
            "| | digest |" \
            "|---|---|" \
            "| pinned in Dockerfile | \`$PINNED\` |" \
            "| registry now returns | \`$CURRENT\` |" \
            "" \
            "Dependabot normally handles this. If it has not opened a PR, check that the" \
            "\`docker\` ecosystem is enabled in \`.github/dependabot.yml\`." \
            "" \
            "**Pin what the registry reports — never copy a digest from a sibling repo.**" \
            "Comparing repos to each other is how a stale value became \"fleet consensus\"" \
            "in rustpanosmcp#127.")
          existing=$(gh issue list --state open --search "$title in:title" --json number -q '.[0].number' || true)
          if [ -n "$existing" ]; then
            gh issue comment "$existing" --body "$body"
          else
            gh issue create --title "$title" --body "$body"
          fi
```

- [ ] **Step 2: Validate the YAML**

```bash
cd /home/mharman/Projects/rust-panosmcp
python3 -c "import yaml;yaml.safe_load(open('.github/workflows/digest-drift.yml'));print('valid YAML')"
```

- [ ] **Step 3: Prove the comparison logic works, both ways**

Run the resolve-and-compare body locally against the real Dockerfile:

```bash
cd /home/mharman/Projects/rust-panosmcp
line=$(grep -m1 '^FROM gcr.io/distroless/cc-debian13' Dockerfile)
pinned=$(printf '%s' "$line" | sed -n 's/.*@\(sha256:[0-9a-f]*\).*/\1/p')
tag=$(printf '%s' "$line" | sed -n 's|^FROM gcr.io/distroless/cc-debian13:\([^@]*\)@.*|\1|p')
token=$(curl -sf "https://gcr.io/v2/token?scope=repository:distroless/cc-debian13:pull&service=gcr.io" | python3 -c "import sys,json;print(json.load(sys.stdin)['token'])")
current=$(curl -sfI -H "Authorization: Bearer $token" -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" "https://gcr.io/v2/distroless/cc-debian13/manifests/$tag" | tr -d '\r' | sed -n 's/^docker-content-digest: //Ip')
echo "tag=$tag"; echo "pinned=$pinned"; echo "current=$current"
[ "$pinned" = "$current" ] && echo "NO DRIFT (expected today)" || echo "DRIFTED"
```

Expected today: `NO DRIFT`, because panos was corrected to the current digest during the sprint.

Then prove the drift branch fires: temporarily edit the Dockerfile digest to `sha256:0000000000000000000000000000000000000000000000000000000000000000`, re-run the block, confirm it prints `DRIFTED`, and restore the file. A check that has only ever printed "no drift" has not been tested.

- [ ] **Step 4: Trigger it once for real**

After merging, run `gh workflow run digest-drift.yml --repo fastrevmd-lab/rust-panosmcp`, then confirm the run succeeded and opened no issue. A scheduled workflow nobody has ever run is not known to work.

- [ ] **Step 5: Commit, PR, merge, close #133**

```bash
cd /home/mharman/Projects/rust-panosmcp
git checkout main && git pull --ff-only
git checkout -b ci/133-digest-drift
git add .github/workflows/digest-drift.yml
git commit -m "ci: weekly advisory check for distroless digest drift

Resolves the pinned tag against the registry and opens (or updates) a single
issue when the Dockerfile pin no longer matches.

Deliberately scheduled and advisory rather than a PR gate: upstream
republishing a tag must not fail an unrelated contributor's build. Dependabot
remains the primary mechanism — this catches the case where it does not fire,
which is what rustjunosmcp#338 turned out to be.

Closes #133"
git push -u origin ci/133-digest-drift
gh pr create --repo fastrevmd-lab/rust-panosmcp --base main --head ci/133-digest-drift \
  --title "ci: weekly advisory digest-drift check" --body "Closes #133."
```

---

## Task 7: Port rustsdcmcp's egress-enforcement probe to the other four (mecmcp #322)

**Files:**
- Read (reference, do not modify): `/home/mharman/Projects/rustsdcmcp/packaging/lxc/install.sh:355-410`, `/home/mharman/Projects/rustsdcmcp/docs/operations.md:100-140`
- Modify: `packaging/lxc/install.sh` in `RustJunosMCP`, `rust-panosmcp`, `rustmistmcp`, `rustproxmoxmcp`
- Modify: the operations doc in each of those four
- Modify: `packaging/systemd/*.service` in each of those four (comment only)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: nothing.

**Do not invent a new check.** rustsdcmcp already has a correct one. It probes *actual* enforcement rather than asserting capability, using IP accounting — which rides the same cgroup BPF attachment, so a populated `IPEgressBytes` counter proves the filter attached. It reports four states, and the distinction between the last two matters:

- `ENFORCED` — host attaches the BPF program **and** the installed unit declares a policy
- `NOT ENFORCED` — host cannot attach it (normal in unprivileged LXC)
- `NO POLICY` — host could enforce, but the installed unit declares none (a preserved custom unit overriding the packaged one)
- `UNKNOWN` — the probe could not run; nothing is claimed

`UNKNOWN` must not be reported as `NOT ENFORCED`. An unmeasured host may well be enforcing.

- [ ] **Step 1: Read the reference implementation**

```bash
sed -n '350,415p' /home/mharman/Projects/rustsdcmcp/packaging/lxc/install.sh
sed -n '96,145p' /home/mharman/Projects/rustsdcmcp/docs/operations.md
```

Note it is `bash` in sdc. `rustproxmoxmcp`'s installer is **POSIX `sh`** (`#!/bin/sh`, `set -eu`) — `[[ ]]` is invalid there and shellcheck will flag SC3010. Use `[ ]` and POSIX syntax in that repo.

- [ ] **Step 2: Port the probe into each installer**

Adapt per repo, substituting the service name and the env-var prefix each installer already uses (`JMCP_`, `PANOSMCP_`, `RUSTMISTMCP_`, `PROXMOXMCP_`). Keep sdc's four verdicts and its wording verbatim where it applies, so the fleet reads consistently. Provide the same opt-in strictness flag, named for the repo, e.g. `JMCP_REQUIRE_EGRESS_FILTER=1`.

Run it at the end of installation, after the unit is in place — the `NO POLICY` verdict requires reading the **installed** unit, not the packaged one.

- [ ] **Step 3: Add the unit comment**

Directly above `IPAddressDeny=` in each of the four `.service` files:

```
# NOTE: IPAddressAllow/IPAddressDeny are accepted by systemd and reported by
# `systemctl show`, but are NOT enforced in an unprivileged LXC — systemd cannot
# attach the cgroup BPF program there. Every guest in this fleet is one. The
# directives stay because they do enforce on a normal host or privileged
# container, but do not read them as active protection here. The installer
# probes real enforcement and prints ENFORCED / NOT ENFORCED / NO POLICY /
# UNKNOWN. See the operations doc, "Enforcing it where systemd cannot" (mecmcp#322).
```

- [ ] **Step 4: Add the operations-doc section**

Add an "Enforcing it where systemd cannot" section to each of the four operations docs, mirroring sdc's: the four verdicts, the standing verification command, and the note that the policy does not change with the runtime — deny `169.254.0.0/16` and `fd00:ec2::254`, and put the control where it sees packets.

```console
systemctl show <service>.service -p IPEgressBytes --value
```

`[no data]` means the egress directives are doing nothing.

- [ ] **Step 5: Verify each installer still parses and passes shellcheck**

```bash
for d in RustJunosMCP rust-panosmcp rustmistmcp rustproxmoxmcp; do
  printf "%-16s " "$d"
  f="/home/mharman/Projects/$d/packaging/lxc/install.sh"
  bash -n "$f" 2>/dev/null && shellcheck "$f" >/dev/null 2>&1 && echo "parses + shellcheck clean" || echo "PROBLEM"
done
```

All four must print `parses + shellcheck clean`. For `rustproxmoxmcp`, also confirm no `[[` was introduced:

```bash
grep -c '\[\[' /home/mharman/Projects/rustproxmoxmcp/packaging/lxc/install.sh
```

Expected: the same count as before your change (POSIX sh must not gain any).

- [ ] **Step 6: Prove the probe reports the truth on this machine**

The probe's own logic can be exercised without installing anything:

```bash
systemd-run --quiet --collect --unit=egress-probe-test \
  --property=IPAccounting=yes --property=RemainAfterExit=yes /bin/true 2>/dev/null \
  && systemctl show egress-probe-test.service -p IPEgressBytes --value
systemctl stop egress-probe-test.service 2>/dev/null || true
systemctl reset-failed egress-probe-test.service 2>/dev/null || true
```

On a normal host this prints a byte count. Record what it prints — the verdict your port produces must match that reality, not a hoped-for value.

- [ ] **Step 7: Per-repo gate, commit, PR, merge**

For each of the four repos run its full gate (fmt, clippy, workspace tests, its packaging scripts, shellcheck), refusing to commit on any failure, then:

```bash
git add packaging/lxc/install.sh packaging/systemd/ docs/
git commit -m "packaging: probe real egress enforcement instead of implying it

IPAddressAllow/IPAddressDeny are accepted by systemd and reported by
systemctl show, but are NOT enforced in an unprivileged LXC — systemd cannot
attach the cgroup BPF program. Every guest in this fleet is one. Measured:
a loopback connection succeeds identically with and without
IPAddressDeny=127.0.0.0/8.

A control that reports as present but does nothing is worse than an absent
one, because it stops anyone looking for the real enforcement point.

Ports rustsdcmcp's existing probe, which tests actual enforcement via IP
accounting rather than asserting capability, and keeps its four verdicts —
UNKNOWN is not NOT ENFORCED.

The directives stay: they do enforce on a normal host or privileged
container. Refs mecmcp#322"
```

- [ ] **Step 8: Close #322**

Once all four have merged, close mecmcp#322 recording which repos now probe, and noting that **moving the control outward is deliberately deferred** as separate ops work — guest nftables, host nftables, or the Proxmox firewall — because it is cluster configuration rather than repo code and would touch production guests.

---

## Self-Review

**Spec coverage.** Group A → Tasks 1–3. Group B → Tasks 4–6 (#338 via coverage in Task 4, sibling coverage in Task 5, #133's backstop in Task 6). Group C → Task 7. The spec's deferred item (moving the egress control outward) is explicitly carried into Task 7 Step 8 as deferred rather than dropped. No spec requirement is unassigned.

**Placeholders.** None. Every code step carries the actual content; the two "adapt per repo" steps in Task 7 name the exact substitutions, the reference file and line ranges, and the POSIX-sh constraint.

**Type and name consistency.** `run_with_capture` keeps its exact signature across Tasks 1 and 3. `CAPTURE_LOCK` is defined once in Task 1 and referenced nowhere else. The tag `v0.18.0` is produced in Task 2 and consumed verbatim in Task 3.

**Independence.** Tasks 4, 5, 6 and 7 have no dependency on 1–3 or on each other and may run in parallel, one agent per repo. Tasks 1 → 2 → 3 are strictly ordered.
