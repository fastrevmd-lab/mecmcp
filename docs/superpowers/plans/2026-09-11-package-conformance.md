# Package Conformance Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A SHA-pinned reusable workflow in mecmcp that checks a
mecmcp-family package against six rules, proven live by adopting it in
rustproxmoxmcp, which fails rule 1 today.

**Architecture:** Two single-responsibility shell scripts plus a manifest
reader. `verify-package.sh` statically inspects a staging directory the
caller populates (rules 1-5). `verify-image.sh` inspects a built container's
argv (rule 6). A `workflow_call` workflow runs both. Each repo commits
`packaging/conformance.toml` describing what it claims to ship. The verifier
collects every violation and reports them all before exiting, rather than
stopping at the first.

**Tech Stack:** bash, python3 `tomllib` (stdlib, 3.11+; ubuntu-24.04 ships
3.12), `systemd-analyze` (preinstalled on the runner), docker (preinstalled).

**Spec:** `docs/superpowers/specs/2026-09-11-package-conformance-design.md`

## Global Constraints

- Runner is `ubuntu-24.04` for every job. No self-hosted runners exist.
- Rule IDs are stable strings `R1`-`R6`. Output lines are exactly
  `FAIL[Rn] <message>` or `WARN[Rn] <message>`. Fixtures assert on these.
- The verifier reports **all** violations, then exits. Never exit on the
  first. (Same principle as #356 point 3.)
- Exit 0 when no `FAIL` lines were printed, 1 otherwise. `WARN` never
  changes the exit code.
- Every rule needs a negative fixture that fails **that rule and no other**.
  A rule without one is not done.
- This proves nothing about runtime enforcement. Both scripts print that
  disclaimer on every run.
- Commit messages end with:
  `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Work on branch `feat/package-conformance` in `~/Projects/mecmcp`
  for Tasks 1-7. Task 8 is a different repo and a different branch.

## File Structure

| Path | Responsibility |
|---|---|
| `packaging/conformance/read-manifest.py` | Parse+validate `conformance.toml`, emit shell-safe `KEY=value`. Rejects unknown keys. |
| `packaging/conformance/verify-package.sh` | Rules R1-R5 against a staging dir. |
| `packaging/conformance/verify-image.sh` | Rule R6 against a built image. |
| `packaging/conformance/fixtures/` | One conformant package + one broken per rule. |
| `packaging/conformance/tests/run-fixtures.sh` | Runs every fixture, asserts exact rule IDs. |
| `.github/workflows/package-conformance.yml` | `workflow_call` workflow consumers invoke. |
| `.github/workflows/ci.yml` | Gains a `conformance` job running the fixture suite. |

## Manifest schema

Authoritative. `read-manifest.py` rejects anything not listed.

```toml
binary     = "bin/rust-proxmoxmcp"      # path within staging dir
installer  = "packaging/lxc/install.sh" # path within staging dir
service    = "rust-proxmoxmcp"          # systemd service name, no .service
config_dir = "/etc/proxmoxmcp"          # absolute, on the target
tokens     = "/var/lib/proxmoxmcp/tokens.json"

build_info     = false   # bool. false => R3 warns instead of failing.
skip_build_env = false   # string or false. Required true-ish before build_info=true.

units = ["packaging/systemd/rust-proxmoxmcp.service"]   # paths within staging

must_survive_override = ["--clusters-file", "--tokens-file"]

[placeholders]           # token -> test value, for rendering units before R5
"@BIND_ADDRESS@" = "127.0.0.1:30031"
```

---

### Task 1: Manifest reader

**Files:**
- Create: `packaging/conformance/read-manifest.py`
- Create: `packaging/conformance/tests/test-read-manifest.sh`

**Interfaces:**
- Consumes: nothing.
- Produces two modes, so no caller has to recover a list from an `eval`:
  - `read-manifest.py <path>` prints one `KEY=value` per line, **scalars
    only**: `CONF_BINARY`, `CONF_INSTALLER`, `CONF_SERVICE`,
    `CONF_CONFIG_DIR`, `CONF_TOKENS`, `CONF_BUILD_INFO` (`true`/`false`),
    `CONF_SKIP_BUILD_ENV` (string or empty).
  - `read-manifest.py <path> --list <name>` prints one item per line for
    `units`, `must_survive_override`, or `placeholders` (the last as
    `TOKEN<TAB>VALUE`).
  Exit 2 on a bad manifest or an unknown `--list` name.

- [ ] **Step 1: Write the failing test**

```bash
#!/usr/bin/env bash
# packaging/conformance/tests/test-read-manifest.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
READER="$HERE/../read-manifest.py"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fails=0
check() { # name expected_exit actual_exit
  if [[ "$2" == "$3" ]]; then echo "ok   - $1"; else echo "FAIL - $1 (want exit $2, got $3)"; fails=$((fails+1)); fi
}

cat > "$tmp/good.toml" <<'EOF'
binary = "bin/svc"
installer = "packaging/lxc/install.sh"
service = "svc"
config_dir = "/etc/svc"
tokens = "/var/lib/svc/tokens.json"
build_info = false
skip_build_env = false
units = ["packaging/systemd/svc.service"]
must_survive_override = ["--tokens-file"]
[placeholders]
"@BIND@" = "127.0.0.1:1"
EOF
out="$(python3 "$READER" "$tmp/good.toml")"; check "valid manifest parses" 0 $?
grep -q '^CONF_BINARY=bin/svc$' <<<"$out" || { echo "FAIL - CONF_BINARY missing"; fails=$((fails+1)); }
grep -q '^CONF_BUILD_INFO=false$' <<<"$out" || { echo "FAIL - CONF_BUILD_INFO missing"; fails=$((fails+1)); }
grep -q '^CONF_UNITS' <<<"$out" && { echo "FAIL - lists must not appear in scalar output"; fails=$((fails+1)); }
[[ "$(python3 "$READER" "$tmp/good.toml" --list units)" == "packaging/systemd/svc.service" ]] \
  || { echo "FAIL - --list units wrong"; fails=$((fails+1)); }
[[ "$(python3 "$READER" "$tmp/good.toml" --list placeholders)" == $'@BIND@\t127.0.0.1:1' ]] \
  || { echo "FAIL - --list placeholders wrong"; fails=$((fails+1)); }
python3 "$READER" "$tmp/good.toml" --list nope >/dev/null 2>&1; check "unknown --list rejected" 2 $?

cat > "$tmp/typo.toml" <<'EOF'
binary = "bin/svc"
installer = "packaging/lxc/install.sh"
service = "svc"
config_dir = "/etc/svc"
tokens = "/var/lib/svc/tokens.json"
build_info = false
skip_build_env = false
units = []
must_survive_override = []
buidl_info = true
EOF
python3 "$READER" "$tmp/typo.toml" >/dev/null 2>&1; check "unknown key rejected" 2 $?

cat > "$tmp/missing.toml" <<'EOF'
binary = "bin/svc"
EOF
python3 "$READER" "$tmp/missing.toml" >/dev/null 2>&1; check "missing required key rejected" 2 $?

cat > "$tmp/badprov.toml" <<'EOF'
binary = "bin/svc"
installer = "packaging/lxc/install.sh"
service = "svc"
config_dir = "/etc/svc"
tokens = "/var/lib/svc/tokens.json"
build_info = true
skip_build_env = false
units = []
must_survive_override = []
EOF
python3 "$READER" "$tmp/badprov.toml" >/dev/null 2>&1; check "build_info=true without skip_build_env rejected" 2 $?

[[ $fails -eq 0 ]] && { echo "all passed"; exit 0; } || { echo "$fails failed"; exit 1; }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash packaging/conformance/tests/test-read-manifest.sh`
Expected: FAIL — `read-manifest.py` does not exist yet.

- [ ] **Step 3: Write the minimal implementation**

```python
#!/usr/bin/env python3
"""Parse and validate a mecmcp-family packaging/conformance.toml.

Emits shell-safe KEY=value lines for eval. Exits 2 on any invalid manifest,
so a typo cannot silently disable a rule.
"""
import sys
import tomllib

REQUIRED = {
    "binary": str, "installer": str, "service": str,
    "config_dir": str, "tokens": str,
    "build_info": bool, "units": list, "must_survive_override": list,
}
OPTIONAL = {"skip_build_env": (str, bool), "placeholders": dict}


def die(message):
    print(f"manifest error: {message}", file=sys.stderr)
    raise SystemExit(2)


def main():
    if len(sys.argv) not in (2, 4) or (len(sys.argv) == 4 and sys.argv[2] != "--list"):
        die("usage: read-manifest.py <conformance.toml> [--list units|must_survive_override|placeholders]")
    try:
        with open(sys.argv[1], "rb") as handle:
            data = tomllib.load(handle)
    except FileNotFoundError:
        die(f"no such file: {sys.argv[1]}")
    except tomllib.TOMLDecodeError as error:
        die(f"not valid TOML: {error}")

    unknown = set(data) - set(REQUIRED) - set(OPTIONAL)
    if unknown:
        die(f"unknown key(s): {', '.join(sorted(unknown))}")
    for key, kind in REQUIRED.items():
        if key not in data:
            die(f"missing required key: {key}")
        if not isinstance(data[key], kind):
            die(f"{key} must be {kind.__name__}")

    skip_build = data.get("skip_build_env", False)
    if data["build_info"] and not skip_build:
        die(
            "build_info = true requires skip_build_env. A repo with no supported "
            "way to package a CI-built binary cannot produce an honest BUILD-INFO, "
            "and demanding one is what produced the forged file in #355."
        )

    if len(sys.argv) == 4:
        name = sys.argv[3]
        if name == "placeholders":
            for token, value in data.get("placeholders", {}).items():
                print(f"{token}\t{value}")
        elif name in ("units", "must_survive_override"):
            for item in data[name]:
                print(item)
        else:
            die(f"unknown list: {name}")
        return

    # Scalars only. Lists are never squeezed through eval.
    print("\n".join([
        f"CONF_BINARY={data['binary']}",
        f"CONF_INSTALLER={data['installer']}",
        f"CONF_SERVICE={data['service']}",
        f"CONF_CONFIG_DIR={data['config_dir']}",
        f"CONF_TOKENS={data['tokens']}",
        f"CONF_BUILD_INFO={'true' if data['build_info'] else 'false'}",
        f"CONF_SKIP_BUILD_ENV={skip_build if isinstance(skip_build, str) else ''}",
    ]))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run it to verify it passes**

Run: `bash packaging/conformance/tests/test-read-manifest.sh`
Expected: `all passed`, exit 0.

- [ ] **Step 5: Commit**

```bash
chmod 0755 packaging/conformance/read-manifest.py packaging/conformance/tests/test-read-manifest.sh
git add packaging/conformance/
git commit -m "feat(conformance): manifest reader that rejects unknown keys

A typo in conformance.toml must not silently disable a rule, so any key
outside the schema exits 2 rather than being ignored.

Also refuses build_info = true without skip_build_env. A repo with no
supported way to package a CI-built binary cannot produce an honest
BUILD-INFO, and demanding one anyway is exactly what produced the forged
file described in #355.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: Fixture harness and the conformant fixture

**Files:**
- Create: `packaging/conformance/fixtures/conformant/` (a staging tree)
- Create: `packaging/conformance/tests/run-fixtures.sh`
- Create: `packaging/conformance/verify-package.sh` (skeleton only)

**Interfaces:**
- Consumes: `read-manifest.py` from Task 1.
- Produces: `verify-package.sh --staging <dir> --manifest <file>`; prints
  `FAIL[Rn] ...` / `WARN[Rn] ...`; exit 1 if any FAIL. `run-fixtures.sh`
  takes no arguments and runs every directory under `fixtures/`.

- [ ] **Step 1: Build the conformant fixture**

```bash
mkdir -p packaging/conformance/fixtures/conformant/{bin,packaging/lxc,packaging/systemd}
cd packaging/conformance/fixtures/conformant
printf '#!/bin/sh\necho svc\n' > bin/svc && chmod 0755 bin/svc
cat > packaging/lxc/install.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
install -d -m 0755 /etc/systemd/system/svc.service.d
install -m 0755 bin/svc /usr/local/bin/svc
EOF
chmod 0755 packaging/lxc/install.sh
cat > packaging/systemd/svc.service <<'EOF'
[Unit]
Description=svc
[Service]
ExecStart=/bin/true --host @BIND_ADDRESS@
SystemCallErrorNumber=EPERM
[Install]
WantedBy=multi-user.target
EOF
cat > conformance.toml <<'EOF'
binary = "bin/svc"
installer = "packaging/lxc/install.sh"
service = "svc"
config_dir = "/etc/svc"
tokens = "/var/lib/svc/tokens.json"
build_info = false
skip_build_env = false
units = ["packaging/systemd/svc.service"]
must_survive_override = ["--tokens-file"]
[placeholders]
"@BIND_ADDRESS@" = "127.0.0.1:30031"
EOF
cd -
```

- [ ] **Step 2: Write the fixture runner**

```bash
#!/usr/bin/env bash
# packaging/conformance/tests/run-fixtures.sh
# Every fixture dir contains: a staging tree, conformance.toml, and EXPECT.
# EXPECT holds the exact rule IDs that must fail, one per line, or is empty.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/../verify-package.sh"
fails=0

for fixture in "$HERE"/../fixtures/*/; do
  name="$(basename "$fixture")"
  expect_file="$fixture/EXPECT"
  [[ -f "$expect_file" ]] || { echo "FAIL - $name has no EXPECT file"; fails=$((fails+1)); continue; }
  want="$(grep -vE '^\s*(#|$)' "$expect_file" | sort -u || true)"

  output="$(bash "$VERIFY" --staging "$fixture" --manifest "$fixture/conformance.toml" 2>&1)"
  got="$(grep -oE '^FAIL\[R[0-9]+\]' <<<"$output" | tr -d 'FAIL[]' | sort -u || true)"

  if [[ "$want" == "$got" ]]; then
    echo "ok   - $name (rules failed: ${got:-none})"
  else
    echo "FAIL - $name: want [${want//$'\n'/,}] got [${got//$'\n'/,}]"
    echo "$output" | sed 's/^/       /'
    fails=$((fails+1))
  fi
done

[[ $fails -eq 0 ]] && { echo "all fixtures passed"; exit 0; } || { echo "$fails fixture(s) failed"; exit 1; }
```

- [ ] **Step 3: Write the verifier skeleton**

```bash
#!/usr/bin/env bash
# packaging/conformance/verify-package.sh
#
# Static conformance check for a mecmcp-family package staging directory.
#
# THIS PROVES NOTHING ABOUT RUNTIME ENFORCEMENT. SystemCallFilter,
# ProtectSystem=strict and SystemCallErrorNumber are inert until a real
# systemd PID 1 on the real guest applies them. A green run here must never
# be read as "the seccomp posture works".
set -uo pipefail

STAGING=""; MANIFEST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --staging)  STAGING="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$STAGING"  ]] || { echo "--staging is required"  >&2; exit 2; }
[[ -n "$MANIFEST" ]] || { echo "--manifest is required" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")" && pwd)"
READER="$HERE/read-manifest.py"

# Scalars only; lists come from --list, so nothing multi-line goes through eval.
scalars="$(python3 "$READER" "$MANIFEST")" || exit 2
while IFS='=' read -r key value; do
  [[ -n "$key" ]] && printf -v "$key" '%s' "$value"
done <<< "$scalars"

FAILED=0
fail() { echo "FAIL[$1] $2"; FAILED=1; }
warn() { echo "WARN[$1] $2"; }

# Rules are added by later tasks.

echo "note: static package check only; runtime enforcement is NOT verified here"
exit "$FAILED"
```

- [ ] **Step 4: Add the conformant fixture's EXPECT and run**

```bash
: > packaging/conformance/fixtures/conformant/EXPECT
chmod 0755 packaging/conformance/verify-package.sh packaging/conformance/tests/run-fixtures.sh
bash packaging/conformance/tests/run-fixtures.sh
```

Expected: `ok   - conformant (rules failed: none)` then `all fixtures passed`.

- [ ] **Step 5: Commit**

```bash
git add packaging/conformance/
git commit -m "feat(conformance): fixture harness and conformant fixture

Every rule added from here on needs a negative fixture that fails that rule
and no other. A checker whose failure path is never exercised is
indistinguishable from one that always passes, and this project has shipped
several.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: Rules R1 and R2 — installer and binary are executable

**Files:**
- Modify: `packaging/conformance/verify-package.sh`
- Create: `packaging/conformance/fixtures/r1-installer-not-executable/`
- Create: `packaging/conformance/fixtures/r2-binary-missing/`

**Interfaces:**
- Consumes: `fail`/`warn` helpers and `CONF_*` variables from Task 2.
- Produces: `FAIL[R1]`, `FAIL[R2]` lines.

- [ ] **Step 1: Write the failing fixtures**

```bash
cd packaging/conformance/fixtures
cp -r conformant r1-installer-not-executable
chmod 0644 r1-installer-not-executable/packaging/lxc/install.sh
echo R1 > r1-installer-not-executable/EXPECT

cp -r conformant r2-binary-missing
rm r2-binary-missing/bin/svc
echo R2 > r2-binary-missing/EXPECT
cd -
bash packaging/conformance/tests/run-fixtures.sh
```

Expected: both new fixtures FAIL the runner — the verifier emits nothing yet,
so `got` is empty while `want` is `R1` / `R2`.

- [ ] **Step 2: Implement R1 and R2**

Insert above the `echo "note:` line in `verify-package.sh`:

```bash
# R1: the installer must be executable. panos and proxmox ship 0644 today,
# which fails with "Permission denied" at the first install step.
installer_path="$STAGING/$CONF_INSTALLER"
if [[ ! -f "$installer_path" ]]; then
  fail R1 "installer not found at declared path: $CONF_INSTALLER"
elif [[ ! -x "$installer_path" ]]; then
  fail R1 "installer is not executable ($(stat -c '%a' "$installer_path")): $CONF_INSTALLER"
fi

# R2: the declared binary must exist where declared, and be executable.
# Three payload layouts exist; the manifest is what makes each checkable.
binary_path="$STAGING/$CONF_BINARY"
if [[ ! -f "$binary_path" ]]; then
  fail R2 "binary not found at declared path: $CONF_BINARY"
elif [[ ! -x "$binary_path" ]]; then
  fail R2 "binary is not executable ($(stat -c '%a' "$binary_path")): $CONF_BINARY"
fi
```

- [ ] **Step 3: Run the fixtures**

Run: `bash packaging/conformance/tests/run-fixtures.sh`
Expected: `all fixtures passed` — conformant clean, `r1-*` fails exactly R1,
`r2-*` fails exactly R2.

- [ ] **Step 4: Commit**

```bash
git add packaging/conformance/
git commit -m "feat(conformance): R1 installer executable, R2 binary present

R1 is why rustproxmoxmcp adopts first: it fails today, so the first real run
proves the rule bites rather than passing vacuously. rustpanosmcp fails it
too; #355 recorded only panos.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Rule R3 — provenance is present and honest

**Files:**
- Modify: `packaging/conformance/verify-package.sh`
- Create: `packaging/conformance/fixtures/r3-forged-build-info/`
- Create: `packaging/conformance/fixtures/r3-absent-warns/`

**Interfaces:**
- Consumes: `CONF_BUILD_INFO`.
- Produces: `FAIL[R3]` when `build_info = true`, `WARN[R3]` when false.

- [ ] **Step 1: Write the fixtures**

```bash
cd packaging/conformance/fixtures

# Declares provenance, ships a BUILD-INFO whose sha256 does not match the
# binary. This is the forged file from #355, reproduced.
cp -r conformant r3-forged-build-info
sed -i 's/^build_info = false/build_info = true/;s/^skip_build_env = false/skip_build_env = "SVC_SKIP_BUILD"/' \
  r3-forged-build-info/conformance.toml
cat > r3-forged-build-info/BUILD-INFO <<'EOF'
binary_sha256=0000000000000000000000000000000000000000000000000000000000000000
rustc=1.89.0
EOF
echo R3 > r3-forged-build-info/EXPECT

# Ships no provenance and does not claim to. Must WARN, not FAIL.
cp -r conformant r3-absent-warns
: > r3-absent-warns/EXPECT
cd -
bash packaging/conformance/tests/run-fixtures.sh
```

Expected: `r3-forged-build-info` fails the runner (wants R3, gets nothing).

- [ ] **Step 2: Implement R3**

Insert after the R2 block:

```bash
# R3: provenance is mandatory as a destination. build_info records whether
# this repo has reached it, not whether it is exempt -- the rule reports
# either way. All three clauses apply wherever it is fatal, because a
# mandatory-but-unverified file launders a fabrication through a green check.
build_info_path="$STAGING/BUILD-INFO"
r3() { if [[ "$CONF_BUILD_INFO" == "true" ]]; then fail R3 "$1"; else warn R3 "$1"; fi; }

if [[ ! -f "$build_info_path" ]]; then
  r3 "no BUILD-INFO in the package (provenance is mandatory; see the spec's Provenance ordering)"
else
  recorded_sha="$(sed -n 's/^binary_sha256=//p' "$build_info_path" | head -1)"
  if [[ -z "$recorded_sha" ]]; then
    r3 "BUILD-INFO records no binary_sha256"
  elif [[ -f "$binary_path" ]]; then
    actual_sha="$(sha256sum "$binary_path" | cut -d' ' -f1)"
    [[ "$recorded_sha" == "$actual_sha" ]] || \
      r3 "BUILD-INFO binary_sha256 does not match the shipped binary (recorded ${recorded_sha:0:12}..., actual ${actual_sha:0:12}...)"
  fi
  recorded_rustc="$(sed -n 's/^rustc=//p' "$build_info_path" | head -1)"
  if [[ -n "$CONF_SKIP_BUILD_ENV" && "${!CONF_SKIP_BUILD_ENV:-0}" == "1" ]] \
     && [[ "$recorded_rustc" != unknown* ]]; then
    r3 "BUILD-INFO names rustc '$recorded_rustc' but the binary was supplied prebuilt via $CONF_SKIP_BUILD_ENV; it must record 'unknown (binary supplied prebuilt; not compiled by this script)'"
  fi
fi
```

- [ ] **Step 3: Run the fixtures**

Run: `bash packaging/conformance/tests/run-fixtures.sh`
Expected: `all fixtures passed`. `r3-absent-warns` emits `WARN[R3]` and still
passes, because WARN never changes the exit code.

- [ ] **Step 4: Commit**

```bash
git add packaging/conformance/
git commit -m "feat(conformance): R3 provenance present, sha256 honest, rustc honest

The forged BUILD-INFO of 2026-09-07 recorded a rustc version, a commit and a
source_date_epoch that never built anything, purely to satisfy validation,
and was installed on two rigs before being caught. Recomputing the sha256 is
the clause that catches it; only rustsdcmcp does this today.

WARN rather than FAIL where build_info = false, because three repos have no
supported way to package a CI binary yet. Demanding a file they cannot
honestly produce is what created the forgery in the first place.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: Rules R4 and R5 — drop-in directory and unit validity

**Files:**
- Modify: `packaging/conformance/verify-package.sh`
- Create: `packaging/conformance/fixtures/r4-no-dropin-dir/`
- Create: `packaging/conformance/fixtures/r5-unit-invalid/`

**Interfaces:**
- Consumes: `CONF_SERVICE` (scalar), plus `read-manifest.py --list units`
  and `--list placeholders`.
- Produces: `WARN[R4]`, `FAIL[R5]`.

- [ ] **Step 1: Write the fixtures**

```bash
cd packaging/conformance/fixtures
cp -r conformant r4-no-dropin-dir
sed -i '/service\.d/d' r4-no-dropin-dir/packaging/lxc/install.sh
: > r4-no-dropin-dir/EXPECT          # R4 warns; exit code unchanged

cp -r conformant r5-unit-invalid
sed -i 's/^SystemCallErrorNumber=EPERM/SystemCallErrorNumber=/' r5-unit-invalid/packaging/systemd/svc.service
sed -i 's|^ExecStart=.*|ExecStart=|' r5-unit-invalid/packaging/systemd/svc.service
echo R5 > r5-unit-invalid/EXPECT
cd -
bash packaging/conformance/tests/run-fixtures.sh
```

Expected: `r5-unit-invalid` fails the runner (wants R5, gets nothing).

- [ ] **Step 2: Implement R4 and R5**

Insert after the R3 block:

```bash
# R4: the installer should create its own drop-in directory. 0 of 6 repos do
# today, so every install needs a manual mkdir -p before site config can be
# placed. WARN until the repos are fixed, then promoted to fail in one PR.
if [[ -f "$installer_path" ]] && ! grep -q "${CONF_SERVICE}\.service\.d" "$installer_path"; then
  warn R4 "installer never creates /etc/systemd/system/${CONF_SERVICE}.service.d; every install needs a manual mkdir -p first"
fi

# R5: shipped units are TEMPLATES carrying @PLACEHOLDER@ tokens. Render them
# with the manifest's test values, then check systemd can resolve the result.
# Installing an unrendered template killed rig 623 with
# "Fatal: invalid socket address syntax".
render_dir="$(mktemp -d)"; trap 'rm -rf "$render_dir"' EXIT
while IFS= read -r unit; do
  [[ -n "$unit" ]] || continue
  if [[ ! -f "$STAGING/$unit" ]]; then
    fail R5 "declared unit not found: $unit"
    continue
  fi
  rendered="$render_dir/$(basename "$unit")"
  cp "$STAGING/$unit" "$rendered"
  while IFS=$'\t' read -r token value; do
    [[ -n "$token" ]] && sed -i "s|${token}|${value}|g" "$rendered"
  done < <(python3 "$READER" "$MANIFEST" --list placeholders)
  if grep -qE '@[A-Z0-9_]+@' "$rendered"; then
    fail R5 "$unit still contains unrendered placeholders: $(grep -oE '@[A-Z0-9_]+@' "$rendered" | sort -u | tr '\n' ' ')"
    continue
  fi
  if ! analyze_output="$(systemd-analyze verify "$rendered" 2>&1)"; then
    fail R5 "$unit does not resolve: $(head -2 <<<"$analyze_output" | tr '\n' ' ')"
  fi
done < <(python3 "$READER" "$MANIFEST" --list units)
```

- [ ] **Step 3: Run the fixtures**

Run: `bash packaging/conformance/tests/run-fixtures.sh`
Expected: `all fixtures passed`.

The conformant fixture already uses `ExecStart=/bin/true` so `systemd-analyze
verify` can resolve it on the runner while still carrying a placeholder in its
arguments. If R5 still reports something on the conformant fixture, fix the
fixture — never weaken the check to accommodate it.

- [ ] **Step 4: Commit**

```bash
git add packaging/conformance/
git commit -m "feat(conformance): R4 drop-in directory, R5 units resolve

R4 warns rather than fails: 0 of 6 repos create their own .service.d
directory, so it cannot be fixed in an adopting PR. It flips to fatal in one
mecmcp PR once they all do.

R5 codifies the render-and-verify done by hand during the 2026-09-06/07
seccomp wave. Doing it by hand is why it happened once. Unrendered
placeholders are a failure in their own right -- installing a template
unrendered is what killed rig 623.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: Rule R6 — security flags survive an operator override

**Files:**
- Create: `packaging/conformance/verify-image.sh`
- Create: `packaging/conformance/tests/test-verify-image.sh`

**Interfaces:**
- Consumes: `read-manifest.py --list must_survive_override`.
- Produces: `verify-image.sh --image <tag> --manifest <file> [--override <arg>...]`;
  `FAIL[R6]` lines; exit 1 on any failure.

- [ ] **Step 1: Write the failing test**

```bash
#!/usr/bin/env bash
# packaging/conformance/tests/test-verify-image.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/../verify-image.sh"
command -v docker >/dev/null || { echo "skip - docker unavailable"; exit 0; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"; docker rmi -f conf-good conf-bad >/dev/null 2>&1' EXIT
fails=0

cat > "$tmp/conformance.toml" <<'EOF'
binary = "bin/svc"
installer = "packaging/lxc/install.sh"
service = "svc"
config_dir = "/etc/svc"
tokens = "/var/lib/svc/tokens.json"
build_info = false
skip_build_env = false
units = []
must_survive_override = ["--tokens-file"]
EOF

# GOOD: the flag is in ENTRYPOINT, so docker appends the override to it.
printf 'FROM busybox\nENTRYPOINT ["/bin/true","--tokens-file","/t.json"]\nCMD ["--host","127.0.0.1"]\n' > "$tmp/Dockerfile.good"
docker build -q -t conf-good -f "$tmp/Dockerfile.good" "$tmp" >/dev/null
bash "$VERIFY" --image conf-good --manifest "$tmp/conformance.toml" --override --host --override 0.0.0.0 >/dev/null 2>&1
[[ $? -eq 0 ]] && echo "ok   - flag in ENTRYPOINT survives" || { echo "FAIL - good image rejected"; fails=$((fails+1)); }

# BAD: the flag is in CMD, which docker replaces wholesale. This is #78.
printf 'FROM busybox\nENTRYPOINT ["/bin/true"]\nCMD ["--tokens-file","/t.json","--host","127.0.0.1"]\n' > "$tmp/Dockerfile.bad"
docker build -q -t conf-bad -f "$tmp/Dockerfile.bad" "$tmp" >/dev/null
bash "$VERIFY" --image conf-bad --manifest "$tmp/conformance.toml" --override --host --override 0.0.0.0 >/dev/null 2>&1
[[ $? -eq 1 ]] && echo "ok   - flag in CMD is caught" || { echo "FAIL - bad image accepted"; fails=$((fails+1)); }

[[ $fails -eq 0 ]] && { echo "all passed"; exit 0; } || { echo "$fails failed"; exit 1; }
```

- [ ] **Step 2: Run it to verify it fails**

Run: `bash packaging/conformance/tests/test-verify-image.sh`
Expected: FAIL — `verify-image.sh` does not exist.

- [ ] **Step 3: Write the implementation**

```bash
#!/usr/bin/env bash
# packaging/conformance/verify-image.sh
#
# R6: every flag in must_survive_override is still in the container's argv
# after a typical operator override.
#
# Docker APPENDS caller arguments to ENTRYPOINT but REPLACES CMD wholesale.
# A security-relevant flag that lives only in CMD is therefore silently lost
# the moment an operator passes anything -- rustmistmcp#78, where any --host
# override dropped audit keying and redaction with no warning.
set -uo pipefail

IMAGE=""; MANIFEST=""; OVERRIDES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)    IMAGE="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --override) OVERRIDES+=("$2"); shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -n "$IMAGE"    ]] || { echo "--image is required"    >&2; exit 2; }
[[ -n "$MANIFEST" ]] || { echo "--manifest is required" >&2; exit 2; }
[[ ${#OVERRIDES[@]} -gt 0 ]] || OVERRIDES=(--host 0.0.0.0)

HERE="$(cd "$(dirname "$0")" && pwd)"
must_survive="$(python3 "$HERE/read-manifest.py" "$MANIFEST" --list must_survive_override)" || exit 2

if [[ -z "${must_survive//[[:space:]]/}" ]]; then
  echo "note: must_survive_override is empty; R6 has nothing to check"
  exit 0
fi

container="$(docker create "$IMAGE" "${OVERRIDES[@]}")" || { echo "FAIL[R6] could not create a container from $IMAGE"; exit 1; }
argv="$(docker inspect "$container" --format '{{.Path}} {{join .Args "\n"}}')"
docker rm "$container" >/dev/null

FAILED=0
while IFS= read -r flag; do
  [[ -n "$flag" ]] || continue
  if ! grep -Fqx -- "$flag" <<<"$argv"; then
    echo "FAIL[R6] '$flag' is absent from argv after override '${OVERRIDES[*]}'; move it from CMD into ENTRYPOINT"
    FAILED=1
  fi
done <<< "$must_survive"

[[ $FAILED -eq 0 ]] && echo "ok: all declared flags survived '${OVERRIDES[*]}'"
echo "note: argv check only; runtime enforcement is NOT verified here"
exit "$FAILED"
```

- [ ] **Step 4: Run it to verify it passes**

Run: `bash packaging/conformance/tests/test-verify-image.sh`
Expected: both `ok` lines, then `all passed`.

- [ ] **Step 5: Commit**

```bash
chmod 0755 packaging/conformance/verify-image.sh packaging/conformance/tests/test-verify-image.sh
git add packaging/conformance/
git commit -m "feat(conformance): R6 declared flags survive an operator override

Docker appends caller args to ENTRYPOINT but replaces CMD wholesale, so a
security-relevant flag living only in CMD disappears the moment an operator
passes anything. rustmistmcp#78: any --host override silently dropped audit
keying and redaction, and the server reported nothing unusual.

The mechanism is central; which flags matter is per-server knowledge and
comes from must_survive_override in the manifest.

Both fixtures build real images -- one with the flag in ENTRYPOINT, one in
CMD -- so the failure path is exercised rather than assumed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: The composite action and mecmcp's own CI job

**Files:**
- Create: `packaging/conformance/action.yml`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: all scripts from Tasks 1-6.
- Produces: a composite action at `fastrevmd-lab/mecmcp/packaging/conformance@<sha>`
  with inputs `staging` (required), `manifest` (required), `image` (optional,
  default `''`), `overrides` (optional, default `--host 0.0.0.0`).

**Why a composite action and not a `workflow_call` workflow:** a reusable
workflow is invoked at job level, and such a job cannot contain `steps:`. The
consumer must stage the package in the same job that built the binary, so it
needs something callable as a *step*. A composite action keeps every property
this was chosen for — central, SHA-pinned, unable to drift silently.

- [ ] **Step 1: Write the composite action**

```yaml
# packaging/conformance/action.yml
name: mecmcp package conformance
description: >
  Check an assembled mecmcp-family package against the shared contract.
  Static inspection only -- this proves nothing about runtime enforcement.

inputs:
  staging:
    description: Directory the caller populated with the assembled package
    required: true
  manifest:
    description: Path to packaging/conformance.toml
    required: true
  image:
    description: Built image tag for R6. Empty skips R6.
    required: false
    default: ''
  overrides:
    description: Operator arguments R6 passes to the container
    required: false
    default: '--host 0.0.0.0'

runs:
  using: composite
  steps:
    - name: Verify the package
      shell: bash
      run: |
        bash "${{ github.action_path }}/verify-package.sh" \
          --staging "${{ inputs.staging }}" \
          --manifest "${{ inputs.manifest }}"

    - name: Verify the image argv
      if: inputs.image != ''
      shell: bash
      run: |
        args=()
        for token in ${{ inputs.overrides }}; do args+=(--override "$token"); done
        bash "${{ github.action_path }}/verify-image.sh" \
          --image "${{ inputs.image }}" \
          --manifest "${{ inputs.manifest }}" \
          "${args[@]}"
```

`github.action_path` resolves to the checked-out action directory, so the
scripts always come from the same SHA the consumer pinned. There is no second
checkout and no way for the action and its scripts to disagree.

- [ ] **Step 2: Add mecmcp's own fixture job**

Append to the `jobs:` block of `.github/workflows/ci.yml`:

```yaml
  conformance:
    name: Conformance fixtures
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout
        uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      - name: Manifest reader
        run: bash packaging/conformance/tests/test-read-manifest.sh
      - name: Package fixtures
        run: bash packaging/conformance/tests/run-fixtures.sh
      - name: Image fixtures
        run: bash packaging/conformance/tests/test-verify-image.sh
```

- [ ] **Step 3: Use the checkout SHA this repo already pins**

Do not invent one. Take the value already in use and reuse it verbatim:

```bash
grep -rhoE 'actions/checkout@[0-9a-f]{40}' .github/workflows/ | sort -u
```

Use that SHA in the new job. If more than one appears, use the one in
`ci.yml`. Every action in these repos is SHA-pinned; never substitute a
floating tag.

- [ ] **Step 4: Run the three suites locally, then commit**

```bash
bash packaging/conformance/tests/test-read-manifest.sh
bash packaging/conformance/tests/run-fixtures.sh
bash packaging/conformance/tests/test-verify-image.sh
git add .github/workflows/
git commit -m "feat(conformance): composite action and mecmcp fixture job

A composite action consumers invoke SHA-pinned, matching the house habit --
every action in these repos is already pinned by SHA. A repo cannot silently
drift: it is on the pinned SHA or it visibly is not.

A composite action rather than a workflow_call workflow because a reusable
workflow is invoked at job level and such a job cannot contain steps, while
the consumer must stage the package in the same job that built the binary.
github.action_path means the scripts always come from the SHA the consumer
pinned, so the action and its scripts cannot disagree.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Adopt in rustproxmoxmcp — the proof

**Files:**
- Create: `~/Projects/rustproxmoxmcp/packaging/conformance.toml`
- Modify: `~/Projects/rustproxmoxmcp/.github/workflows/ci.yml`
- Modify: `~/Projects/rustproxmoxmcp/packaging/lxc/install.sh` (mode only)

**Interfaces:**
- Consumes: the composite action from Task 7, pinned at its merge SHA on
  mecmcp `main`.
- Produces: nothing other repos consume.

This task is in a **different repository**. Do not run it in the mecmcp
worktree. Tasks 1-7 must be merged to mecmcp `main` first, because the
consumer pins a real SHA.

- [ ] **Step 1: Confirm the repo fails R1 today**

```bash
cd ~/Projects/rustproxmoxmcp
git ls-files -s packaging/lxc/install.sh
```

Expected: mode `100644`. This is the violation the adoption is meant to
surface; if it is already `100755`, someone fixed it — say so and pick
rustpanosmcp as the first adopter instead.

- [ ] **Step 2: Write the manifest**

```bash
cd ~/Projects/rustproxmoxmcp
git checkout -b feat/package-conformance
cat > packaging/conformance.toml <<'EOF'
binary     = "bin/rust-proxmoxmcp"
installer  = "packaging/lxc/install.sh"
service    = "rust-proxmoxmcp"
config_dir = "/etc/proxmoxmcp"
tokens     = "/var/lib/proxmoxmcp/tokens.json"

# No supported skip-build path yet, so no honest BUILD-INFO is possible.
# R3 warns until both change together. See the spec's Provenance ordering.
build_info     = false
skip_build_env = false

units = ["packaging/systemd/rust-proxmoxmcp.service"]

# ENTRYPOINT holds the config and credential paths; these must survive any
# operator override. Fixed in #85, guarded centrally from here.
must_survive_override = ["--clusters-file", "--tokens-file"]
EOF
```

- [ ] **Step 3: Add the CI job, with the staging step the repo needs**

Append to `jobs:` in `.github/workflows/ci.yml`, replacing `<SHA>` with the
mecmcp commit that merged Task 7:

```yaml
  conformance:
    name: Package conformance
    runs-on: ubuntu-24.04
    needs: build-and-test
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8
      - name: Build the binary
        run: cargo build --release --locked
      - name: Stage the package
        run: |
          # This repo has no packager. Assembling the staging tree by hand
          # here is itself the divergence #355 describes, now visible in CI.
          mkdir -p staging/bin
          cp target/release/rust-proxmoxmcp staging/bin/
          cp -r packaging staging/packaging
          cp packaging/conformance.toml staging/
      - name: Build the image
        # R6 needs a built image. Omitting `image:` ships R6 dark: the action's
        # argv step is skipped and the log cannot tell "R6 passed" from "R6
        # never ran". The action now prints a note in that case, but the first
        # adopter should not need the note.
        run: docker build -t rust-proxmoxmcp:conformance .
      - name: Conformance
        uses: fastrevmd-lab/mecmcp/packaging/conformance@<SHA>
        with:
          staging: staging
          manifest: staging/conformance.toml
          image: rust-proxmoxmcp:conformance
```

- [ ] **Step 4: Push and confirm the first run FAILS on R1**

```bash
git add packaging/conformance.toml .github/workflows/ci.yml
git commit -m "ci: adopt the mecmcp package conformance check

Expected to fail R1 on this commit: packaging/lxc/install.sh is committed
0644, so ./packaging/lxc/install.sh is Permission denied. The failure is the
point -- it proves the rule bites before anyone relies on it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
git push -u origin feat/package-conformance
gh pr create --fill
```

Expected: the conformance job fails with
`FAIL[R1] installer is not executable (644): packaging/lxc/install.sh`.
**Record that output in the PR body.** A check that has never been seen to
fail is indistinguishable from one that always passes.

- [ ] **Step 5: Fix R1 and confirm green**

```bash
git update-index --chmod=+x packaging/lxc/install.sh
git commit -m "fix(packaging): make install.sh executable

Committed 0644, so ./packaging/lxc/install.sh fails with Permission denied
at the first install step. Caught by R1 of the conformance check on the
commit that introduced it. rustpanosmcp has the same defect.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
git push
```

Expected: the job now passes, with `WARN[R3]` (no provenance yet) and
`WARN[R4]` (no drop-in directory) printed and not failing.

---

## Follow-on, not in this plan

One PR each, same shape as Task 8, in this order:

1. **rustpanosmcp** — the other R1 failure; same two commits.
2. **rustjunosmcp** — has a packager (`scripts/package-lxc.sh`) and an
   existing `packaging/tests/package-smoke.sh` that already extracts an
   archive into a fake rootfs. Stage from the real tarball, not by hand.
3. **rustsdcmcp** — already recomputes a sha256; likely `build_info = true`
   from the start.
4. **rustmistmcp**, **rustunifimcp**.
5. Once all six declare `build_info = true`, delete the key and make R3
   unconditionally fatal. Once all six create their drop-in directory,
   promote R4 from warn to fail. Each is a one-line change in mecmcp that
   every repo inherits at its next pin bump.

Removing the per-repo argv assertions in rustmistmcp and rustproxmoxmcp
happens in each repo's adoption PR, and **only after** R6 is shown to fail
there: delete the flag from the Dockerfile, watch R6 fail, restore it, then
delete the local assertion.
