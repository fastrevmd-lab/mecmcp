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

STAGING=""; MANIFEST=""; PREBUILT=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --staging)  STAGING="$2"; shift 2 ;;
    --manifest) MANIFEST="$2"; shift 2 ;;
    --prebuilt) PREBUILT=1; shift ;;
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
  if [[ "$PREBUILT" == "1" && -n "$CONF_SKIP_BUILD_ENV" ]] \
     && [[ "$recorded_rustc" != unknown* ]]; then
    r3 "BUILD-INFO names rustc '$recorded_rustc' but the binary was supplied prebuilt via $CONF_SKIP_BUILD_ENV; it must record 'unknown (binary supplied prebuilt; not compiled by this script)'"
  fi
  # Clause 3 is armed by the CALLER passing --prebuilt, which no rule can infer.
  # When the repo has a skip-build path and provenance is fatal, silence here
  # means "not asked", not "checked and clean" -- and those must not look alike.
  if [[ "$CONF_BUILD_INFO" == "true" && -n "$CONF_SKIP_BUILD_ENV" && "$PREBUILT" != "1" ]]; then
    warn R3 "clause 3 (BUILD-INFO must not name a toolchain that did not compile the binary) did not run: $CONF_SKIP_BUILD_ENV is declared but --prebuilt was not passed. Pass it from whichever CI path stages a binary it did not compile."
  fi
fi

# R4: the installer should create its own drop-in directory. 0 of 6 repos do
# today, so every install needs a manual mkdir -p before site config can be
# placed. WARN until the repos are fixed, then promoted to fail in one PR.
#
# Comment lines are stripped first. A bare grep matched a mention ANYWHERE, so
# `# TODO: mkdir /etc/systemd/system/svc.service.d by hand` silenced the rule --
# harmless while this is a warn, a false green the day it is promoted to fatal.
if [[ -f "$installer_path" ]] \
   && ! grep -vE '^[[:space:]]*#' "$installer_path" | grep -q "${CONF_SERVICE}\.service\.d"; then
  warn R4 "installer never creates /etc/systemd/system/${CONF_SERVICE}.service.d (mentions in comments do not count); every install needs a manual mkdir -p first"
fi

# R5: shipped units are TEMPLATES carrying @PLACEHOLDER@ tokens. Render them
# with the manifest's test values, then check systemd can resolve the result.
# Installing an unrendered template killed rig 623 with
# "Fatal: invalid socket address syntax".
#
# The reader's exit status is captured before the loop rather than discarded by
# a process substitution: a reader failure there made R5 a silent no-op, which
# is the one failure mode a conformance rule must not have.
reader_ok=1
if ! units_list="$(python3 "$READER" "$MANIFEST" --list units 2>&1)"; then
  fail R5 "could not read 'units' from the manifest, so R5 did not run: $(head -2 <<<"$units_list" | tr '\n' ' ')"
  reader_ok=0; units_list=""
fi
if ! placeholder_list="$(python3 "$READER" "$MANIFEST" --list placeholders 2>&1)"; then
  fail R5 "could not read 'placeholders' from the manifest, so R5 did not run: $(head -2 <<<"$placeholder_list" | tr '\n' ' ')"
  reader_ok=0; placeholder_list=""
fi

# An empty `units` is legitimate -- a repo may ship no unit -- but silence is
# indistinguishable from the rule having been deleted. verify-image.sh already
# announces its empty-list case; R5 now does the same.
if [[ $reader_ok -eq 1 && -z "${units_list//[[:space:]]/}" ]]; then
  echo "note: units is empty; R5 has nothing to check"
fi

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
  done <<< "$placeholder_list"
  if grep -qE '@[A-Z0-9_]+@' "$rendered"; then
    fail R5 "$unit still contains unrendered placeholders: $(grep -oE '@[A-Z0-9_]+@' "$rendered" | sort -u | tr '\n' ' ')"
    continue
  fi

  # `systemd-analyze verify` resolves ExecStart= and friends against the local
  # filesystem. Every family unit names the INSTALLED path
  # (/usr/local/bin/<binary>), which by definition is not there when a package
  # is checked BEFORE installation, so all six repos measured exit 1 on a clean
  # runner with nothing wrong with the unit. R5 asks whether the unit parses and
  # its directives are valid, which is answerable statically; whether the binary
  # is installed is not. Exactly that one diagnostic class is dropped, and the
  # count is printed so a suppressed line is visible rather than silent.
  #
  # Nothing else is filtered. Note also that systemd-analyze exits 0 for some
  # genuine defects (a bad `Restart=` value is reported and still exits 0), so
  # the verdict is taken from the surviving OUTPUT, not from the exit status.
  analyze_output="$(systemd-analyze verify "$rendered" 2>&1)"
  # Anchored to a bare unit id (no '/') so a parse-error line -- prefixed by a
  # PATH:LINE: from the rendered tmp file -- can never match even when its
  # echoed-back offending value happens to contain this same phrase.
  uninstalled_re='^[^[:space:]/]+\.[a-z]+: Command [^ ]+ is not executable: '
  suppressed_lines="$(grep -E "$uninstalled_re" <<<"$analyze_output")"
  suppressed="$(grep -cE "$uninstalled_re" <<<"$analyze_output")"
  residual="$(grep -vE "$uninstalled_re" <<<"$analyze_output" | grep -vE '^[[:space:]]*$')"
  if [[ "$suppressed" != "0" ]]; then
    echo "note: R5 ignored $suppressed unresolvable-command diagnostic(s) for $unit; a package check cannot verify a binary that is not installed yet"
    echo "$suppressed_lines" | sed 's/^/note:   /'
  fi
  if [[ -n "$residual" ]]; then
    fail R5 "$unit does not resolve: $(head -2 <<<"$residual" | tr '\n' ' ')"
  fi
done <<< "$units_list"

echo "note: static package check only; runtime enforcement is NOT verified here"
exit "$FAILED"
