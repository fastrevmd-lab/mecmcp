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
fi

echo "note: static package check only; runtime enforcement is NOT verified here"
exit "$FAILED"
