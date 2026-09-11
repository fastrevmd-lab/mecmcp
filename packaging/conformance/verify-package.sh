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
