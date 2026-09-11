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
argv="$(docker inspect "$container" --format '{{.Path}}{{"\n"}}{{join .Args "\n"}}')"
docker rm "$container" >/dev/null

FAILED=0
while IFS= read -r flag; do
  [[ -n "$flag" ]] || continue
  present=0
  while IFS= read -r line; do
    # A declared flag counts as present as its own argv token, or as the
    # "--flag=value" form -- both are valid CLI shapes for these binaries.
    # Compared literally (never as a regex) so a flag containing
    # regex/glob metacharacters cannot misbehave.
    if [[ "$line" == "$flag" || "$line" == "$flag"'='* ]]; then
      present=1
      break
    fi
  done <<< "$argv"
  if [[ $present -eq 0 ]]; then
    echo "FAIL[R6] '$flag' is absent from argv after override '${OVERRIDES[*]}'; move it from CMD into ENTRYPOINT"
    FAILED=1
  fi
done <<< "$must_survive"

[[ $FAILED -eq 0 ]] && echo "ok: all declared flags survived '${OVERRIDES[*]}'"
echo "note: argv check only; runtime enforcement is NOT verified here"
exit "$FAILED"
