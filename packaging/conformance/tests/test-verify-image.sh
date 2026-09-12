#!/usr/bin/env bash
# packaging/conformance/tests/test-verify-image.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/../verify-image.sh"
command -v docker >/dev/null || { echo "skip - docker unavailable"; exit 0; }
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"; docker rmi -f conf-good conf-good-eq conf-bad >/dev/null 2>&1' EXIT
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
docker build -q -t conf-good -f "$tmp/Dockerfile.good" "$tmp" >/dev/null \
  || { echo "FAIL - conf-good build failed; a build failure must never be reportable as a passing assertion"; exit 1; }
bash "$VERIFY" --image conf-good --manifest "$tmp/conformance.toml" --override --host --override 0.0.0.0 >/dev/null 2>&1
[[ $? -eq 0 ]] && echo "ok   - flag in ENTRYPOINT survives" || { echo "FAIL - good image rejected"; fails=$((fails+1)); }

# GOOD (equals form): --tokens-file=/t.json baked in as a single token is a
# normal, valid CLI convention for these binaries and must also pass.
printf 'FROM busybox\nENTRYPOINT ["/bin/true","--tokens-file=/t.json"]\nCMD ["--host","127.0.0.1"]\n' > "$tmp/Dockerfile.good-eq"
docker build -q -t conf-good-eq -f "$tmp/Dockerfile.good-eq" "$tmp" >/dev/null \
  || { echo "FAIL - conf-good-eq build failed; a build failure must never be reportable as a passing assertion"; exit 1; }
bash "$VERIFY" --image conf-good-eq --manifest "$tmp/conformance.toml" --override --host --override 0.0.0.0 >/dev/null 2>&1
[[ $? -eq 0 ]] && echo "ok   - flag=value form in ENTRYPOINT survives" || { echo "FAIL - good-eq image rejected"; fails=$((fails+1)); }

# BAD: the flag is in CMD, which docker replaces wholesale. This is #78.
# The assertion must check OUTPUT, not just exit code: a docker-create
# failure (e.g. from a build that silently failed) also exits 1 via
# "could not create a container", which must not be mistaken for R6 having
# actually detected the CMD-vs-ENTRYPOINT regression.
printf 'FROM busybox\nENTRYPOINT ["/bin/true"]\nCMD ["--tokens-file","/t.json","--host","127.0.0.1"]\n' > "$tmp/Dockerfile.bad"
docker build -q -t conf-bad -f "$tmp/Dockerfile.bad" "$tmp" >/dev/null \
  || { echo "FAIL - conf-bad build failed; a build failure must never be reportable as a passing assertion"; exit 1; }
bad_output="$(bash "$VERIFY" --image conf-bad --manifest "$tmp/conformance.toml" --override --host --override 0.0.0.0 2>&1)"
bad_status=$?
if [[ $bad_status -eq 1 ]] && grep -Fq -- "FAIL[R6]" <<<"$bad_output" && grep -Fq -- "--tokens-file" <<<"$bad_output"; then
  echo "ok   - flag in CMD is caught"
else
  echo "FAIL - bad image accepted, or detection logic was never exercised (output: $bad_output)"
  fails=$((fails+1))
fi

[[ $fails -eq 0 ]] && { echo "all passed"; exit 0; } || { echo "$fails failed"; exit 1; }
