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
