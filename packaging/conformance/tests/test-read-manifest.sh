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
