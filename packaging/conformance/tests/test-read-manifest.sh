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
check_err() { # name expected_exit expected_substring cmd...
  local name="$1" want="$2" want_msg="$3"; shift 3
  local err; err="$("$@" 2>&1 >/dev/null)"; local got=$?
  if [[ "$got" == "$want" ]] && grep -qF -- "$want_msg" <<<"$err"; then
    echo "ok   - $name"
  else
    echo "FAIL - $name (exit want $want got $got; stderr: $err)"; fails=$((fails+1))
  fi
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
check_err "unknown --list rejected" 2 "unknown list" python3 "$READER" "$tmp/good.toml" --list nope

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
check_err "unknown key rejected" 2 "unknown key" python3 "$READER" "$tmp/typo.toml"

cat > "$tmp/missing.toml" <<'EOF'
binary = "bin/svc"
EOF
check_err "missing required key rejected" 2 "missing required key" python3 "$READER" "$tmp/missing.toml"

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
check_err "build_info=true without skip_build_env rejected" 2 "build_info = true requires skip_build_env" python3 "$READER" "$tmp/badprov.toml"

[[ $fails -eq 0 ]] && { echo "all passed"; exit 0; } || { echo "$fails failed"; exit 1; }
