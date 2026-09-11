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

# A manifest that is valid apart from the lines passed in, so each case below
# differs from a known-good manifest in exactly one way.
manifest() { # file, then any number of replacement "key = value" lines
  local file="$1"; shift
  local base=(
    'binary = "bin/svc"'
    'installer = "packaging/lxc/install.sh"'
    'service = "svc"'
    'config_dir = "/etc/svc"'
    'tokens = "/var/lib/svc/tokens.json"'
    'build_info = false'
    'units = ["packaging/systemd/svc.service"]'
    'must_survive_override = ["--tokens-file"]'
  )
  local line over replaced
  : > "$file"
  for line in "${base[@]}"; do
    replaced=0
    for over in "$@"; do
      [[ "${over%% *}" == "${line%% *}" ]] && replaced=1
    done
    [[ $replaced -eq 0 ]] && printf '%s\n' "$line" >> "$file"
  done
  printf '%s\n' "$@" >> "$file"
}

# --- C2: optional keys were declared and never type-checked. ---------------
# `skip_build_env = true` is truthy, so it satisfied the build_info ordering
# guard, but it emitted an EMPTY CONF_SKIP_BUILD_ENV, which silently turned off
# R3's clause 3 (the `-n "$CONF_SKIP_BUILD_ENV"` guard in verify-package.sh).
manifest "$tmp/skip-true.toml" 'skip_build_env = true'
check_err "skip_build_env = true rejected" 2 "must name the environment variable" \
  python3 "$READER" "$tmp/skip-true.toml"

manifest "$tmp/skip-empty.toml" 'skip_build_env = ""'
check_err "skip_build_env = \"\" rejected" 2 "is not a value" \
  python3 "$READER" "$tmp/skip-empty.toml"

# The true path still works: a named variable reaches CONF_SKIP_BUILD_ENV, which
# is what arms R3 clause 3. Without this the two rejections above would be
# indistinguishable from rejecting the key outright.
manifest "$tmp/skip-named.toml" 'build_info = true' 'skip_build_env = "SVC_SKIP_BUILD"'
out="$(python3 "$READER" "$tmp/skip-named.toml")"; check "skip_build_env names a variable" 0 $?
grep -q '^CONF_SKIP_BUILD_ENV=SVC_SKIP_BUILD$' <<<"$out" \
  || { echo "FAIL - CONF_SKIP_BUILD_ENV not emitted for a named variable"; fails=$((fails+1)); }

# build_info = false with a named variable is legal too, and must still emit it.
manifest "$tmp/skip-named-nobi.toml" 'skip_build_env = "SVC_SKIP_BUILD"'
grep -q '^CONF_SKIP_BUILD_ENV=SVC_SKIP_BUILD$' <<<"$(python3 "$READER" "$tmp/skip-named-nobi.toml")" \
  || { echo "FAIL - CONF_SKIP_BUILD_ENV not emitted with build_info = false"; fails=$((fails+1)); }

manifest "$tmp/placeholders-scalar.toml" 'placeholders = 5'
check_err "optional key of the wrong type rejected" 2 "placeholders must be dict" \
  python3 "$READER" "$tmp/placeholders-scalar.toml"

# --- I4: a newline in a scalar forges a second shell assignment. -----------
manifest "$tmp/newline-scalar.toml" 'tokens = "/var/lib/svc/tokens.json\nCONF_BINARY=bin/other"'
check_err "newline in a scalar rejected" 2 "must not contain a newline" \
  python3 "$READER" "$tmp/newline-scalar.toml"

manifest "$tmp/newline-list.toml" 'units = ["packaging/systemd/svc.service\nextra"]'
check_err "newline in a list item rejected" 2 "must not contain a newline" \
  python3 "$READER" "$tmp/newline-list.toml"

manifest "$tmp/newline-placeholder.toml" '[placeholders]' '"@BIND@" = "127.0.0.1:1\nx"'
check_err "newline in a placeholder value rejected" 2 "must not contain a newline" \
  python3 "$READER" "$tmp/newline-placeholder.toml"

manifest "$tmp/tab-placeholder.toml" '[placeholders]' '"@BIND@" = "127.0.0.1:1\tx"'
check_err "tab in a placeholder value rejected" 2 "must not contain a tab" \
  python3 "$READER" "$tmp/tab-placeholder.toml"

# --- M2: an absolute staging-relative path was joined onto $STAGING anyway. -
manifest "$tmp/abs-binary.toml" 'binary = "/usr/local/bin/svc"'
check_err "absolute binary rejected" 2 "not an absolute path" \
  python3 "$READER" "$tmp/abs-binary.toml"

manifest "$tmp/abs-installer.toml" 'installer = "/opt/svc/install.sh"'
check_err "absolute installer rejected" 2 "not an absolute path" \
  python3 "$READER" "$tmp/abs-installer.toml"

manifest "$tmp/abs-unit.toml" 'units = ["/etc/systemd/system/svc.service"]'
check_err "absolute unit path rejected" 2 "not an absolute path" \
  python3 "$READER" "$tmp/abs-unit.toml"

# config_dir and tokens are absolute ON THE TARGET and must stay accepted.
manifest "$tmp/abs-target.toml" 'config_dir = "/etc/svc"' 'tokens = "/var/lib/svc/tokens.json"'
python3 "$READER" "$tmp/abs-target.toml" >/dev/null; check "absolute config_dir/tokens still accepted" 0 $?

[[ $fails -eq 0 ]] && { echo "all passed"; exit 0; } || { echo "$fails failed"; exit 1; }
