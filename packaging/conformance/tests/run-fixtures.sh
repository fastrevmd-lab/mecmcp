#!/usr/bin/env bash
# packaging/conformance/tests/run-fixtures.sh
# Every fixture dir contains: a staging tree, conformance.toml, and EXPECT.
# EXPECT holds the exact rule IDs that must FAIL, one per line, or is empty.
#
# EXPECT_WARN is optional and holds the exact rule IDs that must WARN. A fixture
# with no EXPECT_WARN asserts that NO warning is emitted. Without this, the
# warn-only rules asserted nothing: replacing the whole R4 block with `:`, and
# separately making warn() a no-op, both left "all fixtures passed" exit 0.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/../verify-package.sh"
fails=0

ids() { # stream -> sorted unique rule IDs for the given verdict keyword
  sed -n "s/^$1\[\(R[0-9]\+\)\].*/\1/p" | sort -u
}

for fixture in "$HERE"/../fixtures/*/; do
  name="$(basename "$fixture")"
  expect_file="$fixture/EXPECT"
  [[ -f "$expect_file" ]] || { echo "FAIL - $name has no EXPECT file"; fails=$((fails+1)); continue; }
  want="$(grep -vE '^\s*(#|$)' "$expect_file" | sort -u || true)"

  want_warn=""
  [[ -f "$fixture/EXPECT_WARN" ]] && want_warn="$(grep -vE '^\s*(#|$)' "$fixture/EXPECT_WARN" | sort -u || true)"

  flags=""
  [[ -f "$fixture/FLAGS" ]] && flags="$(cat "$fixture/FLAGS")"

  output="$(bash "$VERIFY" --staging "$fixture" --manifest "$fixture/conformance.toml" $flags 2>&1)"
  got="$(ids FAIL <<<"$output" || true)"
  got_warn="$(ids WARN <<<"$output" || true)"

  joined_fail="${got//$'\n'/,}"; joined_warn="${got_warn//$'\n'/,}"
  if [[ "$want" == "$got" && "$want_warn" == "$got_warn" ]]; then
    echo "ok   - $name (failed: ${joined_fail:-none}; warned: ${joined_warn:-none})"
  else
    echo "FAIL - $name:"
    [[ "$want" == "$got" ]] || echo "       FAIL rules: want [${want//$'\n'/,}] got [${got//$'\n'/,}]"
    [[ "$want_warn" == "$got_warn" ]] || echo "       WARN rules: want [${want_warn//$'\n'/,}] got [${got_warn//$'\n'/,}]"
    echo "$output" | sed 's/^/       /'
    fails=$((fails+1))
  fi
done

[[ $fails -eq 0 ]] && { echo "all fixtures passed"; exit 0; } || { echo "$fails fixture(s) failed"; exit 1; }
