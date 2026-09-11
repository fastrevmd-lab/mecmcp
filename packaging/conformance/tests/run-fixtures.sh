#!/usr/bin/env bash
# packaging/conformance/tests/run-fixtures.sh
# Every fixture dir contains: a staging tree, conformance.toml, and EXPECT.
# EXPECT holds the exact rule IDs that must fail, one per line, or is empty.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
VERIFY="$HERE/../verify-package.sh"
fails=0

for fixture in "$HERE"/../fixtures/*/; do
  name="$(basename "$fixture")"
  expect_file="$fixture/EXPECT"
  [[ -f "$expect_file" ]] || { echo "FAIL - $name has no EXPECT file"; fails=$((fails+1)); continue; }
  want="$(grep -vE '^\s*(#|$)' "$expect_file" | sort -u || true)"

  flags=""
  [[ -f "$fixture/FLAGS" ]] && flags="$(cat "$fixture/FLAGS")"

  output="$(bash "$VERIFY" --staging "$fixture" --manifest "$fixture/conformance.toml" $flags 2>&1)"
  got="$(grep -oE '^FAIL\[R[0-9]+\]' <<<"$output" | tr -d 'FAIL[]' | sort -u || true)"

  if [[ "$want" == "$got" ]]; then
    echo "ok   - $name (rules failed: ${got:-none})"
  else
    echo "FAIL - $name: want [${want//$'\n'/,}] got [${got//$'\n'/,}]"
    echo "$output" | sed 's/^/       /'
    fails=$((fails+1))
  fi
done

[[ $fails -eq 0 ]] && { echo "all fixtures passed"; exit 0; } || { echo "$fails fixture(s) failed"; exit 1; }
