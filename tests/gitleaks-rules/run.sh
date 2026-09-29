#!/usr/bin/env bash
# Verifies every vendor gitleaks rule in .gitleaks-vendor.toml against the
# positive/negative fixtures in this directory: each rule's positive.txt
# must trigger *that* rule and negative.txt must trigger nothing, scanned
# in isolation via --enable-rule so unrelated default rules can't mask a
# false result either way.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
config="$repo_root/.gitleaks-vendor.toml"
samples_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

fail=0

for rule_dir in "$samples_dir"/*/; do
  rule_id="$(basename "$rule_dir")"
  positive="$rule_dir/positive.txt"
  negative="$rule_dir/negative.txt"

  if [[ ! -f "$positive" || ! -f "$negative" ]]; then
    echo "FAIL $rule_id: missing positive.txt or negative.txt" >&2
    fail=1
    continue
  fi

  # --ignore-gitleaks-allow: positive.txt carries an inline gitleaks:allow
  # marker (it's committed on purpose, so CI's own scan doesn't flag it) but
  # this check is verifying the rule itself still matches the shape.
  if gitleaks dir -c "$config" --enable-rule "$rule_id" --ignore-gitleaks-allow --no-banner --redact \
      -f json -r - "$positive" >/tmp/gitleaks-rule-samples-positive.json 2>/dev/null; then
    echo "FAIL $rule_id: positive.txt did not trigger the rule" >&2
    fail=1
  elif ! grep -q "\"RuleID\": \"$rule_id\"" /tmp/gitleaks-rule-samples-positive.json; then
    echo "FAIL $rule_id: positive.txt triggered a leak but not rule $rule_id" >&2
    fail=1
  else
    echo "PASS $rule_id: positive.txt triggers the rule"
  fi

  if gitleaks dir -c "$config" --enable-rule "$rule_id" --no-banner --redact \
      -f json -r - "$negative" >/dev/null 2>&1; then
    echo "PASS $rule_id: negative.txt stays silent"
  else
    echo "FAIL $rule_id: negative.txt unexpectedly triggered the rule" >&2
    fail=1
  fi
done

rm -f /tmp/gitleaks-rule-samples-positive.json
exit "$fail"
