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

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

fail=0

# Cross-check rule ids against sample dirs both ways, so a 12th rule added to
# the config without a sample dir (or a stray sample dir for a removed rule)
# fails loudly instead of being silently skipped by the directory-driven loop.
mapfile -t config_rule_ids < <(grep -oP '^id = "\K[^"]+' "$config" | sort)
mapfile -t sample_rule_ids < <(find "$samples_dir" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort)

for rule_id in "${config_rule_ids[@]}"; do
  if [[ ! -d "$samples_dir/$rule_id" ]]; then
    echo "FAIL $rule_id: no tests/gitleaks-rules/$rule_id/ sample dir for this rule" >&2
    fail=1
  fi
done
for rule_id in "${sample_rule_ids[@]}"; do
  if ! printf '%s\n' "${config_rule_ids[@]}" | grep -qx "$rule_id"; then
    echo "FAIL $rule_id: sample dir has no matching rule id in $config" >&2
    fail=1
  fi
done

for rule_id in "${config_rule_ids[@]}"; do
  rule_dir="$samples_dir/$rule_id"
  positive="$rule_dir/positive.txt"
  negative="$rule_dir/negative.txt"

  if [[ ! -f "$positive" || ! -f "$negative" ]]; then
    [[ -d "$rule_dir" ]] && { echo "FAIL $rule_id: missing positive.txt or negative.txt" >&2; fail=1; }
    continue
  fi

  # --ignore-gitleaks-allow on BOTH scans: positive.txt carries an inline
  # gitleaks:allow marker (committed on purpose, so CI's own scan doesn't
  # flag it), and the flag makes sure that marker can't also mask a real
  # match in negative.txt. Without it, a negative sample that copies the
  # positive fixture's gitleaks:allow convention passes vacuously even
  # though the rule matched it.
  if gitleaks dir -c "$config" --enable-rule "$rule_id" --ignore-gitleaks-allow --no-banner --redact \
      -f json -r - "$positive" >"$tmp"; then
    echo "FAIL $rule_id: positive.txt did not trigger the rule" >&2
    fail=1
  elif ! grep -q "\"RuleID\": \"$rule_id\"" "$tmp"; then
    echo "FAIL $rule_id: positive.txt triggered a leak but not rule $rule_id" >&2
    fail=1
  else
    echo "PASS $rule_id: positive.txt triggers the rule"
  fi

  if gitleaks dir -c "$config" --enable-rule "$rule_id" --ignore-gitleaks-allow --no-banner --redact \
      -f json -r - "$negative" >"$tmp"; then
    echo "PASS $rule_id: negative.txt stays silent"
  else
    echo "FAIL $rule_id: negative.txt unexpectedly triggered the rule" >&2
    fail=1
  fi
done

exit "$fail"
