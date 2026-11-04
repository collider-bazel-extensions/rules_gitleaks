#!/usr/bin/env bash
# The vendored tomli parses the config when forced (as on Python < 3.11),
# and the key check still catches a misspelt key.
# Argv: <config_typo_vendored_toml_test>
set -euo pipefail
out=$(RULES_GITLEAKS_VENDORED_TOML=1 "$TEST_SRCDIR/_main/$1" 2>&1) || { echo "FAIL: $out" >&2; exit 1; }
grep -q "keys checked with tomli 2.2.1" <<<"$out" || { echo "FAIL: vendored tomli not used: $out" >&2; exit 1; }
grep -q "unknown key 'pathss'" <<<"$out" || { echo "FAIL: typo not caught: $out" >&2; exit 1; }
echo "PASS"
