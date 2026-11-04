#!/usr/bin/env bash
# gitleaks_config_test fails when the check's outcome isn't the expected
# one: a non-matching error, a pass where an error was expected, an error
# where a pass was expected. Each failure names the file.
# Argv: <wrong_error> <wrong_pass> <wrong_fail>
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
expect() {  # expect <target> <message>
  local rc=0 out
  out=$("$TEST_SRCDIR/_main/$1" 2>&1) || rc=$?
  [[ "$rc" != 0 ]] || fail "$1 passed: $out"
  grep -qF "$2" <<<"$out" || fail "$1: want '$2' in: $out"
  echo "ok: $1"
}
expect "$1" "FAIL: tests/testdata/typo.toml"
expect "$1" "the message doesn't match 'no such message'"
expect "$2" "FAIL: tests/testdata/corp.toml"
expect "$2" "passed the config check; expected an error matching 'anything'"
expect "$3" "should pass the config check, but:"
expect "$3" "unknown key 'pathss'"
echo "PASS"
