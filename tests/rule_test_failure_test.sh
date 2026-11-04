#!/usr/bin/env bash
# A gitleaks_rule_test whose expectations are wrong fails, naming each
# case: an expected rule that didn't fire, an unexpected one that did.
#
# Argv: <wrong_rule_test executable>
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
rc=0
out=$(XML_OUTPUT_FILE="$TEST_TMPDIR/junit.xml" "$TEST_SRCDIR/_main/$1" 2>&1) || rc=$?
echo "$out"
[[ "$rc" == 1 ]] || fail "exit status $rc, want 1"
grep -q "FAIL tests/leaky/corp.txt: expected but not found: github-pat; found but not expected: corp-token (line 1)" <<<"$out" || fail "corp case"
grep -q "FAIL tests/leaky/aws.ini: found but not expected: aws-access-token (line 1), generic-api-key (line 2)" <<<"$out" || fail "clean case"
grep -q "ok   tests/leaky/corp_doc.txt: no leaks" <<<"$out" || fail "passing case"
grep -q "2 of 3 case(s) failed" <<<"$out" || fail "summary"
grep -q 'failures="2"' "$TEST_TMPDIR/junit.xml" || fail "junit"
echo "PASS"
