#!/usr/bin/env bash
# A gitleaks_test over leaky files (generated, a tree artifact, an allowed
# line) fails, names workspace paths and fingerprints, redacts the
# secrets, and writes JUnit and JSON reports.
#
# Argv: <leaky_scan test executable>
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }

out_dir="$TEST_TMPDIR/outputs"; mkdir -p "$out_dir"
rc=0
out=$(TEST_UNDECLARED_OUTPUTS_DIR="$out_dir" XML_OUTPUT_FILE="$TEST_TMPDIR/junit.xml" \
      "$TEST_SRCDIR/_main/$1" 2>&1) || rc=$?
echo "$out"
[[ "$rc" == 1 ]] || fail "exit status $rc, want 1"

for fp in tests/leaky/aws.ini:aws-access-token:1 \
          tests/leaky/aws.ini:generic-api-key:2 \
          tests/leaky/ci.yaml:github-pat:2 \
          tests/tree/nested/ci.env:github-pat:1; do
  grep -qF "fingerprint: $fp" <<<"$out" || fail "missing $fp"
done
grep -q "4 leak(s) in 3 file(s)" <<<"$out" || fail "summary"
grep -q "allowed.yaml" <<<"$out" && fail "gitleaks:allow line reported"
for piece in Z7Q2XKQ3RS4TUVWX 1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX /bPxRfiCYzq3tqLW9pQ; do
  grep -qF "$piece" <<<"$out" && fail "secret not redacted in output: $piece"
done
grep -q "/sandbox/\|execroot\|runfiles" <<<"$(grep fingerprint <<<"$out")" && fail "non-workspace path in a fingerprint"
echo "ok: findings, workspace paths, redaction"

grep -q 'failures="4"' "$TEST_TMPDIR/junit.xml" || fail "junit: $(cat "$TEST_TMPDIR/junit.xml")"
python3 - "$out_dir/gitleaks.json" "$out_dir/gitleaks.sarif" <<'PY' || fail "reports"
import json, sys
r = json.load(open(sys.argv[1]))
assert len(r) == 4 and all(f["Secret"] == "REDACTED" for f in r), r
s = json.load(open(sys.argv[2]))
assert len(s["runs"][0]["results"]) == 4, s
PY
echo "ok: JUnit, JSON and SARIF reports"
echo "PASS"
