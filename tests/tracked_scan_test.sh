#!/usr/bin/env bash
# tracked_only: gitleaks_scan (bazel run) and gitleaks_workspace_test scan
# what git tracks (committed + staged), not gitignored files; outside a git
# checkout they fail, saying so. tracked_only = False scans the tree.
#
# Argv: <tracked gitleaks_scan> <gitleaks_workspace_test> <tree workspace test> <make_fixture.sh>
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
D="$TEST_SRCDIR/_main"; export RUNFILES_DIR="$TEST_SRCDIR"
SCAN="$D/$1"; WS="$D/$2"; TREE="$D/$3"; FIX="$D/$4"
command -v git >/dev/null || fail "git is needed for this test"

repo="$TEST_TMPDIR/repo"; mkdir -p "$repo/conf"; cd "$repo"
git init -q; git config user.email t@example.com; git config user.name t
echo "nothing secret" > README
"$FIX" aws conf/aws.ini                  # tracked, leaky
"$FIX" github .env.local                 # gitignored, leaky
printf '.env.local\n' > .gitignore
git add README conf/aws.ini .gitignore; git commit -qm init
"$FIX" corp staged.txt; git add staged.txt   # staged, never committed
"$FIX" corp untracked.txt                # untracked (not ignored): not in the index

want="conf/aws.ini:aws-access-token:1 conf/aws.ini:generic-api-key:2 staged.txt:corp-token:1"
fps() { python3 -c 'import json,sys; print(" ".join(sorted(f["Fingerprint"] for f in json.load(open(sys.argv[1])))))' "$1"; }

rc=0; out=$(BUILD_WORKSPACE_DIRECTORY="$repo" "$SCAN" --json="$TEST_TMPDIR/scan.json" 2>&1) || rc=$?
[[ "$rc" == 1 ]] || fail "gitleaks_scan: exit $rc: $out"
grep -q "scanning 4 git-tracked file(s)" <<<"$out" || fail "tracked count: $out"
[[ "$(fps "$TEST_TMPDIR/scan.json")" == "$want" ]] || fail "gitleaks_scan findings: $(fps "$TEST_TMPDIR/scan.json")"
grep -q ".env.local\|untracked.txt" <<<"$out" && fail "ignored/untracked file reported: $out"
echo "ok: gitleaks_scan(tracked_only): tracked + staged found, gitignored and untracked skipped"

outs="$TEST_TMPDIR/ws_out"; mkdir -p "$outs"
rc=0; out=$(BUILD_WORKSPACE_DIRECTORY="$repo" TEST_UNDECLARED_OUTPUTS_DIR="$outs" XML_OUTPUT_FILE="$TEST_TMPDIR/ws.xml" "$WS" 2>&1) || rc=$?
[[ "$rc" == 1 ]] || fail "gitleaks_workspace_test: exit $rc: $out"
[[ "$(fps "$outs/gitleaks.json")" == "$want" ]] || fail "workspace test findings: $(fps "$outs/gitleaks.json")"
grep -q 'failures="3"' "$TEST_TMPDIR/ws.xml" || fail "junit"
echo "ok: gitleaks_workspace_test: same findings, JUnit"

printf '%s\n' $want > .gitleaksignore; git add .gitleaksignore
BUILD_WORKSPACE_DIRECTORY="$repo" "$WS" >/dev/null 2>&1 || fail "workspace .gitleaksignore not used"
echo "ok: the workspace's .gitleaksignore applies"

rc=0; out=$(BUILD_WORKSPACE_DIRECTORY="$repo" TEST_UNDECLARED_OUTPUTS_DIR="$outs" "$TREE" 2>&1) || rc=$?
[[ "$rc" == 1 ]] || fail "tree scan: exit $rc: $out"
grep -q ".env.local:github-pat" <<<"$out" || fail "tree scan should include the gitignored file: $out"
echo "ok: tracked_only = False scans the whole tree"

plain="$TEST_TMPDIR/plain"; mkdir -p "$plain"; echo hi > "$plain/x"
for t in "$SCAN" "$WS"; do
  rc=0; out=$(BUILD_WORKSPACE_DIRECTORY="$plain" "$t" 2>&1) || rc=$?
  [[ "$rc" == 2 ]] || fail "outside a checkout: exit $rc: $out"
  grep -q "is not inside a git checkout" <<<"$out" || fail "outside a checkout: $out"
done
echo "ok: outside a git checkout both fail, saying so"
echo "PASS"
