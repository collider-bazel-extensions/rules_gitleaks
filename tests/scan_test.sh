#!/usr/bin/env bash
# gitleaks_scan (`bazel run`): scans BUILD_WORKSPACE_DIRECTORY's working
# tree, honours its .gitleaksignore and passes arguments through; in git
# mode it finds a secret that only exists in history.
#
# Argv: <scan> <history scan> <aws.ini fixture> <ci.yaml fixture>
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
D="$TEST_SRCDIR/_main"
SCAN="$D/$1"; HISTORY="$D/$2"
export RUNFILES_DIR="$TEST_SRCDIR"

ws="$TEST_TMPDIR/ws"; mkdir -p "$ws/conf"
cp "$D/$3" "$ws/conf/aws.ini"; chmod u+w "$ws/conf/aws.ini"
ln -s /nonexistent "$ws/bazel-out"
rc=0; out=$(BUILD_WORKSPACE_DIRECTORY="$ws" "$SCAN" --report-path="report.json" --report-format=json 2>&1) || rc=$?
[[ "$rc" == 1 ]] || fail "leaky tree: exit $rc: $out"
python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); assert sorted(f["Fingerprint"] for f in r)==["conf/aws.ini:aws-access-token:1","conf/aws.ini:generic-api-key:2"], r' \
  "$ws/report.json" || fail "report (relative to the workspace root)"
echo "ok: working tree, args passed, paths relative to the workspace"

printf 'conf/aws.ini:aws-access-token:1\nconf/aws.ini:generic-api-key:2\n' > "$ws/.gitleaksignore"
rm "$ws/report.json"
BUILD_WORKSPACE_DIRECTORY="$ws" "$SCAN" >/dev/null 2>&1 || fail ".gitleaksignore not honoured"
echo "ok: ./.gitleaksignore"

if ! command -v git >/dev/null; then echo "skip: no git for history mode"; echo PASS; exit 0; fi
repo="$TEST_TMPDIR/repo"; mkdir -p "$repo"; cd "$repo"
git init -q; git config user.email t@example.com; git config user.name t
cp "$D/$4" ci.yaml; chmod u+w ci.yaml; git add ci.yaml; git commit -qm leak
echo "clean: true" > ci.yaml; git commit -qam "remove it"
BUILD_WORKSPACE_DIRECTORY="$repo" "$SCAN" >/dev/null 2>&1 || fail "working tree should be clean now"
rc=0; out=$(BUILD_WORKSPACE_DIRECTORY="$repo" "$HISTORY" 2>&1) || rc=$?
[[ "$rc" == 1 ]] || fail "history: exit $rc: $out"
grep -q "leaks found: 1" <<<"$out" || fail "history: $out"
echo "ok: git history"
echo "PASS"
