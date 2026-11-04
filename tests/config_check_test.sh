#!/usr/bin/env bash
# gitleaks_config's validation action, run directly on good and bad configs.
#
# Argv: <gitleaks.py> <gitleaks> <testdata/corp.toml>
set -euo pipefail
fail() { echo "FAIL: $*" >&2; exit 1; }
D="$TEST_SRCDIR/_main"; dir="$(dirname "$D/$3")"; marker="$TEST_TMPDIR/marker"

check() {
  rm -f "$marker"; rc=0
  out=$(python3 "$D/$1" check-config --gitleaks "$D/$2" --config "$dir/$4" --label "//t:$4" --marker "$marker" 2>&1) || rc=$?
}
expect() {  # expect <file> <message>
  check "$1" "$2" "$3" "$4"
  [[ "$rc" != 0 && ! -f "$marker" ]] || fail "$4 accepted"
  grep -q "gitleaks_config //t:$4" <<<"$out" || fail "$4: label not named: $out"
  grep -qF "$5" <<<"$out" || fail "$4: want '$5' in: $out"
  echo "ok: $4 refused ($5)"
}

check "$1" "$2" "$3" corp.toml
[[ "$rc" == 0 && -f "$marker" ]] || fail "corp.toml refused: $out"
echo "ok: good config"
expect "$1" "$2" "$3" typo.toml "allowlists[0]: unknown key 'pathss'"
expect "$1" "$2" "$3" extend_url.toml "[extend] url: not supported"
expect "$1" "$2" "$3" bad_regex.toml "error parsing regexp: missing closing )"
expect "$1" "$2" "$3" bad_toml.toml "not valid TOML"
expect "$1" "$2" "$3" no_id.toml "rule |id| is missing or empty"
echo "PASS"
