#!/usr/bin/env bash
# The toolchain binary is DEFAULT_VERSION, which MODULE.bazel names too.
# Argv: <versions.bzl> <MODULE.bazel> <gitleaks>
set -euo pipefail
r="$TEST_SRCDIR/_main"
default=$(sed -n 's/^DEFAULT_VERSION = "\(.*\)"/\1/p' "$r/$1")
module=$(sed -n 's/^gitleaks.version(version = "\(.*\)")/\1/p' "$r/$2")
binary=$("$r/$3" version)
echo "DEFAULT_VERSION=$default MODULE.bazel=$module binary=$binary"
[[ -n "$default" && "$module" == "$default" && "$binary" == "$default" ]] || { echo "FAIL: versions differ" >&2; exit 1; }
echo "PASS"
