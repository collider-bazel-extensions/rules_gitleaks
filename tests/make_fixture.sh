#!/usr/bin/env bash
# Writes a test fixture. The secrets are fake, and split here so this file
# (and the repository) never contains one: only the generated files do.
#
#   make_fixture.sh <kind> <out>
set -euo pipefail
kind="$1"; out="$2"
case "$kind" in
  aws)       printf 'aws_access_key_id = %s%s\naws_secret_access_key = "%s%s"\n' \
               AKIA Z7Q2XKQ3RS4TUVWX wJalrXUtnFEMI/K7MDENG /bPxRfiCYzq3tqLW9pQ > "$out" ;;
  github)    printf 'env:\n  GITHUB_TOKEN: %s%s\n' ghp_ 1aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX > "$out" ;;
  allowed)   printf 'token: %s%s # gitleaks:allow\n' ghp_ 9aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wZ > "$out" ;;
  corp)      printf 'internal_token = "%s%s"\n' corp_ 7f3k9q2m4x8w1z5v > "$out" ;;
  corp_doc)  printf '# example: internal_token = "%s%s"\n' corp_ example0example0 > "$out" ;;
  tree)      mkdir -p "$out/nested"
             printf 'clean\n' > "$out/readme.txt"
             printf 'GITHUB_TOKEN=%s%s\n' ghp_ 5aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wQ > "$out/nested/ci.env" ;;
  *) echo "make_fixture: unknown kind $kind" >&2; exit 1 ;;
esac
