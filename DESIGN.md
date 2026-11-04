# rules_gitleaks — design notes

rules_gitleaks wraps a CLI scanner rather than a service, so its closest siblings are rules_opa and rules_helm, which provide a toolchain plus check and test rules. It takes these conventions from rules_vault, rules_valkey and rules_otel:
- a binary toolchain pinned from published checksums;
- checks as validation actions;
- analysis tests;
- `tools/update_checksums.sh`;
- the README / DESIGN / CLAUDE.md set.

There's no server, health check or cluster install: gitleaks has no long-running mode.

## Binary and toolchain

- **The binary:** the upstream release tarballs (`gitleaks_<ver>_<os>_<x64|arm64>.tar.gz`), one static Go binary each, for linux and darwin on amd64 and arm64. The SHA-256s come from the release's `checksums.txt`, and `tools/update_checksums.sh` downloads every tarball to cross-check them.
- **Repo names carry no version:** `gitleaks_<platform>`. Each repo declares its own `gitleaks_toolchain`, so `//toolchain:BUILD` never changes with the version. The root module's `gitleaks.version()` wins; otherwise rules_gitleaks' own tag applies. So consumers declare nothing by default. This is the same scheme as rules_otel v0.2.

## Staging: why every scan copies its inputs

The rules had to handle this first. Bazel hands actions and tests their inputs as symlinks (sandbox, runfiles), and `gitleaks dir`:
- **skips symlinks** by default. A scan of a runfiles tree finds nothing and exits 0: a silent pass, the worst failure for a secret scanner;
- with `--follow-symlinks`, **reports the link's target**: a sandbox, execroot or source-tree absolute path that changes per machine and per run, so fingerprints can't be ignored stably.

So `private/gitleaks.py` stages every input as a real file under its workspace path: a hard link to the real file, or a copy across filesystems. Tree artifacts are staged file by file. It then runs `gitleaks dir .` in that tree. As a result:
- findings name `pkg/file`, for generated files too;
- fingerprints (`<path>:<rule>:<line>`) are the same in `gitleaks_test`, `gitleaks_check`, `gitleaks_aspect` and a `gitleaks_scan` of the workspace, so one `.gitleaksignore` serves all of them;
- files from other repositories are staged as `external/<repo>/...`.

## Nothing implicit

gitleaks reads several things implicitly:
- a `.gitleaks.toml` in the scanned directory;
- `GITLEAKS_CONFIG` / `GITLEAKS_CONFIG_TOML` from the environment;
- `.gitleaksignore` from the *working directory* (`--gitleaks-ignore-path` defaults to `.`).

The driver always passes `--config`, removes the two variables, and passes `--gitleaks-ignore-path` as the given file or `/dev/null`. A directory path to `-i` is accepted but silently ignored, which is why the attribute is a single file. Without a config, the default is `config/default.toml`: `[extend] useDefault = true`, which is exactly gitleaks' built-in rules.

## Exit codes

Scans use `--exit-code 3`, which gitleaks' own failures don't use:
- a bad config is fatal and exits 1;
- a regex that doesn't compile panics and exits 2.

So the driver tells "leaks" (test fails and lists them, exit 1) from "gitleaks broke" (exit 2, with the useful lines of its output and the Go stack trace dropped).

## `gitleaks_config`: two checks

1. **gitleaks loads it,** by scanning an empty directory with it: TOML syntax, rule regexes (compiled at load), missing ids, empty rules.
2. **A key check against gitleaks' schema** (`config.ViperConfig`; keys are case-insensitive, as viper reads them). gitleaks ignores unknown keys, so `pathss = [...]` in an allowlist allows nothing, and a misspelt `keywords` silently drops a rule's prefilter. This check needs `tomllib` (Python 3.11+); on older Pythons it is skipped, and the marker file says so.

`[extend] path` and `url` are refused. A path is resolved at scan time relative to gitleaks' working directory, which the staging changes; a URL is a network fetch during the build.

## Reports

- **One gitleaks pass:** writes the JSON report. The driver reads it to print the summary and to write JUnit itself, one test case per finding, so a CI test-results view lists the leaks.
- **SARIF:** a second pass, only with `sarif = True`. gitleaks writes one report format per run, and most users don't need SARIF.
- **Redaction:** `redact` (default 100) applies to the output and every report. Test logs and outputs are uploaded by CI, so they shouldn't carry the secret they warn about.

## `gitleaks_aspect`

- **What it scans:** each main-repository target's own files, from a fixed list of attributes (`srcs`, `hdrs`, `textual_hdrs`, `data`, `resources`, `src`, `template`). It doesn't scan `deps`, which would rescan other targets' outputs (and binaries).
- **How:** one action per target, as a validation action, so a plain `bazel build --aspects=...` fails on a leak. The output group `gitleaks` exposes the reports. Bazel's action cache makes it incremental.
- **Configuration:** label flags (`//:aspect_config`, `//:aspect_ignore`), because aspects applied from the command line take no attributes.
- **Opting out:** `no-gitleaks` skips a target. This repository uses it for its own fixtures, so `bazel build //... --aspects=...` passes here (CI checks it).

## `gitleaks_rule_test`

- **What it is:** unit tests for a config, in the spirit of promtool's rule tests and rules_alertmanager's routing tests.
- **How it runs:** all cases are staged and scanned in one pass, then grouped by file.
- **Exact matching:** each `leaks` file must produce exactly its rule IDs. With `useDefault = true`, built-in rules often fire alongside a custom one (`generic-api-key`, notably). Exact matching makes that visible instead of letting a test pass while another rule masks a broken one.

## Fixtures without secrets

This repository contains no real-looking secret. `tests/make_fixture.sh` assembles fake keys from split pieces in genrules, so:
- the repository passes its own `gitleaks_scan` of the working tree and history (CI runs both);
- GitHub push protection has nothing to block;
- the fixtures' targets carry `no-gitleaks`.

## Not done (v0.1)

- `[extend] path` (layered configs) and `url`.
- `gitleaks git` inside a test: a test sandbox has no repository; history scans are `bazel run` only.
- Archive traversal and decoding tuning beyond `extra_args`.
- Report templates (`--report-template`).
