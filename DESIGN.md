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
2. **A key check against gitleaks' schema** (`config.ViperConfig`; keys are case-insensitive, as viper reads them). gitleaks ignores unknown keys, so `pathss = [...]` in an allowlist allows nothing, and a misspelt `keywords` silently drops a rule's prefilter. It parses the TOML with the standard library's `tomllib` (Python 3.11+).

   **Before v0.2 (#1)** the check was skipped on older Pythons, so a typo passed the build on one host and failed it on another. Two fixes were possible:
   - **A hermetic Python toolchain (rules_python):** a heavy dependency for one parser.
   - **Vendoring (chosen):** `private/third_party/tomli` is tomli 2.2.1 (MIT), the pure-Python library `tomllib` was adopted from. It's used when `tomllib` is missing, so the check now runs on any Python 3.8+. `RULES_GITLEAKS_VENDORED_TOML=1` forces it, and tests run both parsers. The marker file and `gitleaks_config_test`'s output say which parser was used.

`[extend] path` and `url` are refused. A path is resolved at scan time relative to gitleaks' working directory, which the staging changes; a URL is a network fetch during the build.

## Reports

- **One gitleaks pass:** writes the JSON report. The driver reads it to print the summary and to write JUnit itself, one test case per finding, so a CI test-results view lists the leaks.
- **SARIF:** a second pass, only with `sarif = True`. gitleaks writes one report format per run, and most users don't need SARIF.
- **Redaction:** `redact` (default 100) applies to the output and every report. Test logs and outputs are uploaded by CI, so they shouldn't carry the secret they warn about.

## `gitleaks_config_test`

The check is a validation action, so a `gitleaks_config` of a broken file fails the build: users couldn't show in their own tests that a typo is caught without calling the private driver path. `gitleaks_config_test(src, expect_error)` runs the same check at test time on a plain `.toml`. It passes iff the check fails with a message matching `expect_error` (a Python regex), or passes when `expect_error` is empty, and it names the file either way. The in-tree config tests use it.

## Tracked-only scans (v0.2, #1)

Scanning the working tree picks up files that aren't part of the repository: a developer's `.env.local`, other git worktrees under `.claude/worktrees/`, scratch output. One local secret would then fail everyone's `bazel test //...`, while `gitleaks_test`'s explicit `srcs` can't express "what git tracks".

- **The file list:** the driver's `workspace` mode lists `git ls-files --cached`, which is the index: committed plus staged files. It keeps the regular files that exist in the working tree; deleted-but-unstaged files, submodules and symlinks are skipped, as `gitleaks dir` would skip them too.
- **Staging:** those files are staged exactly as `gitleaks_test` stages its `srcs`, so findings, fingerprints and reports match. Their working-tree content is scanned, not the staged blob, so a change staged and then edited further is scanned as edited.
- **Outside a git checkout** (a release archive, a vendored copy) there is no index, so it fails, naming the directory and git's message, rather than quietly scanning nothing.
- **`gitleaks_scan(tracked_only = True)`** is the `bazel run` form. `mode = "git"` already scans git's history, so combining it with `tracked_only` is an analysis error.
- **`gitleaks_workspace_test`** is the test form. A test normally sees only its declared inputs in a sandbox with no checkout, so this one is deliberately the exception:
  - it is tagged `local`, `external` and `no-sandbox`, so it is never cached and always reads the live tree;
  - it locates the tree by resolving a runfile of the workspace's `MODULE.bazel` to its real path (or `$BUILD_WORKSPACE_DIRECTORY` under `bazel run`).

  It's a macro, so the default `marker = "//:MODULE.bazel"` resolves in the caller's repository.

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

## Arguments that start with `@` (v0.2)

v0.1.0's driver let argparse read `@file` arguments. In a consumer, rules_gitleaks' own labels are external and print as `@rules_gitleaks+//config:default`; passed as `--label`, argparse tried to open that as a file. So every scan using the default config failed to build outside this repository. In-tree tests never see an external label, so `tests/consumer/` is now a separate consumer module that CI builds and tests, and the driver no longer reads `@file` arguments.

## Release archive contents (v0.2.1)

`tests/` is `export-ignore` (`.gitattributes`): its packages load the dev-only `rules_shell`, which made `@rules_gitleaks//...` unloadable for consumers. `REPO.bazel` `ignore_directories` would also hide `tests/` from this repo's own `bazel test //tests/...`, so it isn't used. A `git_override` clone (the README's first pin) still contains `tests/`. CI's `consumer` job queries `//...` from the commit's `git archive`.

## Not done

- `[extend] path` (layered configs) and `url`.
- `gitleaks git` inside a test: a test sandbox has no repository; history scans are `bazel run` only.
- Archive traversal and decoding tuning beyond `extra_args`.
- Report templates (`--report-template`).
