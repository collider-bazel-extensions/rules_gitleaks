# rules_gitleaks

Bazel rules for gitleaks:
- build-time config checks (`gitleaks_config`);
- scans as tests (`gitleaks_test`), validation actions (`gitleaks_check`) or an aspect (`gitleaks_aspect`);
- rule unit tests (`gitleaks_rule_test`);
- `bazel run` over the working tree or history (`gitleaks_scan`).

See DESIGN.md.

## Commit requirements

- All tests must pass before any commit with code changes: `bazel test //tests/...`, plus `bazel build //... --aspects=//:defs.bzl%gitleaks_aspect`.
- All documentation (`README.md`, `DESIGN.md`, `CLAUDE.md`) must be updated to reflect any code changes before committing: new rules, changed attributes, new public API surface, behaviour changes.
- Never commit a real-looking secret, even a fake one. Generate fixtures with `tests/make_fixture.sh` (split pieces) and tag their targets `no-gitleaks`. CI runs `bazel run //:gitleaks` and `//:gitleaks_history` on this repository.

## Repo layout

```
rules_gitleaks/
├── MODULE.bazel              # module; gitleaks extension + toolchains
├── .gitattributes            # tests/ export-ignore: the release archive loads with //... for consumers
├── .github/consumer/check.sh # CI: @rules_gitleaks//... loads from the commit's git archive
├── BUILD.bazel               # aspect label flags; //:gitleaks, //:gitleaks_history (dogfood)
├── defs.bzl                  # public API re-exports
├── extensions.bzl            # `gitleaks.version()` → gitleaks_<plat> repos (root tag, else ours)
├── config/                   # default.toml (useDefault = true) as //config:default; no_ignore
├── private/
│   ├── versions.bzl          # DEFAULT_VERSION, GITLEAKS_VERSIONS (sha256 pins), PLATFORMS
│   ├── repositories.bzl      # per-platform repo: tarball + its gitleaks_toolchain impl
│   ├── providers.bzl         # GitleaksBinaryInfo, GitleaksConfigInfo
│   ├── common.bzl            # SCAN_ATTRS, workspace paths, manifest lines
│   ├── gitleaks.py           # driver: check-config, config-test, scan (staging, reports),
│   │                         # workspace (git ls-files / tree), rule-test
│   ├── third_party/tomli/    # vendored tomli 2.2.1 (MIT) for Python < 3.11; README.md says why
│   ├── config.bzl            # gitleaks_config, gitleaks_config_test
│   ├── test.bzl              # gitleaks_test, gitleaks_rule_test (+ run.sh.tmpl)
│   ├── check.bzl             # gitleaks_check
│   ├── aspect.bzl            # gitleaks_aspect
│   ├── scan.bzl              # gitleaks_scan (+ scan.sh.tmpl; tracked_only via the driver)
│   └── workspace.bzl         # gitleaks_workspace_test macro (+ workspace_test.sh.tmpl)
├── toolchain/                # toolchain_type, per-platform toolchains, :current
├── tools/update_checksums.sh
└── tests/
    ├── BUILD.bazel, analysis_tests.bzl, fixtures.bzl, make_fixture.sh
    ├── testdata/             # corp.toml + bad configs, all_fixtures.gitleaksignore
    ├── aspect/               # clean / leaky / skipped targets for the aspect (CI)
    ├── consumer/             # separate consumer module (default config = external labels; CI)
    ├── leak_detection_test.sh, rule_test_failure_test.sh, scan_test.sh,
    ├── tracked_scan_test.sh  # temp git repo: tracked/staged found, gitignored skipped, non-git fails
    ├── vendored_toml_test.sh, config_test_failure_test.sh  # gitleaks_config_test
    └── checksums_test.sh, version_test.sh
```

## Key concepts

- **Staging.** Inputs become real files (hard link, else copy) under their workspace paths. `gitleaks dir` skips symlinks, or with `--follow-symlinks` reports their targets. Findings and fingerprints are workspace paths everywhere.
- **Nothing implicit.** Always `--config` and `--gitleaks-ignore-path <file or /dev/null>`; `GITLEAKS_CONFIG*` are removed from the environment.
- **Exit codes.** `--exit-code 3` = leaks; gitleaks' own errors are 1 (fatal) and 2 (regex panic). Driver: 0 clean, 1 leaks, 2 gitleaks failed.
- **Config check.** gitleaks loads it (empty-dir scan) + a key check against `config.ViperConfig`, parsed with `tomllib` or the vendored tomli 2.2.1 (`private/third_party`, MIT; `RULES_GITLEAKS_VENDORED_TOML=1` forces it), so it runs on Python 3.8+. `[extend] path/url` are refused. `gitleaks_config_test` runs the check as a test (`expect_error` regex).
- **Tracked-only.** `git ls-files --cached` (committed + staged) of the workspace, staged like `srcs`: `gitleaks_scan(tracked_only)` and `gitleaks_workspace_test` (tagged local/external/no-sandbox; finds the tree via the `//:MODULE.bazel` runfile's realpath or `$BUILD_WORKSPACE_DIRECTORY`). Outside a checkout: exit 2, saying so.
- **Toolchain.** Unversioned `gitleaks_<plat>` repos; keep `DEFAULT_VERSION` and `gitleaks.version()` in `MODULE.bazel` equal (`//tests:version_test`).

## Public API

```python
load("@rules_gitleaks//:defs.bzl",
    "gitleaks_config",     # src
    "gitleaks_config_test",  # src (.toml), expect_error (regex; empty = must pass), env
    "gitleaks_test",       # srcs, config, ignore, baseline, redact, enable_rules, extra_args, sarif
    "gitleaks_check",      # same, minus sarif
    "gitleaks_aspect",     # --@rules_gitleaks//:aspect_config / :aspect_ignore; tag no-gitleaks
    "gitleaks_rule_test",  # config, leaks = {file: "id,id"}, clean = [files]
    "gitleaks_scan",       # mode = dir|git, tracked_only, config, ignore, baseline, redact, extra_args
    "gitleaks_workspace_test",  # tracked_only (default True), marker, config, ignore, baseline, ...
    "GitleaksBinaryInfo", "GitleaksConfigInfo",
)
```

## Development

```sh
bazel test //tests/...
bazel build //... --aspects=//:defs.bzl%gitleaks_aspect
bazel build //tests/testdata:typo        # must fail: unknown key 'pathss'
bazel build //tests:leaky_check          # must fail: tests/leaky/corp.txt:corp-token:1
bazel run //:gitleaks && bazel run //:gitleaks_tracked && bazel run //:gitleaks_history
(cd tests/consumer && bazel test //...)  # rules_gitleaks from another repository
tools/update_checksums.sh 8.30.1         # re-pin; --check verifies
```

### Test results (last full run: 2026-11-08)

All 34 test targets pass on Linux x86_64 (gitleaks 8.30.1): 33 in `//tests/...` and the dogfood `//:workspace_tracked_test`. Other checks:
- **Consumer:** `tests/consumer` (default config, `gitleaks_config_test`) passes; with v0.1.0's `@file` argument parsing restored it fails to build, as v0.1.0 did for consumers using the default config. A scratch consumer git repo also ran `gitleaks_workspace_test`: a staged secret fails it, a gitignored `.env.local` doesn't.
- **Release archive:** `.github/consumer/check.sh` (CI `consumer` job): the commit's `git archive` has no `tests/`, and `@rules_gitleaks//...` loads for a consumer module (v0.2.1; it failed on `tests/` loading the dev-only `rules_shell`).
- **Python:** the driver and the vendored tomli parse as Python 3.8 syntax (`ast.parse(feature_version=(3, 8))`); the vendored parser is exercised by the `*_vendored_toml_test` targets. No Python older than 3.14 was available to run them on.
- **Aspect:** `bazel build //... --aspects=...` passes, including with network blocked in the sandbox.
- **Build-time failures:** the typo config, `leaky_check` and the aspect on `//tests/aspect:leaky` each fail `bazel build` with the expected message; `//tests/aspect:skipped` (`no-gitleaks`) passes. CI checks all of these.
- **Platforms:** all four archives fetch, with the binary at their root.
- **Consumer module:** a scratch consumer passed with a custom config: `gitleaks_test`, `gitleaks_rule_test`, a leaky `gitleaks_check` (fails), the aspect with `aspect_config`, and `gitleaks_scan`.

| Test target | What it verifies | Result |
|---|---|---|
| `//tests:clean_test` | this repo's sources and a `gitleaks:allow` line are clean (dogfood) | PASSED |
| `//tests:leak_detection_test` | generated files + tree artifact: 4 leaks, workspace-path fingerprints, redaction, JUnit/JSON/SARIF | PASSED |
| `//tests:ignore_test`, `//tests:baseline_test` | `.gitleaksignore` and a baseline report suppress every finding | PASSED |
| `//tests:enable_rules_test` | `enable_rules` limits the rules | PASSED |
| `//tests:custom_config_clean_test` | a custom config's allowlist | PASSED |
| `//tests:corp_rules_test` | custom + built-in rules give exactly the expected IDs; clean files stay clean | PASSED |
| `//tests:rule_test_failure_test` | wrong expectations fail per case: missing / unexpected rules, JUnit | PASSED |
| `//tests:config_*_test` (6) | `gitleaks_config_test`: good config passes; unknown key, `[extend] url`, bad regex, bad TOML, missing id fail with their messages | PASSED |
| `//tests:config_*_vendored_toml_test` (2), `//tests:vendored_toml_test` | the same with the vendored tomli forced; it really ran and caught the typo | PASSED |
| `//tests:config_test_failure_test` | `gitleaks_config_test` fails on a non-matching error, an unexpected pass, an unexpected failure | PASSED |
| `//tests:tracked_scan_test` | `gitleaks_scan(tracked_only)` / `gitleaks_workspace_test` on a temp repo: tracked + staged found, gitignored/untracked skipped, `.gitleaksignore`, tree mode, non-git dir fails | PASSED |
| `//:workspace_tracked_test` | this checkout's tracked files are clean (uncached) | PASSED |
| `//tests:scan_test` | `bazel run` scan: working tree, args, `./.gitleaksignore`, git history | PASSED |
| `//tests:checksums_test`, `//tests:version_test` | pins well-formed; binary = DEFAULT_VERSION = MODULE.bazel | PASSED |
| `//tests:analysis_tests_*` (11) | providers, executables, output groups, bad redact, empty srcs, rule-test attribute errors, tracked_only + git | PASSED |

## Known limitations

- `python3` (3.8+) is required on the host.
- `tracked_only` / `gitleaks_workspace_test` need git and a checkout; the workspace test is uncached by design.
- `[extend] path` / `url` aren't supported.
- History scans (`mode = "git"`) are `bazel run` only and use the host's git.
