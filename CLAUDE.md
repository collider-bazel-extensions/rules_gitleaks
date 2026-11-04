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
├── BUILD.bazel               # aspect label flags; //:gitleaks, //:gitleaks_history (dogfood)
├── defs.bzl                  # public API re-exports
├── extensions.bzl            # `gitleaks.version()` → gitleaks_<plat> repos (root tag, else ours)
├── config/                   # default.toml (useDefault = true) as //config:default; no_ignore
├── private/
│   ├── versions.bzl          # DEFAULT_VERSION, GITLEAKS_VERSIONS (sha256 pins), PLATFORMS
│   ├── repositories.bzl      # per-platform repo: tarball + its gitleaks_toolchain impl
│   ├── providers.bzl         # GitleaksBinaryInfo, GitleaksConfigInfo
│   ├── common.bzl            # SCAN_ATTRS, workspace paths, manifest lines
│   ├── gitleaks.py           # driver: check-config, scan (staging, reports), rule-test
│   ├── config.bzl            # gitleaks_config
│   ├── test.bzl              # gitleaks_test, gitleaks_rule_test (+ run.sh.tmpl)
│   ├── check.bzl             # gitleaks_check
│   ├── aspect.bzl            # gitleaks_aspect
│   └── scan.bzl              # gitleaks_scan (+ scan.sh.tmpl)
├── toolchain/                # toolchain_type, per-platform toolchains, :current
├── tools/update_checksums.sh
└── tests/
    ├── BUILD.bazel, analysis_tests.bzl, fixtures.bzl, make_fixture.sh
    ├── testdata/             # corp.toml + bad configs, all_fixtures.gitleaksignore
    ├── aspect/               # clean / leaky / skipped targets for the aspect (CI)
    ├── leak_detection_test.sh, rule_test_failure_test.sh,
    └── config_check_test.sh, scan_test.sh, checksums_test.sh, version_test.sh
```

## Key concepts

- **Staging.** Inputs become real files (hard link, else copy) under their workspace paths. `gitleaks dir` skips symlinks, or with `--follow-symlinks` reports their targets. Findings and fingerprints are workspace paths everywhere.
- **Nothing implicit.** Always `--config` and `--gitleaks-ignore-path <file or /dev/null>`; `GITLEAKS_CONFIG*` are removed from the environment.
- **Exit codes.** `--exit-code 3` = leaks; gitleaks' own errors are 1 (fatal) and 2 (regex panic). Driver: 0 clean, 1 leaks, 2 gitleaks failed.
- **Config check.** gitleaks loads it (empty-dir scan) + a key check against `config.ViperConfig` (Python 3.11+). `[extend] path/url` are refused.
- **Toolchain.** Unversioned `gitleaks_<plat>` repos; keep `DEFAULT_VERSION` and `gitleaks.version()` in `MODULE.bazel` equal (`//tests:version_test`).

## Public API

```python
load("@rules_gitleaks//:defs.bzl",
    "gitleaks_config",     # src
    "gitleaks_test",       # srcs, config, ignore, baseline, redact, enable_rules, extra_args, sarif
    "gitleaks_check",      # same, minus sarif
    "gitleaks_aspect",     # --@rules_gitleaks//:aspect_config / :aspect_ignore; tag no-gitleaks
    "gitleaks_rule_test",  # config, leaks = {file: "id,id"}, clean = [files]
    "gitleaks_scan",       # mode = dir|git, config, ignore, baseline, redact, extra_args
    "GitleaksBinaryInfo", "GitleaksConfigInfo",
)
```

## Development

```sh
bazel test //tests/...
bazel build //... --aspects=//:defs.bzl%gitleaks_aspect
bazel build //tests/testdata:typo        # must fail: unknown key 'pathss'
bazel build //tests:leaky_check          # must fail: tests/leaky/corp.txt:corp-token:1
bazel run //:gitleaks && bazel run //:gitleaks_history
tools/update_checksums.sh 8.30.1         # re-pin; --check verifies
```

### Test results (last full run: 2026-11-04)

All 22 test targets pass on Linux x86_64 (gitleaks 8.30.1), also at 5 runs each. Other checks:
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
| `//tests:config_check_test` | good config; unknown key, `[extend] url`, bad regex, bad TOML, missing id | PASSED |
| `//tests:scan_test` | `bazel run` scan: working tree, args, `./.gitleaksignore`, git history | PASSED |
| `//tests:checksums_test`, `//tests:version_test` | pins well-formed; binary = DEFAULT_VERSION = MODULE.bazel | PASSED |
| `//tests:analysis_tests_*` (10) | providers, executables, output groups, bad redact, empty srcs, rule-test attribute errors | PASSED |

## Known limitations

- `python3` is required on the host; the config key check needs 3.11+.
- `[extend] path` / `url` aren't supported.
- History scans (`mode = "git"`) are `bazel run` only and use the host's git.
