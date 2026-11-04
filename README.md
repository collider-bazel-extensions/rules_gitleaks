# rules_gitleaks

Bazel rules for [gitleaks](https://github.com/gitleaks/gitleaks), the secret scanner. They check gitleaks configs at build time, scan files (including **generated** ones) in tests or as part of `bazel build`, unit-test custom rules, and scan the workspace or its git history with `bazel run`.

- **Config (build time)**
  - `gitleaks_config` — a `.gitleaks.toml`, loaded by gitleaks and schema-checked on every build. A bad regex, a rule without an id or a typo that gitleaks would silently ignore (`pathss` in an allowlist) fails `bazel build`.
- **Scans**
  - `gitleaks_test` — a test that fails if `srcs` contain secrets. `srcs` can be files, filegroups, or any target's outputs: rendered manifests, packaged configs, tree artifacts. Writes JUnit, JSON and optionally SARIF reports.
  - `gitleaks_check` — the same scan as a validation action, so a leak fails `bazel build`.
  - `gitleaks_aspect` — scans every target's own files, incrementally: `bazel build //... --aspects=@rules_gitleaks//:defs.bzl%gitleaks_aspect`.
  - `gitleaks_scan` — `bazel run` over the workspace's working tree or its git history.
- **Rule tests**
  - `gitleaks_rule_test` — sample files that must produce exactly the expected rule IDs, or none: unit tests for custom rules and allowlists.

No host gitleaks needed. The binary is the upstream release for linux and darwin on amd64 and arm64, pinned by SHA-256 (gitleaks 8.30.1). The rules need `python3` on the host; the config key check needs Python 3.11+ (`tomllib`), and is skipped on older Pythons.

## Install (Bzlmod)

```python
bazel_dep(name = "rules_gitleaks", version = "0.1.0")
git_override(
    module_name = "rules_gitleaks",
    remote = "https://github.com/collider-bazel-extensions/rules_gitleaks",
    tag = "v0.1.0",
)
```

To pin by archive and integrity instead of a git tag, replace the `git_override` with:

```python
archive_override(
    module_name = "rules_gitleaks",
    urls = ["https://github.com/collider-bazel-extensions/rules_gitleaks/archive/refs/tags/v0.1.0.tar.gz"],
    strip_prefix = "rules_gitleaks-0.1.0",
    integrity = "sha256-BtEeiPaYo/aB+6ODQZq7k+Iu4RpMpZdxBynoMyM2ztQ=",
)
```

That's all: rules_gitleaks registers its toolchain and fetches the binary only for the platform a build needs. To pick another pinned version, name it in your own `MODULE.bazel` (only the root module's tag counts):

```python
gitleaks = use_extension("@rules_gitleaks//:extensions.bzl", "gitleaks")
gitleaks.version(version = "8.30.1")
```

## Config

```python
load("@rules_gitleaks//:defs.bzl", "gitleaks_config")

gitleaks_config(
    name = "gitleaks_config",
    src = ".gitleaks.toml",
)
```

```toml
# .gitleaks.toml
[extend]
useDefault = true            # gitleaks' built-in rules

[[rules]]
id = "acme-key"
description = "ACME API key"
regex = '''acme_live_[0-9a-f]{24}'''
keywords = ["acme_live_"]

  [[rules.allowlists]]
  regexes = ['''acme_live_0{24}''']   # the documented example key
```

- **Checked on every build:** gitleaks loads the config as a scan would, so TOML errors, bad regexes and invalid rules fail with its own message.
- **Unknown keys are errors.** gitleaks ignores keys it doesn't know, so a misspelt allowlist key silently allows nothing (or a misspelt `keywords` makes a rule slow). rules_gitleaks checks every key against gitleaks' config schema:

  ```
  gitleaks_config //:gitleaks_config: rule 'acme-key' allowlists[0]: unknown key 'pathss' (known: commits, condition, description, paths, regexes, regextarget, stopwords)
  ```

- **`[extend] path` and `url` are refused:** a path can't be staged reliably, and a URL is fetched at scan time. Use `useDefault = true` (optionally with `disabledRules`), and put your rules in this file.
- Without `config`, every scan uses `@rules_gitleaks//config:default`: gitleaks' built-in rules.

## `gitleaks_test`

```python
load("@rules_gitleaks//:defs.bzl", "gitleaks_test")

gitleaks_test(
    name = "secrets_test",
    srcs = [
        "//deploy:rendered_manifests",   # generated
        "//services/api:config_files",
        ".github/workflows/ci.yml",
    ],
    config = ":gitleaks_config",
    ignore = ".gitleaksignore",         # optional
)
```

On a leak the test fails, naming the workspace path, line, rule and fingerprint, with the secret redacted:

```
gitleaks //:secrets_test: 1 leak(s) in 1 file(s):
  deploy/rendered/api.yaml:14  generic-api-key  api_key: REDACTED
      fingerprint: deploy/rendered/api.yaml:generic-api-key:14
A real secret must be removed and rotated. To accept a false positive, add its fingerprint to the .gitleaksignore given as `ignore`, or put `gitleaks:allow` in a comment on that line.
```

- **Workspace paths, even for generated files.** Bazel's inputs are symlinks, and `gitleaks dir` skips symlinks unless it is told to follow them; then it reports the link's *target* (a sandbox path). So each input is staged as a real file (hard link, or copy) under its workspace path. Findings say `deploy/rendered/api.yaml`, not `bazel-out/k8-fastbuild/bin/...`, and fingerprints match a `.gitleaksignore` written for the repository (and `gitleaks_scan`'s).
- **Directories:** a tree artifact in `srcs` is scanned file by file under its workspace path.
- **Reports:**
  - JUnit goes to `$XML_OUTPUT_FILE`, one test case per finding;
  - `gitleaks.json` goes to the test's undeclared outputs (`bazel-testlogs/<pkg>/<name>/test.outputs/`);
  - `gitleaks.sarif` too, with `sarif = True`, for code-scanning uploads.
- **Nothing implicit:** the config, ignore file and baseline are always passed explicitly. A `.gitleaksignore` in the working directory, `GITLEAKS_CONFIG` or `GITLEAKS_CONFIG_TOML` in the environment never change a result.

| Argument (`gitleaks_test`, `gitleaks_check`) | Default | |
|---|---|---|
| `srcs` | | files and targets to scan (required, non-empty) |
| `config` | gitleaks' built-in rules | a `gitleaks_config` |
| `ignore` | none | a `.gitleaksignore`: one fingerprint (`<path>:<rule>:<line>`) per line |
| `baseline` | none | a gitleaks JSON report whose findings are ignored |
| `redact` | `100` | percent of each secret hidden in output and reports |
| `enable_rules` | all | only these rule IDs |
| `extra_args` | `[]` | extra gitleaks arguments, e.g. `["--max-decode-depth=2"]` |
| `sarif` | `False` | also write SARIF (`gitleaks_test` only; a second pass) |

## `gitleaks_check`

```python
load("@rules_gitleaks//:defs.bzl", "gitleaks_check")

gitleaks_check(
    name = "manifests_check",
    srcs = [":rendered_manifests"],
    config = "//:gitleaks_config",
)
```

The scan runs as a validation action, so any `bazel build` that includes the package fails on a leak with the same message. Use it for artifacts that must never carry a secret: generated config, rendered Helm charts, a container's file tree. The JSON report is in the `gitleaks` output group.

## `gitleaks_aspect`

```sh
bazel build //... --aspects=@rules_gitleaks//:defs.bzl%gitleaks_aspect
```

```
# .bazelrc
build:secrets --aspects=@rules_gitleaks//:defs.bzl%gitleaks_aspect
build:secrets --@rules_gitleaks//:aspect_config=//:gitleaks_config
build:secrets --@rules_gitleaks//:aspect_ignore=//:.gitleaksignore
```

- **What it scans:** each target in the main repository gets one scan of the files in its `srcs`, `hdrs`, `textual_hdrs`, `data`, `resources`, `src` and `template` attributes, source and generated. External repositories are skipped.
- **Incremental:** results are cached like any action, so after a change only the affected targets are scanned again.
- **Failures:** leaks fail the build (it is a validation action). The reports are in the `gitleaks` output group (`--output_groups=+gitleaks`).
- **Opting out:** tag a target `no-gitleaks` to skip it, for example test fixtures with fake secrets.

## `gitleaks_rule_test`

```python
load("@rules_gitleaks//:defs.bzl", "gitleaks_rule_test")

gitleaks_rule_test(
    name = "gitleaks_rules_test",
    config = ":gitleaks_config",
    leaks = {
        "testdata/acme_key.env": "acme-key",
        "testdata/aws.ini": "aws-access-token, generic-api-key",
    },
    clean = [
        "testdata/acme_example.md",   # the allowlisted documentation key
    ],
)
```

- **What it checks:** each `leaks` file must produce *exactly* the listed rule IDs (other rules firing fails too), and each `clean` file none.
- **Output:** every case is reported, with JUnit per case:

  ```
  FAIL testdata/aws.ini: found but not expected: generic-api-key (line 2)
  ok   testdata/acme_example.md: no leaks
  ```

- **Keep real secrets out of samples.** Write sample secrets so they don't trip scanners of your repository: generate them with a `genrule` from split pieces (as this repo's `tests/make_fixture.sh` does), and tag the targets `no-gitleaks`.

## `gitleaks_scan`

```python
load("@rules_gitleaks//:defs.bzl", "gitleaks_scan")

gitleaks_scan(name = "gitleaks", config = ":gitleaks_config")
gitleaks_scan(name = "gitleaks_history", config = ":gitleaks_config", mode = "git")
```

```sh
bazel run //:gitleaks                      # the working tree
bazel run //:gitleaks_history              # every commit (needs git on PATH)
bazel run //:gitleaks -- --report-path=gitleaks-baseline.json --report-format=json --exit-code=0
```

- **Where it runs:** in the workspace root, so paths and fingerprints match `gitleaks_test`'s.
- **What it skips:** symlinks, including `bazel-*`, are not followed.
- **Ignore file:** without `ignore`, gitleaks reads `./.gitleaksignore` if present.
- **Arguments** after `--` go to gitleaks; relative paths are relative to the workspace root. The last command writes a baseline to pass as `baseline`.

## Pinned versions

| Component | Version | Source |
|---|---|---|
| gitleaks | `8.30.1` | gitleaks/gitleaks releases (published checksums) |

To pin another version, run `tools/update_checksums.sh <version>`. It pins all four platforms from the release's checksums file, cross-checked against the downloads, and `--check` verifies the pins. Then bump `DEFAULT_VERSION` and `gitleaks.version()` in `MODULE.bazel` (`//tests:version_test`).

## Development

```sh
bazel test //tests/...
bazel build //... --aspects=//:defs.bzl%gitleaks_aspect
bazel run //:gitleaks && bazel run //:gitleaks_history     # dogfood
```

See [DESIGN.md](DESIGN.md) for the design and trade-offs, and [CLAUDE.md](CLAUDE.md) for the repo layout and test inventory.
