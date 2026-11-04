"""Public API for rules_gitleaks.

  gitleaks_config     — a .gitleaks.toml, loaded and schema-checked on every build
  gitleaks_test       — test: no secrets in these files / targets' outputs
  gitleaks_check      — the same scan as a validation action (fails `bazel build`)
  gitleaks_aspect     — scans every target's own files:
                        bazel build //... --aspects=@rules_gitleaks//:defs.bzl%gitleaks_aspect
  gitleaks_rule_test  — unit tests for a config's rules and allowlists
  gitleaks_scan       — `bazel run`: the workspace's working tree (optionally only
                        what git tracks) or git history
  gitleaks_workspace_test — uncached test over the live checkout's tracked files
  gitleaks_config_test — test that a config passes, or fails with a given error
"""

load("//private:aspect.bzl", _gitleaks_aspect = "gitleaks_aspect")
load("//private:check.bzl", _gitleaks_check = "gitleaks_check")
load("//private:config.bzl", _gitleaks_config = "gitleaks_config", _gitleaks_config_test = "gitleaks_config_test")
load("//private:providers.bzl", _GitleaksBinaryInfo = "GitleaksBinaryInfo", _GitleaksConfigInfo = "GitleaksConfigInfo")
load("//private:scan.bzl", _gitleaks_scan = "gitleaks_scan")
load("//private:test.bzl", _gitleaks_rule_test = "gitleaks_rule_test", _gitleaks_test = "gitleaks_test")
load("//private:workspace.bzl", _gitleaks_workspace_test = "gitleaks_workspace_test")

gitleaks_config = _gitleaks_config
gitleaks_config_test = _gitleaks_config_test
gitleaks_workspace_test = _gitleaks_workspace_test
gitleaks_test = _gitleaks_test
gitleaks_check = _gitleaks_check
gitleaks_aspect = _gitleaks_aspect
gitleaks_rule_test = _gitleaks_rule_test
gitleaks_scan = _gitleaks_scan

GitleaksBinaryInfo = _GitleaksBinaryInfo
GitleaksConfigInfo = _GitleaksConfigInfo
