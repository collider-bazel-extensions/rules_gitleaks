"""Analysis-time tests: providers, executables, output groups, and the
analysis errors for bad attributes."""

load("@bazel_skylib//lib:unittest.bzl", "analysistest", "asserts")
load(
    "//:defs.bzl",
    "GitleaksConfigInfo",
    "gitleaks_check",
    "gitleaks_rule_test",
    "gitleaks_scan",
    "gitleaks_test",
)

def _config_info_impl(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    asserts.equals(env, "corp.toml", target[GitleaksConfigInfo].config.basename)
    asserts.equals(env, 1, len(target[OutputGroupInfo]._validation.to_list()))
    return analysistest.end(env)

_config_info_test = analysistest.make(_config_info_impl)

def _has_executable_impl(ctx):
    env = analysistest.begin(ctx)
    target = analysistest.target_under_test(env)
    asserts.true(env, target[DefaultInfo].files_to_run.executable != None,
                 "expected target to expose an executable")
    return analysistest.end(env)

_has_executable_test = analysistest.make(_has_executable_impl)

def _check_groups_impl(ctx):
    env = analysistest.begin(ctx)
    groups = analysistest.target_under_test(env)[OutputGroupInfo]
    asserts.equals(env, ["generated_check.gitleaks.json"], [f.basename for f in groups.gitleaks.to_list()])
    # _validation also carries the config's own check (Bazel merges it in).
    asserts.true(env, groups.gitleaks.to_list()[0] in groups._validation.to_list())
    return analysistest.end(env)

_check_groups_test = analysistest.make(_check_groups_impl)

def _fails_impl(ctx):
    env = analysistest.begin(ctx)
    asserts.expect_failure(env, ctx.attr.message)
    return analysistest.end(env)

_fails_test = analysistest.make(
    _fails_impl,
    expect_failure = True,
    attrs = {"message": attr.string()},
)

def analysis_test_suite(name):
    s = name + "_subject"
    m = ["manual", "no-gitleaks"]
    gitleaks_test(name = s + "_test", srcs = ["//:defs.bzl"], tags = m)
    gitleaks_scan(name = s + "_scan", tags = m)
    gitleaks_test(name = s + "_bad_redact", srcs = ["//:defs.bzl"], redact = 101, tags = m)
    gitleaks_test(name = s + "_empty", srcs = [], tags = m)
    gitleaks_check(name = s + "_check_empty", srcs = [], tags = m)
    gitleaks_rule_test(name = s + "_no_cases", config = "//tests/testdata:corp", tags = m)
    gitleaks_rule_test(
        name = s + "_no_ids",
        config = "//tests/testdata:corp",
        leaks = {"//:defs.bzl": " , "},
        tags = m,
    )
    gitleaks_rule_test(
        name = s + "_both",
        config = "//tests/testdata:corp",
        leaks = {"//:defs.bzl": "x"},
        clean = ["//:defs.bzl"],
        tags = m,
    )

    tests = {
        "_config_info": (_config_info_test, "//tests/testdata:corp", None),
        "_test_executable": (_has_executable_test, ":" + s + "_test", None),
        "_scan_executable": (_has_executable_test, ":" + s + "_scan", None),
        "_check_groups": (_check_groups_test, ":generated_check", None),
        "_bad_redact": (_fails_test, ":" + s + "_bad_redact", "expected 0..100"),
        "_empty": (_fails_test, ":" + s + "_empty", "srcs is empty"),
        "_check_empty": (_fails_test, ":" + s + "_check_empty", "srcs is empty"),
        "_no_cases": (_fails_test, ":" + s + "_no_cases", "no cases"),
        "_no_ids": (_fails_test, ":" + s + "_no_ids", "no rule IDs"),
        "_both": (_fails_test, ":" + s + "_both", "in both leaks and clean"),
    }
    for suffix, (rule, target, message) in tests.items():
        if message:
            rule(name = name + suffix, target_under_test = target, message = message, tags = ["no-gitleaks"])
        else:
            rule(name = name + suffix, target_under_test = target, tags = ["no-gitleaks"])
    native.test_suite(name = name, tests = [":" + name + t for t in tests])
