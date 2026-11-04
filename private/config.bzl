"""gitleaks_config — a .gitleaks.toml checked at build time.

The validation action loads the config the way a scan does (TOML, rule
regexes, allowlists) and checks every key against gitleaks' config schema,
so a bad regex, a missing rule id or a typo such as `pathss` in an
allowlist (which gitleaks itself would silently ignore) fails
`bazel build`, e.g.

    gitleaks_config //:gitleaks: rule 'corp-token' allowlists[0]: unknown key 'pathss'
"""

load(":common.bzl", "TOOLCHAIN", "label_text")
load(":providers.bzl", "GitleaksConfigInfo")

def _gitleaks_config_impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    marker = ctx.actions.declare_file(ctx.label.name + ".checked")
    args = ctx.actions.args()
    args.add(ctx.file._driver)
    args.add("check-config")
    args.add("--gitleaks", gl.gitleaks)
    args.add("--config", ctx.file.src)
    args.add("--label", label_text(ctx.label))
    args.add("--marker", marker)
    ctx.actions.run_shell(
        command = 'exec python3 "$@"',
        arguments = [args],
        inputs = [ctx.file.src, ctx.file._driver, gl.gitleaks] + ctx.files._tomli,
        outputs = [marker],
        # python3 from the user's PATH, as for the test-time scans.
        use_default_shell_env = True,
        mnemonic = "GitleaksCheckConfig",
        progress_message = "Checking gitleaks config %{label}",
    )
    return [
        DefaultInfo(files = depset([ctx.file.src])),
        GitleaksConfigInfo(config = ctx.file.src),
        OutputGroupInfo(_validation = depset([marker])),
    ]

gitleaks_config = rule(
    implementation = _gitleaks_config_impl,
    doc = "A gitleaks config, loaded by gitleaks and schema-checked on every build.",
    attrs = {
        "src": attr.label(
            mandatory = True,
            allow_single_file = [".toml"],
            doc = "The config (`.gitleaks.toml`). `[extend] useDefault = true` " +
                  "adds gitleaks' built-in rules; `[extend] path` / `url` are refused.",
        ),
        "_driver": attr.label(default = "//private:gitleaks.py", allow_single_file = True),
        "_tomli": attr.label(default = "//private/third_party:tomli"),
    },
    toolchains = [TOOLCHAIN],
)

# ---- gitleaks_config_test -------------------------------------------------------

def _gitleaks_config_test_impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    driver = ctx.file._driver.short_path
    args = ["--gitleaks", gl.gitleaks.short_path, "--config", ctx.file.src.short_path,
            "--label", ctx.file.src.short_path]
    if ctx.attr.expect_error:
        args += ["--expect-error", ctx.attr.expect_error]
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = out,
        substitutions = {
            "__DRIVER__": driver,
            "__DRIVER_EXT__": driver[3:] if driver.startswith("../") else driver,
            "__MODE__": "config-test",
            "__ARGS__": " ".join([_shell_quote(a) for a in args]),
            "__REPORTS__": "",
            "__EXTRA__": "",
        },
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [out, ctx.file._driver, gl.gitleaks, ctx.file.src] + ctx.files._tomli)
    return [
        DefaultInfo(executable = out, runfiles = runfiles),
        RunEnvironmentInfo(environment = ctx.attr.env),
    ]

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

gitleaks_config_test = rule(
    implementation = _gitleaks_config_test_impl,
    test = True,
    doc = """\
Runs gitleaks_config's check on `src` as a test. With `expect_error`
(a Python regex), the check must fail with a matching message; without
it, it must pass. For showing that a broken config is caught — a
gitleaks_config target of it would fail the build instead.
""",
    attrs = {
        "src": attr.label(
            mandatory = True,
            allow_single_file = [".toml"],
            doc = "The config file (a .toml, not a gitleaks_config target).",
        ),
        "env": attr.string_dict(
            doc = "Environment for the test, e.g. {\"RULES_GITLEAKS_VENDORED_TOML\": \"1\"} " +
                  "to force the vendored TOML parser.",
        ),
        "expect_error": attr.string(
            doc = "Python regex the check's message must match (re.search). " +
                  "Empty: the check must pass.",
        ),
        "_driver": attr.label(default = "//private:gitleaks.py", allow_single_file = True),
        "_tomli": attr.label(default = "//private/third_party:tomli"),
        "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
    },
    toolchains = [TOOLCHAIN],
)
