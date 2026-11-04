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
        inputs = [ctx.file.src, ctx.file._driver, gl.gitleaks],
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
    },
    toolchains = [TOOLCHAIN],
)
