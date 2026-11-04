"""gitleaks_scan — `bazel run` target that scans the workspace.

    bazel run //:gitleaks                      # the working tree (`gitleaks dir .`)
    bazel run //:gitleaks_history              # mode = "git": every commit (needs git)
    bazel run //:gitleaks -- --report-path=gitleaks-baseline.json --exit-code=0

It runs in the workspace root with the given config, so paths and
fingerprints match gitleaks_test's. Symlinks (bazel-* included) are not
followed. Without `ignore`, gitleaks reads ./.gitleaksignore if present.
Arguments after `--` go to gitleaks; relative paths are relative to the
workspace root.
"""

load(":common.bzl", "TOOLCHAIN", "check_redact")
load(":providers.bzl", "GitleaksConfigInfo")

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def _gitleaks_scan_impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    check_redact(ctx.label, ctx.attr.redact)
    config = ctx.attr.config[GitleaksConfigInfo].config
    lines, files = [], [gl.gitleaks, config]
    for flag, f in (("--gitleaks-ignore-path", ctx.file.ignore), ("--baseline-path", ctx.file.baseline)):
        if f:
            lines.append("p=\"$(resolve {})\"; opts+=({} \"$p\")".format(_shell_quote(f.short_path), flag))
            files.append(f)
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = out,
        substitutions = {
            "__GITLEAKS__": gl.gitleaks.short_path,
            "__CONFIG__": config.short_path,
            "__OPTS__": "\n".join(lines),
            "__MODE__": ctx.attr.mode,
            "__REDACT__": str(ctx.attr.redact),
            "__EXTRA__": " ".join([_shell_quote(a) for a in ctx.attr.extra_args]),
        },
        is_executable = True,
    )
    return [DefaultInfo(executable = out, runfiles = ctx.runfiles(files = [out] + files))]

gitleaks_scan = rule(
    implementation = _gitleaks_scan_impl,
    executable = True,
    doc = "`bazel run` gitleaks over the workspace's working tree or git history.",
    attrs = {
        "mode": attr.string(
            default = "dir",
            values = ["dir", "git"],
            doc = "`dir`: the working tree. `git`: the repository's history (needs git on PATH).",
        ),
        "config": attr.label(
            default = "//config:default",
            providers = [GitleaksConfigInfo],
            doc = "A gitleaks_config.",
        ),
        "ignore": attr.label(allow_single_file = True, doc = "A .gitleaksignore (default: ./.gitleaksignore if present)."),
        "baseline": attr.label(allow_single_file = [".json"], doc = "A gitleaks JSON report to ignore."),
        "redact": attr.int(default = 100, doc = "Percent of each secret hidden (0..100)."),
        "extra_args": attr.string_list(doc = "Extra gitleaks arguments."),
        "_tmpl": attr.label(default = "//private:scan.sh.tmpl", allow_single_file = True),
    },
    toolchains = [TOOLCHAIN],
)
