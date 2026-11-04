"""gitleaks_scan — `bazel run` target that scans the workspace.

    bazel run //:gitleaks                      # the working tree (`gitleaks dir .`)
    bazel run //:gitleaks_history              # mode = "git": every commit (needs git)
    bazel run //:gitleaks -- --report-path=gitleaks-baseline.json --exit-code=0
    bazel run //:gitleaks_tracked              # tracked_only: what `git ls-files` lists

It runs in the workspace root with the given config, so paths and
fingerprints match gitleaks_test's. Symlinks (bazel-* included) are not
followed. Without `ignore`, gitleaks reads ./.gitleaksignore if present.
Arguments after `--` go to gitleaks; relative paths are relative to the
workspace root.

With `tracked_only = True` (dir mode) only the files in the git index
(`git ls-files`: committed plus staged) are scanned, their working-tree
content staged under their workspace paths as gitleaks_test does, so
gitignored files (.env.local, worktrees) are skipped. Outside a git
checkout it fails, saying so. Reports then come from the driver:
`-- --json=PATH --sarif=PATH --junit=PATH`; other arguments go to gitleaks.
"""

load(":common.bzl", "TOOLCHAIN", "check_redact", _label_text = "label_text")
load(":providers.bzl", "GitleaksConfigInfo")

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def _gitleaks_scan_impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    check_redact(ctx.label, ctx.attr.redact)
    if ctx.attr.tracked_only and ctx.attr.mode != "dir":
        fail("{}: tracked_only applies to mode = \"dir\"; mode = \"git\" already scans only what git has.".format(ctx.label))
    config = ctx.attr.config[GitleaksConfigInfo].config
    lines, files = [], [gl.gitleaks, config, ctx.file._driver]
    tracked = ctx.attr.tracked_only
    for flag, f in (("--ignore" if tracked else "--gitleaks-ignore-path", ctx.file.ignore),
                    ("--baseline" if tracked else "--baseline-path", ctx.file.baseline)):
        if f:
            lines.append("p=\"$(resolve {})\"; opts+=({} \"$p\")".format(_shell_quote(f.short_path), flag))
            files.append(f)
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = out,
        substitutions = {
            "__GITLEAKS__": gl.gitleaks.short_path,
            "__DRIVER__": ctx.file._driver.short_path,
            "__TRACKED__": "1" if tracked else "",
            "__LABEL__": _label_text(ctx.label),
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
        "tracked_only": attr.bool(
            doc = "Scan only the files git tracks (`git ls-files`: committed plus staged), " +
                  "skipping gitignored ones. dir mode only; needs git and a checkout.",
        ),
        "_driver": attr.label(default = "//private:gitleaks.py", allow_single_file = True),
        "_tmpl": attr.label(default = "//private:scan.sh.tmpl", allow_single_file = True),
    },
    toolchains = [TOOLCHAIN],
)
