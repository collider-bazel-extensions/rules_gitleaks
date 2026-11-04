"""gitleaks_workspace_test — scans the live checkout as a test.

Tests normally see only declared inputs, in a sandbox with no git
checkout. This test is the exception: it's tagged `local`, `external`
and `no-sandbox`, so it's never cached or sandboxed, and it reads the
workspace directly. It finds it from `$BUILD_WORKSPACE_DIRECTORY` if set,
else by resolving its `marker` runfile (default `//:MODULE.bazel`) to the
real file and taking the nearest directory above it with a MODULE.bazel.

With `tracked_only = True` (the default) it scans the files in the git
index (`git ls-files`: committed plus staged), so gitignored files such as
`.env.local` or `.claude/worktrees/` can't fail it. Outside a git checkout
(e.g. a source archive) it fails, saying so. With `tracked_only = False`
it scans the whole working tree, skipping `.git` and symlinks (bazel-*).

Findings, fingerprints and reports are as for gitleaks_test; without
`ignore`, the workspace's `.gitleaksignore` is used if present.
"""

load(":common.bzl", "SCAN_ATTRS", "TOOLCHAIN", "label_text", "scan_args")

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def _impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    opts, inputs = scan_args(ctx, True)
    args = ["--gitleaks", gl.gitleaks.short_path, "--label", label_text(ctx.label)] + opts
    if ctx.attr.tracked_only:
        args.append("--tracked-only")
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = out,
        substitutions = {
            "__DRIVER__": ctx.file._driver.short_path,
            "__MARKER__": ctx.file.marker.short_path,
            "__ARGS__": " ".join([_shell_quote(a) for a in args]),
            "__SARIF__": "1" if ctx.attr.sarif else "",
            "__EXTRA__": " ".join([_shell_quote(a) for a in ctx.attr.extra_args]),
        },
        is_executable = True,
    )
    runfiles = ctx.runfiles(files = [out, ctx.file._driver, gl.gitleaks, ctx.file.marker] + inputs)
    return [DefaultInfo(executable = out, runfiles = runfiles)]

_gitleaks_workspace_test = rule(
    implementation = _impl,
    test = True,
    attrs = dict(SCAN_ATTRS, **{
        "marker": attr.label(
            mandatory = True,
            allow_single_file = True,
            doc = "A source file in the workspace (resolved to find it).",
        ),
        "tracked_only": attr.bool(default = True),
        "sarif": attr.bool(),
        "_tmpl": attr.label(default = "//private:workspace_test.sh.tmpl", allow_single_file = True),
    }),
    toolchains = [TOOLCHAIN],
)

def gitleaks_workspace_test(name, marker = "//:MODULE.bazel", tracked_only = True, tags = None, **kwargs):
    """Scans the live workspace checkout (uncached; see the module docstring).

    Args:
      name: target name.
      marker: a source file of the workspace, resolved to locate it.
        Default `//:MODULE.bazel` of the calling repository (with
        --incompatible_no_implicit_file_export it needs
        exports_files(["MODULE.bazel"]) in the root BUILD file).
      tracked_only: scan only `git ls-files` (default), or the whole tree.
      tags: extra tags; `local`, `external` and `no-sandbox` are always added.
      **kwargs: config, ignore, baseline, redact, enable_rules, extra_args,
        sarif, size, timeout, ...
    """
    tags = list(tags or [])
    for t in ("local", "external", "no-sandbox"):
        if t not in tags:
            tags.append(t)
    _gitleaks_workspace_test(
        name = name,
        marker = marker,
        tracked_only = tracked_only,
        tags = tags,
        **kwargs
    )
