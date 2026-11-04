"""gitleaks_aspect — scans every target's own files, incrementally.

    bazel build //... --aspects=@rules_gitleaks//:defs.bzl%gitleaks_aspect

Each target in the main repository gets one scan of the files in its
`srcs`, `hdrs`, `textual_hdrs`, `data`, `resources`, `src` and `template`
attributes (source and generated files; external repositories' files are
skipped). The scan is a validation action, so leaks fail the build; the
reports are in the `gitleaks` output group. Only targets whose files
changed are scanned again. Tag a target `no-gitleaks` to skip it.

The config and ignore file come from label flags:

    --@rules_gitleaks//:aspect_config=//:gitleaks_config
    --@rules_gitleaks//:aspect_ignore=//:.gitleaksignore
"""

load(":common.bzl", "TOOLCHAIN", "label_text", "manifest_line")
load(":providers.bzl", "GitleaksConfigInfo")

_FILE_ATTRS = ["srcs", "hdrs", "textual_hdrs", "data", "resources", "src", "template"]

def _gitleaks_aspect_impl(target, ctx):
    if ctx.label.workspace_name or "no-gitleaks" in ctx.rule.attr.tags:
        return []
    files = {}
    for name in _FILE_ATTRS:
        for f in getattr(ctx.rule.files, name, []) or []:
            if not f.owner or not f.owner.workspace_name:
                files[f.path] = f
    if not files:
        return []
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    config = ctx.attr._config[GitleaksConfigInfo].config
    ignore = ctx.files._ignore
    manifest = ctx.actions.declare_file(ctx.label.name + ".gitleaks_aspect_manifest")
    ctx.actions.write(manifest, "\n".join([manifest_line(f, False) for f in files.values()]) + "\n")
    report = ctx.actions.declare_file(ctx.label.name + ".gitleaks_aspect.json")
    args = ctx.actions.args()
    args.add(ctx.file._driver)
    args.add("scan")
    args.add_all(["--gitleaks", gl.gitleaks, "--label", label_text(ctx.label),
                  "--manifest", manifest, "--json", report, "--config", config])
    if ignore:
        args.add("--ignore", ignore[0])
    ctx.actions.run_shell(
        command = 'exec python3 "$@"',
        arguments = [args],
        inputs = [ctx.file._driver, gl.gitleaks, manifest, config] + ignore + files.values(),
        outputs = [report],
        use_default_shell_env = True,
        mnemonic = "GitleaksScan",
        progress_message = "Scanning %{label} for secrets",
    )
    return [OutputGroupInfo(_validation = depset([report]), gitleaks = depset([report]))]

gitleaks_aspect = aspect(
    implementation = _gitleaks_aspect_impl,
    doc = "Scans each target's own files with gitleaks; leaks fail the build.",
    attrs = {
        "_config": attr.label(default = "//:aspect_config", providers = [GitleaksConfigInfo]),
        "_ignore": attr.label(default = "//:aspect_ignore", allow_files = True),
        "_driver": attr.label(default = "//private:gitleaks.py", allow_single_file = True),
    },
    toolchains = [TOOLCHAIN],
)
