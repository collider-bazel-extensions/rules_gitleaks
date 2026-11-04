"""gitleaks_check — the gitleaks_test scan as a validation action, so leaks
fail `bazel build`. Meant for generated artifacts (rendered manifests,
packaged configs, images' file trees) that should never carry a secret.

The JSON report is in the `gitleaks` output group.
"""

load(":common.bzl", "SCAN_ATTRS", "TOOLCHAIN", "label_text", "manifest_line", "scan_args")

def _gitleaks_check_impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    files = ctx.files.srcs
    if not files:
        fail("{}: srcs is empty: nothing to scan.".format(ctx.label))
    manifest = ctx.actions.declare_file(ctx.label.name + ".gitleaks_manifest")
    ctx.actions.write(manifest, "\n".join([manifest_line(f, False) for f in files]) + "\n")
    report = ctx.actions.declare_file(ctx.label.name + ".gitleaks.json")
    opts, inputs = scan_args(ctx, False)
    args = ctx.actions.args()
    args.add(ctx.file._driver)
    args.add("scan")
    args.add_all(["--gitleaks", gl.gitleaks, "--label", label_text(ctx.label),
                  "--manifest", manifest, "--json", report])
    args.add_all(opts)
    args.add("--")
    args.add_all(ctx.attr.extra_args)
    ctx.actions.run_shell(
        command = 'exec python3 "$@"',
        arguments = [args],
        inputs = [ctx.file._driver, gl.gitleaks, manifest] + inputs + files,
        outputs = [report],
        use_default_shell_env = True,
        mnemonic = "GitleaksScan",
        progress_message = "Scanning %{label} for secrets",
    )
    return [
        DefaultInfo(files = depset()),
        OutputGroupInfo(_validation = depset([report]), gitleaks = depset([report])),
    ]

gitleaks_check = rule(
    implementation = _gitleaks_check_impl,
    doc = "Fails `bazel build` if gitleaks finds secrets in `srcs`.",
    attrs = dict(SCAN_ATTRS, **{
        "srcs": attr.label_list(
            allow_files = True,
            doc = "Files to scan, typically generated ones.",
        ),
    }),
    toolchains = [TOOLCHAIN],
)
