"""Test fixtures generated at build time (see make_fixture.sh)."""

def fixture(name, kind, out):
    native.genrule(
        name = name,
        outs = [out],
        cmd = "$(location //tests:make_fixture.sh) {} $@".format(kind),
        tools = ["//tests:make_fixture.sh"],
    )

def _tree_impl(ctx):
    out = ctx.actions.declare_directory(ctx.label.name)
    ctx.actions.run(
        executable = ctx.executable._gen,
        arguments = ["tree", out.path],
        outputs = [out],
    )
    return [DefaultInfo(files = depset([out]))]

fixture_tree = rule(
    implementation = _tree_impl,
    doc = "A tree artifact: readme.txt (clean) and nested/ci.env (a token).",
    attrs = {"_gen": attr.label(default = "//tests:make_fixture.sh", executable = True, cfg = "exec", allow_single_file = True)},
)

def _baseline_impl(ctx):
    """A gitleaks JSON report of `srcs`, for gitleaks_test(baseline = ...)."""
    gl = ctx.toolchains["//toolchain:gitleaks"].gitleaks
    config = ctx.file._config
    manifest = ctx.actions.declare_file(ctx.label.name + ".manifest")
    ctx.actions.write(manifest, "\n".join(["{}\t{}".format(f.short_path, f.path) for f in ctx.files.srcs]) + "\n")
    out = ctx.actions.declare_file(ctx.label.name + ".json")
    ctx.actions.run_shell(
        command = 'python3 "$@" || [ $? = 1 ]',  # leaks expected
        arguments = [ctx.file._driver.path, "scan", "--gitleaks", gl.gitleaks.path, "--config", config.path,
                     "--manifest", manifest.path, "--json", out.path],
        inputs = ctx.files.srcs + [manifest, config, ctx.file._driver, gl.gitleaks],
        outputs = [out],
        use_default_shell_env = True,
    )
    return [DefaultInfo(files = depset([out]))]

baseline = rule(
    implementation = _baseline_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "_config": attr.label(default = "//config:default.toml", allow_single_file = True),
        "_driver": attr.label(default = "//private:gitleaks.py", allow_single_file = True),
    },
    toolchains = ["//toolchain:gitleaks"],
)
