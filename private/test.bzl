"""gitleaks_test and gitleaks_rule_test — test rules.

gitleaks_test scans files and targets' outputs (generated files and tree
artifacts included). Each is staged as a real file under its workspace
path, so findings and fingerprints name `pkg/file`, as a .gitleaksignore
written for the repository expects. Leaks fail the test, listed with
their fingerprints (secrets redacted). The test writes JUnit to
$XML_OUTPUT_FILE and the gitleaks JSON report (plus SARIF with
`sarif = True`) to its undeclared outputs (bazel-testlogs/.../test.outputs).

gitleaks_rule_test runs a config's rules over sample files and checks
each file produces exactly the expected rule IDs — unit tests for custom
rules and allowlists.
"""

load(":common.bzl", "SCAN_ATTRS", "TOOLCHAIN", "label_text", "manifest_line", "scan_args")
load(":providers.bzl", "GitleaksConfigInfo")

def _shell_quote(s):
    return "'" + s.replace("'", "'\\''") + "'"

def _wrapper(ctx, mode, args, reports, extra):
    driver = ctx.file._driver.short_path
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file._tmpl,
        output = out,
        substitutions = {
            "__DRIVER__": driver,
            "__DRIVER_EXT__": driver[3:] if driver.startswith("../") else driver,
            "__MODE__": mode,
            "__ARGS__": " ".join([_shell_quote(a) for a in args]),
            "__REPORTS__": "\n".join(reports),
            "__EXTRA__": " ".join([_shell_quote(a) for a in extra]),
        },
        is_executable = True,
    )
    return out

def _gitleaks_test_impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    files = ctx.files.srcs
    if not files:
        fail("{}: srcs is empty: nothing to scan.".format(ctx.label))
    manifest = ctx.actions.declare_file(ctx.label.name + ".gitleaks_manifest")
    ctx.actions.write(manifest, "\n".join([manifest_line(f, True) for f in files]) + "\n")
    opts, inputs = scan_args(ctx, True)
    args = ["--gitleaks", gl.gitleaks.short_path, "--label", label_text(ctx.label),
            "--manifest", manifest.short_path] + opts
    reports = ['reports+=(--json "$out/gitleaks.json")']
    if ctx.attr.sarif:
        reports.append('reports+=(--sarif "$out/gitleaks.sarif")')
    wrapper = _wrapper(ctx, "scan", args, reports, ctx.attr.extra_args)
    runfiles = ctx.runfiles(files = [wrapper, ctx.file._driver, gl.gitleaks, manifest] + inputs + files)
    return [DefaultInfo(executable = wrapper, runfiles = runfiles)]

gitleaks_test = rule(
    implementation = _gitleaks_test_impl,
    test = True,
    doc = "Fails if gitleaks finds secrets in `srcs` (files, generated files, directories).",
    attrs = dict(SCAN_ATTRS, **{
        "srcs": attr.label_list(
            allow_files = True,
            doc = "Files to scan: source files, filegroups, or any target's " +
                  "outputs (e.g. rendered manifests, tree artifacts).",
        ),
        "sarif": attr.bool(
            doc = "Also write gitleaks.sarif to the test's undeclared outputs (a second pass).",
        ),
        "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
    }),
    toolchains = [TOOLCHAIN],
)

def _gitleaks_rule_test_impl(ctx):
    gl = ctx.toolchains[TOOLCHAIN].gitleaks
    lines, files, seen = [], [], {}
    for target, ids in ctx.attr.leaks.items():
        want = ",".join(sorted([i.strip() for i in ids.split(",") if i.strip()]))
        if not want:
            fail("{}: leaks[{}]: no rule IDs; list the files that must stay clean in `clean`.".format(
                ctx.label, target.label))
        for f in target.files.to_list():
            lines.append(manifest_line(f, True, want))
            files.append(f)
            seen[f.short_path] = True
    for f in ctx.files.clean:
        if f.short_path in seen:
            fail("{}: {} is in both leaks and clean.".format(ctx.label, f.short_path))
        lines.append(manifest_line(f, True, ""))
        files.append(f)
    if not files:
        fail("{}: no cases: give `leaks` and/or `clean`.".format(ctx.label))
    manifest = ctx.actions.declare_file(ctx.label.name + ".gitleaks_manifest")
    ctx.actions.write(manifest, "\n".join(lines) + "\n")
    config = ctx.attr.config[GitleaksConfigInfo].config
    args = ["--gitleaks", gl.gitleaks.short_path, "--label", label_text(ctx.label),
            "--manifest", manifest.short_path, "--config", config.short_path]
    wrapper = _wrapper(ctx, "rule-test", args, [], [])
    runfiles = ctx.runfiles(files = [wrapper, ctx.file._driver, gl.gitleaks, manifest, config] + files)
    return [DefaultInfo(executable = wrapper, runfiles = runfiles)]

gitleaks_rule_test = rule(
    implementation = _gitleaks_rule_test_impl,
    test = True,
    doc = "Checks a config's rules: each `leaks` file yields exactly its rule IDs, each `clean` file none.",
    attrs = {
        "config": attr.label(
            mandatory = True,
            providers = [GitleaksConfigInfo],
            doc = "The gitleaks_config under test.",
        ),
        "leaks": attr.label_keyed_string_dict(
            allow_files = True,
            doc = "Sample file → comma-separated rule IDs it must produce (exactly).",
        ),
        "clean": attr.label_list(
            allow_files = True,
            doc = "Sample files that must produce no findings (false-positive guards).",
        ),
        "_driver": attr.label(default = "//private:gitleaks.py", allow_single_file = True),
        "_tmpl": attr.label(default = "//private:run.sh.tmpl", allow_single_file = True),
    },
    toolchains = [TOOLCHAIN],
)
