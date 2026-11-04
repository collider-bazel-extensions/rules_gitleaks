"""Shared pieces of the gitleaks scanning rules."""

load(":providers.bzl", "GitleaksConfigInfo")

TOOLCHAIN = "//toolchain:gitleaks"

def workspace_path(f):
    """Where a file is staged for scanning: its workspace path
    (`external/<repo>/...` for files from other repositories)."""
    p = f.short_path
    return "external/" + p[3:] if p.startswith("../") else p

def manifest_line(f, runfiles, extra = None):
    src = f.short_path if runfiles else f.path
    return "\t".join([workspace_path(f), src] + ([extra] if extra != None else []))

def check_redact(label, redact):
    if redact < 0 or redact > 100:
        fail("{}: redact = {}: expected 0..100 (percent of each secret hidden).".format(label, redact))

# Attributes every scanning rule takes.
SCAN_ATTRS = {
    "config": attr.label(
        default = "//config:default",
        providers = [GitleaksConfigInfo],
        doc = "A gitleaks_config. Default: gitleaks' built-in rules.",
    ),
    "ignore": attr.label(
        allow_single_file = True,
        doc = "A .gitleaksignore: one finding fingerprint (`<path>:<rule>:<line>`) per line.",
    ),
    "baseline": attr.label(
        allow_single_file = [".json"],
        doc = "A gitleaks JSON report whose findings are ignored.",
    ),
    "redact": attr.int(
        default = 100,
        doc = "Percent of each secret hidden in output and reports (0..100).",
    ),
    "enable_rules": attr.string_list(
        doc = "Only these rule IDs (default: every rule in the config).",
    ),
    "extra_args": attr.string_list(
        doc = "Extra gitleaks arguments, e.g. [\"--max-decode-depth=2\"].",
    ),
    "_driver": attr.label(default = "//private:gitleaks.py", allow_single_file = True),
}

def scan_args(ctx, runfiles):
    """Driver options from SCAN_ATTRS -> (list of strings, list of input Files)."""
    check_redact(ctx.label, ctx.attr.redact)
    path = (lambda f: f.short_path) if runfiles else (lambda f: f.path)
    config = ctx.attr.config[GitleaksConfigInfo].config
    out = ["--config", path(config), "--redact", str(ctx.attr.redact)]
    inputs = [config]
    if ctx.file.ignore:
        out += ["--ignore", path(ctx.file.ignore)]
        inputs.append(ctx.file.ignore)
    if ctx.file.baseline:
        out += ["--baseline", path(ctx.file.baseline)]
        inputs.append(ctx.file.baseline)
    for r in ctx.attr.enable_rules:
        out += ["--enable-rule", r]
    return out, inputs

def label_text(label):
    s = str(label)
    return s[2:] if s.startswith("@@//") else s
