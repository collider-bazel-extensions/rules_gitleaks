"""gitleaks_toolchain — exposes the platform-resolved `gitleaks` binary
as a `ToolchainInfo`, so rules resolve it via
`ctx.toolchains["@rules_gitleaks//toolchain:gitleaks"]`.

`current_gitleaks_toolchain` forwards the resolved binary as a plain target
(files + runfiles) for `data = [...]` use in tests.
"""

load("//private:providers.bzl", "GitleaksBinaryInfo")

GITLEAKS_TOOLCHAIN_TYPE = Label("//toolchain:gitleaks")

def _toolchain_impl(ctx):
    info = GitleaksBinaryInfo(
        version = ctx.attr.version,
        gitleaks = ctx.file.gitleaks,
    )
    return [
        platform_common.ToolchainInfo(gitleaks = info),
        DefaultInfo(
            files = depset([ctx.file.gitleaks]),
            runfiles = ctx.runfiles(files = [ctx.file.gitleaks]),
        ),
    ]

gitleaks_toolchain = rule(
    implementation = _toolchain_impl,
    attrs = {
        "version": attr.string(mandatory = True),
        "gitleaks": attr.label(allow_single_file = True, mandatory = True),
    },
)

def _current_impl(ctx):
    info = ctx.toolchains[GITLEAKS_TOOLCHAIN_TYPE].gitleaks
    return [
        info,
        DefaultInfo(
            files = depset([info.gitleaks]),
            runfiles = ctx.runfiles(files = [info.gitleaks]),
        ),
    ]

current_gitleaks_toolchain = rule(
    implementation = _current_impl,
    toolchains = [GITLEAKS_TOOLCHAIN_TYPE],
    doc = "The resolved gitleaks binary, as files and runfiles.",
)
