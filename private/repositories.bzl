"""Per-platform gitleaks repo: downloads the release tarball at the pinned
sha and declares the platform's toolchain implementation, so the repo
name (`gitleaks_<platform>`) doesn't change with the version.
"""

load(":versions.bzl", "GITLEAKS_VERSIONS")

_BUILD = """\
load("{toolchain_bzl}", "gitleaks_toolchain")

package(default_visibility = ["//visibility:public"])

exports_files(["gitleaks"])

gitleaks_toolchain(
    name = "toolchain_impl",
    version = "{version}",
    gitleaks = "gitleaks",
)
"""

def _impl(rctx):
    version = rctx.attr.version
    platform = rctx.attr.platform
    if version not in GITLEAKS_VERSIONS:
        fail("rules_gitleaks: unknown gitleaks version '{}'. Known: {} ".format(
            version,
            sorted(GITLEAKS_VERSIONS.keys()),
        ) + "(add one with tools/update_checksums.sh <version>)")
    pin = GITLEAKS_VERSIONS[version].get(platform)
    if not pin:
        fail("rules_gitleaks: platform '{}' missing for version {}".format(platform, version))

    rctx.download_and_extract(url = pin["url"], sha256 = pin["sha256"])
    rctx.file("BUILD.bazel", _BUILD.format(
        toolchain_bzl = str(Label("//toolchain:toolchain.bzl")),
        version = version,
    ))

gitleaks_binary_repo = repository_rule(
    implementation = _impl,
    attrs = {
        "version":  attr.string(mandatory = True),
        "platform": attr.string(mandatory = True),
    },
)
