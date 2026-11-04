"""gitleaks binary pins.

One release tarball per platform from gitleaks/gitleaks, holding the
single `gitleaks` binary:

    https://github.com/gitleaks/gitleaks/releases/download/v<ver>/gitleaks_<ver>_<os>_<arch>.tar.gz

(upstream names amd64 `x64`). SHA-256s are the release's published
`gitleaks_<ver>_checksums.txt`. Maintainer flow:

    tools/update_checksums.sh <ver>     # add / re-pin <ver> from the checksums file
    tools/update_checksums.sh --check   # verify every pin, no writes

//tests:checksums_test fails on an empty or malformed value.
"""

# The version the `gitleaks` extension fetches when the root module names none.
DEFAULT_VERSION = "8.30.1"

GITLEAKS_VERSIONS = {
    "8.30.1": {
        "linux_amd64": {
            "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
            "sha256": "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        },
        "linux_arm64": {
            "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_arm64.tar.gz",
            "sha256": "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
        },
        "darwin_amd64": {
            "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_x64.tar.gz",
            "sha256": "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
        },
        "darwin_arm64": {
            "url": "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_darwin_arm64.tar.gz",
            "sha256": "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
        },
    },
}

PLATFORMS = {
    "linux_amd64":  ["@platforms//os:linux", "@platforms//cpu:x86_64"],
    "linux_arm64":  ["@platforms//os:linux", "@platforms//cpu:arm64"],
    "darwin_amd64": ["@platforms//os:osx",   "@platforms//cpu:x86_64"],
    "darwin_arm64": ["@platforms//os:osx",   "@platforms//cpu:arm64"],
}
