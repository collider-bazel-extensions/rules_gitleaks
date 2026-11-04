"""Providers exposed by rules_gitleaks."""

GitleaksBinaryInfo = provider(
    doc = "The gitleaks toolchain binary.",
    fields = {
        "version":  "string — pinned gitleaks version",
        "gitleaks": "File — the gitleaks executable",
    },
)

GitleaksConfigInfo = provider(
    doc = "A gitleaks config checked at build time (gitleaks_config).",
    fields = {
        "config": "File — the .gitleaks.toml",
    },
)
