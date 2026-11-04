#!/usr/bin/env python3
"""Runs gitleaks for rules_gitleaks. Standard library only.

  gitleaks.py check-config --gitleaks BIN --config FILE --label L --marker OUT
      gitleaks_config's validation action. Loads the config the way a scan
      does (TOML, rule regexes, allowlists) by scanning an empty directory,
      and checks every key against gitleaks' config schema (gitleaks itself
      ignores unknown keys, so a typo such as `pathss` in an allowlist
      silently disables it). `[extend] path` / `url` are refused: the
      first can't be staged reliably, the second fetches at scan time.

  gitleaks.py scan --gitleaks BIN --config FILE --label L --manifest M
                   [--runfiles] [--ignore F] [--baseline F] [--redact N]
                   [--enable-rule ID]... [--json OUT] [--junit OUT]
                   [--sarif OUT] [--marker OUT] [-- EXTRA...]
      gitleaks_test / gitleaks_check / gitleaks_aspect. M lists
      "<workspace path>\t<file>" lines. Each file (or every file under a
      directory) is staged as a real file, hard-linked or copied, under its
      workspace path. That matters: `gitleaks dir` skips symlinks unless
      told to follow them, and then reports the link's target, so a scan
      of Bazel's symlinked inputs would either see nothing or report
      sandbox paths. Findings therefore name workspace paths, and their
      fingerprints (`<path>:<rule>:<line>`) match a .gitleaksignore written
      for the repository. Exits 0 when clean, 1 on leaks (after printing
      them), 2 if gitleaks itself failed.

  gitleaks.py rule-test --gitleaks BIN --config FILE --label L --manifest M
                        [--junit OUT]
      gitleaks_rule_test. M lists "<workspace path>\t<file>\t<rule ids>"
      lines; an empty rule-id list means the file must be clean. Every file
      must produce exactly the listed rule IDs.

With --runfiles, manifest files are runfiles paths (short paths), resolved
against $RUNFILES_DIR / $TEST_SRCDIR; otherwise they are relative to the
working directory (an action's exec root).
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape, quoteattr

LEAKS_EXIT = 3  # --exit-code: tells leaks apart from gitleaks' own errors (1, 2)


def _log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---- config schema ------------------------------------------------------------
# From gitleaks' config.ViperConfig (v8). Keys are case-insensitive (viper).

_ALLOWLIST = {"description", "condition", "commits", "paths", "regextarget",
              "regexes", "stopwords"}
_GLOBAL_ALLOWLIST = _ALLOWLIST | {"targetrules"}
_RULE = {"id", "description", "path", "regex", "secretgroup", "entropy",
         "keywords", "tags", "allowlist", "allowlists", "required", "skipreport"}
_REQUIRED = {"id", "withinlines", "withincolumns"}
_EXTEND = {"path", "url", "usedefault", "disabledrules"}
_TOP = {"title", "description", "extend", "rules", "allowlist", "allowlists",
        "minversion"}


def schema_errors(doc):
    errs = []

    def keys(where, table, allowed):
        if not isinstance(table, dict):
            errs.append(f"{where}: expected a table")
            return
        for k in table:
            if k.lower() not in allowed:
                errs.append(f"{where}: unknown key {k!r} (known: {', '.join(sorted(allowed))})")

    def tables(where, value):
        if isinstance(value, dict):
            return [(where, value)]
        if isinstance(value, list):
            return [(f"{where}[{i}]", v) for i, v in enumerate(value)]
        errs.append(f"{where}: expected a table or an array of tables")
        return []

    keys("top level", doc, _TOP)
    low = {k.lower(): v for k, v in doc.items()}
    if "extend" in low:
        ext = low["extend"]
        keys("[extend]", ext, _EXTEND)
        if isinstance(ext, dict):
            for k in ext:
                if k.lower() in ("path", "url"):
                    errs.append(f"[extend] {k}: not supported by rules_gitleaks (it can't be "
                                f"staged or fetched hermetically); use useDefault = true, or "
                                f"merge the rules into this file")
    for name in ("allowlist", "allowlists"):
        if name in low:
            for where, t in tables(f"[{name}]", low[name]):
                keys(where, t, _GLOBAL_ALLOWLIST)
    for i, rule in enumerate(low.get("rules", []) if isinstance(low.get("rules"), list) else []):
        rid = rule.get("id", f"#{i}") if isinstance(rule, dict) else f"#{i}"
        where = f"rule {rid!r}"
        keys(where, rule, _RULE)
        if not isinstance(rule, dict):
            continue
        rlow = {k.lower(): v for k, v in rule.items()}
        for name in ("allowlist", "allowlists"):
            if name in rlow:
                for w, t in tables(f"{where} {name}", rlow[name]):
                    keys(w, t, _ALLOWLIST)
        if "required" in rlow:
            for w, t in tables(f"{where} required", rlow["required"]):
                keys(w, t, _REQUIRED)
    return errs


def _gitleaks_error(text):
    """The useful part of gitleaks' error output (a bad regex panics with a
    long Go stack trace)."""
    lines = [l for l in text.splitlines()
             if l.strip() and not l.startswith("WARNING: All log messages before absl")]
    keep = [l for l in lines if any(m in l for m in (
        "FTL", "ERR", "panic:", "error parsing", "Error parsing", "unable to", "Failed"))]
    return "\n".join("  " + l for l in (keep or lines[-15:])[:15])


def _run(cmd, cwd=None):
    env = {k: v for k, v in os.environ.items()
           if k not in ("GITLEAKS_CONFIG", "GITLEAKS_CONFIG_TOML")}
    env["NO_COLOR"] = "1"
    return subprocess.run(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, errors="replace")


def check_config(args):
    errs = []
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        tomllib = None
    if tomllib is not None:
        try:
            with open(args.config, "rb") as f:
                doc = tomllib.load(f)
        except tomllib.TOMLDecodeError as e:
            errs.append(f"not valid TOML: {e}")
        else:
            errs += schema_errors(doc)
    if not errs:
        empty = tempfile.mkdtemp(prefix="gitleaks-check-")
        try:
            p = _run([args.gitleaks, "dir", empty, "--no-banner", "--no-color",
                      "--log-level", "error", "--exit-code", str(LEAKS_EXIT),
                      "--config", os.path.abspath(args.config),
                      "--gitleaks-ignore-path", os.devnull])
        finally:
            shutil.rmtree(empty, ignore_errors=True)
        if p.returncode not in (0, LEAKS_EXIT):
            errs.append("gitleaks refused it:\n" + _gitleaks_error(p.stdout))
    if errs:
        _log(f"gitleaks_config {args.label}: " + "\n  ".join(errs))
        return 1
    with open(args.marker, "w") as f:
        f.write("ok\n" if tomllib else "ok (no key check: needs Python 3.11+)\n")
    return 0


# ---- staging ------------------------------------------------------------------


def _resolve(path, runfiles):
    if not runfiles:
        return path
    root = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    if not root:
        raise SystemExit("gitleaks: no RUNFILES_DIR / TEST_SRCDIR")
    cands = [os.path.join(root, "_main", path), os.path.join(root, path)]
    if path.startswith("../"):
        cands.append(os.path.join(root, path[3:]))
    for c in cands:
        if os.path.exists(c):
            return c
    raise SystemExit(f"gitleaks: not in runfiles: {path}")


def _place(src, dest):
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    real = os.path.realpath(src)
    try:
        os.link(real, dest)
    except OSError:
        shutil.copyfile(real, dest)


def stage(manifest, runfiles, root):
    """Stages manifest entries under root. Returns {workspace path: extra}."""
    os.makedirs(root, exist_ok=True)
    entries = {}
    with open(manifest) as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("\t")
            dest, src = parts[0], parts[1]
            entries[dest] = parts[2] if len(parts) > 2 else None
            src = _resolve(src, runfiles)
            target = os.path.join(root, dest)
            if os.path.isdir(src):
                for d, _, files in os.walk(src, followlinks=True):
                    for name in files:
                        p = os.path.join(d, name)
                        _place(p, os.path.join(target, os.path.relpath(p, src)))
            elif os.path.exists(target):
                continue  # listed twice
            else:
                _place(src, target)
    return entries


def _gitleaks_scan(args, root, report_format, report_path):
    cmd = [args.gitleaks, "dir", ".", "--no-banner", "--no-color",
           "--log-level", "warn", "--exit-code", str(LEAKS_EXIT),
           "--config", os.path.abspath(args.config),
           "--report-format", report_format, "--report-path", report_path,
           f"--redact={args.redact}"]
    # Always explicit: the default (".") would read a .gitleaksignore from
    # the working directory, and a directory path is silently ignored.
    cmd += ["--gitleaks-ignore-path", os.path.abspath(args.ignore) if args.ignore else os.devnull]
    if args.baseline:
        cmd += ["--baseline-path", os.path.abspath(args.baseline)]
    for r in args.enable_rule or []:
        cmd += ["--enable-rule", r]
    return _run(cmd + list(args.extra), cwd=root)


def _junit(path, suite, cases):
    """cases: [(name, failure message or None)]."""
    fails = sum(1 for _, m in cases if m)
    out = ['<?xml version="1.0" encoding="UTF-8"?>',
           f'<testsuites><testsuite name={quoteattr(suite)} tests="{len(cases)}" failures="{fails}">']
    for name, msg in cases:
        if msg:
            out.append(f"<testcase name={quoteattr(name)}><failure message={quoteattr(msg.splitlines()[0])}>"
                       f"{escape(msg)}</failure></testcase>")
        else:
            out.append(f"<testcase name={quoteattr(name)}/>")
    out.append("</testsuite></testsuites>")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")


def _findings(report):
    with open(report) as f:
        return json.load(f) or []


def scan(args):
    work = tempfile.mkdtemp(prefix="gitleaks-")
    # Reports live next to the staged tree, not in it, so a second pass
    # (SARIF) doesn't scan the first one's report.
    root, report = os.path.join(work, "src"), os.path.join(work, "report.json")
    try:
        entries = stage(args.manifest, args.runfiles, root)
        p = _gitleaks_scan(args, root, "json", report)
        if p.returncode not in (0, LEAKS_EXIT):
            _log(f"gitleaks {args.label}: gitleaks failed (exit {p.returncode}):\n" + _gitleaks_error(p.stdout))
            return 2
        found = _findings(report) if os.path.exists(report) else []
        if args.json:
            with open(args.json, "w") as f:
                json.dump(found, f, indent=1)
        if args.sarif:
            sarif = os.path.join(work, "report.sarif")
            _gitleaks_scan(args, root, "sarif", sarif)
            shutil.copyfile(sarif, args.sarif)
        if args.junit:
            cases = [(f"{f['File']}:{f['StartLine']} {f['RuleID']}",
                      f"{f['Description']}\nfingerprint: {f['Fingerprint']}\nmatch: {f['Match']}")
                     for f in found] or [(f"no leaks in {len(entries)} inputs", None)]
            _junit(args.junit, f"gitleaks {args.label}", cases)
        if not found:
            if args.marker:
                with open(args.marker, "w") as f:
                    f.write(f"no leaks in {len(entries)} inputs\n")
            return 0
        files = sorted({f["File"] for f in found})
        lines = [f"gitleaks {args.label}: {len(found)} leak(s) in {len(files)} file(s):"]
        for f in sorted(found, key=lambda f: (f["File"], f["StartLine"], f["RuleID"])):
            lines.append(f"  {f['File']}:{f['StartLine']}  {f['RuleID']}  {f['Match'].strip()[:120]}")
            lines.append(f"      fingerprint: {f['Fingerprint']}")
        lines.append("A real secret must be removed and rotated. To accept a false positive, add its "
                     "fingerprint to the .gitleaksignore given as `ignore`, or put "
                     "`gitleaks:allow` in a comment on that line.")
        _log("\n".join(lines))
        return 1
    finally:
        shutil.rmtree(work, ignore_errors=True)


def rule_test(args):
    work = tempfile.mkdtemp(prefix="gitleaks-rules-")
    root, report = os.path.join(work, "src"), os.path.join(work, "report.json")
    try:
        entries = stage(args.manifest, args.runfiles, root)
        args.ignore, args.baseline, args.enable_rule = None, None, []
        p = _gitleaks_scan(args, root, "json", report)
        if p.returncode not in (0, LEAKS_EXIT):
            _log(f"gitleaks_rule_test {args.label}: gitleaks failed (exit {p.returncode}):\n"
                 + _gitleaks_error(p.stdout))
            return 2
        got = {}
        for f in _findings(report) if os.path.exists(report) else []:
            got.setdefault(f["File"], {}).setdefault(f["RuleID"], []).append(f["StartLine"])
        cases, failed = [], 0
        for path, expected in sorted(entries.items()):
            want = {r for r in (expected or "").split(",") if r}
            have = got.get(path, {})
            missing, extra = sorted(want - set(have)), sorted(set(have) - want)
            msg = None
            if missing or extra:
                failed += 1
                parts = []
                if missing:
                    parts.append("expected but not found: " + ", ".join(missing))
                if extra:
                    parts.append("found but not expected: " + ", ".join(
                        f"{r} (line {', '.join(map(str, sorted(have[r])))})" for r in extra))
                msg = "; ".join(parts)
            label = "clean" if not want else ", ".join(sorted(want))
            cases.append((f"{path} [{label}]", msg))
            print(f"{'FAIL' if msg else 'ok  '} {path}: {msg or ('no leaks' if not want else 'found ' + label)}")
        if args.junit:
            _junit(args.junit, f"gitleaks_rule_test {args.label}", cases)
        if failed:
            _log(f"gitleaks_rule_test {args.label}: {failed} of {len(cases)} case(s) failed")
            return 1
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv):
    p = argparse.ArgumentParser(prog="gitleaks.py", fromfile_prefix_chars="@")
    sub = p.add_subparsers(dest="mode", required=True)
    for mode in ("check-config", "scan", "rule-test"):
        s = sub.add_parser(mode, fromfile_prefix_chars="@")
        s.add_argument("--gitleaks", required=True)
        s.add_argument("--config", required=True)
        s.add_argument("--label", default="")
        if mode == "check-config":
            s.add_argument("--marker", required=True)
            continue
        s.add_argument("--manifest", required=True)
        s.add_argument("--runfiles", action="store_true")
        s.add_argument("--redact", type=int, default=100)
        s.add_argument("--junit")
        if mode == "scan":
            s.add_argument("--ignore")
            s.add_argument("--baseline")
            s.add_argument("--enable-rule", action="append")
            s.add_argument("--json")
            s.add_argument("--sarif")
            s.add_argument("--marker")
        s.add_argument("extra", nargs="*")
    args = p.parse_args(argv)
    if args.mode == "check-config":
        return check_config(args)
    # Absolute: the scan runs with the staged tree as its working directory.
    for name in ("gitleaks", "config", "ignore", "baseline", "manifest"):
        if getattr(args, name, None):
            setattr(args, name, os.path.abspath(_resolve(getattr(args, name), args.runfiles)))
    return scan(args) if args.mode == "scan" else rule_test(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
