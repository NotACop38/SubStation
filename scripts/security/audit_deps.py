#!/usr/bin/env python3
"""Audit Substation's locked dependency closure with pip-audit.

Why not bare ``pip-audit``? With no arguments pip-audit audits whatever happens
to be installed in the ambient interpreter — in a dev container that includes
dozens of OS/system packages Substation neither ships nor controls, so the gate
would fail on advisories that have nothing to do with the product. This script
audits exactly the hash-locked closure in ``requirements.lock`` after checking
that it satisfies the requirements declared in ``pyproject.toml`` (runtime
``dependencies`` + the ``dev`` extra), and applies a small, **documented**
ignore-list for advisories that are transitive, unfixed upstream, and
unreachable in our usage. A missing or drifted lock fails the gate.

Run: ``python scripts/security/audit_deps.py`` (invoked by ``make security``).
"""

from __future__ import annotations

import subprocess
import sys
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))
from scripts.security.lockfile import parse_lock

_PYPROJECT = _REPO_ROOT / "pyproject.toml"

# Advisories accepted with justification. Each entry MUST explain why it is safe
# to ignore for Substation specifically (not a blanket suppression).
#
#   id -> rationale
_IGNORED: dict[str, str] = {
    # diskcache is a *transitive* dependency of pySigma (its processing-pipeline
    # cache). The advisory is a pickle-deserialization RCE that requires an
    # attacker to already have WRITE access to the on-disk cache directory. It is
    # unfixed upstream (no release addresses it). Substation only uses pySigma to
    # PARSE rules (substation/detect/sigma_eval.py walks the parsed AST) and never
    # exercises the disk-cache code path — asserted by
    # tests/test_diskcache_unused.py. The Tier-1 build is local, single-user and
    # single-process, so the exploit precondition (a shared/untrusted cache dir)
    # does not hold. Re-evaluate if pySigma ships a fix or we start caching.
    "CVE-2025-69872": (
        "transitive (pysigma->diskcache); unfixed upstream; cache path unused "
        "(tests/test_diskcache_unused.py); local single-user build"
    ),
    "GHSA-w8v5-vhqr-4h9v": "same advisory as CVE-2025-69872 (GHSA alias)",
    "PYSEC-2025-69872": "same advisory as CVE-2025-69872 (PYSEC alias)",
}

# The committed, hash-locked closure this gate audits.
_LOCKFILE = _REPO_ROOT / "requirements.lock"


def _pinned_requirements() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    reqs: list[str] = list(project.get("dependencies", []))
    reqs += list(project.get("optional-dependencies", {}).get("dev", []))
    # Strip inline trailing comments / whitespace from each requirement line.
    return [r.split("#", 1)[0].strip() for r in reqs if r.split("#", 1)[0].strip()]


def _add_ignored(cmd: list[str]) -> list[str]:
    out = list(cmd)
    for advisory in _IGNORED:
        out += ["--ignore-vuln", advisory]
    return out


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=_REPO_ROOT, text=True, capture_output=True)


def _print_process_output(result: subprocess.CompletedProcess[str]) -> None:
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n", file=sys.stderr)


def _looks_like_tool_failure(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout}\n{result.stderr}".lower()
    return (
        result.returncode not in (0, 1)
        or "traceback" in output
        or "calledprocesserror" in output
        or "no module named pip_audit" in output
    )


def _report_failure(result: subprocess.CompletedProcess[str]) -> None:
    _print_process_output(result)
    if _looks_like_tool_failure(result):
        print(
            "audit_deps: FAILED — pip-audit could not complete. This is a tooling "
            "failure, not a confirmed vulnerability finding.",
            file=sys.stderr,
        )
        return
    print(
        "audit_deps: FAILED — pip-audit found an un-ignored vulnerability in a "
        "declared dependency. Bump the pin, or (if transitive/unreachable) add a "
        "documented entry to _IGNORED with justification.",
        file=sys.stderr,
    )


def _check_locked_requirements(declared: list[str], locked: list[str]) -> None:
    """Reject lock drift before auditing a different dependency set than declared."""
    pins = {}
    for line in locked:
        req = Requirement(line)
        specs = list(req.specifier)
        if (
            req.url
            or req.marker
            or req.extras
            or len(specs) != 1
            or specs[0].operator != "=="
            or "*" in specs[0].version
        ):
            raise ValueError(f"lock entry must be an unconditional exact pin: {line}")
        name = canonicalize_name(req.name)
        if name in pins:
            raise ValueError(f"duplicate locked dependency: {name}")
        pins[name] = specs[0].version
    for line in declared:
        req = Requirement(line)
        if req.marker and not req.marker.evaluate():
            continue
        version = pins.get(canonicalize_name(req.name))
        if version is None or version not in req.specifier:
            raise ValueError(f"requirements.lock does not satisfy {line}; regenerate the lock")


def _locked_requirements(declared: list[str]) -> list[str]:
    """The committed lock's exact pins, checked against the declared requirements."""
    pins = parse_lock(_LOCKFILE.read_text(encoding="utf-8"))
    locked = [f"{name}=={pin['version']}" for name, pin in pins.items()]
    if not locked:
        raise ValueError(f"{_LOCKFILE.name} pins no packages")
    _check_locked_requirements(declared, locked)
    return locked


def main() -> int:
    try:
        locked = _locked_requirements(_pinned_requirements())
    except (OSError, ValueError) as exc:
        print(f"audit_deps: FAILED — {exc}", file=sys.stderr)
        return 2
    print(
        f"audit_deps: auditing {len(locked)} locked package(s) from {_LOCKFILE.name} "
        f"(ignoring {len(_IGNORED)} documented advisory id(s))"
    )
    # The hash-locked file is audited as-is. --strict: a package pip-audit cannot
    # collect fails the audit instead of being skipped with a warning.
    result = _run(
        _add_ignored(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "-r",
                str(_LOCKFILE),
                "--require-hashes",
                "--disable-pip",
                "--strict",
                "--progress-spinner",
                "off",
            ]
        )
    )
    if result.returncode == 0:
        _print_process_output(result)
        print("audit_deps: OK — no actionable vulnerabilities in the locked closure")
        return 0
    _report_failure(result)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
