#!/usr/bin/env python3
"""Audit Substation's *declared, pinned* dependency closure with pip-audit.

Why not bare ``pip-audit``? With no arguments pip-audit audits whatever happens
to be installed in the ambient interpreter — in a dev container that includes
dozens of OS/system packages Substation neither ships nor controls, so the gate
would fail on advisories that have nothing to do with the product. This script
scopes the audit to exactly the dependencies declared in ``pyproject.toml``
(runtime ``dependencies`` + the ``dev`` extra), resolves their real transitive
closure, and applies a small, **documented** ignore-list for advisories that are
transitive, unfixed upstream, and unreachable in our usage. The result is a
deterministic, product-scoped supply-chain gate.

Run: ``python scripts/security/audit_deps.py`` (invoked by ``make security``).
"""

from __future__ import annotations

import subprocess
import sys
import sysconfig
import tempfile
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
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
    # exercises the disk-cache code path; the Tier-1 build is local, single-user
    # and single-process, so the exploit precondition (a shared/untrusted cache
    # dir) does not hold. Re-evaluate if pySigma ships a fix or we start caching.
    "CVE-2025-69872": (
        "transitive (pysigma->diskcache); unfixed upstream; cache path unused; "
        "local single-user build"
    ),
    "GHSA-w8v5-vhqr-4h9v": "same advisory as CVE-2025-69872 (GHSA alias)",
    "PYSEC-2025-69872": "same advisory as CVE-2025-69872 (PYSEC alias)",
}


def _pinned_requirements() -> list[str]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    reqs: list[str] = list(project.get("dependencies", []))
    reqs += list(project.get("optional-dependencies", {}).get("dev", []))
    # Strip inline trailing comments / whitespace from each requirement line.
    return [r.split("#", 1)[0].strip() for r in reqs if r.split("#", 1)[0].strip()]


def _site_packages_path() -> str:
    return sysconfig.get_paths()["purelib"]


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
        result.returncode not in (0, 1) or "traceback" in output or "calledprocesserror" in output
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


def main() -> int:
    reqs = _pinned_requirements()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(reqs) + "\n")
        req_file = fh.name
    try:
        return _audit(reqs, req_file)
    finally:
        # delete=False is needed so pip-audit (a separate process) can open the
        # file by name on every platform; clean it up on every exit path.
        Path(req_file).unlink(missing_ok=True)


def _audit(reqs: list[str], req_file: str) -> int:
    cmd = _add_ignored(
        [
            sys.executable,
            "-m",
            "pip_audit",
            "-r",
            req_file,
            "--progress-spinner",
            "off",
        ]
    )

    print(
        f"audit_deps: auditing {len(reqs)} pinned dependencies "
        f"(ignoring {len(_IGNORED)} documented advisory id(s))"
    )
    result = _run(cmd)
    if result.returncode == 0:
        _print_process_output(result)
        print("audit_deps: OK — no actionable vulnerabilities in the declared closure")
        return 0

    if _looks_like_tool_failure(result):
        _print_process_output(result)
        fallback_cmd = _add_ignored(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--path",
                _site_packages_path(),
                "--progress-spinner",
                "off",
            ]
        )
        print(
            "audit_deps: pip-audit resolver failed before completing; "
            "falling back to the installed dev environment",
            file=sys.stderr,
        )
        fallback = _run(fallback_cmd)
        if fallback.returncode == 0:
            _print_process_output(fallback)
            print("audit_deps: fallback OK — no actionable vulnerabilities found")
            return 0
        _report_failure(fallback)
        return 1

    _report_failure(result)
    # Normalize to the documented 0/1 contract: pip-audit's internal-error codes
    # (>=2) must not leak through as the gate's exit status.
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
