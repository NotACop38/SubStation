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

import json
import subprocess
import sys
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


def _write_requirements(path: Path, requirements: list[str]) -> None:
    path.write_text("\n".join(requirements) + "\n", encoding="utf-8")


def _read_resolver_report(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    resolved: set[str] = set()
    for package in data.get("install", []):
        metadata = package.get("metadata", {})
        name = metadata.get("name")
        version = metadata.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("missing package name/version in pip resolver report")
        resolved.add(f"{name}=={version}")
    if not resolved:
        raise ValueError("pip resolver report did not contain resolved packages")
    return sorted(resolved, key=str.casefold)


def _looks_like_tool_failure(result: subprocess.CompletedProcess[str]) -> bool:
    output = f"{result.stdout}\n{result.stderr}".lower()
    return (
        result.returncode not in (0, 1)
        or "traceback" in output
        or "calledprocesserror" in output
        or "no module named pip_audit" in output
    )


def _report_resolver_failure(result: subprocess.CompletedProcess[str]) -> None:
    _print_process_output(result)
    print(
        "audit_deps: FAILED — dependency resolver could not complete. This is a "
        "tooling failure, not a confirmed vulnerability finding.",
        file=sys.stderr,
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
    print(
        f"audit_deps: auditing {len(reqs)} pinned dependencies "
        f"(ignoring {len(_IGNORED)} documented advisory id(s))"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        declared_req_file = Path(tmpdir) / "declared-requirements.txt"
        resolver_report = Path(tmpdir) / "resolver-report.json"
        resolved_req_file = Path(tmpdir) / "resolved-requirements.txt"
        _write_requirements(declared_req_file, reqs)

        resolver_cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--ignore-installed",
            "--no-input",
            "--keyring-provider=subprocess",
            "--report",
            str(resolver_report),
            "-r",
            str(declared_req_file),
        ]
        resolver = _run(resolver_cmd)
        if resolver.returncode != 0:
            _report_resolver_failure(resolver)
            return resolver.returncode

        try:
            resolved = _read_resolver_report(resolver_report)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(
                f"audit_deps: FAILED — dependency resolver produced an unreadable report: {exc}",
                file=sys.stderr,
            )
            return 2

        _write_requirements(resolved_req_file, resolved)
        print(f"audit_deps: resolved {len(resolved)} packages in the declared closure")

        cmd = _add_ignored(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "-r",
                str(resolved_req_file),
                "--no-deps",
                "--disable-pip",
                "--progress-spinner",
                "off",
            ]
        )
        result = _run(cmd)
        if result.returncode == 0:
            _print_process_output(result)
            print("audit_deps: OK — no actionable vulnerabilities in the declared closure")
            return 0

        _report_failure(result)
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
