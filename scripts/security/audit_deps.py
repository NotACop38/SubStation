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
    "CVE-2025-69872": "transitive (pysigma->diskcache); unfixed upstream; cache path unused; local single-user build",
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


def main() -> int:
    reqs = _pinned_requirements()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(reqs) + "\n")
        req_file = fh.name

    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        req_file,
        "--progress-spinner",
        "off",
    ]
    for advisory in _IGNORED:
        cmd += ["--ignore-vuln", advisory]

    print(f"audit_deps: auditing {len(reqs)} pinned dependencies "
          f"(ignoring {len(_IGNORED)} documented advisory id(s))")
    result = subprocess.run(cmd, cwd=_REPO_ROOT)
    if result.returncode == 0:
        print("audit_deps: OK — no actionable vulnerabilities in the declared closure")
    else:
        print(
            "audit_deps: FAILED — pip-audit found an un-ignored vulnerability in a "
            "declared dependency. Bump the pin, or (if transitive/unreachable) add a "
            "documented entry to _IGNORED with justification.",
            file=sys.stderr,
        )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
