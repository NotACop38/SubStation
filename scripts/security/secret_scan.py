#!/usr/bin/env python3
"""Scan the git-tracked tree for committed secrets.

Backend selection, in order of preference:

  1. **gitleaks** — native binary if on PATH, else a digest-pinned Docker
     image when Docker is usable. The canonical secret
     scanner.
  2. **detect-secrets** — the pinned dev dependency (``make security`` installs
     it); a pure-Python fallback that needs no Docker.
  3. **builtin** — a small high-signal regex sweep (private keys, AWS keys,
     generic tokens) so the gate still does *something* even with neither tool.

Exits non-zero if any backend reports a finding. Run:
``python scripts/security/secret_scan.py`` (invoked by ``make security``).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
GITLEAKS_DOCKER_IMAGE = (
    "zricethezav/gitleaks:v8.30.1"
    "@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
)

# High-signal patterns for the builtin fallback. Deliberately conservative to
# avoid false positives on a detection-content repo full of sample hex/IDs.
_BUILTIN_PATTERNS: dict[str, re.Pattern[str]] = {
    "private-key-block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "aws-access-key-id": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "aws-secret-access-key": re.compile(r"\baws_secret_access_key\b\s*[=:]\s*[A-Za-z0-9/+=]{40}"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack-token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "generic-api-key": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|passwd|password|token)\b\s*[=:]\s*['\"][A-Za-z0-9/+=_\-]{16,}['\"]"
    ),
    "private-key-pem-marker": re.compile(r"PRIVATE KEY-----"),
}


def _git_tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=_REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [_REPO_ROOT / line for line in out.stdout.splitlines() if line]


def _docker_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, text=True).returncode == 0


def _run_gitleaks_native() -> int | None:
    """Run a native gitleaks binary if present. Returns exit code, or None."""
    if shutil.which("gitleaks") is None:
        return None
    print("secret_scan: backend = gitleaks (native)")
    return subprocess.run(
        ["gitleaks", "detect", "--source", str(_REPO_ROOT), "--no-banner", "--redact"],
        cwd=_REPO_ROOT,
    ).returncode


def _run_gitleaks_docker() -> int | None:
    """Run gitleaks via Docker (opt-in). Returns exit code, or None if unusable.

    Off by default so `make security`/`make ci` never trigger a surprise image
    pull (and never flake on a registry rate limit). Opt in with
    ``SUBSTATION_SECRET_SCANNER=gitleaks-docker``.
    """
    if not _docker_usable():
        print("secret_scan: gitleaks-docker requested but Docker is not usable", file=sys.stderr)
        return None
    print("secret_scan: backend = gitleaks (Docker)")
    return subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{_REPO_ROOT}:/repo:ro",
            GITLEAKS_DOCKER_IMAGE,
            "detect",
            "--source",
            "/repo",
            "--no-banner",
            "--redact",
        ],
    ).returncode


def _run_detect_secrets() -> int | None:
    """Run detect-secrets over tracked files. Returns exit code, or None if absent."""
    try:
        import importlib.util

        if importlib.util.find_spec("detect_secrets") is None:
            return None
    except ImportError:
        return None
    print("secret_scan: backend = detect-secrets")
    # Scan only git-tracked files so build caches (.mypy_cache, .ruff_cache, …)
    # and other gitignored artifacts never enter the scan.
    tracked = [str(p.relative_to(_REPO_ROOT)) for p in _git_tracked_files() if p.is_file()]
    proc = subprocess.run(
        [sys.executable, "-m", "detect_secrets", "scan", *tracked],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        return proc.returncode
    import json

    report = json.loads(proc.stdout or "{}")
    findings = report.get("results", {})
    if findings:
        print("secret_scan: detect-secrets flagged potential secrets in:")
        for path in findings:
            print(f"  - {path}")
        return 1
    print("secret_scan: detect-secrets found no secrets")
    return 0


def _run_builtin() -> int:
    print("secret_scan: backend = builtin regex sweep")
    findings: list[str] = []
    for path in _git_tracked_files():
        if not path.is_file():
            continue
        # This scanner itself defines the patterns; skip it to avoid self-matches.
        if path.resolve() == Path(__file__).resolve():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for name, pattern in _BUILTIN_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(_REPO_ROOT)}: {name}")
    if findings:
        print("secret_scan: builtin sweep flagged:")
        for f in findings:
            print(f"  - {f}")
        return 1
    print("secret_scan: builtin sweep found no secrets")
    return 0


def main() -> int:
    import os

    # Explicit opt-in to gitleaks-via-Docker (the canonical scanner) when asked.
    if os.environ.get("SUBSTATION_SECRET_SCANNER") == "gitleaks-docker":
        rc = _run_gitleaks_docker()
    else:
        # Default order: native gitleaks if installed, else the pinned
        # detect-secrets, else a builtin regex sweep.
        rc = _run_gitleaks_native()
        if rc is None:
            rc = _run_detect_secrets()
    if rc is None:
        rc = _run_builtin()
    if rc == 0:
        print("secret_scan: OK")
    else:
        print("secret_scan: FAILED — review the findings above", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
