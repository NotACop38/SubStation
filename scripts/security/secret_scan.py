#!/usr/bin/env python3
"""Scan a snapshot of current source files, or the exact index with --staged.

Native gitleaks is preferred; pinned detect-secrets is the Python alternative.
Docker gitleaks is explicit opt-in. Every backend scans the same snapshot,
including new non-ignored files for a working-tree scan. This is not a history
scan. Missing scanners and unreadable input fail the gate.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
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


def _snapshot(destination: Path, *, staged: bool) -> None:
    """Copy only regular Git source files; never follow links outside the tree."""
    cmd = ["git", "ls-files", "-z"]
    cmd += ["--stage"] if staged else ["--cached", "--others", "--exclude-standard"]
    proc = subprocess.run(cmd, cwd=_REPO_ROOT, capture_output=True, check=True)
    for entry in sorted(set(proc.stdout.split(b"\0")) - {b""}):
        if staged:
            metadata, raw_name = entry.split(b"\t", 1)
            mode, object_id, stage = metadata.split()
            if mode not in (b"100644", b"100755") or stage != b"0":
                raise ValueError("cannot scan non-regular or conflicted index entry")
            data = subprocess.run(
                ["git", "cat-file", "blob", object_id.decode("ascii")],
                cwd=_REPO_ROOT,
                capture_output=True,
                check=True,
            ).stdout
        else:
            raw_name = entry
        relative = Path(os.fsdecode(raw_name))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid source path")
        if not staged:
            source = _REPO_ROOT / relative
            # A deleted tracked file is absent from the proposed working tree.
            if not source.exists() and not source.is_symlink():
                continue
            if source.is_symlink() or not source.resolve().is_relative_to(_REPO_ROOT.resolve()):
                raise ValueError(f"cannot scan symlink source: {relative}")
            data = source.read_bytes()
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def _docker_usable() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True, text=True).returncode == 0


def _run_gitleaks_native(root: Path) -> int | None:
    """Run a native gitleaks binary if present. Returns exit code, or None."""
    if shutil.which("gitleaks") is None:
        return None
    print("secret_scan: backend = gitleaks (native)")
    return subprocess.run(
        ["gitleaks", "dir", str(root), "--no-banner", "--redact"],
        cwd=root,
    ).returncode


def _run_gitleaks_docker(root: Path = _REPO_ROOT) -> int | None:
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
            "--network",
            "none",
            "-v",
            f"{root}:/repo:ro",
            GITLEAKS_DOCKER_IMAGE,
            "dir",
            "/repo",
            "--no-banner",
            "--redact",
        ],
    ).returncode


def _run_detect_secrets(root: Path) -> int | None:
    """Run detect-secrets over tracked files. Returns exit code, or None if absent."""
    try:
        if importlib.util.find_spec("detect_secrets") is None:
            return None
    except ImportError:
        return None
    print("secret_scan: backend = detect-secrets")
    proc = subprocess.run(
        [sys.executable, "-m", "detect_secrets", "scan", "--all-files", "."],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr)
        return proc.returncode

    report = json.loads(proc.stdout or "{}")
    findings = report.get("results", {})
    if findings:
        print("secret_scan: detect-secrets flagged potential secrets in:")
        for path in findings:
            print(f"  - {path}")
        return 1
    print("secret_scan: detect-secrets found no secrets")
    return 0


def _run_builtin(root: Path) -> int:
    print("secret_scan: backend = builtin regex sweep")
    findings: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        # This scanner itself defines the patterns; skip it to avoid self-matches.
        if path.relative_to(root) == Path("scripts/security/secret_scan.py"):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, pattern in _BUILTIN_PATTERNS.items():
            if pattern.search(text):
                findings.append(f"{path.relative_to(root)}: {name}")
    if findings:
        print("secret_scan: builtin sweep flagged:")
        for f in findings:
            print(f"  - {f}")
        return 1
    print("secret_scan: builtin sweep found no secrets")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="Scan the exact complete Git index.")
    args = parser.parse_args(argv)
    backend = os.environ.get("SUBSTATION_SECRET_SCANNER", "auto")
    if backend not in ("auto", "gitleaks-docker"):
        print(f"secret_scan: unknown scanner {backend!r}", file=sys.stderr)
        return 2
    try:
        with tempfile.TemporaryDirectory(prefix="substation-secret-scan-") as tmp:
            root = Path(tmp)
            _snapshot(root, staged=args.staged)
            print(f"secret_scan: scope = {'index' if args.staged else 'working tree'}")
            if backend == "gitleaks-docker":
                rc = _run_gitleaks_docker(root)
            else:
                rc = _run_gitleaks_native(root)
                if rc is None:
                    rc = _run_detect_secrets(root)
            if rc is None:
                _run_builtin(root)
                print(
                    "secret_scan: required scanner unavailable; install .[dev] or gitleaks",
                    file=sys.stderr,
                )
                return 2
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"secret_scan: could not scan the complete source tree: {exc}", file=sys.stderr)
        return 2
    if rc == 0:
        print("secret_scan: OK")
    else:
        print("secret_scan: FAILED — review the findings above", file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
