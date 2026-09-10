"""Secret scanners must inspect proposed content rather than only old commits."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from scripts.security import secret_scan


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)  # noqa: S603,S607


def test_index_scan_reads_staged_bytes_even_after_worktree_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    source = repo / "new config.txt"
    # Deliberately synthetic credential shape, assembled to avoid fixture flags.
    source.write_text("api_key = '" + "AKIA" + "Z" * 16 + "'\n")
    _git(repo, "add", "--", source.name)
    source.write_text("clean working copy\n")
    monkeypatch.setattr(secret_scan, "_REPO_ROOT", repo)
    index = tmp_path / "index"
    index.mkdir()
    secret_scan._snapshot(index, staged=True)
    assert secret_scan._run_builtin(index) == 1
    assert secret_scan._run_detect_secrets(index) == 1
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    secret_scan._snapshot(worktree, staged=False)
    assert secret_scan._run_builtin(worktree) == 0


def test_worktree_scan_includes_new_nonignored_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    (repo / ".gitignore").write_text("cache/\n")
    (repo / "new.py").write_text("synthetic example\n")
    (repo / "cache").mkdir()
    (repo / "cache" / "ignored.py").write_text("ignored\n")
    monkeypatch.setattr(secret_scan, "_REPO_ROOT", repo)
    snapshot = tmp_path / "scan"
    snapshot.mkdir()
    secret_scan._snapshot(snapshot, staged=False)
    assert (snapshot / "new.py").read_text() == "synthetic example\n"
    assert not (snapshot / "cache").exists()


def test_missing_scanners_cannot_report_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _git(tmp_path, "init")
    monkeypatch.setattr(secret_scan, "_REPO_ROOT", tmp_path)
    monkeypatch.delenv("SUBSTATION_SECRET_SCANNER", raising=False)
    monkeypatch.setattr(secret_scan, "_run_gitleaks_native", lambda _root: None)
    monkeypatch.setattr(secret_scan, "_run_detect_secrets", lambda _root: None)
    assert secret_scan.main([]) == 2


def test_reviewed_hash_is_bound_to_exact_line_path_and_detector(tmp_path: Path) -> None:
    import hashlib
    import json

    from scripts.security.secret_scan import _unreviewed_findings

    source = tmp_path / "evidence.json"
    line = '"sha256": "' + "0123456789abcdef" * 4 + '"'
    source.write_text(line + "\n")
    digest = hashlib.sha256(line.encode()).hexdigest()
    directory = tmp_path / "scripts/security"
    directory.mkdir(parents=True)
    (directory / "reviewed-hash-lines.json").write_text(
        json.dumps({"evidence.json": [":".join(digest[i : i + 16] for i in range(0, 64, 16))]})
    )
    findings = {"evidence.json": [{"line_number": 1, "type": "Hex High Entropy String"}]}
    assert not _unreviewed_findings(tmp_path, findings)
    source.write_text(line + ', "extra": "unreviewed"\n')
    assert _unreviewed_findings(tmp_path, findings) == findings
    source.write_text(line + "\n")
    findings["evidence.json"][0]["type"] = "Secret Keyword"
    assert _unreviewed_findings(tmp_path, findings) == findings
