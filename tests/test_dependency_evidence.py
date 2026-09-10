"""Complete dependency graphs and artifact hashes must fail closed on drift."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest


def test_lock_rejects_unhashed_duplicate_or_unpinned_entries() -> None:
    from scripts.security.lockfile import parse_lock

    for text in (
        "demo==1\n",
        "demo>=1 --hash=sha256:" + "a" * 64,
        ("demo==1 --hash=sha256:" + "a" * 64 + "\n") * 2,
    ):
        with pytest.raises(ValueError):
            parse_lock(text)
    result = parse_lock("demo==1 \\\n    --hash=sha256:" + "a" * 64 + "\n")
    assert result["demo"]["version"] == "1"


def test_real_evidence_has_transitive_edges_and_all_leaves() -> None:
    from scripts.security.sbom import build_sbom

    bom = build_sbom()
    components = {component["name"]: component for component in bom["components"]}
    assert len(components) >= 50
    edges = {node["ref"]: node["dependsOn"] for node in bom["dependencies"]}
    assert components["diskcache"]["bom-ref"] in edges[components["pysigma"]["bom-ref"]]
    assert all(c["bom-ref"] in edges and c["hashes"] for c in components.values())


def test_missing_transitive_dependency_and_version_conflict_fail() -> None:
    from scripts.security.lockfile import dependency_graph

    environment = {"python_version": "3.12", "extra": ""}
    packages: dict[str, Any] = {
        "parent": {"version": "1", "requires_dist": ["child>=2"]},
        "child": {"version": "2", "requires_dist": []},
    }
    assert dependency_graph(["parent==1"], packages, environment)[0]["parent"] == ["child"]
    for bad in (
        {"parent": packages["parent"]},
        {**packages, "child": {"version": "1", "requires_dist": []}},
    ):
        with pytest.raises(ValueError):
            dependency_graph(["parent==1"], bad, environment)


def test_extras_markers_and_cycles_terminate_with_complete_edges() -> None:
    from scripts.security.lockfile import dependency_graph

    packages = {
        "parent": {"version": "1", "requires_dist": ['child[feature]; python_version >= "3.11"']},
        "child": {"version": "1", "requires_dist": ["parent", 'leaf; extra == "feature"']},
        "leaf": {"version": "1", "requires_dist": []},
    }
    graph, roots = dependency_graph(["parent"], packages, {"python_version": "3.12"})
    assert roots == ["parent"]
    assert graph == {"parent": ["child"], "child": ["leaf", "parent"], "leaf": []}


def test_metadata_and_lock_drift_fail(tmp_path: Path) -> None:
    from scripts.security.lockfile import load_evidence

    root = Path(__file__).resolve().parents[1]
    for name in ("pyproject.toml", "requirements.lock", "requirements.metadata.json"):
        (tmp_path / name).write_bytes((root / name).read_bytes())
    path = tmp_path / "requirements.metadata.json"
    data = json.loads(path.read_text())
    name = next(iter(data["packages"]))
    bad = copy.deepcopy(data)
    bad["packages"][name]["artifact"]["sha256"] = "0" * 64
    path.write_text(json.dumps(bad))
    with pytest.raises(ValueError):
        load_evidence(tmp_path)


def test_real_pip_rejects_modified_artifact_hash(tmp_path: Path) -> None:
    import hashlib
    import subprocess
    import sys
    import zipfile

    wheel = tmp_path / "local_hash_fixture-1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "local_hash_fixture-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: local-hash-fixture\nVersion: 1.0\n",
        )
        archive.writestr(
            "local_hash_fixture-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        archive.writestr("local_hash_fixture-1.0.dist-info/RECORD", "")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    for good in (True, False):
        requirements = tmp_path / "requirements.txt"
        requirements.write_text(
            "local-hash-fixture==1.0 --hash=sha256:" + (digest if good else "0" * 64) + "\n"
        )
        result = subprocess.run(  # noqa: S603 (fixed local pip download; no index or execution)
            [
                sys.executable,
                "-m",
                "pip",
                "download",
                "--no-index",
                "--no-deps",
                "--no-cache-dir",
                "--require-hashes",
                "--find-links",
                str(tmp_path),
                "-r",
                str(requirements),
                "--dest",
                str(tmp_path / ("good" if good else "bad")),
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert (result.returncode == 0) is good, result.stdout + result.stderr
        if not good:
            assert "DO NOT MATCH THE HASHES" in result.stderr


def test_dependency_fingerprint_ignores_release_version_but_detects_pin_changes() -> None:
    from scripts.security.lockfile import declarations_hash

    original = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_bytes()
    assert declarations_hash(original) == declarations_hash(
        original.replace(b'version = "0.1.0"', b'version = "0.2.0"')
    )
    assert declarations_hash(original) != declarations_hash(
        original.replace(b"scapy==2.7.0", b"scapy==2.6.0")
    )
