"""Strict hash lock parsing and metadata-based dependency graph verification."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.utils import canonicalize_name


def parse_lock(text: str) -> dict[str, dict[str, Any]]:
    logical = []
    pending = ""
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        pending += " " + line.removesuffix("\\").strip()
        if not line.endswith("\\"):
            logical.append(pending.strip())
            pending = ""
    if pending:
        raise ValueError("unterminated lock continuation")
    packages: dict[str, dict[str, Any]] = {}
    for line in logical:
        parts = line.split()
        requirement = Requirement(parts[0])
        pins = list(requirement.specifier)
        if (
            requirement.url
            or requirement.marker
            or requirement.extras
            or len(pins) != 1
            or pins[0].operator != "=="
            or "*" in pins[0].version
        ):
            raise ValueError("lock requires unconditional exact pins")
        if len(parts) < 2 or any(
            not re.fullmatch("--hash=sha256:[a-f0-9]{64}", token) for token in parts[1:]
        ):
            raise ValueError("every locked package requires SHA-256 artifact hashes")
        name = canonicalize_name(requirement.name)
        if name in packages:
            raise ValueError(f"duplicate lock entry: {name}")
        packages[name] = {
            "version": pins[0].version,
            "hashes": sorted({part.split(":", 1)[1] for part in parts[1:]}),
        }
    if not packages:
        raise ValueError("empty dependency lock")
    return packages


def dependency_graph(
    roots: list[str], packages: dict[str, Any], environment: dict[str, str]
) -> tuple[dict[str, list[str]], list[str]]:
    """Resolve markers/extras to a fixed point; reject missing/conflicting closure."""
    graph: dict[str, set[str]] = {}
    extras: dict[str, set[str]] = {}
    processed: dict[str, frozenset[str]] = {}
    pending: list[str] = []

    def visit(text: str, parent: str | None, active_extras: set[str]) -> str | None:
        requirement = Requirement(text)
        if requirement.marker and not any(
            requirement.marker.evaluate({**environment, "extra": extra})
            for extra in active_extras | {""}
        ):
            return None
        name = canonicalize_name(requirement.name)
        if requirement.url or name not in packages:
            raise ValueError(f"missing or non-index dependency: {text}")
        if packages[name]["version"] not in requirement.specifier:
            raise ValueError(f"locked version does not satisfy {text}")
        graph.setdefault(name, set())
        if parent is not None:
            graph[parent].add(name)
        requested = extras.setdefault(name, set())
        requested.update(requirement.extras)
        if processed.get(name) != frozenset(requested):
            pending.append(name)
        return name

    root_names = {name for root in roots if (name := visit(root, None, set())) is not None}
    while pending:
        name = pending.pop()
        requested = frozenset(extras[name])
        if processed.get(name) == requested:
            continue
        processed[name] = requested
        package = packages[name]
        if package.get("requires_python") and environment[
            "python_full_version"
        ] not in SpecifierSet(package["requires_python"]):
            raise ValueError(f"{name} does not support the recorded Python environment")
        for requirement in package["requires_dist"]:
            visit(requirement, name, set(requested))
    return {name: sorted(children) for name, children in graph.items()}, sorted(root_names)


def declarations_hash(project_bytes: bytes) -> str:
    """Fingerprint dependency inputs; a release version/readme edit is not drift."""
    document = tomllib.loads(project_bytes.decode("utf-8"))
    project = document["project"]
    declarations = {
        key: project.get(key)
        for key in ("requires-python", "dependencies", "optional-dependencies")
    }
    declarations["build-system"] = document["build-system"]
    return hashlib.sha256(
        json.dumps(declarations, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_evidence(
    root: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, list[str]], dict[str, list[str]], list[str]]:
    project_bytes = (root / "pyproject.toml").read_bytes()
    lock_bytes = (root / "requirements.lock").read_bytes()
    lock = parse_lock(lock_bytes.decode("utf-8"))
    evidence = json.loads((root / "requirements.metadata.json").read_text(encoding="utf-8"))
    if evidence.get("schema") != "substation-dependency-evidence/v1":
        raise ValueError("unsupported dependency evidence schema")
    for key, contents in [("declarations_sha256", None), ("lock_sha256", lock_bytes)]:
        expected = (
            declarations_hash(project_bytes)
            if contents is None
            else hashlib.sha256(contents).hexdigest()
        )
        if evidence.get(key) != expected:
            raise ValueError(f"stale dependency metadata: {key}; regenerate with make lock")
    packages = evidence["packages"]
    if packages.keys() != lock.keys():
        raise ValueError("metadata package set differs from lock")
    for name, package in packages.items():
        if (
            package["version"] != lock[name]["version"]
            or package["artifact"]["sha256"] not in lock[name]["hashes"]
        ):
            raise ValueError(f"{name}: distribution version/hash differs from lock")
        if not isinstance(package["requires_dist"], list) or not all(
            isinstance(r, str) for r in package["requires_dist"]
        ):
            raise ValueError(f"{name}: invalid Requires-Dist metadata")
    environment = evidence["environment"]
    if environment.keys() != default_environment().keys() or not all(
        isinstance(v, str) for v in environment.values()
    ):
        raise ValueError("incomplete dependency marker environment")
    project = tomllib.loads(project_bytes.decode())["project"]
    runtime, runtime_roots = dependency_graph(project["dependencies"], packages, environment)
    combined, roots = dependency_graph(
        project["dependencies"] + project["optional-dependencies"]["dev"], packages, environment
    )
    return project, evidence, runtime, combined, roots
