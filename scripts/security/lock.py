#!/usr/bin/env python3
"""Refresh artifact hashes and verified wheel metadata for existing version pins.

Explicit network operation. Review pin changes separately; this does not upgrade
packages. Metadata describes wheels selected for the invoking interpreter.
"""

from __future__ import annotations

import concurrent.futures
import email.parser
import hashlib
import io
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

from packaging.markers import default_environment
from packaging.tags import sys_tags
from packaging.utils import canonicalize_name, parse_wheel_filename

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.security.lockfile import declarations_hash, dependency_graph


def fetch(url: str) -> bytes:
    if not url.startswith(("https://pypi.org/", "https://files.pythonhosted.org/")):
        raise ValueError("expected official HTTPS PyPI artifact URL")
    with urllib.request.urlopen(url, timeout=60) as response:  # nosec B310
        data = response.read(128 * 1024 * 1024 + 1)
    if len(data) > 128 * 1024 * 1024:
        raise ValueError("artifact exceeds download cap")
    return data


def package_evidence(pin: tuple[str, str]) -> tuple[str, dict, list[str]]:
    name, version = pin
    release = json.loads(fetch(f"https://pypi.org/pypi/{name}/{version}/json"))
    artifacts = [item for item in release["urls"] if not item["yanked"]]
    hashes = sorted({item["digests"]["sha256"] for item in artifacts})
    if not hashes or any(not re.fullmatch("[a-f0-9]{64}", digest) for digest in hashes):
        raise ValueError(f"{name}: missing/invalid artifact hashes")
    order = {tag: index for index, tag in enumerate(sys_tags())}
    wheels = []
    for item in artifacts:
        if not item["filename"].endswith(".whl"):
            continue
        _, _, _, tags = parse_wheel_filename(item["filename"])
        rank = min((order[tag] for tag in tags if tag in order), default=None)
        if rank is not None:
            wheels.append((rank, item["filename"], item))
    if not wheels:
        raise ValueError(f"{name}: no compatible wheel; metadata extraction never executes a build")
    artifact = min(wheels, key=lambda item: (item[0], item[1]))[2]
    data = fetch(artifact["url"])
    digest = hashlib.sha256(data).hexdigest()
    if digest != artifact["digests"]["sha256"]:
        raise ValueError(f"{name}: downloaded wheel hash mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [
            member
            for member in archive.infolist()
            if member.filename.endswith(".dist-info/METADATA") and member.filename.count("/") == 1
        ]
        if len(members) != 1 or members[0].file_size > 4 * 1024 * 1024:
            raise ValueError(f"{name}: invalid wheel metadata")
        metadata_bytes = archive.read(members[0])
    metadata = email.parser.BytesParser().parsebytes(metadata_bytes)
    if canonicalize_name(metadata["Name"]) != name or metadata["Version"] != version:
        raise ValueError(f"{name}: wheel identity differs from requested pin")
    return (
        name,
        {
            "version": version,
            "requires_dist": metadata.get_all("Requires-Dist", []),
            "requires_python": metadata.get("Requires-Python", ""),
            "artifact": {
                "filename": artifact["filename"],
                "sha256": digest,
                "url": artifact["url"],
                "metadata_sha256": hashlib.sha256(metadata_bytes).hexdigest(),
            },
        },
        hashes,
    )


def main() -> int:
    import tomllib

    text = (ROOT / "requirements.lock").read_text()
    pins = [
        (canonicalize_name(name), version)
        for name, version in re.findall(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", text, re.M)
    ]
    if not pins or len({name for name, _ in pins}) != len(pins):
        raise ValueError("expected unique existing version pins")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = sorted(pool.map(package_evidence, pins))
    lock = "# Version-pinned artifact hashes from PyPI; regenerate explicitly with make lock.\n"
    packages = {}
    for name, metadata, hashes in results:
        packages[name] = metadata
        lock += (
            f"{name}=={metadata['version']} \\\n"
            + " \\\n".join("    --hash=sha256:" + digest for digest in hashes)
            + "\n"
        )
    project_bytes = (ROOT / "pyproject.toml").read_bytes()
    project = tomllib.loads(project_bytes.decode())["project"]
    environment = default_environment()
    dependency_graph(
        project["dependencies"] + project["optional-dependencies"]["dev"], packages, environment
    )
    evidence = {
        "schema": "substation-dependency-evidence/v1",
        "environment": environment,
        "declarations_sha256": declarations_hash(project_bytes),
        "lock_sha256": hashlib.sha256(lock.encode()).hexdigest(),
        "packages": packages,
    }
    # All downloads, identities and closure checks pass before either file changes.
    (ROOT / "requirements.lock").write_text(lock, encoding="utf-8")
    (ROOT / "requirements.metadata.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"lock: verified {len(packages)} distributions; review lock + metadata together")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
