#!/usr/bin/env python3
"""Build an offline CycloneDX inventory and complete recorded-environment graph.

Artifact hashes and Requires-Dist were verified during explicit lock generation.
This describes runtime/dev reachability for that marker environment; it does not
claim a universal graph for every Python/OS combination or an installed inventory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import uuid
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))
from scripts.security.lockfile import load_evidence

_DEFAULT_OUT = _REPO_ROOT / "dist/sbom.cdx.json"


def build_sbom() -> dict[str, Any]:
    project, evidence, runtime, graph, roots = load_evidence(_REPO_ROOT)
    packages = evidence["packages"]
    refs = {name: f"pkg:pypi/{name}@{package['version']}" for name, package in packages.items()}
    app = f"pkg:pypi/{project['name']}@{project['version']}"
    components = []
    for name, package in sorted(packages.items()):
        scope = "runtime" if name in runtime else "dev" if name in graph else "locked-only"
        artifact = package["artifact"]
        components.append(
            {
                "type": "library",
                "bom-ref": refs[name],
                "name": name,
                "version": package["version"],
                "purl": refs[name],
                "hashes": [{"alg": "SHA-256", "content": artifact["sha256"]}],
                "externalReferences": [{"type": "distribution", "url": artifact["url"]}],
                "properties": [
                    {"name": "substation:scope", "value": scope},
                    {"name": "substation:hashed-artifact", "value": artifact["filename"]},
                    {"name": "substation:metadata-sha256", "value": artifact["metadata_sha256"]},
                ],
            }
        )
    dependencies = [{"ref": app, "dependsOn": [refs[name] for name in roots]}]
    # Every resolved leaf has an explicit empty list. Unreachable lock inventory
    # entries have no edge assertion, rather than being mislabeled as leaves.
    dependencies.extend(
        {"ref": refs[name], "dependsOn": [refs[child] for child in children]}
        for name, children in sorted(graph.items())
    )
    digest = hashlib.sha256(json.dumps(evidence, sort_keys=True).encode()).hexdigest()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, digest)}",
        "metadata": {
            "tools": [{"vendor": "Substation", "name": "sbom.py", "version": "2.0"}],
            "component": {
                "type": "application",
                "bom-ref": app,
                "name": project["name"],
                "version": project["version"],
                "purl": app,
            },
            "properties": [
                {
                    "name": "substation:inventory-scope",
                    "value": "Hash-locked inventory; complete runtime/dev graph for recorded marker environment",
                },
                {
                    "name": "substation:marker-environment",
                    "value": json.dumps(evidence["environment"], sort_keys=True),
                },
                {"name": "substation:lock-sha256", "value": evidence["lock_sha256"]},
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=_DEFAULT_OUT)
    args = parser.parse_args()
    try:
        sbom = build_sbom()
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"sbom: FAILED: {exc}", file=sys.stderr)
        return 1
    print(
        f"sbom: wrote {args.out.name} ({len(sbom['components'])} components, {len(sbom['dependencies'])} dependency records)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
