#!/usr/bin/env python3
"""Generate a CycloneDX SBOM for Substation's declared dependency closure.

Emits a CycloneDX 1.5 JSON SBOM listing the application plus every pinned
dependency (runtime + dev) from ``pyproject.toml``, each with a PEP 508 / Package
URL (``pkg:pypi/...``) identifier. Pure stdlib (``tomllib`` ships with 3.11) so it
runs with only Python installed — no external SBOM tool or network needed, which
keeps it deterministic and consistent with the project's Tier-1 "Python-only"
promise.

Run: ``python scripts/security/sbom.py [--out PATH]`` (invoked by ``make security``).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import tomllib
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PYPROJECT = _REPO_ROOT / "pyproject.toml"
_DEFAULT_OUT = _REPO_ROOT / "dist" / "sbom.cdx.json"


def _split_pin(requirement: str) -> tuple[str, str | None]:
    """Split a pinned ``name==version`` requirement into (name, version)."""
    req = requirement.split("#", 1)[0].strip()
    if "==" in req:
        name, version = req.split("==", 1)
        return name.strip(), version.strip()
    return req, None


def _component(name: str, version: str | None, scope: str) -> dict[str, Any]:
    purl = f"pkg:pypi/{name.lower()}@{version}" if version else f"pkg:pypi/{name.lower()}"
    ref = f"{name}@{version}" if version else name
    comp: dict[str, Any] = {
        "type": "library",
        "bom-ref": ref,
        "name": name,
        "purl": purl,
        "properties": [{"name": "substation:scope", "value": scope}],
    }
    if version:
        comp["version"] = version
    return comp


def build_sbom() -> dict[str, Any]:
    data = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    app_name = project["name"]
    app_version = project.get("version", "0.0.0")

    components: list[dict[str, Any]] = []
    for req in project.get("dependencies", []):
        name, version = _split_pin(req)
        components.append(_component(name, version, "runtime"))
    for req in project.get("optional-dependencies", {}).get("dev", []):
        name, version = _split_pin(req)
        components.append(_component(name, version, "dev"))

    # Deterministic serial number derived from the (sorted) component set so an
    # unchanged dependency set yields a stable SBOM.
    digest_src = "|".join(sorted(c["bom-ref"] for c in components)).encode("utf-8")
    serial = hashlib.sha256(digest_src).hexdigest()[:32]

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial[:8]}-{serial[8:12]}-{serial[12:16]}-{serial[16:20]}-{serial[20:32]}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "tools": [{"vendor": "Substation", "name": "sbom.py", "version": "1.0"}],
            "component": {
                "type": "application",
                "bom-ref": f"{app_name}@{app_version}",
                "name": app_name,
                "version": app_version,
                "purl": f"pkg:pypi/{app_name}@{app_version}",
            },
        },
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out", type=Path, default=_DEFAULT_OUT, help="output path (CycloneDX JSON)"
    )
    args = parser.parse_args()

    sbom = build_sbom()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    # timestamp varies run-to-run; everything else is deterministic.
    args.out.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    # Show a repo-relative path when the output lives in the checkout, else the
    # absolute path — an --out outside the repo must not raise after a good write.
    out = args.out.resolve()
    try:
        shown = out.relative_to(_REPO_ROOT)
    except ValueError:
        shown = out
    print(f"sbom: wrote {shown} ({len(sbom['components'])} components, CycloneDX 1.5)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
