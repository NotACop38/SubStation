"""CLI: generate the ATT&CK-for-ICS coverage map + Navigator layer.

Usage::

    python -m substation.coverage [--check] [--out DIR]

Default: render every coverage artifact from ``detections/registry.yaml`` into the
committed snapshot directory ``docs/coverage/`` (``coverage.md``, ``coverage.json``,
``navigator-layer.json``). These are GENERATED — never hand-edit them.

``--check``: render in memory and compare against the committed files; exit 1 if
any is missing or stale (drift). This is what ``make ci`` runs so the committed
coverage map can never fall out of sync with the registry (PRD.md §6.7).

Exit code is 0 on success, 1 on drift / write failure.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from substation.coverage.builder import render_all
from substation.detect.registry import REPO_ROOT, RegistryError

# The committed, published snapshot is the single output home; `make ci`
# drift-checks it so it can never fall out of sync with the registry.
_DEFAULT_OUT = REPO_ROOT / "docs" / "coverage"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m substation.coverage",
        description="Generate the ATT&CK-for-ICS coverage map + Navigator layer.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the committed coverage files are up to date; do not write.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=_DEFAULT_OUT,
        help="Output directory (default: ./coverage).",
    )
    args = parser.parse_args(argv)
    out_dir: Path = args.out

    try:
        artifacts = render_all()
    except RegistryError as exc:
        print(f"coverage: {exc}", file=sys.stderr)
        return 1

    if args.check:
        stale: list[str] = []
        for name, content in artifacts.items():
            path = out_dir / name
            current = path.read_text(encoding="utf-8") if path.exists() else None
            if current != content:
                reason = "missing" if current is None else "out of date"
                stale.append(f"  {name}: {reason}")
        if stale:
            print(
                "coverage: committed coverage map is stale — run `make coverage-build`:\n"
                + "\n".join(stale),
                file=sys.stderr,
            )
            return 1
        print(f"coverage: OK — {len(artifacts)} artifact(s) up to date")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, content in artifacts.items():
        (out_dir / name).write_text(content, encoding="utf-8")
        print(f"coverage: wrote {out_dir / name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
