#!/usr/bin/env python3
"""Check S7 golden/example drift; --write explicitly regenerates both artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from substation.protocols.s7comm import build_events, event_to_dict
from substation.scenarios import load_scenario
from substation.schema import validate_event

BEGIN = "<!-- BEGIN GENERATED S7 EXAMPLES -->"
END = "<!-- END GENERATED S7 EXAMPLES -->"


def rendered(root: Path) -> dict[Path, str]:
    scenario = load_scenario(root / "tests/data/fidelity/s7/operations.yaml")
    records = [event_to_dict(event) for event in build_events(scenario)]
    for record in records:
        validate_event(record)
    golden = "".join(json.dumps(record) + "\n" for record in records)
    examples = [
        next(e for e in records if e["is_orig"] and "read_szl" in e["detail"]),
        next(e for e in records if not e["is_orig"] and e["func_name"] == "Request Download"),
    ]
    block = BEGIN + "\n```json\n" + "".join(json.dumps(e) + "\n" for e in examples) + "```\n" + END
    path = root / "docs/schema.md"
    document = path.read_text(encoding="utf-8")
    if document.count(BEGIN) != 1 or document.count(END) != 1:
        raise ValueError("expected exactly one generated S7 example block")
    start, end = document.index(BEGIN), document.index(END)
    if end <= start:
        raise ValueError("S7 example markers are out of order")
    return {
        root / "tests/data/events/s7/valid.jsonl": golden,
        path: document[:start] + block + document[end + len(END) :],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--write", action="store_true", help="explicitly regenerate golden JSON and documentation"
    )
    args = parser.parse_args()
    # Compute and validate both artifacts before making any requested writes.
    outputs = rendered(ROOT)
    stale = [
        p for p, text in outputs.items() if not p.exists() or p.read_text(encoding="utf-8") != text
    ]
    if args.write:
        for path in stale:
            path.write_text(outputs[path], encoding="utf-8")
    elif stale:
        print("S7 examples: stale; run python scripts/s7_examples.py --write", file=sys.stderr)
        return 1
    print("S7 examples: current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
