"""Differential qualification of shipped Sigma with the official SQLite backend.

Development-only; no SIEM adapter or runtime backend is installed by the product.
The explicit flat columns below describe the tested SQLite ingestion contract.
Missing values stay NULL. Do not hide SQLite's three-valued NOT semantics.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from importlib.metadata import version
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sigma.backends.sqlite.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

from substation.detect import load_events
from substation.detect.registry import load_registry
from substation.detect.sigma_eval import matching_indices, parse_rule
from substation.emit import write_artifacts
from substation.policy import compile_policy, load_policy
from substation.scenarios import load_scenarios

FIELDS = (
    "proto",
    "direction",
    "action_class",
    "func_name",
    "func_code",
    "is_exception",
    "error",
    "conn.orig_h",
    "conn.resp_h",
    "conn.resp_p",
    "detail.unit",
    "detail.address",
    "detail.quantity",
    "detail.subfunction_code",
)


def sqlite_hits(source: str, events: list[dict[str, Any]]) -> list[int]:
    """Run unmodified backend SQL on native typed values and ASCII NOCASE text.

    Only trusted repository rules/site exports are accepted by this test helper.
    Every value is bound as a parameter; fixed columns have no SQLite affinity,
    so importing a number never coerces it into text (or vice versa).
    """
    backend = sqliteBackend()
    backend.table = "logs"
    queries = backend.convert(SigmaCollection.from_yaml(source))
    if len(queries) != 1:
        raise ValueError("qualification expects one single-event SQL query")
    rows = []
    for index, event in enumerate(events):
        values: list[Any] = [index]
        for field in FIELDS:
            value: Any = event
            for component in field.split("."):
                value = value.get(component) if isinstance(value, dict) else None
            if value is not None and not isinstance(value, (str, int, float)):
                raise ValueError(f"{field}: expected a scalar SQLite value")
            values.append(value)
        rows.append(values)
    with sqlite3.connect(":memory:") as db:
        # Column names are the fixed contract above; event data is parameterized.
        db.execute(
            "CREATE TABLE logs (event_index INTEGER,"
            + ",".join(f'"{field}" COLLATE NOCASE' for field in FIELDS)
            + ")"
        )
        db.executemany(
            "INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        return sorted(row[0] for row in db.execute(queries[0]))


def qualify(rules: dict[str, str], events: list[dict[str, Any]]) -> dict[str, int]:
    hits = {}
    for name, source in rules.items():
        local = matching_indices(parse_rule(source), events)
        independent = sqlite_hits(source, events)
        if local != independent:
            raise ValueError(
                f"{name}: backend hit identities differ: python={local}, sqlite={independent}"
            )
        hits[name] = len(local)
    return hits


def main() -> int:
    records = []
    with tempfile.TemporaryDirectory() as temporary:
        for scenario in load_scenarios(ROOT / "scenarios"):
            records.extend(load_events(write_artifacts(scenario, temporary).jsonl))
    corpus = ROOT / "tests/data/corpus/modbus"
    for name in ("core", "exception"):
        records.extend(load_events(corpus / f"{name}.jsonl"))
    rules = {d.id: d.rule_path.read_text() for d in load_registry() if d.engine == "sigma"}
    report = {
        "scope": "catalogue and external Modbus fixtures; not general SIEM equivalence",
        "events": len(records),
        "backend": version("pysigma-backend-sqlite"),
        "pysigma": version("pysigma"),
        "sqlite": sqlite3.sqlite_version,
        "authored": qualify(rules, records),
        "site_export": qualify(
            compile_policy(load_policy(ROOT / "detections/policies/bundled-demo.yaml")), records
        ),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
