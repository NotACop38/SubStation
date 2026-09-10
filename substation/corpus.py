"""Offline, labeled regression metrics with checked artifact provenance."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from substation.detect import load_events, run_detections
from substation.detect.registry import load_registry
from substation.policy import load_policy
from substation.schema import SchemaValidationError, iter_jsonl_lines, parse_json_event


def _file(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise SchemaValidationError("corpus paths must be local artifact basenames")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise SchemaValidationError(f"corpus artifact must be a regular local file: {name}")
    return path


def evaluate_corpus(root: Path) -> dict[str, Any]:
    """Report per-event confusion counts for every explicitly labeled rule/case.

    Unlisted rules are unevaluated. Every event in a listed rule is labeled: the
    positive index list identifies positives and its complement is negative.
    A repeated capture under another policy is another case, not independent data.
    """
    try:
        raw = "".join(
            line for _, line in iter_jsonl_lines(root / "manifest.json", max_bytes=1048576)
        )
        manifest = parse_json_event(raw)
        if not isinstance(manifest, dict) or manifest.get("schema") != "substation-corpus/v1":
            raise ValueError("unsupported corpus manifest")
        artifacts = manifest["artifacts"]
        if not isinstance(artifacts, dict) or not 1 <= len(artifacts) <= 128:
            raise ValueError("expected 1..128 hashed artifacts")
        for name, expected in artifacts.items():
            path = _file(root, name)
            if not isinstance(expected, str) or not re.fullmatch("[a-f0-9]{64}", expected):
                raise ValueError(f"invalid artifact hash: {name}")
            if path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("corpus artifact exceeds 64 MiB")
            with path.open("rb") as stream:
                observed = hashlib.file_digest(stream, "sha256").hexdigest()
            if observed != expected:
                raise ValueError(f"corpus artifact hash mismatch: {name}")
        cases = manifest["cases"]
        if not isinstance(cases, list) or not 1 <= len(cases) <= 128:
            raise ValueError("expected 1..128 labeled cases")
        totals: dict[str, dict[str, Any]] = {}
        ids: set[str] = set()
        event_count = 0
        results = []
        eligible = {
            det.id: det for det in load_registry() if det.tier == 1 and det.engine == "sigma"
        }
        for case in cases:
            if not isinstance(case, dict) or case.keys() != {
                "id",
                "events",
                "capture",
                "policy",
                "positive",
                "label_basis",
            }:
                raise ValueError("case requires id/events/capture/policy/positive/label_basis")
            if not isinstance(case["id"], str) or not case["id"] or case["id"] in ids:
                raise ValueError("case ids must be nonempty and unique")
            ids.add(case["id"])
            for key in ("events", "capture", "policy"):
                _file(root, case[key])
                if case[key] not in artifacts:
                    raise ValueError(f"case {key} lacks an artifact hash")
            if not isinstance(case["label_basis"], str) or not case["label_basis"]:
                raise ValueError("case needs an explicit label basis")
            events = load_events(root / case["events"])
            if not events:
                raise ValueError("empty event corpus is not validation evidence")
            positive = case["positive"]
            if not isinstance(positive, dict) or not positive or positive.keys() - eligible.keys():
                raise ValueError("positive labels must name supported Tier-1 rules")
            for name, indices in positive.items():
                if (
                    not isinstance(indices, list)
                    or any(type(i) is not int or not 0 <= i < len(events) for i in indices)
                    or len(indices) != len(set(indices))
                ):
                    raise ValueError(
                        f"{name}: positive indices must be unique integers within the event log"
                    )
            policy = load_policy(root / case["policy"])
            hits = run_detections(
                root / case["events"], [eligible[name] for name in positive], policy=policy
            )
            case_result = {}
            for name, indices in positive.items():
                want = set(indices)
                got = {hit.event_index for hit in hits if hit.detection_id == name}
                counts = {
                    "tp": len(want & got),
                    "fp": len(got - want),
                    "fn": len(want - got),
                    "tn": len(events) - len(want | got),
                }
                case_result[name] = counts
                total = totals.setdefault(name, dict.fromkeys(("tp", "fp", "fn", "tn"), 0))
                for key, value in counts.items():
                    total[key] += value
            event_count += len(events)
            results.append(
                {"id": case["id"], "event_count": len(events), "detections": case_result}
            )
        for total in totals.values():
            for key, numerator, denominator in [
                ("precision", total["tp"], total["tp"] + total["fp"]),
                ("recall", total["tp"], total["tp"] + total["fn"]),
                ("false_positive_rate", total["fp"], total["fp"] + total["tn"]),
            ]:
                total[key] = numerator / denominator if denominator else None
        return {
            "schema": "substation-corpus-report/v1",
            "case_count": len(cases),
            "event_evaluations": event_count,
            "detections": totals,
            "cases": results,
            "passed": all(v["fp"] == v["fn"] == 0 for v in totals.values()),
            "scope": (
                "Labeled regression cases; reused captures and policy counterfactuals "
                "are not field effectiveness estimates."
            ),
        }
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        raise SchemaValidationError(f"{root}: invalid corpus: {exc}") from exc
