"""Coverage-map + ATT&CK Navigator layer builder (PRD.md §6.7).

Reads the detection registry (:mod:`substation.detect.registry`) and renders, from
that single metadata source:

* a **human-readable table** (markdown) and the same data as **JSON** — technique,
  tactic, protocol, detection ID, engine, status; and
* an **ATT&CK Navigator layer** (JSON) users can load directly into the Navigator.

All three are *generated*, never hand-maintained, so they cannot drift from the
detections (PRD.md §6.7). Rendering is deterministic — given the same registry the
byte output is identical — so ``make ci`` can diff the committed copies against a
fresh build and fail on drift (see :mod:`substation.coverage.__main__`).
"""

from __future__ import annotations

import json
from typing import Any

from substation.detect.registry import Detection, load_registry

__all__ = [
    "MARKDOWN_FILENAME",
    "JSON_FILENAME",
    "NAVIGATOR_FILENAME",
    "render_markdown",
    "render_json",
    "render_navigator_layer",
    "render_all",
]

MARKDOWN_FILENAME = "coverage.md"
JSON_FILENAME = "coverage.json"
NAVIGATOR_FILENAME = "navigator-layer.json"

# ATT&CK-for-ICS domain identifier used by the Navigator layer format.
_ATTACK_DOMAIN = "ics-attack"
# Navigator layer-format / app versions this layer targets (configuration, not an
# ATT&CK content claim). Score gradient runs pale -> strong with coverage count.
_LAYER_VERSION = "4.5"
_NAVIGATOR_VERSION = "4.9.1"
_GRADIENT_COLORS = ["#fff7b3", "#ff6f59"]


def _techniques_str(det: Detection) -> str:
    """Comma-joined technique IDs for a detection (primary first)."""
    return ", ".join(t.id for t in det.attack.techniques)


def render_markdown(detections: list[Detection]) -> str:
    """Render the human-readable coverage table as markdown."""
    lines = [
        "# Substation — ATT&CK-for-ICS coverage map",
        "",
        "> **Generated** by `python -m substation.coverage` from "
        "`detections/registry.yaml`. Do not hand-edit — rerun the generator "
        "(`make coverage-build`). `make ci` fails if this file is out of date.",
        "",
        f"Detections: **{len(detections)}**. "
        "Tier 1 = Sigma-over-JSON (zero-dep headline path); "
        "Tier 2 = Zeek/Suricata over PCAP.",
        "",
        "| Detection | Title | Protocol | Technique(s) | Tactic | Engine | Tier | Status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for det in detections:
        lines.append(
            f"| {det.id} | {det.title} | {det.protocol} | {_techniques_str(det)} "
            f"| {det.attack.tactic} ({det.attack.tactic_id}) | {det.engine} "
            f"| {det.tier} | {det.status} |"
        )
    lines.append("")
    return "\n".join(lines)


def _detection_record(det: Detection) -> dict[str, Any]:
    return {
        "id": det.id,
        "title": det.title,
        "protocol": det.protocol,
        "engine": det.engine,
        "tier": det.tier,
        "status": det.status,
        "rule": det.rule,
        "doc": det.doc,
        "tactic": det.attack.tactic,
        "tactic_id": det.attack.tactic_id,
        "techniques": [{"id": t.id, "name": t.name} for t in det.attack.techniques],
    }


def render_json(detections: list[Detection]) -> str:
    """Render the coverage table as a structured JSON document."""
    doc = {
        "schema": "substation-coverage/v1",
        "generated_by": "python -m substation.coverage",
        "domain": _ATTACK_DOMAIN,
        "detection_count": len(detections),
        "detections": [_detection_record(det) for det in detections],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _navigator_techniques(detections: list[Detection]) -> list[dict[str, Any]]:
    """Aggregate registry entries into Navigator technique objects.

    One object per (technique, tactic) pair, with a score equal to the number of
    detections covering it and metadata naming those detections. Insertion order
    follows the registry so the output is deterministic.
    """
    # key -> aggregated record; ordered by first appearance for determinism.
    agg: dict[tuple[str, str], dict[str, Any]] = {}
    for det in detections:
        shortname = det.attack.tactic_shortname
        for technique in det.attack.techniques:
            key = (technique.id, shortname)
            record = agg.get(key)
            if record is None:
                record = {
                    "techniqueID": technique.id,
                    "tactic": shortname,
                    "score": 0,
                    "color": "",
                    "comment_parts": [],
                    "metadata": [],
                    "enabled": True,
                    "showSubtechniques": False,
                }
                agg[key] = record
            record["score"] += 1
            record["comment_parts"].append(f"{det.id} — {det.title}")
            record["metadata"].append(
                {"name": det.id, "value": f"{det.engine}/tier{det.tier}, {det.status}"}
            )

    techniques: list[dict[str, Any]] = []
    for record in agg.values():
        comment = "; ".join(record.pop("comment_parts"))
        techniques.append(
            {
                "techniqueID": record["techniqueID"],
                "tactic": record["tactic"],
                "score": record["score"],
                "color": record["color"],
                "comment": comment,
                "enabled": record["enabled"],
                "metadata": record["metadata"],
                "showSubtechniques": record["showSubtechniques"],
            }
        )
    return techniques


def render_navigator_layer(detections: list[Detection]) -> str:
    """Render an ATT&CK Navigator layer (ics-attack) covering the detections."""
    techniques = _navigator_techniques(detections)
    max_score = max((t["score"] for t in techniques), default=1)
    layer = {
        "name": "Substation ICS detection coverage",
        "versions": {"layer": _LAYER_VERSION, "navigator": _NAVIGATOR_VERSION},
        "domain": _ATTACK_DOMAIN,
        "description": (
            "Auto-generated by Substation (python -m substation.coverage) from "
            "detections/registry.yaml. Score = number of detections mapped to the "
            "technique."
        ),
        "techniques": techniques,
        "gradient": {
            "colors": _GRADIENT_COLORS,
            "minValue": 0,
            # Avoid a degenerate min==max gradient when only single-cover techniques exist.
            "maxValue": max(max_score, 1),
        },
        "legendItems": [],
        "showTacticRowBackground": False,
        "hideDisabled": False,
    }
    return json.dumps(layer, indent=2, ensure_ascii=False) + "\n"


def render_all(detections: list[Detection] | None = None) -> dict[str, str]:
    """Render every coverage artifact; return ``{filename: content}``.

    Loads the registry when ``detections`` is not supplied.
    """
    dets = load_registry() if detections is None else detections
    return {
        MARKDOWN_FILENAME: render_markdown(dets),
        JSON_FILENAME: render_json(dets),
        NAVIGATOR_FILENAME: render_navigator_layer(dets),
    }
