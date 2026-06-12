"""JSON event-log emitter: envelope records -> schema-valid ``.jsonl``.

Writes pre-built normalized-envelope records (one per protocol message) to
newline-delimited JSON (PRD §6.3). The per-protocol mapping from a scenario event to
its envelope + ICSNPP-aligned ``detail`` lives in each protocol module
(``modbus.event_to_dict`` / ``dnp3.event_to_dict``, ``docs/schema.md``); this writer
is protocol-agnostic so every protocol shares one schema-validated write path.

Every record is validated against the frozen event-log JSON Schema before it is
written; a violation raises :class:`~substation.schema.SchemaValidationError` so the
emitter can never silently produce telemetry that breaks the contract the detections
bind to. Pure Python — no scapy — so JSON-only consumers stay dependency-light.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from substation.schema import SchemaValidationError, iter_event_errors, load_event_schema

__all__ = ["write_jsonl"]


def write_jsonl(
    records: Iterable[dict[str, Any]], path: str | Path, *, validate: bool = True
) -> int:
    """Write envelope ``records`` to ``path`` as ``.jsonl``; return the number of lines.

    With ``validate`` (the default) each record is checked against the frozen schema
    before writing and a violation raises ``SchemaValidationError``. ``allow_nan=False``
    guarantees no ``NaN``/``Infinity`` barewords (which the schema gate rejects) can
    ever be emitted.
    """
    schema: dict[str, Any] | None = load_event_schema() if validate else None
    lines: list[str] = []
    for index, record in enumerate(records):
        if schema is not None:
            errors = list(iter_event_errors(record, schema))
            if errors:
                proto = record.get("proto", "?")
                name = record.get("func_name", "?")
                direction = record.get("direction", "?")
                raise SchemaValidationError(
                    f"emitted {proto} event {index} ({name}, {direction}) "
                    f"violates the event-log schema: {'; '.join(errors)}"
                )
        lines.append(json.dumps(record, allow_nan=False))

    text = "\n".join(lines)
    if lines:
        text += "\n"
    Path(path).write_text(text, encoding="utf-8")
    return len(lines)
