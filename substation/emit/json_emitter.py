"""JSON event-log emitter: shared Modbus events -> schema-valid ``.jsonl``.

Maps each :class:`~substation.protocols.modbus.ModbusEvent` to the normalized
envelope + ICSNPP-aligned Modbus ``detail`` defined in ``docs/schema.md`` and
writes one event per line (newline-delimited JSON, PRD §6.3).

Every emitted event is validated against the frozen event-log JSON Schema before
it is written; a violation raises :class:`~substation.schema.SchemaValidationError`
so the emitter can never silently produce telemetry that breaks the contract the
detections bind to. This is pure Python — no scapy — so JSON-only consumers stay
dependency-light.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from substation.protocols.modbus import ModbusEvent
from substation.schema import iter_event_errors, load_event_schema

__all__ = ["event_to_dict", "write_jsonl"]


def event_to_dict(event: ModbusEvent) -> dict[str, Any]:
    """Render one Modbus event as the schema's envelope + Modbus ``detail`` dict."""
    detail: dict[str, Any] = {"tid": event.tid, "unit": event.unit, "func": event.func_name}
    if event.address is not None:
        detail["address"] = event.address
    if event.quantity is not None:
        detail["quantity"] = event.quantity
    if event.request_values:
        detail["request_values"] = list(event.request_values)
    if event.response_values:
        detail["response_values"] = list(event.response_values)
    if event.exception_code is not None:
        detail["exception_code"] = event.exception_code
    if event.matched:
        detail["matched"] = True

    return {
        "ts": event.ts,
        "uid": event.uid,
        "conn": {
            "orig_h": event.orig_h,
            "orig_p": event.orig_p,
            "resp_h": event.resp_h,
            "resp_p": event.resp_p,
        },
        "proto": "modbus",
        "is_orig": event.is_orig,
        "direction": event.direction,
        "func_code": event.func_code,
        "func_name": event.func_name,
        "action_class": event.action_class,
        "is_exception": event.is_exception,
        "error": event.error,
        "detail": detail,
    }


def write_jsonl(events: Iterable[ModbusEvent], path: str | Path, *, validate: bool = True) -> int:
    """Write ``events`` to ``path`` as ``.jsonl``; return the number of lines.

    With ``validate`` (the default) each event is checked against the frozen
    schema before writing and a violation raises ``SchemaValidationError``.
    ``allow_nan=False`` guarantees no ``NaN``/``Infinity`` barewords (which the
    schema gate rejects) can ever be emitted.
    """
    from substation.schema import SchemaValidationError

    schema: dict[str, Any] | None = load_event_schema() if validate else None
    records: Sequence[ModbusEvent] = list(events)
    lines: list[str] = []
    for index, event in enumerate(records):
        record = event_to_dict(event)
        if schema is not None:
            errors = list(iter_event_errors(record, schema))
            if errors:
                raise SchemaValidationError(
                    f"emitted event {index} ({event.func_name}, {event.direction}) "
                    f"violates the event-log schema: {'; '.join(errors)}"
                )
        lines.append(json.dumps(record, allow_nan=False))

    text = "\n".join(lines)
    if lines:
        text += "\n"
    Path(path).write_text(text, encoding="utf-8")
    return len(lines)
