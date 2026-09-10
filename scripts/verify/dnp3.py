"""Compare model fields with independently decoded, message-associated DNP3 rows.

This is a fixture oracle, not a general sensor-log importer. The observer records
parser callbacks directly because Zeek's transaction log loses consecutive
requests. Timestamps, application/transport sequencing, point values and physical
device behavior are not qualified by this comparison.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any


def compare_dnp3_events(
    events: Iterable[Mapping[str, Any]], observed: Iterable[dict[str, str]]
) -> list[str]:
    """Compare headers and details, retaining message order within each connection."""
    expected: list[dict[str, str]] = []
    messages: Counter[tuple[str, ...]] = Counter()
    for event in events:
        conn = {f"id.{k}": str(event["conn"][k]) for k in ("orig_h", "orig_p", "resp_h", "resp_p")}
        key = tuple(conn.values())
        messages[key] += 1
        header = {
            **conn,
            "message": str(messages[key]),
            "kind": "header",
            "is_orig": "T" if event["is_orig"] else "F",
            "func_code": str(event["func_code"]),
            "func_name": event["func_name"],
        }
        detail = event["detail"]
        if "iin" in detail:
            header["iin"] = str(detail["iin"])
        expected.append(header)
        for kind in ("objects", "control"):
            if kind not in detail:
                continue
            fields = dict(detail[kind])
            if fields.pop("function_code") != event["func_name"]:
                raise ValueError("DNP3 detail function differs from its message header")
            expected.append(
                {
                    **header,
                    "kind": kind,
                    **{
                        k: ("T" if v else "F") if isinstance(v, bool) else str(v)
                        for k, v in fields.items()
                    },
                }
            )

    def row_key(row: dict[str, str]) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((k, v) for k, v in row.items() if v != "-"))

    want, got = Counter(map(row_key, expected)), Counter(map(row_key, observed))
    return [
        f"{dict(row)!r}: expected {want[row]}, observed {got[row]}"
        for row in sorted(want.keys() | got.keys())
        if want[row] != got[row]
    ]
