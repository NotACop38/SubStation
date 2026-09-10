"""S7 fixture oracle for the pinned ICSNPP S7comm 1.3.0 log representation.

Compare every modeled detail and each COTP frame, ordered within a connection
and log. This does not reconstruct arbitrary sensor sessions or qualify timing,
variable values, downloaded programs or S7-plus integrity/object semantics.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

LOGS = (
    "cotp.log",
    "s7comm.log",
    "s7comm_read_szl.log",
    "s7comm_upload_download.log",
    "s7comm_plus.log",
)


def compare_s7_events(
    events: Iterable[Mapping[str, Any]], observed: Mapping[str, list[dict[str, str]]]
) -> list[str]:
    """Fail on missing, extra, reordered or changed message/detail observations.

    ICSNPP 1.3.0 byte-swaps the PDU reference. The model/wire remain big-endian
    (also Wireshark's interpretation); apply that known transform to expectations,
    never accept either byte order opportunistically. See spike 09.
    """
    expected: dict[str, list[dict[str, str]]] = {name: [] for name in LOGS}
    for event in events:
        conn = event["conn"]
        source, target = ("orig", "resp") if event["is_orig"] else ("resp", "orig")
        identity = {
            **{f"id.{k}": str(conn[k]) for k in ("orig_h", "orig_p", "resp_h", "resp_p")},
            "is_orig": "T" if event["is_orig"] else "F",
            "source_h": conn[f"{source}_h"],
            "source_p": str(conn[f"{source}_p"]),
            "destination_h": conn[f"{target}_h"],
            "destination_p": str(conn[f"{target}_p"]),
        }
        detail = dict(event["detail"])
        cotp = detail.pop("cotp", {"pdu_code": "0x0f", "pdu_name": "DT Data"})
        expected["cotp.log"].append({**identity, **cotp})
        if not detail:
            continue
        plus = detail.pop("plus", None)
        if plus is not None:
            expected["s7comm_plus.log"].append({**identity, **{k: str(v) for k, v in plus.items()}})
            continue
        reference = int(detail["pdu_reference"])
        reference = ((reference & 0xFF) << 8) | (reference >> 8)
        detail["pdu_reference"] = reference
        for key in ("read_szl", "upload_download"):
            sub = detail.pop(key, None)
            if sub is not None:
                expected[f"s7comm_{key}.log"].append(
                    {
                        **identity,
                        "pdu_reference": str(reference),
                        **{k: str(v) for k, v in sub.items()},
                    }
                )
        expected["s7comm.log"].append({**identity, **{k: str(v) for k, v in detail.items()}})

    def rows_by_connection(rows: list[dict[str, str]]) -> Counter[tuple[tuple[str, str], ...]]:
        counts: Counter[tuple[str, ...]] = Counter()
        result: Counter[tuple[tuple[str, str], ...]] = Counter()
        for row in rows:
            conn = tuple(row[k] for k in ("id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p"))
            counts[conn] += 1
            clean = {k: v for k, v in row.items() if k not in ("ts", "uid") and v != "-"}
            clean["message"] = str(counts[conn])
            result[tuple(sorted(clean.items()))] += 1
        return result

    differences = []
    for name in sorted(set(LOGS) | observed.keys()):
        want = rows_by_connection(expected.get(name, []))
        got = rows_by_connection(observed.get(name, []))
        for row in sorted(want.keys() | got.keys()):
            if want[row] != got[row]:
                differences.append(
                    f"{name} {dict(row)!r}: expected {want[row]}, observed {got[row]}"
                )
    return differences
