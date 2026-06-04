"""Dual emitter: one scenario model -> PCAP + JSON (PRD §6.1, §6.4).

:func:`write_artifacts` builds the shared per-protocol event list **once** from the
scenario, then hands the same list to the JSON emitter and the PCAP emitter — the
LOCKED design that guarantees the two artifacts can never drift. Each supported
protocol contributes a ``(build_events, event_to_dict, write_pcap)`` triple; the JSON
write/validate path is shared. Both emitters run inside
:func:`~substation.emit.guard.files_only_guard`, enforcing the non-negotiable
files-only invariant: the simulator writes files and never opens a sending socket or
transmits on a live interface.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from substation.protocols import dnp3, modbus, s7comm
from substation.scenarios import Protocol, Scenario

from .dnp3_pcap import write_pcap as write_dnp3_pcap
from .guard import files_only_guard
from .json_emitter import write_jsonl
from .pcap_emitter import write_pcap as write_modbus_pcap
from .s7comm_pcap import write_pcap as write_s7comm_pcap

__all__ = ["EmitError", "EmitResult", "write_artifacts"]


class EmitError(RuntimeError):
    """Raised when a scenario cannot be emitted (e.g. an unsupported protocol)."""


# Per-protocol emission triple: build the shared event list, render an envelope dict
# per event, and write the protocol-specific PCAP. The event types differ per
# protocol, so the triple is typed structurally (each protocol's build/render/pcap
# agree on their own event type). The JSON path is shared (write_jsonl).
_Emitter = tuple[
    Callable[[Scenario], list[Any]],
    Callable[[Any], dict[str, Any]],
    Callable[[Iterable[Any], Path], int],
]
_EMITTERS: dict[Protocol, _Emitter] = {
    Protocol.MODBUS: (modbus.build_events, modbus.event_to_dict, write_modbus_pcap),
    Protocol.DNP3: (dnp3.build_events, dnp3.event_to_dict, write_dnp3_pcap),
    Protocol.S7COMM: (s7comm.build_events, s7comm.event_to_dict, write_s7comm_pcap),
}


@dataclass(frozen=True, slots=True)
class EmitResult:
    """Paths of the artifacts written for one scenario, plus the event count."""

    pcap: Path
    jsonl: Path
    event_count: int


def write_artifacts(scenario: Scenario, out_dir: str | Path) -> EmitResult:
    """Emit ``<name>.pcap`` and ``<name>.jsonl`` for ``scenario`` into ``out_dir``.

    The PCAP and JSON are produced from a single shared event model, so they stay in
    lockstep. Returns the artifact paths and the number of JSON events written.
    Files-only: emission runs under the guard and touches nothing but the filesystem.
    """
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    pcap = base / f"{scenario.name}.pcap"
    jsonl = base / f"{scenario.name}.jsonl"

    emitter = _EMITTERS.get(scenario.protocol)
    if emitter is None:
        # All v1 protocols are wired; an unknown protocol fails clearly.
        raise EmitError(
            f"emission is not yet implemented for {scenario.protocol.value}; "
            f"scenario {scenario.name!r} (supported: "
            f"{', '.join(p.value for p in _EMITTERS)})"
        )

    build_events, event_to_dict, write_pcap = emitter
    events = build_events(scenario)
    records = [event_to_dict(event) for event in events]
    with files_only_guard():
        event_count = write_jsonl(records, jsonl)
        write_pcap(events, pcap)
    return EmitResult(pcap=pcap, jsonl=jsonl, event_count=event_count)
