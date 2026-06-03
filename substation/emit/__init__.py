"""Dual emitter: one scenario model -> PCAP + JSON (PRD §6.1, §6.4).

:func:`write_artifacts` builds the shared Modbus event list **once** from the
scenario, then hands the same list to the JSON emitter and the PCAP emitter — the
LOCKED design that guarantees the two artifacts can never drift. Both emitters run
inside :func:`~substation.emit.guard.files_only_guard`, enforcing the non-negotiable
files-only invariant: the simulator writes files and never opens a sending socket
or transmits on a live interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from substation.protocols.modbus import build_events
from substation.scenarios import Protocol, Scenario

from .guard import files_only_guard
from .json_emitter import write_jsonl
from .pcap_emitter import write_pcap

__all__ = ["EmitError", "EmitResult", "write_artifacts"]


class EmitError(RuntimeError):
    """Raised when a scenario cannot be emitted (e.g. an unsupported protocol)."""


@dataclass(frozen=True, slots=True)
class EmitResult:
    """Paths of the artifacts written for one scenario, plus the event count."""

    pcap: Path
    jsonl: Path
    event_count: int


def write_artifacts(scenario: Scenario, out_dir: str | Path) -> EmitResult:
    """Emit ``<name>.pcap`` and ``<name>.jsonl`` for ``scenario`` into ``out_dir``.

    The PCAP and JSON are produced from a single shared event model, so they stay
    in lockstep. Returns the artifact paths and the number of JSON events written.
    Files-only: emission runs under the guard and touches nothing but the
    filesystem.
    """
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    pcap = base / f"{scenario.name}.pcap"
    jsonl = base / f"{scenario.name}.jsonl"

    if scenario.protocol is not Protocol.MODBUS:
        # DNP3 and S7 emitters arrive in Phases 3/4; fail clearly until then.
        raise EmitError(
            f"emission is implemented for Modbus only; scenario {scenario.name!r} "
            f"is {scenario.protocol.value}"
        )

    events = build_events(scenario)
    with files_only_guard():
        event_count = write_jsonl(events, jsonl)
        write_pcap(events, pcap)
    return EmitResult(pcap=pcap, jsonl=jsonl, event_count=event_count)
