"""PCAP and JSON emitters sharing one scenario model.

Phase 0 is a NO-OP: the emitter exercises the "generate" stage of the pipeline
by writing **empty** PCAP and JSONL artifacts so the end-to-end wiring is proven
before any real protocol bytes are produced. The dual-emit design (one scenario
model -> PCAP + JSON, `PRD.md` §6.1/§6.4) lands in Phase 1.

Safety invariant (LOCKED, PRD.md §6.4): emitters **only ever write files**. They
never open a sending socket and never transmit on a live interface.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from substation.scenarios import Scenario

__all__ = ["EmitResult", "write_artifacts"]


@dataclass(frozen=True, slots=True)
class EmitResult:
    """Paths of the artifacts written for one scenario."""

    pcap: Path
    jsonl: Path
    event_count: int


def write_artifacts(scenario: Scenario, out_dir: str | Path) -> EmitResult:
    """Write (empty, Phase-0) PCAP + JSONL artifacts for ``scenario``.

    Returns the artifact paths and the number of events emitted (0 for now).
    Files-only: this function touches the filesystem and nothing else.
    """
    base = Path(out_dir)
    base.mkdir(parents=True, exist_ok=True)
    pcap = base / f"{scenario.name}.pcap"
    jsonl = base / f"{scenario.name}.jsonl"
    # Phase 0 no-op: create empty artifacts to prove the generate stage runs.
    pcap.write_bytes(b"")
    jsonl.write_text("", encoding="utf-8")
    return EmitResult(pcap=pcap, jsonl=jsonl, event_count=0)
