"""Typed internal scenario model (Phase 0).

A *scenario* is the single source of truth for one simulator run (`PRD.md` §6.1).
It is authored as human-editable YAML under `scenarios/<proto>/` and loaded into
the immutable dataclasses below, which later phases hand to the dual emitters
(PCAP + JSON) so the two outputs can never drift.

Nothing here builds real protocol logic yet — these are the shapes the YAML
binds to. The wire-format of exchanges (`params`) is intentionally an opaque
mapping until the per-protocol encoders land in Phase 1+.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType

__all__ = [
    "Protocol",
    "Label",
    "ActorRole",
    "Actor",
    "Exchange",
    "Timing",
    "Exercises",
    "Scenario",
]

_EMPTY_PARAMS: Mapping[str, object] = MappingProxyType({})


def _empty_params() -> Mapping[str, object]:
    """Default factory: a shared immutable empty params mapping."""
    return _EMPTY_PARAMS


class Protocol(StrEnum):
    """Supported industrial protocols (PRD.md §5). v1 set is closed."""

    MODBUS = "modbus"
    DNP3 = "dnp3"
    S7COMM = "s7comm"


class Label(StrEnum):
    """Ground-truth intent of a scenario, used by the Detection Contract.

    A ``benign`` scenario must keep its ``exercises.quiet`` detections silent; an
    ``anomalous`` scenario must make its ``exercises.fires`` detections fire.
    """

    BENIGN = "benign"
    ANOMALOUS = "anomalous"


class ActorRole(StrEnum):
    """Network actor roles (PRD.md §6.4).

    Masters/HMIs/EWS initiate requests; outstations/PLCs respond. Modelling a
    legitimate writer (HMI/EWS) is required for credible allow-list and scan
    detections (PRD.md §8), so the roles are first-class.
    """

    MASTER = "master"
    HMI = "hmi"
    EWS = "ews"
    OUTSTATION = "outstation"
    PLC = "plc"


@dataclass(frozen=True, slots=True)
class Actor:
    """A named participant on the simulated network."""

    id: str
    role: ActorRole
    host: str
    port: int | None = None


@dataclass(frozen=True, slots=True)
class Exchange:
    """One ordered protocol exchange between two actors.

    ``offset`` is seconds from the scenario start (``Timing.start``). ``params``
    is an opaque per-protocol payload bag — its shape is frozen per protocol when
    the encoders land; Phase 0 treats it as free-form. It is an immutable mapping
    so no pipeline stage can mutate the shared scenario (single source of truth).
    """

    source: str
    target: str
    function: str
    offset: float = 0.0
    params: Mapping[str, object] = field(default_factory=_empty_params)


@dataclass(frozen=True, slots=True)
class Timing:
    """Scenario-level timing controls."""

    start: float = 0.0
    default_interval: float = 1.0


@dataclass(frozen=True, slots=True)
class Exercises:
    """Detection IDs this scenario is meant to exercise (the contract link).

    ``fires`` = detections that must alert on this scenario; ``quiet`` =
    detections that must stay silent. Both are detection IDs (e.g. ``M1``).
    """

    fires: tuple[str, ...] = ()
    quiet: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Scenario:
    """A complete, validated scenario — the single source of truth for a run."""

    name: str
    protocol: Protocol
    label: Label
    actors: tuple[Actor, ...]
    exchanges: tuple[Exchange, ...]
    timing: Timing = field(default_factory=Timing)
    exercises: Exercises = field(default_factory=Exercises)
    description: str = ""

    def actor(self, actor_id: str) -> Actor:
        """Look up an actor by id, raising ``KeyError`` if absent."""
        for a in self.actors:
            if a.id == actor_id:
                return a
        raise KeyError(actor_id)
