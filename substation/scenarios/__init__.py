"""Scenario model and YAML loader.

A scenario is the single source of truth for one simulator run (`PRD.md` §6.1):
it declares actors, an ordered list of protocol exchanges, timing, a
``benign|anomalous`` label, and the detection IDs it exercises. The format is
documented in ``docs/scenario-format.md`` with a fully commented example at
``scenarios/modbus/benign-poll.yaml``.
"""

from __future__ import annotations

from .loader import ScenarioError, load_scenario, load_scenarios
from .model import (
    Actor,
    ActorRole,
    Exchange,
    Exercises,
    Label,
    Protocol,
    Scenario,
    Timing,
)

__all__ = [
    "Actor",
    "ActorRole",
    "Exchange",
    "Exercises",
    "Label",
    "Protocol",
    "Scenario",
    "ScenarioError",
    "Timing",
    "load_scenario",
    "load_scenarios",
]
