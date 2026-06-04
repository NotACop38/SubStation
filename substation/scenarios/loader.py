"""Scenario YAML loader (Phase 0).

Parses a human-editable scenario file into the typed :mod:`model`. The loader is
strict: it rejects unknown top-level keys, unknown actor roles/protocols/labels,
and exchanges that reference actors not declared in the scenario. Every failure
raises :class:`ScenarioError` with a path-prefixed message so authoring mistakes
are obvious.

See ``docs/scenario-format.md`` and the fully commented example at
``scenarios/modbus/benign-poll.yaml`` for the format.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType

import yaml

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

__all__ = ["ScenarioError", "load_scenario", "load_scenarios"]

_SCENARIO_KEYS = {
    "name",
    "description",
    "protocol",
    "label",
    "actors",
    "exchanges",
    "timing",
    "exercises",
}
_ACTOR_KEYS = {"id", "role", "host", "port"}
_EXCHANGE_KEYS = {"source", "target", "function", "offset", "params"}
_TIMING_KEYS = {"start", "default_interval"}
_EXERCISES_KEYS = {"fires", "quiet"}

# A scenario name is used to derive artifact filenames (artifacts/<name>.pcap),
# so it must be a filesystem-safe basename: no path separators, no traversal.
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


class ScenarioError(ValueError):
    """Raised when a scenario file is malformed or internally inconsistent."""


class _StrictLoader(yaml.SafeLoader):  # type: ignore[misc]  # yaml is untyped (Any base)
    """A safe YAML loader that rejects duplicate mapping keys.

    PyYAML's default safe loader silently keeps the *last* value when a key is
    repeated, so a hand-authored scenario with two ``label:`` (or ``exercises:``)
    blocks could quietly change the Detection Contract. The strict loader makes
    that a parse error instead.
    """


def _construct_mapping_no_duplicates(
    loader: _StrictLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[object, object]:
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_no_duplicates,
)


def _require_mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ScenarioError(f"{where}: expected a mapping, got {type(value).__name__}")
    return {str(k): v for k, v in value.items()}


def _reject_unknown(mapping: dict[str, object], allowed: set[str], where: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise ScenarioError(f"{where}: unknown key(s) {sorted(unknown)}; allowed {sorted(allowed)}")


def _require_str(mapping: dict[str, object], key: str, where: str) -> str:
    if key not in mapping:
        raise ScenarioError(f"{where}: missing required key '{key}'")
    value = mapping[key]
    if not isinstance(value, str) or not value:
        raise ScenarioError(f"{where}.{key}: expected a non-empty string")
    return value


def _opt_number(mapping: dict[str, object], key: str, where: str, default: float) -> float:
    if key not in mapping:
        return default
    value = mapping[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ScenarioError(f"{where}.{key}: expected a number")
    return float(value)


def _str_tuple(value: object, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ScenarioError(f"{where}: expected a list of strings")
    out: list[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item:
            raise ScenarioError(f"{where}[{i}]: expected a non-empty string")
        out.append(item)
    return tuple(out)


def _deep_freeze(value: object) -> object:
    """Recursively make a parsed params value immutable.

    ``MappingProxyType`` only protects the top level, so a nested mapping/list in
    ``params`` could still be mutated through the shared scenario — breaking the
    single-source-of-truth invariant and letting the PCAP and JSON emitters
    observe different data. Freeze mappings to read-only proxies and lists to
    tuples, all the way down.
    """
    if isinstance(value, dict):
        return MappingProxyType({str(k): _deep_freeze(v) for k, v in value.items()})
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _freeze_params(params: dict[str, object]) -> Mapping[str, object]:
    """Deep-freeze a params mapping into an immutable ``Mapping``."""
    return MappingProxyType({k: _deep_freeze(v) for k, v in params.items()})


def _parse_actor(raw: object, where: str) -> Actor:
    data = _require_mapping(raw, where)
    _reject_unknown(data, _ACTOR_KEYS, where)
    role_str = _require_str(data, "role", where)
    try:
        role = ActorRole(role_str)
    except ValueError:
        valid = [r.value for r in ActorRole]
        raise ScenarioError(f"{where}.role: unknown role '{role_str}'; valid {valid}") from None
    port_raw = data.get("port")
    port: int | None = None
    if port_raw is not None:
        if isinstance(port_raw, bool) or not isinstance(port_raw, int):
            raise ScenarioError(f"{where}.port: expected an integer")
        # A TCP/Zeek endpoint must be in range; an out-of-range port here would
        # later produce PCAP/JSON that violates the event schema's 0–65535 bound.
        if not 0 <= port_raw <= 65535:
            raise ScenarioError(f"{where}.port: {port_raw} out of range (0–65535)")
        port = port_raw
    return Actor(
        id=_require_str(data, "id", where),
        role=role,
        host=_require_str(data, "host", where),
        port=port,
    )


def _parse_exchange(raw: object, where: str) -> Exchange:
    data = _require_mapping(raw, where)
    _reject_unknown(data, _EXCHANGE_KEYS, where)
    params_raw = data.get("params")
    # Only an absent or explicit-null params defaults to empty; any present value
    # (including falsy ones like [] or 0) must be a real mapping.
    params = {} if params_raw is None else _require_mapping(params_raw, f"{where}.params")
    # An omitted offset is left as None so the emitter can auto-space the exchange
    # by Timing.default_interval; an explicit value (including 0.0) is preserved.
    offset = _opt_number(data, "offset", where, 0.0) if "offset" in data else None
    return Exchange(
        source=_require_str(data, "source", where),
        target=_require_str(data, "target", where),
        function=_require_str(data, "function", where),
        offset=offset,
        params=_freeze_params(params),
    )


def _parse_timing(raw: object) -> Timing:
    if raw is None:
        return Timing()
    data = _require_mapping(raw, "timing")
    _reject_unknown(data, _TIMING_KEYS, "timing")
    return Timing(
        start=_opt_number(data, "start", "timing", 0.0),
        default_interval=_opt_number(data, "default_interval", "timing", 1.0),
    )


def _parse_exercises(raw: object) -> Exercises:
    if raw is None:
        return Exercises()
    data = _require_mapping(raw, "exercises")
    _reject_unknown(data, _EXERCISES_KEYS, "exercises")
    fires = _str_tuple(data.get("fires"), "exercises.fires")
    quiet = _str_tuple(data.get("quiet"), "exercises.quiet")
    # A detection cannot be required to both fire and stay quiet on one run.
    both = set(fires) & set(quiet)
    if both:
        raise ScenarioError(
            f"exercises: detection(s) {sorted(both)} listed in both 'fires' and 'quiet'"
        )
    return Exercises(fires=fires, quiet=quiet)


def _parse_scenario(raw: object) -> Scenario:
    data = _require_mapping(raw, "scenario")
    _reject_unknown(data, _SCENARIO_KEYS, "scenario")

    protocol_str = _require_str(data, "protocol", "scenario")
    try:
        protocol = Protocol(protocol_str)
    except ValueError:
        valid = [p.value for p in Protocol]
        raise ScenarioError(
            f"scenario.protocol: unknown protocol '{protocol_str}'; valid {valid}"
        ) from None

    label_str = _require_str(data, "label", "scenario")
    try:
        label = Label(label_str)
    except ValueError:
        valid = [item.value for item in Label]
        raise ScenarioError(f"scenario.label: unknown label '{label_str}'; valid {valid}") from None

    actors_raw = data.get("actors")
    if not isinstance(actors_raw, list) or not actors_raw:
        raise ScenarioError("scenario.actors: expected a non-empty list")
    actors = tuple(_parse_actor(a, f"actors[{i}]") for i, a in enumerate(actors_raw))
    actor_ids = {a.id for a in actors}
    if len(actor_ids) != len(actors):
        raise ScenarioError("scenario.actors: duplicate actor id(s)")

    exchanges_raw = data.get("exchanges")
    if not isinstance(exchanges_raw, list):
        raise ScenarioError("scenario.exchanges: expected a list")
    exchanges = tuple(_parse_exchange(e, f"exchanges[{i}]") for i, e in enumerate(exchanges_raw))
    for i, ex in enumerate(exchanges):
        if ex.source not in actor_ids:
            raise ScenarioError(f"exchanges[{i}].source: unknown actor '{ex.source}'")
        if ex.target not in actor_ids:
            raise ScenarioError(f"exchanges[{i}].target: unknown actor '{ex.target}'")

    name = _require_str(data, "name", "scenario")
    if not _SAFE_NAME.match(name):
        raise ScenarioError(
            f"scenario.name: '{name}' is not a filesystem-safe basename "
            "(allowed: letters, digits, '.', '_', '-'; no path separators)"
        )

    return Scenario(
        name=name,
        protocol=protocol,
        label=label,
        actors=actors,
        exchanges=exchanges,
        timing=_parse_timing(data.get("timing")),
        exercises=_parse_exercises(data.get("exercises")),
        description=str(data.get("description", "")),
    )


def load_scenario(path: str | Path) -> Scenario:
    """Load and validate a single scenario YAML file."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ScenarioError(f"{p}: cannot read scenario file: {exc}") from exc
    try:
        # _StrictLoader is a SafeLoader subclass (no arbitrary object construction)
        # that additionally rejects duplicate mapping keys; this is as safe as
        # yaml.safe_load. noqa/nosec silence the ruff/bandit yaml.load heuristics,
        # which only whitelist the loader by name.
        raw = yaml.load(text, Loader=_StrictLoader)  # noqa: S506  # nosec B506
    except yaml.YAMLError as exc:
        raise ScenarioError(f"{p}: invalid YAML: {exc}") from exc
    if raw is None:
        raise ScenarioError(f"{p}: empty scenario file")
    try:
        return _parse_scenario(raw)
    except ScenarioError as exc:
        raise ScenarioError(f"{p}: {exc}") from None


def load_scenarios(directory: str | Path) -> list[Scenario]:
    """Load every ``*.yaml`` / ``*.yml`` scenario under ``directory`` (sorted)."""
    base = Path(directory)
    files = sorted(p for p in base.rglob("*") if p.suffix in {".yaml", ".yml"})
    return [load_scenario(p) for p in files]
