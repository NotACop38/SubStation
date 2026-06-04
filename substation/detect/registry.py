"""Detection registry: the typed view of ``detections/registry.yaml``.

The registry is the authoritative, machine-readable metadata index for every
shipped detection (PRD.md §6.6 "coverage-map entry"). Both the Tier-1 pytest
harness and the coverage generator (PRD.md §6.7) load it through here, so the
coverage map and Navigator layer are generated from one source and cannot drift
from the detections.

The loader is strict — unknown keys, unknown enums, duplicate IDs, and malformed
ATT&CK mappings all raise :class:`RegistryError` with an actionable message — for
the same reason the scenario loader is: a silent metadata mistake would quietly
corrupt the coverage map and the Detection Contract checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

__all__ = [
    "RegistryError",
    "Technique",
    "AttackMapping",
    "Detection",
    "REGISTRY_PATH",
    "REPO_ROOT",
    "load_registry",
]

# substation/detect/registry.py -> parents[2] is the repo root. detections/ and
# scenarios/ live outside the package (PRD.md §6.9), so they resolve from here.
REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = REPO_ROOT / "detections" / "registry.yaml"

_ENGINES = {"sigma", "zeek", "suricata"}
_TIERS = {1, 2}
_STATUSES = {"validated", "partial", "tier2", "experimental"}
_PROTOCOLS = {"modbus", "dnp3", "s7comm"}

_DETECTION_KEYS = {"id", "title", "protocol", "engine", "tier", "status", "rule", "doc", "attack"}
_ATTACK_KEYS = {"tactic", "tactic_id", "techniques"}
_TECHNIQUE_KEYS = {"id", "name"}


class RegistryError(ValueError):
    """Raised when the detection registry is malformed or internally inconsistent."""


@dataclass(frozen=True, slots=True)
class Technique:
    """One ATT&CK-for-ICS technique mapping (verified ID + name)."""

    id: str
    name: str


@dataclass(frozen=True, slots=True)
class AttackMapping:
    """A detection's ATT&CK-for-ICS mapping: one tactic, one or more techniques."""

    tactic: str
    tactic_id: str
    techniques: tuple[Technique, ...]

    @property
    def primary(self) -> Technique:
        """The primary technique (first listed)."""
        return self.techniques[0]

    @property
    def tactic_shortname(self) -> str:
        """ATT&CK Navigator tactic shortname, e.g. ``impair-process-control``."""
        return self.tactic.lower().replace(" ", "-")


@dataclass(frozen=True, slots=True)
class Detection:
    """One shipped detection's metadata — the registry's unit."""

    id: str
    title: str
    protocol: str
    engine: str
    tier: int
    status: str
    rule: str
    doc: str
    attack: AttackMapping

    @property
    def rule_path(self) -> Path:
        """Absolute path to the authored rule file."""
        return REPO_ROOT / self.rule

    @property
    def doc_path(self) -> Path:
        """Absolute path to the Detection Contract doc."""
        return REPO_ROOT / self.doc


def _require_mapping(value: object, where: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise RegistryError(f"{where}: expected a mapping, got {type(value).__name__}")
    return {str(k): v for k, v in value.items()}


def _reject_unknown(mapping: dict[str, object], allowed: set[str], where: str) -> None:
    unknown = set(mapping) - allowed
    if unknown:
        raise RegistryError(f"{where}: unknown key(s) {sorted(unknown)}; allowed {sorted(allowed)}")


def _require_str(mapping: dict[str, object], key: str, where: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise RegistryError(f"{where}.{key}: expected a non-empty string")
    return value


def _parse_technique(raw: object, where: str) -> Technique:
    data = _require_mapping(raw, where)
    _reject_unknown(data, _TECHNIQUE_KEYS, where)
    return Technique(id=_require_str(data, "id", where), name=_require_str(data, "name", where))


def _parse_attack(raw: object, where: str) -> AttackMapping:
    data = _require_mapping(raw, where)
    _reject_unknown(data, _ATTACK_KEYS, where)
    techniques_raw = data.get("techniques")
    if not isinstance(techniques_raw, list) or not techniques_raw:
        raise RegistryError(f"{where}.techniques: expected a non-empty list")
    techniques = tuple(
        _parse_technique(t, f"{where}.techniques[{i}]") for i, t in enumerate(techniques_raw)
    )
    return AttackMapping(
        tactic=_require_str(data, "tactic", where),
        tactic_id=_require_str(data, "tactic_id", where),
        techniques=techniques,
    )


def _parse_detection(raw: object, where: str) -> Detection:
    data = _require_mapping(raw, where)
    _reject_unknown(data, _DETECTION_KEYS, where)

    det_id = _require_str(data, "id", where)
    protocol = _require_str(data, "protocol", where)
    if protocol not in _PROTOCOLS:
        raise RegistryError(f"{where}.protocol: unknown protocol {protocol!r}; valid {_PROTOCOLS}")
    engine = _require_str(data, "engine", where)
    if engine not in _ENGINES:
        raise RegistryError(f"{where}.engine: unknown engine {engine!r}; valid {_ENGINES}")
    tier = data.get("tier")
    if isinstance(tier, bool) or not isinstance(tier, int) or tier not in _TIERS:
        raise RegistryError(f"{where}.tier: expected one of {sorted(_TIERS)}")
    status = _require_str(data, "status", where)
    if status not in _STATUSES:
        raise RegistryError(f"{where}.status: unknown status {status!r}; valid {_STATUSES}")

    return Detection(
        id=det_id,
        title=_require_str(data, "title", where),
        protocol=protocol,
        engine=engine,
        tier=tier,
        status=status,
        rule=_require_str(data, "rule", where),
        doc=_require_str(data, "doc", where),
        attack=_parse_attack(data.get("attack"), f"{where}.attack"),
    )


def load_registry(path: str | Path = REGISTRY_PATH) -> list[Detection]:
    """Load and validate the detection registry, preserving file order."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise RegistryError(f"{p}: cannot read registry: {exc}") from exc
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RegistryError(f"{p}: invalid YAML: {exc}") from exc

    data = _require_mapping(raw, str(p))
    _reject_unknown(data, {"detections"}, str(p))
    entries = data.get("detections")
    if not isinstance(entries, list) or not entries:
        raise RegistryError(f"{p}.detections: expected a non-empty list")

    detections = [_parse_detection(e, f"detections[{i}]") for i, e in enumerate(entries)]
    seen: set[str] = set()
    for det in detections:
        if det.id in seen:
            raise RegistryError(f"{p}: duplicate detection id {det.id!r}")
        seen.add(det.id)
    return detections
