"""Event-log schema: the binding contract for Substation's `.jsonl` output.

This package ships the machine-readable JSON Schema (`event-log.schema.json`,
draft 2020-12) for one event-log line — the normalized envelope (`PRD.md` §6.3)
plus a per-protocol ``detail`` object modeled on **ICSNPP** fields (Modbus frozen
against ``docs/spikes/01-icsnpp-modbus-fields.md``). The event log is
newline-delimited JSON: one event object per line.

It also ships a small, dependency-free validator for the **subset** of JSON
Schema the contract uses, so the Tier-1 headline path stays zero-dep (only
Python; `PRD.md` §6.2). The same schema file is standard draft-2020-12 and can be
fed to any external validator (e.g. ``jsonschema``) unchanged.

Supported keywords: ``type`` (incl. type arrays), ``enum``, ``const``,
``required``, ``properties``, ``additionalProperties`` (bool/schema), ``items``,
``minItems``/``maxItems``, ``minimum``/``maximum``, ``minLength``/``maxLength``,
``pattern``, local ``$ref`` (``#/$defs/NAME``), ``allOf``/``anyOf``/``oneOf`` and
``if``/``then``/``else``. Annotation keywords (``$schema``, ``$id``, ``title``,
``description``) are ignored.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable, Iterator
from importlib.resources import files
from pathlib import Path
from typing import Any

__all__ = [
    "EVENT_SCHEMA_PATH",
    "SchemaValidationError",
    "load_event_schema",
    "iter_event_errors",
    "validate_event",
    "iter_jsonl_errors",
    "validate_jsonl_file",
]

# Path to the packaged JSON Schema (also a normal file on disk for external tools).
EVENT_SCHEMA_PATH: Path = Path(str(files(__package__).joinpath("event-log.schema.json")))


# JSON Schema "type" -> Python predicate. ``bool`` is a subclass of ``int`` in
# Python, so integer/number must explicitly exclude it. JSON numbers are finite:
# NaN and +/-Infinity are not valid JSON values and must not satisfy ``number``.
def _is_json_number(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return True
    return isinstance(value, float) and math.isfinite(value)


_TYPE_CHECKS: dict[str, Callable[[Any], bool]] = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": _is_json_number,
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}


class SchemaValidationError(ValueError):
    """Raised when an event (or jsonl file) violates the event-log schema."""


def load_event_schema() -> dict[str, Any]:
    """Load and parse the packaged event-log JSON Schema."""
    text = EVENT_SCHEMA_PATH.read_text(encoding="utf-8")
    schema: dict[str, Any] = json.loads(text)
    return schema


def _reject_json_constant(constant: str) -> Any:
    """``json.loads`` ``parse_constant`` hook: refuse NaN/Infinity barewords."""
    raise ValueError(f"non-standard JSON constant {constant!r}")


def _type_name(value: Any) -> str:
    for name, check in _TYPE_CHECKS.items():
        if check(value):
            return name
    return type(value).__name__


def _resolve_ref(ref: str, root: dict[str, Any]) -> dict[str, Any]:
    if not ref.startswith("#/"):
        raise SchemaValidationError(f"unsupported $ref (only local '#/...' refs): {ref!r}")
    node: Any = root
    for token in ref[2:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(node, dict) or token not in node:
            raise SchemaValidationError(f"unresolvable $ref: {ref!r}")
        node = node[token]
    if not isinstance(node, dict):
        raise SchemaValidationError(f"$ref does not point to a schema object: {ref!r}")
    return node


def _has_errors(value: Any, schema: dict[str, Any], root: dict[str, Any]) -> bool:
    """True if ``value`` violates ``schema`` (used by anyOf/oneOf/if)."""
    return next(_validate(value, schema, "", root), None) is not None


def _validate(value: Any, schema: dict[str, Any], path: str, root: dict[str, Any]) -> Iterator[str]:
    """Yield human-readable error strings for ``value`` against ``schema``.

    ``path`` is a JSON-pointer-ish location used only in messages.
    """
    loc = path or "<root>"

    if "$ref" in schema:
        yield from _validate(value, _resolve_ref(schema["$ref"], root), path, root)

    if "type" in schema:
        types = schema["type"]
        types = [types] if isinstance(types, str) else types
        if not any(_TYPE_CHECKS[t](value) for t in types):
            yield f"{loc}: expected type {' | '.join(types)}, got {_type_name(value)}"
            return  # further keywords assume the type matched

    if "const" in schema and value != schema["const"]:
        yield f"{loc}: expected const {schema['const']!r}, got {value!r}"

    if "enum" in schema and value not in schema["enum"]:
        yield f"{loc}: {value!r} not in enum {schema['enum']!r}"

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            yield f"{loc}: string shorter than minLength {schema['minLength']}"
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            yield f"{loc}: string longer than maxLength {schema['maxLength']}"
        if "pattern" in schema and re.search(schema["pattern"], value) is None:
            yield f"{loc}: string does not match pattern {schema['pattern']!r}"

    if isinstance(value, int | float) and not isinstance(value, bool):
        if not _is_json_number(value):
            yield f"{loc}: non-finite number {value!r} is not valid JSON"
            return
        if "minimum" in schema and value < schema["minimum"]:
            yield f"{loc}: {value} < minimum {schema['minimum']}"
        if "maximum" in schema and value > schema["maximum"]:
            yield f"{loc}: {value} > maximum {schema['maximum']}"

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            yield f"{loc}: array shorter than minItems {schema['minItems']}"
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            yield f"{loc}: array longer than maxItems {schema['maxItems']}"
        if "items" in schema:
            for i, item in enumerate(value):
                yield from _validate(item, schema["items"], f"{path}[{i}]", root)

    if isinstance(value, dict):
        props: dict[str, Any] = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                yield f"{loc}: missing required property {key!r}"
        for key, val in value.items():
            sub = f"{path}.{key}" if path else key
            if key in props:
                yield from _validate(val, props[key], sub, root)
            else:
                add = schema.get("additionalProperties", True)
                if add is False:
                    yield f"{loc}: unexpected property {key!r}"
                elif isinstance(add, dict):
                    yield from _validate(val, add, sub, root)

    for sub in schema.get("allOf", []):
        yield from _validate(value, sub, path, root)

    if "anyOf" in schema and not any(not _has_errors(value, sub, root) for sub in schema["anyOf"]):
        yield f"{loc}: does not match any schema in anyOf"

    if "oneOf" in schema:
        matched = sum(not _has_errors(value, sub, root) for sub in schema["oneOf"])
        if matched != 1:
            yield f"{loc}: matched {matched} schemas in oneOf (expected exactly 1)"

    if "if" in schema:
        branch = "then" if not _has_errors(value, schema["if"], root) else "else"
        if branch in schema:
            yield from _validate(value, schema[branch], path, root)


def iter_event_errors(event: Any, schema: dict[str, Any] | None = None) -> Iterator[str]:
    """Yield every schema violation for a single decoded ``event`` object."""
    root = schema if schema is not None else load_event_schema()
    yield from _validate(event, root, "", root)


def validate_event(event: Any, schema: dict[str, Any] | None = None) -> None:
    """Validate one decoded event object; raise ``SchemaValidationError`` if invalid."""
    errors = list(iter_event_errors(event, schema))
    if errors:
        raise SchemaValidationError("; ".join(errors))


def iter_jsonl_errors(path: str | Path, schema: dict[str, Any] | None = None) -> Iterator[str]:
    """Yield ``"<file>:<line>: <error>"`` for every violation in a ``.jsonl`` file.

    Blank lines are skipped. A line that is not valid JSON is itself an error.
    The non-standard ``NaN``/``Infinity``/``-Infinity`` constants (which Python's
    ``json.dumps`` emits by default) are rejected like any other malformed line —
    otherwise they parse to floats whose comparisons silently pass every numeric
    bound and slip through the gate.
    """
    root = schema if schema is not None else load_event_schema()
    p = Path(path)
    with p.open(encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped, parse_constant=_reject_json_constant)
            except json.JSONDecodeError as exc:
                yield f"{p}:{lineno}: not valid JSON: {exc.msg}"
                continue
            except ValueError as exc:
                yield f"{p}:{lineno}: not valid JSON: {exc}"
                continue
            for err in _validate(event, root, "", root):
                yield f"{p}:{lineno}: {err}"


def validate_jsonl_file(path: str | Path, schema: dict[str, Any] | None = None) -> None:
    """Validate every event line in a ``.jsonl`` file; raise on the first batch of errors."""
    errors = list(iter_jsonl_errors(path, schema))
    if errors:
        raise SchemaValidationError("\n".join(errors))
