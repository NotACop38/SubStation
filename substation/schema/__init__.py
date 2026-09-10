"""Event-log schema: the binding contract for Substation's `.jsonl` output.

This package ships the machine-readable JSON Schema (`event-log.schema.json`,
draft 2020-12) for one event-log line — the normalized envelope (`PRD.md` §6.3)
plus a per-protocol ``detail`` object modeled on **ICSNPP** fields (Modbus frozen
against ``docs/spikes/01-icsnpp-modbus-fields.md``). The event log is
newline-delimited JSON: one event object per line.

It also ships a small, dependency-free validator for the **subset** of JSON
Schema the contract uses, without adding a validator dependency to Tier 1.
The same schema file is standard draft-2020-12 and can be
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
import os
import re
import stat
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
    "parse_json_event",
    "iter_jsonl_lines",
    "MAX_JSONL_BYTES",
    "MAX_JSONL_LINES",
]

# Path to the packaged JSON Schema (also a normal file on disk for external tools).
EVENT_SCHEMA_PATH: Path = Path(str(files(__package__).joinpath("event-log.schema.json")))
MAX_JSONL_BYTES = 64 * 1024 * 1024
MAX_JSONL_LINES = 100_000


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


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate JSON key {key!r}")
        obj[key] = value
    return obj


def parse_json_event(raw: str) -> Any:
    """Decode a JSON line without accepting duplicate keys or non-JSON numbers."""
    try:
        return json.loads(
            raw, parse_constant=_reject_json_constant, object_pairs_hook=_unique_json_object
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the parser limit") from exc


def iter_jsonl_lines(
    path: str | Path,
    *,
    max_bytes: int = MAX_JSONL_BYTES,
    max_lines: int = MAX_JSONL_LINES,
) -> Iterator[tuple[int, str]]:
    """Read bounded UTF-8 lines from a regular file, retaining physical line numbers.

    Check the opened descriptor, not just the path. A nonblocking open avoids
    waiting for a writer if the path is a FIFO (including a raced replacement).
    Bound every read as well as the initial size, since a file may grow later.
    """
    p = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(p, flags), "rb") as fh:
        info = os.fstat(fh.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise SchemaValidationError(f"{p}: event log must be a regular file")
        if info.st_size > max_bytes:
            raise SchemaValidationError(
                f"event log {p} is {info.st_size} bytes; exceeds the {max_bytes} byte load cap"
            )
        consumed = 0
        line_no = 0
        while raw := fh.readline(max_bytes - consumed + 1):
            consumed += len(raw)
            line_no += 1
            if consumed > max_bytes:
                raise SchemaValidationError(f"event log {p} exceeds the {max_bytes} byte load cap")
            if line_no > max_lines:
                raise SchemaValidationError(f"event log {p} exceeds the {max_lines} line load cap")
            try:
                yield line_no, raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SchemaValidationError(f"{p}:{line_no}: not valid UTF-8: {exc}") from exc


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
    try:
        for lineno, raw in iter_jsonl_lines(p):
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                event = parse_json_event(stripped)
            except json.JSONDecodeError as exc:
                yield f"{p}:{lineno}: not valid JSON: {exc.msg}"
                continue
            except ValueError as exc:
                yield f"{p}:{lineno}: not valid JSON: {exc}"
                continue
            for err in _validate(event, root, "", root):
                yield f"{p}:{lineno}: {err}"
    except (OSError, SchemaValidationError) as exc:
        yield f"{p}: {exc}"


def validate_jsonl_file(path: str | Path, schema: dict[str, Any] | None = None) -> None:
    """Validate every event line in a ``.jsonl`` file; raise on the first batch of errors."""
    errors = list(iter_jsonl_errors(path, schema))
    if errors:
        raise SchemaValidationError("\n".join(errors))
