"""Tier-1 Sigma offline evaluator: run a Sigma rule directly over event dicts.

This is the mechanism the Sigma evaluation spike confirmed
(`docs/spikes/03-sigma-offline-evaluation.md`): pySigma parses a rule's YAML into
a typed boolean condition tree (``ConditionAND``/``OR``/``NOT`` with
``ConditionFieldEqualsValueExpression`` leaves); a small recursive evaluator walks
that tree over each JSON event. Zero SIEM, in-process, pure Python — the Tier-1
path (docs/design.md §6.2). A SIEM deployment still needs a tested backend, field
normalization and site policy; this evaluator is a deliberate subset.

Supported: field equality and the numeric comparison modifiers ``|gt``, ``|gte``,
``|lt`` and ``|lte``, with dotted-path lookup into the envelope (``conn.orig_h``,
``detail.unit``, ...), boolean logic, and ``1 of``/``all of`` selections (pySigma
expands those). Equality is typed, as in the SQLite backend the project compares
against: a quoted rule value matches only string fields (case-insensitively unless
``|cased``), an unquoted number only numeric fields, a boolean only booleans. A
missing field never matches, so ``not`` of a missing field is true.

Everything else — value wildcards, ``|expand`` placeholders, timestamp-part
modifiers, regular expressions, CIDR, field references, null, keyword searches
and correlation rules — is rejected with :class:`SigmaEvalError` when the rule is
parsed, before any event is evaluated.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.exceptions import SigmaError
from sigma.rule import SigmaRule
from sigma.types import (
    SigmaBool,
    SigmaCasedString,
    SigmaCompareExpression,
    SigmaNumber,
    SigmaString,
    SigmaTimestampPart,
)

from substation._yaml import safe_load_strict

__all__ = ["ParsedRule", "SigmaEvalError", "load_rule", "parse_rule", "matching_indices"]

_COMPARE_OPS = SigmaCompareExpression.CompareOperators


class SigmaEvalError(ValueError):
    """Raised when a rule is invalid or uses a construct the evaluator does not support."""


@dataclass(frozen=True, slots=True, eq=False)
class ParsedRule:
    """A parsed Sigma rule and its validated condition trees."""

    sigma: SigmaRule
    conditions: tuple[Any, ...]


def parse_rule(rule_yaml: str) -> ParsedRule:
    """Parse Sigma YAML text holding exactly one detection rule.

    Conditions are parsed and every leaf is checked here, so an unsupported or
    malformed rule fails before it is applied to any event.
    """
    try:
        # pySigma's default YAML loader silently accepts duplicate selections.
        safe_load_strict(rule_yaml)
        rules = SigmaCollection.from_yaml(rule_yaml).rules
        if len(rules) != 1:
            raise SigmaEvalError(f"expected exactly one rule, found {len(rules)}")
        [rule] = rules
        if not isinstance(rule, SigmaRule):
            raise SigmaEvalError("correlation rules are not supported by the Tier-1 evaluator")
        conditions = tuple(parsed.parse() for parsed in rule.detection.parsed_condition)
    except (yaml.YAMLError, SigmaError, RecursionError) as exc:
        raise SigmaEvalError(f"invalid Sigma rule: {exc}") from exc
    for node in conditions:
        _validate_node(node)
    return ParsedRule(sigma=rule, conditions=conditions)


def load_rule(path: str | Path) -> ParsedRule:
    """Load and parse a Sigma rule file.

    Cache by file content so edits in a long-lived process take effect, even
    when the path, size or filesystem timestamp is unchanged.
    """
    return _parse_rule_cached(Path(path).read_text(encoding="utf-8"))


@lru_cache(maxsize=128)
def _parse_rule_cached(rule_yaml: str) -> ParsedRule:
    return parse_rule(rule_yaml)


def _validate_node(node: Any) -> None:
    """Reject unsupported syntax independently of input and boolean shortcuts."""
    if isinstance(node, (ConditionAND, ConditionOR, ConditionNOT)):
        for arg in node.args:
            _validate_node(arg)
        return
    if not isinstance(node, ConditionFieldEqualsValueExpression):
        raise SigmaEvalError(f"unsupported condition node {type(node).__name__}")
    value = node.value
    if isinstance(value, SigmaString):
        if value.contains_special():
            raise SigmaEvalError(f"field {node.field!r}: value wildcards are not supported")
        if value.contains_placeholder():
            raise SigmaEvalError(f"field {node.field!r}: |expand placeholders are not supported")
    elif isinstance(value, SigmaTimestampPart):
        raise SigmaEvalError(f"field {node.field!r}: timestamp-part modifiers are not supported")
    elif isinstance(value, SigmaCompareExpression):
        if value.op not in (_COMPARE_OPS.GT, _COMPARE_OPS.GTE, _COMPARE_OPS.LT, _COMPARE_OPS.LTE):
            raise SigmaEvalError(f"field {node.field!r}: unsupported comparison {value.op!r}")
    elif not isinstance(value, (SigmaBool, SigmaNumber)):
        raise SigmaEvalError(
            f"field {node.field!r}: unsupported leaf value type {type(value).__name__}"
        )


def _lookup(event: Mapping[str, Any], dotted: str) -> Any:
    """Resolve a dotted field path against the event; ``None`` if absent."""
    cur: Any = event
    for part in dotted.split("."):
        if not isinstance(cur, Mapping) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _compare_matches(actual: Any, expr: SigmaCompareExpression) -> bool:
    """Evaluate a numeric comparison modifier (``|gte``, ``|lte``, ...)."""
    if not _is_number(actual):
        return False
    bound = expr.number.to_plain()
    if not _is_number(bound):
        raise SigmaEvalError(f"comparison bound is not numeric: {bound!r}")
    op = expr.op
    if op is _COMPARE_OPS.GTE:
        return bool(actual >= bound)
    if op is _COMPARE_OPS.LTE:
        return bool(actual <= bound)
    if op is _COMPARE_OPS.GT:
        return bool(actual > bound)
    return bool(actual < bound)  # LT; others are rejected by _validate_node.


def _leaf_matches(node: Any, event: Mapping[str, Any]) -> bool:
    """Evaluate one ``field == value`` (or comparison) leaf with typed equality."""
    actual = _lookup(event, node.field)
    value = node.value
    if isinstance(value, SigmaCompareExpression):
        return _compare_matches(actual, value)
    if isinstance(value, SigmaBool):
        return isinstance(actual, bool) and actual is value.to_plain()
    if isinstance(value, SigmaNumber):
        return _is_number(actual) and bool(actual == value.to_plain())
    if not isinstance(actual, str):
        return False
    # Validated plain strings hold only literal parts; joining them keeps escaped
    # wildcard characters literal (to_plain() would re-add the backslash).
    expected = "".join(part for part in value.s if isinstance(part, str))
    if isinstance(value, SigmaCasedString):
        return actual == expected
    return actual.casefold() == expected.casefold()


def _node_matches(node: Any, event: Mapping[str, Any]) -> bool:
    """Recursively evaluate a validated condition node against one event."""
    if isinstance(node, ConditionAND):
        return all(_node_matches(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_node_matches(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _node_matches(node.args[0], event)
    return _leaf_matches(node, event)


def matching_indices(rule: ParsedRule, events: Sequence[Mapping[str, Any]]) -> list[int]:
    """Return the indices of ``events`` the rule fires on.

    A rule with multiple conditions fires when *any* of them matches (the Sigma
    default for a condition list).
    """
    return [
        i
        for i, event in enumerate(events)
        if any(_node_matches(node, event) for node in rule.conditions)
    ]
