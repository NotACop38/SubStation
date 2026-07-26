"""Tier-1 Sigma offline evaluator: run a Sigma rule directly over event dicts.

This is the mechanism the Phase-0 spike confirmed
(`docs/spikes/03-sigma-offline-evaluation.md`): pySigma already parses a rule's
YAML into a typed boolean condition tree (``ConditionAND``/``OR``/``NOT`` with
``ConditionFieldEqualsValueExpression`` leaves); a small recursive evaluator walks
that tree over each JSON event. Zero SIEM, in-process, pure-Python — exactly the
Tier-1 headline path (PRD.md §6.2). The *same* rule compiles to a production SIEM
via stock pySigma backends, so detections transfer unchanged (PRD.md §6.5).

Scope: plain field equality and numeric compare modifiers (``|gt`` / ``|gte`` /
``|lt`` / ``|lte`` / ``|neq``) with dotted-path lookup into the normalized
envelope (``conn.orig_h``, ``detail.unit``, …). Multi-value fields expand by
pySigma into an OR of leaves. This covers the Modbus/DNP3/S7 Sigma slice.
Anything the walk does not understand — value wildcards, keyword-only searches,
correlation rules — raises :class:`SigmaEvalError` rather than silently
mis-evaluating (spike 03 "Scope / follow-ups").
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND,
    ConditionFieldEqualsValueExpression,
    ConditionNOT,
    ConditionOR,
)
from sigma.types import SigmaBool, SigmaCompareExpression, SigmaNumber, SigmaString

__all__ = ["SigmaEvalError", "load_rule", "parse_rule", "matching_indices"]

_COMPARE_OPS = SigmaCompareExpression.CompareOperators


class SigmaEvalError(ValueError):
    """Raised when a rule uses a construct the Tier-1 evaluator does not support."""


def parse_rule(rule_yaml: str) -> Any:
    """Parse Sigma YAML text into a single pySigma ``SigmaRule``."""
    rules = SigmaCollection.from_yaml(rule_yaml).rules
    if len(rules) != 1:
        raise SigmaEvalError(f"expected exactly one rule, found {len(rules)}")
    return rules[0]


def load_rule(path: str | Path) -> Any:
    """Load and parse a Sigma rule file into a single pySigma ``SigmaRule``.

    Parsed rules are cached by resolved path: the demo and the Detection
    Contract harness evaluate the same shipped rules over many scenarios, and
    re-reading + re-parsing the YAML per scenario is pure waste. Shipped rules
    never change mid-process; the cache is invisible to correctness.
    """
    return _load_rule_cached(str(Path(path).resolve()))


@cache
def _load_rule_cached(resolved_path: str) -> Any:
    return parse_rule(Path(resolved_path).read_text(encoding="utf-8"))


def _lookup(event: dict[str, Any], dotted: str) -> Any:
    """Resolve a dotted field path against the event dict; ``None`` if absent."""
    cur: Any = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _numeric_actual(actual: Any) -> int | float | None:
    """Return a non-bool number from ``actual``, else ``None``."""
    if isinstance(actual, bool) or not isinstance(actual, (int, float)):
        return None
    return int(actual) if isinstance(actual, int) else float(actual)


def _compare_matches(actual: Any, expr: SigmaCompareExpression) -> bool:
    """Evaluate a Sigma numeric compare modifier (``|gte``, ``|lte``, …)."""
    number = _numeric_actual(actual)
    if number is None:
        return False
    bound_raw = expr.number.to_plain()
    if isinstance(bound_raw, bool) or not isinstance(bound_raw, (int, float)):
        raise SigmaEvalError(f"compare modifier bound is not numeric: {bound_raw!r}")
    bound: int | float = bound_raw
    op = expr.op
    if op is _COMPARE_OPS.GTE:
        return bool(number >= bound)
    if op is _COMPARE_OPS.LTE:
        return bool(number <= bound)
    if op is _COMPARE_OPS.GT:
        return bool(number > bound)
    if op is _COMPARE_OPS.LT:
        return bool(number < bound)
    if op is _COMPARE_OPS.NEQ:
        return bool(number != bound)
    raise SigmaEvalError(f"unsupported compare operator {op!r}")


def _leaf_matches(node: Any, event: dict[str, Any]) -> bool:
    """Evaluate a single ``field == value`` (or compare-modifier) leaf."""
    actual = _lookup(event, node.field)
    if actual is None:
        return False
    value = node.value
    if isinstance(value, SigmaCompareExpression):
        return _compare_matches(actual, value)
    if isinstance(value, SigmaBool):
        # bool is an int subclass; require an actual boolean on both sides so a
        # 0/1 integer field never matches a true/false rule value by coincidence.
        return isinstance(actual, bool) and actual == value.to_plain()
    if isinstance(value, SigmaNumber):
        return (
            isinstance(actual, (int, float))
            and not isinstance(actual, bool)
            and actual == value.to_plain()
        )
    if isinstance(value, SigmaString):
        if value.contains_special():
            raise SigmaEvalError(
                f"field {node.field!r}: value wildcards/modifiers are not supported by the "
                "Tier-1 evaluator (spike 03 follow-up)"
            )
        # A boolean field never equals a string token; compare other scalars as text.
        return not isinstance(actual, bool) and str(actual) == str(value.to_plain())
    raise SigmaEvalError(
        f"field {node.field!r}: unsupported leaf value type {type(value).__name__}"
    )


def _node_matches(node: Any, event: dict[str, Any]) -> bool:
    """Recursively evaluate a parsed Sigma condition node against one event."""
    if isinstance(node, ConditionAND):
        return all(_node_matches(arg, event) for arg in node.args)
    if isinstance(node, ConditionOR):
        return any(_node_matches(arg, event) for arg in node.args)
    if isinstance(node, ConditionNOT):
        return not _node_matches(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return _leaf_matches(node, event)
    raise SigmaEvalError(
        f"unsupported condition node {type(node).__name__} "
        "(Tier-1 evaluator handles AND/OR/NOT + field-equals leaves only)"
    )


def matching_indices(rule: Any, events: list[dict[str, Any]]) -> list[int]:
    """Return the indices of ``events`` the rule fires on.

    A rule with multiple parsed conditions fires when *any* of them match (the
    Sigma default for a multi-condition list).
    """
    asts = [parsed.parse() for parsed in rule.detection.parsed_condition]
    return [i for i, event in enumerate(events) if any(_node_matches(ast, event) for ast in asts)]
