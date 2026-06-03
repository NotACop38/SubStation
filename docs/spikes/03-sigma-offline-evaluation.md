# Spike 3 — Sigma offline evaluation over `.jsonl` (no SIEM)

**Status:** RESOLVED. **Verdict:** evaluate the **pySigma-parsed condition AST**
directly against event dicts in pytest. Working mechanism confirmed with a passing
prototype.
**VERIFY gate:** `PRD.md` §6.5 / §7 — "Sigma offline evaluation mechanism."
**Date:** 2026-06-03 · **pySigma:** 1.3.3 (pinned in `pyproject.toml`).

## Goal

Confirm a concrete, dependency-light way to evaluate Sigma rules **directly against
our `.jsonl` event log inside pytest**, with **no SIEM** and no compile-to-query
round trip — the Tier-1 headline path (`PRD.md` §6.2, Detection Contract §6.6).

## Options considered

1. **Compile to a SIEM query** (Splunk/Elastic backends) — rejected for Tier 1: needs
   the SIEM to actually run the query. (Still our *production* story — same rules
   compile to those backends via standard pySigma plugins.)
2. **`sigma.backends.test.TextQueryTestBackend`** — emits a generic query string but
   does **not** evaluate it against data. Not an evaluator.
3. ✅ **Walk pySigma's parsed condition AST and evaluate it in Python.** pySigma
   already parses YAML → resolves search-identifiers → a typed boolean tree
   (`ConditionAND/OR/NOT` with `ConditionFieldEqualsValueExpression` leaves). A small
   recursive evaluator runs that tree over each JSON event. Zero SIEM, in-process,
   pure-Python — fits Tier 1 exactly.

## Chosen mechanism

```python
from sigma.collection import SigmaCollection

rule = SigmaCollection.from_yaml(rule_yaml).rules[0]
ast  = rule.detection.parsed_condition[0].parse()   # resolved boolean tree
```

`ast` is composed of:

- `ConditionAND` / `ConditionOR` / `ConditionNOT` (`.args`)
- `ConditionFieldEqualsValueExpression` leaves with `.field` (str) and `.value`
  (`SigmaString`/`SigmaNumber`; `.to_plain()` → python scalar)

A field that lists multiple values expands to a `ConditionOR` of leaves
automatically, and named selections (`selection and not filter`) are inlined into the
tree — so the evaluator only handles the three boolean nodes + the equals leaf.

### Smallest passing example (validated under pytest, 1 passed)

```python
import json
from sigma.collection import SigmaCollection
from sigma.conditions import (
    ConditionAND, ConditionOR, ConditionNOT, ConditionFieldEqualsValueExpression,
)

RULE = """
title: Modbus write from non-allowlisted source
logsource: {product: ot, service: modbus}
detection:
    writes:
        action_class: write
    filter_allowlisted:
        conn.orig_h: [10.0.0.5, 10.0.0.6]   # HMI, EWS
    condition: writes and not filter_allowlisted
"""

def _get(event, dotted):                     # dotted path -> envelope (conn.orig_h)
    cur = event
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur

def _matches(node, event):
    if isinstance(node, ConditionAND):
        return all(_matches(a, event) for a in node.args)
    if isinstance(node, ConditionOR):
        return any(_matches(a, event) for a in node.args)
    if isinstance(node, ConditionNOT):
        return not _matches(node.args[0], event)
    if isinstance(node, ConditionFieldEqualsValueExpression):
        return str(_get(event, node.field)) == str(node.value.to_plain())
    raise NotImplementedError(type(node).__name__)

def evaluate(rule_yaml, events):
    ast = SigmaCollection.from_yaml(rule_yaml).rules[0].detection.parsed_condition[0].parse()
    return [i for i, ev in enumerate(events) if _matches(ast, ev)]
```

Against three events (benign HMI write, rogue write, benign read) the rule fires on
**only** the rogue write — i.e. fire-on-anomaly + quiet-on-benign in one assertion.
This is the kernel of the Phase-1 Detection-Contract harness.

## Scope / follow-ups for the Phase-1 harness (not blockers)

The prototype implements **plain field equality + dotted-path lookup**, which covers
M1 (allow-list) and M2 (illegal function code). Before the harness ships it must also
handle:

- **Sigma value modifiers** — `contains`, `startswith`, `endswith`, `re`, `all`, `lt/gt`.
  pySigma keeps these on the `SigmaDetectionItem`; the leaf value carries
  wildcards/special tokens (`SigmaString.contains_special()`). Plan: branch in the
  leaf handler on modifier/special-char presence.
- **Numeric vs string** comparisons (cast both sides via `to_plain()`; the `str()==str()`
  shortcut above is intentionally minimal).
- **`ConditionValueExpression`** (keyword/value-only searches with no field).
- **Sigma correlation rules** (M3 sweep): pySigma exposes these as
  `SigmaCorrelationRule`; evaluate with a windowed group-by pass over the event
  stream. Out of scope for this spike; flagged for M3.

These are extensions of the same AST-walk, not a different mechanism — the approach
holds.

## Dependency note (fixed as part of this spike)

`pysigma==1.3.3` requires `PyYAML>=6.0.3`, but `pyproject.toml` pinned `PyYAML==6.0.1`,
making the dependency set **uninstallable** (pip `ResolutionImpossible`). Bumped the
pin to `PyYAML==6.0.3` so Tier-1 deps install. (Both pySigma and our YAML scenario
loader use PyYAML — single shared pin.)

## Decision / impact

- Tier-1 harness evaluates Sigma via the **parsed-AST walk** above; production users
  compile the *same* rules to their SIEM with stock pySigma backends. One rule
  source, two execution paths — exactly `PRD.md` §6.5.
- Record this mechanism in `docs/schema.md` notes when the Modbus schema is frozen.

## Nothing blocked

Mechanism confirmed with a passing pytest prototype. No escalation needed.
