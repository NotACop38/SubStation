"""Shipped and site-compiled Sigma rules pass pySigma's own rule validators.

The Tier-1 evaluator only proves the rules behave as intended on the scenarios.
These checks hold the rule *files* to the Sigma ecosystem's conventions (unique
identifiers, no dangling detections or conditions, well-formed tags, no
wildcard or modifier misuse), so the content imports cleanly into other tools.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path

import pytest
from sigma.collection import SigmaCollection
from sigma.rule import SigmaRule
from sigma.validation import SigmaValidator
from sigma.validators.core import validators as core_validators

from substation.detect.registry import load_registry
from substation.policy import compile_policy, load_policy

# These validators download or embed Enterprise-centric reference data (ATT&CK
# Enterprise, D3FEND, CAR, Sigma threat-group tags). ATT&CK-for-ICS tags are
# instead verified per detection against the live ICS matrix and cross-checked
# with the registry by tests/test_detection_contract.py.
_NETWORK_OR_ENTERPRISE_ONLY = {"attacktag", "cartag", "d3_fendtag", "stptag"}

_REPO = Path(__file__).resolve().parents[1]


def _validator() -> SigmaValidator:
    return SigmaValidator(
        [cls for name, cls in core_validators.items() if name not in _NETWORK_OR_ENTERPRISE_ONLY]
    )


def _rules(collection: SigmaCollection) -> Iterator[SigmaRule]:
    return iter([rule for rule in collection.rules if isinstance(rule, SigmaRule)])


def _describe(issues: Sequence[object]) -> list[str]:
    return [
        f"{type(issue).__name__}: {[rule.title for rule in getattr(issue, 'rules', [])]}"
        for issue in issues
    ]


def test_expected_validators_are_available() -> None:
    # Guard against a pySigma upgrade silently shrinking the check to nothing.
    selected = set(core_validators) - _NETWORK_OR_ENTERPRISE_ONLY
    assert {"identifier_uniqueness", "dangling_detection", "tag_format"} <= selected


def test_shipped_rules_pass_core_validators() -> None:
    paths: list[str | Path] = [det.rule_path for det in load_registry() if det.engine == "sigma"]
    assert paths
    rules = SigmaCollection.load_ruleset(paths)
    assert _describe(_validator().validate_rules(_rules(rules))) == []


@pytest.mark.parametrize("policy_file", ["bundled-demo.yaml"])
def test_site_compiled_rules_pass_core_validators(policy_file: str) -> None:
    policy = load_policy(_REPO / "detections" / "policies" / policy_file)
    compiled = compile_policy(policy)
    rules = SigmaCollection.from_yaml("\n---\n".join(compiled.values()))
    assert len(rules.rules) == len(compiled)
    assert _describe(_validator().validate_rules(_rules(rules))) == []
