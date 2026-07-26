"""Assert Substation never imports diskcache (justifies the pip-audit ignore).

diskcache is a transitive pySigma dependency with an unfixed pickle advisory
(see scripts/security/audit_deps.py ``_IGNORED``). Our Tier-1 path only parses
Sigma rules and walks the AST — it must not touch diskcache.
"""

from __future__ import annotations

import sys

from substation.detect import sigma_eval
from substation.detect.sigma_eval import matching_indices, parse_rule


def test_sigma_eval_does_not_import_diskcache() -> None:
    # Importing/using the evaluator must not pull diskcache into sys.modules.
    rule = parse_rule(
        """
title: t
id: 00000000-0000-0000-0000-000000000099
logsource: {product: ot}
detection:
  sel: {action_class: write}
  condition: sel
"""
    )
    assert matching_indices(rule, [{"action_class": "write"}]) == [0]
    assert "diskcache" not in sys.modules
    assert sigma_eval.__name__ == "substation.detect.sigma_eval"
