"""Phase 0 smoke tests: prove the skeleton imports and the CLI wiring runs.

These are placeholders that keep the harness (and `make ci`) green until the
Detection Contract tests arrive in Phase 1.
"""

from __future__ import annotations

import importlib

import pytest
from substation import cli

PACKAGES = [
    "substation",
    "substation.scenarios",
    "substation.protocols",
    "substation.emit",
    "substation.detect",
    "substation.coverage",
]


@pytest.mark.parametrize("name", PACKAGES)
def test_packages_import(name: str) -> None:
    assert importlib.import_module(name) is not None


def test_cli_no_args_prints_help() -> None:
    assert cli.main([]) == 0


def test_cli_demo_stub_succeeds() -> None:
    assert cli.main(["demo"]) == 0


def test_cli_verify_stub_succeeds() -> None:
    assert cli.main(["verify"]) == 0
