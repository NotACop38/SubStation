"""Assert the Tier-1 path never imports diskcache (justifies the pip-audit ignore).

diskcache is a transitive pySigma dependency with an unfixed pickle advisory
(see scripts/security/audit_deps.py ``_IGNORED``). Substation's runtime path only
parses Sigma rules and walks the AST, so it must not touch diskcache.

The check runs a complete demo in a fresh interpreter: other tests in this
process (for example pySigma's rule validators) may legitimately import it.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path


def test_demo_and_detect_path_does_not_import_diskcache(tmp_path: Path) -> None:
    code = textwrap.dedent(
        f"""
        import contextlib, io, sys
        from substation import cli
        with contextlib.redirect_stdout(io.StringIO()):
            assert cli.main(["demo", "--artifacts", {str(tmp_path)!r}]) == 0
        print("diskcache" in sys.modules)
        """
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and inline code
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip().splitlines()[-1] == "False"
