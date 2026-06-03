"""CLI: validate event-log ``.jsonl`` files against the frozen schema.

Usage::

    python -m substation.schema [PATH ...]

Each PATH may be a ``.jsonl`` file or a directory (searched recursively for
``*.jsonl``). With no PATH, the committed golden events under
``tests/data/events/`` are validated — this is what ``make ci`` runs so any
emitted event that violates the schema fails the pipeline (`PRD.md` §6.3).

Exit code is 0 when every event validates, 1 otherwise.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from substation.schema import iter_jsonl_errors, load_event_schema

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_TARGETS = (_REPO_ROOT / "tests" / "data" / "events",)


def _gather(targets: Sequence[Path]) -> list[Path]:
    files: list[Path] = []
    for target in targets:
        if target.is_dir():
            files.extend(sorted(target.rglob("*.jsonl")))
        else:
            files.append(target)
    return files


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    targets = [Path(a) for a in args] if args else list(_DEFAULT_TARGETS)

    files = _gather(targets)
    if not files:
        print("schema: no .jsonl files to validate", file=sys.stderr)
        return 0

    schema = load_event_schema()
    total_errors = 0
    for path in files:
        if not path.exists():
            print(f"schema: file not found: {path}", file=sys.stderr)
            total_errors += 1
            continue
        errors = list(iter_jsonl_errors(path, schema))
        for err in errors:
            print(err, file=sys.stderr)
        total_errors += len(errors)
        if not errors:
            print(f"schema: OK {path}")

    if total_errors:
        print(f"schema: FAILED — {total_errors} violation(s)", file=sys.stderr)
        return 1
    print(f"schema: OK — {len(files)} file(s) validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
