#!/usr/bin/env bash
# PostToolUse hook (matcher: Edit|Write).
# Formats, lints, and type-checks the file that was just edited/written.
#
# Receives the hook payload as JSON on stdin; we pull tool_input.file_path.
# Advisory by design: it reports problems but exits 0 so editing is never blocked
# (the hard gate is `make ci` via the Stop hook and the pre-push hook).
set -uo pipefail

payload="$(cat)"
file="$(printf '%s' "$payload" | jq -r '.tool_input.file_path // empty')"

# Only act on Python source inside this repo.
case "$file" in
    *.py) ;;
    *) exit 0 ;;
esac
[ -f "$file" ] || exit 0

status=0
echo "post_edit: checking $file"

if command -v ruff >/dev/null 2>&1; then
    ruff format "$file" || status=1
    ruff check "$file" || status=1
else
    echo "post_edit: ruff not found (run 'make dev')" >&2
fi

if command -v mypy >/dev/null 2>&1; then
    mypy "$file" || status=1
else
    echo "post_edit: mypy not found (run 'make dev')" >&2
fi

if [ "$status" -ne 0 ]; then
    echo "post_edit: issues found in $file — review above (not blocking)." >&2
fi
exit 0
