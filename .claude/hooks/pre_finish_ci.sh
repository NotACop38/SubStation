#!/usr/bin/env bash
# Stop hook — the pre-finish gate.
# Before Claude finishes responding, run `make ci`. If it fails, block the stop
# (exit 2) and feed the failure back so the task is not considered done until CI
# is green — per the standing rule in CLAUDE.md.
#
# Receives the hook payload as JSON on stdin. We honor stop_hook_active to avoid
# an infinite stop/continue loop.
set -uo pipefail

payload="$(cat)"
active="$(printf '%s' "$payload" | jq -r '.stop_hook_active // false')"
if [ "$active" = "true" ]; then
    exit 0
fi

root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$root" || exit 0

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/substation_ci.XXXXXX")" || exit 2
log="$tmpdir/ci.log"
cleanup() {
    rm -rf "$tmpdir"
}
trap cleanup EXIT HUP INT TERM
: >"$log"
chmod 600 "$log"

if make ci >"$log" 2>&1; then
    exit 0
fi

echo "make ci failed — task is not done until it passes. Last output:" >&2
tail -n 40 "$log" >&2
exit 2
