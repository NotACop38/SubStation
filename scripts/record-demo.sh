#!/usr/bin/env bash
# =============================================================================
# record-demo.sh — record `make demo` to an animated SVG (and optional GIF)
# =============================================================================
# Produces a terminal recording of Substation's one-command Tier-1 demo for the
# README, using asciinema (capture) + agg (render). Output: docs/assets/demo.svg
# (and docs/assets/demo.gif if you flip RENDER_GIF=1 below).
#
# WHY THIS ISN'T RUN IN CI/AGENT ENVIRONMENTS
# -------------------------------------------------------------------------------
# asciinema records a real PTY, so this needs an interactive TTY. It will refuse
# to run when stdout is not a terminal (e.g. inside a non-interactive agent or
# the no-TTY CI runner). Run it locally, then commit the generated asset.
#
# ONE-TIME SETUP
# -------------------------------------------------------------------------------
#   asciinema:  pipx install asciinema      # or: brew install asciinema
#   agg:        cargo install --git https://github.com/asciinema/agg
#               (or download a release binary from
#                https://github.com/asciinema/agg/releases)
#
# USAGE
# -------------------------------------------------------------------------------
#   make demo-cast            # capture + render docs/assets/demo.svg
#   RENDER_GIF=1 make demo-cast   # also render docs/assets/demo.gif
#
# Then reference docs/assets/demo.svg from README.md (it currently links a
# placeholder until the first real cast is recorded).
# -----------------------------------------------------------------------------
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="${REPO_ROOT}/docs/assets"
CAST_FILE="${ASSETS_DIR}/demo.cast"
SVG_FILE="${ASSETS_DIR}/demo.svg"
GIF_FILE="${ASSETS_DIR}/demo.gif"
RENDER_GIF="${RENDER_GIF:-0}"

mkdir -p "${ASSETS_DIR}"

# --- preconditions ----------------------------------------------------------
if [ ! -t 1 ]; then
  cat >&2 <<'EOF'
error: `make demo-cast` needs an interactive TTY to record the terminal.
       This environment has no TTY (non-interactive agent / CI runner), so the
       recording cannot be driven here. Run `make demo-cast` locally instead.
EOF
  exit 1
fi

if ! command -v asciinema >/dev/null 2>&1; then
  echo "error: asciinema not found. Install it (see this script's header) and retry." >&2
  exit 1
fi
if ! command -v agg >/dev/null 2>&1; then
  echo "error: agg not found. Install it (see this script's header) and retry." >&2
  exit 1
fi

# --- capture ----------------------------------------------------------------
echo "Recording \`make demo\` -> ${CAST_FILE}"
rm -f "${CAST_FILE}"
asciinema rec --overwrite --command "make -C '${REPO_ROOT}' demo" "${CAST_FILE}"

# --- render -----------------------------------------------------------------
echo "Rendering SVG -> ${SVG_FILE}"
agg "${CAST_FILE}" "${SVG_FILE}"

if [ "${RENDER_GIF}" = "1" ]; then
  echo "Rendering GIF -> ${GIF_FILE}"
  agg "${CAST_FILE}" "${GIF_FILE}"
fi

echo "Done. Reference ${SVG_FILE#"${REPO_ROOT}/"} from README.md."
