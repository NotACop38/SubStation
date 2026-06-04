#!/usr/bin/env bash
# =============================================================================
# record-demo.sh — record `make demo` to an animated SVG (and optional GIF)
# =============================================================================
# Produces a terminal recording of Substation's one-command Tier-1 demo for the
# README. Capture is done once with asciinema; the cast is then rendered to the
# README's embedded animated SVG (docs/assets/demo.svg) and, optionally, a GIF.
#
# RENDERER CHOICE
# -------------------------------------------------------------------------------
# The README embeds an animated *SVG* (crisp, tiny, diff-friendly). agg (the
# asciinema renderer) only emits GIF, so the SVG is rendered with svg-term-cli;
# agg is used only for the optional GIF.
#   SVG (default, embedded in README): svg-term-cli  -> docs/assets/demo.svg
#   GIF (optional, RENDER_GIF=1):      agg           -> docs/assets/demo.gif
#
# WHY THIS ISN'T RUN IN CI/AGENT ENVIRONMENTS
# -------------------------------------------------------------------------------
# asciinema records a real PTY, so this needs an interactive TTY. It will refuse
# to run when stdout is not a terminal (e.g. inside a non-interactive agent or
# the no-TTY CI runner). Run it locally, then commit the generated asset.
#
# ONE-TIME SETUP
# -------------------------------------------------------------------------------
#   asciinema:     pipx install asciinema           # or: brew install asciinema
#   svg-term-cli:  npm install -g svg-term-cli       # renders the SVG
#   agg (GIF only): cargo install --git https://github.com/asciinema/agg
#                   (or a release binary from
#                    https://github.com/asciinema/agg/releases)
#
# USAGE
# -------------------------------------------------------------------------------
#   make demo-cast                 # capture + render docs/assets/demo.svg
#   RENDER_GIF=1 make demo-cast    # also render docs/assets/demo.gif (needs agg)
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
if ! command -v svg-term >/dev/null 2>&1; then
  echo "error: svg-term not found (npm install -g svg-term-cli). See this script's header." >&2
  exit 1
fi
if [ "${RENDER_GIF}" = "1" ] && ! command -v agg >/dev/null 2>&1; then
  echo "error: RENDER_GIF=1 but agg not found. Install agg (see this script's header) and retry." >&2
  exit 1
fi

# --- capture ----------------------------------------------------------------
echo "Recording \`make demo\` -> ${CAST_FILE}"
rm -f "${CAST_FILE}"
asciinema rec --overwrite --command "make -C '${REPO_ROOT}' demo" "${CAST_FILE}"

# --- render -----------------------------------------------------------------
echo "Rendering SVG -> ${SVG_FILE}"
svg-term --in "${CAST_FILE}" --out "${SVG_FILE}" --window

if [ "${RENDER_GIF}" = "1" ]; then
  echo "Rendering GIF -> ${GIF_FILE}"
  agg "${CAST_FILE}" "${GIF_FILE}"
fi

echo "Done. Reference ${SVG_FILE#"${REPO_ROOT}/"} from README.md."
