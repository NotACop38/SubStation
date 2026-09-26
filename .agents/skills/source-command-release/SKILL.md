---
name: "source-command-release"
description: "Use when the user requests a local Substation release or retries an interrupted release."
---

# source-command-release

This includes the migrated source command `release`.

## Command Template

Releases are local, with no cloud release pipeline. `scripts/release/run.py` is
authoritative for the pipeline and step order.

1. Inspect the current version, local tags and worktree. The worktree must be
   clean and `CHANGELOG.md` must hold notes under `## [Unreleased]`.
2. Choose the target once and use it for every attempt:
   `make release RELEASE_ARGS="--version <target>"`.
3. Keep both gates: `make ci` (Tier 1) and `make verify` (Tier 2). If Docker is
   unavailable, `--no-verify` skips only Tier 2; report it as **unverified**, not
   passed.
4. A failure before the release commit rolls back the version, changelog and
   regenerated artifacts. Diagnose the cause, fix it within the release scope,
   and re-run the same command. Do not tag over a failed required gate.
5. Report the target version, local tag, built files and each gate's result.
   **Do not push the tag** as part of this local release command.
