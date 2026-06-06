---
name: "source-command-release"
description: "Cut a local Substation release (gate -> build -> artifacts -> bump -> tag)."
---

# source-command-release

Use this skill when the user asks to run the migrated source command `release`.

## Command Template

Cut a release for Substation. Releases are **local and Codex-driven** — there is
no GitHub Actions / cloud release pipeline (AGENTS.md). `make release` is the
pipeline; it is idempotent and repeatable.

The pipeline (see `scripts/release/run.py`):

1. **Gate** — re-run `make ci` (Tier 1) and `make verify` (Tier 2). A release
   only happens over a green gate.
2. **Build** — sdist + wheel into `dist/`.
3. **Regenerate + commit** the coverage map + ATT&CK Navigator layer snapshot
   (`docs/coverage/`) and the demo transcript (`docs/demo-output.txt`).
4. **Bump** the version in `pyproject.toml` and promote `CHANGELOG.md`'s
   `[Unreleased]` section to the new version.
5. **Commit + tag** the release locally (the tag is **not** pushed).

Steps:

1. Run `make release` (defaults to a minor bump). To target a specific version
   pass args, e.g. `make release RELEASE_ARGS="--version 0.2.0"`, or a different
   bump with `RELEASE_ARGS="--bump patch"`. In an environment without Docker, add
   `--no-verify` to drop only the Tier-2 gate.
2. If a gate fails, show the failing output, diagnose, fix, and re-run — do not
   tag over a red gate.
3. On success, report the new version, the tag, and the regenerated artifacts.
   Re-running for an already-released version is a safe no-op (re-syncs
   artifacts, creates no duplicate commit/tag/changelog entry).
