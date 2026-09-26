---
description: Cut a local Substation release (preflight -> gate -> build -> commit + tag).
allowed-tools: Bash(make:*), Bash(python3:*), Bash(git tag:*), Bash(git status:*), Bash(git log:*)
---

Cut a Substation release. Releases are local: there is no cloud release
pipeline, and `make release` (`scripts/release/run.py`) is the pipeline.

1. **Preflight** — clean working tree, a target version not older than the
   current one, no existing tag, and release notes under `## [Unreleased]` in
   `CHANGELOG.md`.
2. **Gate** — `make ci` (Tier 1) and `make verify` (Tier 2).
3. **Prepare** — set the version, promote the changelog notes, regenerate
   `docs/coverage/` and `docs/demo-output.txt`, stage exactly those paths and
   secret-scan the staged tree.
4. **Build** — sdist + wheel from an export of the staged tree into `dist/`.
5. **Record** — one release commit and an annotated `v<version>` tag, both local.

Steps:

1. Choose the target once: `make release RELEASE_ARGS="--version X.Y.Z"` (or
   `--bump patch|minor|major`). Without Docker, add `--no-verify` and report the
   release as Tier-2 **unverified**.
2. If a gate or step fails, the pipeline restores every file it touched. Show the
   failing output, fix the cause, and re-run the same command. Never tag over a
   red gate.
3. On success, report the version, the tag and the built files. Do not push the tag.
