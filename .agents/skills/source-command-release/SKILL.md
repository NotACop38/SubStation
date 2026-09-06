---
name: "source-command-release"
description: "Use when the user requests a local Substation release or retries an interrupted release."
---

# source-command-release

This includes the migrated source command `release`.

## Command Template

Releases are **local and Codex-driven**, with no cloud release pipeline.
`scripts/release/run.py` is authoritative for the pipeline and step order.

1. Inspect the current version, local tags and worktree. Resolve the requested
   version or bump **once**, before running the pipeline; the default bump is
   minor. Record that target and use it for every attempt:
   `make release RELEASE_ARGS="--version <target>"`.
2. Preserve the dirty-tree check and both release gates: `make ci` (Tier 1) and
   `make verify` (Tier 2). If Docker is unavailable, the existing `--no-verify`
   exception skips only Tier 2; report it as **unverified**, not passed.
3. After a failure, timeout or uncertain result, inspect the current version,
   worktree, release commit and target tag before retrying. Reconcile partial
   release edits while preserving unrelated work. Reuse the recorded target:
   rerunning the default bump can create another release. An existing target
   tag is left in place, but artifact regeneration can still change the worktree.
4. Diagnose failed gates and fix causes within the authorized release scope.
   Report any unresolved blocker; do not tag over a failed required gate.
5. Report the target version, local tag, regenerated artifacts and each gate's
   result. **Do not push the tag** as part of this local release command.
