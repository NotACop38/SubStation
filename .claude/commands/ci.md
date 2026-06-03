---
description: Run the local CI gate (make ci) and report pass/fail.
allowed-tools: Bash(make:*), Bash(ruff:*), Bash(mypy:*), Bash(pytest:*)
---

Run the project's local CI gate. There is no cloud CI for Substation — `make ci`
is the gate.

1. Run `make ci`.
2. If it passes, report success concisely (which checks ran).
3. If it fails, show the failing check's output, diagnose the root cause, fix it,
   and re-run `make ci`. Repeat until green.
4. Do not consider the task done until `make ci` passes.
