---
description: Run the local CI gate (make ci) and report pass/fail.
allowed-tools: Bash(make:*)
---

Run the project's local CI gate. There is no cloud CI for Substation — `make ci`
is the gate.

1. Run `make ci` once and report pass/fail with the checks that ran and the
   relevant failure output. A status-only request ends with that report; it does
   not authorize repairs.
2. When repairs are authorized, diagnose and fix causes within scope. Run the
   focused failing check during edits, then rerun `make ci` at completion.
3. If a required dependency, owner decision or unrelated failure blocks the
   repair, report the concrete blocker and the completed work. Do not claim the
   gate passed or the repair is complete until `make ci` passes.
