---
name: "source-command-ci"
description: "Use when the user asks to run Substation CI, check its status, or repair its failing local gate."
---

# source-command-ci

This includes the migrated source command `ci`.

## Command Template

Run the project's local CI gate. There is no cloud CI for Substation — `make ci`
is the gate.

1. Run `make ci` once and report pass/fail with the checks that ran and relevant
   failure output. A status-only request ends with that report; it does not
   authorize repairs.
2. When repairs are authorized, diagnose and fix causes within scope. Run the
   focused failing check during edits, then rerun `make ci` at completion.
3. If a required dependency, owner decision or unrelated failure blocks the
   repair, report the concrete blocker and completed work. Do not claim the gate
   passed or the repair is complete until `make ci` passes.
