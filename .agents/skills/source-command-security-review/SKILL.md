---
name: "source-command-security-review"
description: "Use when the user requests a security review of the Substation working tree."
---

# source-command-security-review

This includes the migrated source command `security-review`.

## Command Template

Perform a security review of the **current working tree** for Substation. This is
a defensive project with a hard safety invariant: the simulator is **files-only**
and must never transmit on a live interface.

Produce a concise findings report (severity, file:line, why it matters,
recommended fix). Prioritize anything that violates the safety invariants in
`AGENTS.md`.

Use the interpreter the Makefile selects as `PY` (the project `.venv` when present,
else `python3`) in place of `<python>` below; bare tool commands can resolve to an
unrelated environment.

1. **Static analysis:** run `<python> -m bandit -q -r substation` and
   `<python> -m bandit -q -r scripts --skip B404,B603,B607`, matching
   `make security`. The scripts-only exclusions cover intentional subprocess
   calls. Summarize real findings and explain any false-positive dispositions.
2. **Dependency vulnerabilities:** run `<python> scripts/security/audit_deps.py`.
   It audits the hash-locked closure in `requirements.lock` with documented
   exceptions; bare `pip-audit` scans whatever the ambient environment holds.
3. **Unsafe network / socket calls (safety invariant):** search for anything that
   would break the files-only invariant — `socket.socket`, `.connect(`, `.send(`,
   `.sendto(`, `sendp(`, `srp(`, scapy transmit functions, `requests.`, `urllib`,
   `httpx`, raw sockets, `subprocess` or `os.system` in the package. Any sending
   path in the simulator or emitters is a blocking finding. File I/O is fine.
4. **Secrets:** run `<python> scripts/security/secret_scan.py` and review
   `git diff` / `git diff --staged` for keys, tokens, private keys, passwords and
   high-entropy strings.
5. **Defensive-only posture:** flag any exploit or weaponization code, or anything
   that could be aimed at live OT. Substation models network signatures for
   detection; it does not perform attacks.

If you find nothing, say so explicitly and note what was checked. Do not modify
files unless asked — this command reports.
