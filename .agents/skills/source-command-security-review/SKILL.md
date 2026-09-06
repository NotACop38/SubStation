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

Do all of the following and produce a concise findings report (severity, file:line,
why it matters, recommended fix). Prioritize anything that violates the safety
invariants in `AGENTS.md`.

Use the same Python executable selected by the Makefile's `PY` variable
(`python3` in the activated project environment by default). Use that executable
in place of `<python>` below; bare tool commands can use an unrelated environment.

1. **Static analysis (code):** run `<python> -m bandit -q -r substation` and
   `<python> -m bandit -q -r scripts --skip B404,B603,B607`, matching
   `make security`. The scripts-only exclusions cover intentional subprocess
   calls. Summarize real findings and explain any false-positive dispositions.
2. **Dependency vulnerabilities:** run
   `<python> scripts/security/audit_deps.py` and report project-scoped advisories.
   This uses the declared dependency closure and documented exceptions; bare
   `pip-audit` instead scans whatever is installed in the ambient environment.
3. **Unsafe network / socket calls (safety-invariant check):** search the tree for
   outbound/transmitting calls that would break the files-only invariant —
   e.g. `socket.socket`, `.connect(`, `.send(`, `.sendto(`, `sendp(`, `srp(`,
   `scapy ... send`, `requests.`, `urllib`, `httpx`, raw sockets. Any sending
   path in the simulator/emitters is a blocking finding. Reading/writing files
   (PCAP/JSON) is fine.
4. **Secrets:** scan tracked + staged changes for hardcoded secrets — API keys,
   tokens, private keys, passwords, `.pem`/`.key` material, high-entropy strings.
   Use `git diff` / `git diff --staged` plus a tree-wide grep.
5. **Defensive-only posture:** flag any exploit/weaponization code or anything that
   could be aimed at live OT — Substation models network signatures for detection,
   it does not perform attacks.

If you find nothing, say so explicitly and note what was checked. Do not modify
files unless asked — this command reports.
