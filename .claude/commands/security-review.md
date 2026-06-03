---
description: Audit the working tree for vulnerabilities, unsafe network/socket calls, and secrets.
allowed-tools: Bash(git:*), Bash(bandit:*), Bash(pip-audit:*), Bash(rg:*), Bash(grep:*), Read, Glob, Grep
---

Perform a security review of the **current working tree** for Substation. This is
a defensive project with a hard safety invariant: the simulator is **files-only**
and must never transmit on a live interface.

Do all of the following and produce a concise findings report (severity, file:line,
why it matters, recommended fix). Prioritize anything that violates the safety
invariants in `CLAUDE.md`.

1. **Static analysis (code):** run `bandit -q -r substation` and summarize real
   findings (filter obvious false positives, but explain why).
2. **Dependency vulnerabilities:** run `pip-audit` and report any vulnerable pins
   in `pyproject.toml`.
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
