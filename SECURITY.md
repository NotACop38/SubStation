# Security policy

Substation is defensive tooling: a detection-content pack and a simulator that
only writes files. This policy covers vulnerabilities in the tooling itself.

## Reporting a vulnerability

Report privately through GitHub's
[private vulnerability reporting](https://github.com/NotACop38/SubStation/security/advisories/new)
(**Security → Report a vulnerability**). Include the affected version or commit,
reproduction steps and the impact you observed. Please do not open a public
issue for a suspected vulnerability. If private reporting is unavailable, open an
issue that asks for a private contact and leave out the details.

Fixes land on `main`; only the latest release is supported.

## In scope

- Any path by which the simulator, `substation demo` or another CLI command
  transmits on a network interface or opens an outbound connection. The
  files-only guarantee is a safety invariant, not a convenience.
- Code execution, path traversal or unbounded resource use when parsing
  untrusted input: scenario YAML, JSONL event logs, site policies, ICSNPP logs,
  Sigma rules or corpus manifests.
- The optional Modbus honeypot: exposure beyond its documented loopback default,
  outbound traffic, or crashes on malformed frames.
- Weaknesses in the release, dependency-lock or secret-scanning tooling.

## Out of scope

- Detection gaps, false positives or tuning of the example rules. These are
  expected in experimental content; open a regular issue.
- Attacks that already require write access to the checkout, the Python
  environment or the Docker daemon.
- Anything involving live operational technology. Substation must never be
  pointed at real control systems, and reports should not describe doing so.
