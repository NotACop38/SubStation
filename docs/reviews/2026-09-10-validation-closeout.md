# Codebase review closeout — 2026-09-10

Substation's useful purpose remains a small **offline detection regression and
teaching toolkit**. Keep the shared scenario model, files-only simulator,
experimental detection catalog and separate stateful-engine checks. The review
found no evidence justifying a product rewrite or a larger protocol catalog.
Independent parsing and backend execution exposed defects that more internally
consistent synthetic examples would have missed.

This record supersedes current-readiness claims in older launch/review snapshots.
The [initial review](2026-09-09-codebase-review.md), [validation guide](../independent-validation.md)
and protocol spikes preserve the detailed reasoning and earlier evidence.

## Delivered review work

- [PR 44](https://github.com/NotACop38/SubStation/pull/44): complete-span and
  destination policy, stable X1 trust, strict inputs, S7 wire repairs, release and
  packaging corrections, and honest product/coverage framing.
- [PR 45](https://github.com/NotACop38/SubStation/pull/45): bounded Modbus sensor
  import, versioned site policy and portable export, attributed external
  observations, artifact hashes and dependency-graph evidence.
- [PR 46](https://github.com/NotACop38/SubStation/pull/46): independent DNP3
  per-message/detail checks, operation/IIN/object encoding fixes, and removal of
  fabricated or unused response behavior.
- This batch: S7 request/response detail comparison and corrections, fixed-width
  block filenames, complete SZL names, a bounded-parser verification build, and
  independent SQLite execution of authored/site-exported rules.

The S7 field oracle reproduced nondeterministic Start Upload lengths in upstream
ICSNPP's unterminated numeric buffer. A small tracked patch also bounds an empty
filename read. The native build helper verifies and copies pinned upstream source,
applies the patch and records provenance. Complete S7 verification requires its
compatibility marker. See the [S7 evidence](../spikes/09-s7-field-fidelity.md).

The official SQLite backend agrees with the local evaluator on the catalog,
external Modbus observations and complete small-span policy boundaries. It also
demonstrates two limits: missing fields under a negated permission can suppress
an alert through SQL NULL semantics, and a full coil grant exceeds the standard
expression-depth limit. These are recorded failing deployment cases; no claim of
general SIEM equivalence is made. See the [backend evidence](../spikes/10-sigma-backend-qualification.md).

## Verification

Local `make ci` passed: **521 tests passed, 21 explicit Tier-2 contract skips**,
with formatting, lint, strict types, schema, coverage drift checks and the full
security gate. Native S7 tests were enabled, including numeric-buffer bounds and
all SZL identifiers. The full native Tier-2 run passed **46 checks, 0 failures**;
the one optional skip is Suricata, for which no rules are shipped.

`make verify-sigma` compared exact hits for seven authored rules and seven site
exports over **245 observations**, using SQLite 3.53.1, backend 1.2.4 and pySigma
1.3.3. Target/span/empty-policy and known-limit cases run in pytest. The SBOM
records **54 locked components and 55 dependency records**.

Native results use Zeek 8.2.2 with ICSNPP S7comm 1.3.0 **plus the tracked bounds patch**. The original
upstream checkout remains clean. The backend is a development dependency;
runtime installation remains Scapy, pySigma and PyYAML plus their dependencies.

## Remaining qualification boundaries

| Boundary | Why it remains outside the delivered claim |
|---|---|
| Production precision/recall and alert volume | Requires independently labeled, representative operational traffic. The small external Modbus corpus is a regression fixture, not an operational benchmark. |
| General DNP3/S7 sensor import | Existing transaction logs lose information or need version-specific joins/normalization. The field comparators are fixture oracles, not deployable adapters. |
| SIEM deployment | Needs the selected backend, field mapping, missing-data policy and actual site permissions tested together. Known SQLite limits prevent a blanket portability claim. |
| Timing and device semantics | No PLC process, complete transfer session, all extension payloads, S7-plus integrity or encrypted traffic is modeled. |
| Pinned S7 Docker image | The review host qualified native Zeek. A Docker build/run needs separate evidence; no native result is presented as container qualification. |

These boundaries are deliberately retained in the checklist. New detections,
protocols and honeypot expansion remain deferred until they serve a demonstrated
use case with corresponding evidence. No live-OT traffic, release tag, cloud CI
or honeypot deployment is part of this review.
