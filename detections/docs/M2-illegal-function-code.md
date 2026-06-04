# M2 — Illegal / abnormal Modbus function code

A Modbus request carrying a reserved/undefined function code, or an exception
response indicating illegal-function / illegal-address probing — the
function-code-probing detection for the Modbus slice (`PRD.md` §5.1).

| | |
|---|---|
| **Detection ID** | M2 |
| **Engine** | Sigma (Tier 1, over the `.jsonl` event log) |
| **Rule** | [`detections/sigma/modbus_m2_illegal_function_code.yml`](../sigma/modbus_m2_illegal_function_code.yml) |
| **Status** | experimental · **Level** | medium |

## Behavior

A source probes a device with reserved/undefined Modbus function codes, or
provokes the exception responses (`ILLEGAL_FUNCTION`, `ILLEGAL_DATA_ADDRESS`)
that such probing draws from a compliant outstation. This is reconnaissance:
enumerating which functions and addresses a device supports. The detection keys
on **the code / exception itself**, not on the source or the request rate.

## Engine choice + rationale

**Sigma.** The signal is visible in a **single event** — a request whose
function code is reserved/undefined (normalized to `action_class: other`), or an
exception event whose `error` names an illegal-function/address response. No
state or correlation is required, so Sigma is the simplest correct engine
(Sigma-first, `PRD.md` §6.5). It transfers unchanged to a production SIEM/Zeek
via pySigma backends, where the same fields map to ICSNPP
`modbus_detailed.exception_code` and Zeek's `Modbus::function_codes`.

**Why code/exception, not volume.** A single malformed or unsupported request is
enough to be interesting; the abnormality is the *code*, not how often it
appears. Volume-based scanning is M3's concern (and is deliberately
diversity-keyed, not rate-keyed — `PRD.md` §8).

## Data source

Tier-1 `.jsonl` event log (`docs/schema.md`):

- `action_class` = `other` on a request — the schema maps reserved/undefined
  codes here (every supported standard code maps to `read`/`write`/`diagnostic`,
  so `other` is the abnormal-code marker).
- `is_exception` = `true` with `error` ∈ {`ILLEGAL_FUNCTION`,
  `ILLEGAL_DATA_ADDRESS`}. On a Modbus exception the schema **requires** a
  non-null `error` mirroring `detail.exception_code`, so the field is always
  present to key on.

## Detection logic

```
abnormal_function_code:      proto=modbus AND direction=request AND action_class=other
illegal_function_exception:  proto=modbus AND is_exception=true
                             AND error in { ILLEGAL_FUNCTION, ILLEGAL_DATA_ADDRESS }
fire when:                   abnormal_function_code OR illegal_function_exception
```

## Scenarios

- **Fires:** [`anomalous-m2-illegal-function.yaml`](../../scenarios/modbus/anomalous-m2-illegal-function.yaml)
  — a host probes the PLC with reserved function code `0x09`, drawing an
  `ILLEGAL_FUNCTION` exception.
- **Quiet:** [`benign-baseline.yaml`](../../scenarios/modbus/benign-baseline.yaml)
  — only standard read/write codes, no exceptions.

> **Status note.** The M2 scenario is a forward-looking fixture: the current
> emitter encodes only the eight standard read/write codes, so emitting an
> undefined code **and** its `ILLEGAL_FUNCTION` exception is the emitter
> extension that lands alongside M2 (see the header of
> `anomalous-m2-illegal-function.yaml`). The rule is authored against the frozen
> schema's `action_class: other` + `error` contract; its fire/quiet test runs
> once that emitter extension and the harness land (separate
> `ENGINEERING_CHECKLIST.md` Phase-1 items). The rule itself parses cleanly under
> the pinned pySigma.

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Remote System Information Discovery | **T0888** | Discovery (TA0102) |

Probing reserved/undefined function codes (and reading the exception responses)
maps onto T0888: the live page describes adversaries discovering *"what logical
nodes the device supports"* and searching for specific control functions —
i.e. enumerating a device's supported functions/capabilities.

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS
> matrix on 2026-06-04. Sources: <https://attack.mitre.org/techniques/T0888/>,
> tactic <https://attack.mitre.org/tactics/TA0102/>.

## False-positive profile

- **Benign off-by-one address reads.** A misconfigured but legitimate client
  reading a slightly-too-large register range draws a single
  `ILLEGAL_DATA_ADDRESS` — a low-rate, self-correcting event, not recon. In
  environments with chatty off-by-one clients, drop the `ILLEGAL_DATA_ADDRESS`
  value from the rule; the `ILLEGAL_FUNCTION` and abnormal-code arms still fire.
  (Confidence rises when an illegal-address exception co-occurs with an M3 sweep.)
- **Vendor function extensions.** A master speaking a vendor-specific function
  code the field-map does not classify can surface as `action_class: other`.
  Confirm the code's meaning before treating it as recon, and classify known
  vendor codes in the schema so they stop reading as `other`.
- **Why benign polling stays quiet.** Standard read/write polling uses only
  classified codes and draws no exceptions, so neither arm engages — the benign
  baseline produces zero M2 signal.
