# X1 — Cross-protocol baseline deviation

A source/destination/function combination that is **not in the learned baseline**,
across **any** supported protocol (Modbus, DNP3, S7comm) — the flagship
cross-protocol detection (`PRD.md` §5.4). Three deviation classes: **new talker**,
**new asset pair**, **new function for a pair**.

| | |
|---|---|
| **Detection ID** | X1 |
| **Engine** | Zeek (Tier 2, over the PCAP; learned state + set membership) |
| **Rule** | [`detections/zeek/x1_cross_protocol_baseline.zeek`](../zeek/x1_cross_protocol_baseline.zeek) |
| **Protocol** | cross (Modbus + DNP3 + S7comm, normalized) |
| **Status** | tier2 · **Notice** | `CrossProtoBaseline::BaselineDeviation` |

X1 is the **flagship reason for the normalized envelope** (`PRD.md` §6.3) and the
**primary justification for a stateful Zeek detection** (`PRD.md` §6.5, §5.4). It
is the one detection that runs a single baseline over **all three** protocols.

## Behavior

OT networks are remarkably static: a fixed set of masters/HMIs/EWS talk to a fixed
set of PLCs/RTUs/outstations, each pair exercising a small, stable set of
functions. Against that backdrop, three deviations are high-signal:

1. **New talker** — an originator host never seen before speaking *any* OT
   protocol. The strongest signal: a host that has no business on the OT segment
   suddenly originating ICS traffic (a foothold, a rogue laptop, a compromised
   jump box).
2. **New asset pair** — a *known* talker reaching a (src→dst) pair never seen
   before. The network signature of **lateral movement** to an asset that talker
   never legitimately spoke to.
3. **New function for a pair** — a *known* pair exercising a normalized verb never
   seen for that pair (e.g. a link that has only ever polled suddenly issuing a
   control/write). Privilege/capability creep on an existing channel.

Only the **highest-precedence** novelty is reported per observation (talker > pair
> function): a brand-new talker is reported as a new talker, not redundantly as a
new pair and new function. Each distinct novel tuple alerts **once** — it is
folded into the baseline after alerting — so a sustained anomalous flow yields one
notice, not a storm.

## Engine choice + rationale

**Zeek**, because X1 is the canonical "real state" case the engine policy reserves
Zeek for (`PRD.md` §6.5). It needs two things a stateless Sigma field-match cannot
express:

- **Learned state** — a durable baseline of known talkers / pairs / functions,
  accumulated from a known-good learning period and carried across connections.
- **Set membership** — every observed tuple is tested against that baseline; the
  alert is "**not** in the set," which is inherently a stateful set operation.

It is also the flagship justification for the **normalized envelope** (`PRD.md`
§6.3): the per-protocol Zeek/ICSNPP logs are not uniformly shaped, so X1
normalizes every protocol event down to one `(orig_h, resp_h, func)` tuple via
`norm_func()` and runs **one** baseline over Modbus, DNP3 and S7comm together. A
Modbus-only or DNP3-only rule could never see a talker that pivots *between*
protocols; X1 can.

## Data source

Per-protocol Zeek events, each normalized into one cross-protocol tuple by
`observe()`:

| Protocol | Event | Normalized func |
|---|---|---|
| Modbus | base `modbus_message` (`headers$function_code`) | `modbus:<code>` |
| DNP3 | base `dnp3_application_request_header` (`fc`) | `dnp3:<code>` |
| S7comm | ICSNPP `s7comm_read_szl` (`szl_id`) | `s7comm:szl=0x<id>` |

Only `is_orig` (request) messages are observed; the matched response echoes the
request and would distort the originator's apparent behaviour.

> **VERIFY (`CLAUDE.md` gate).** The three event signatures are the same ones
> verified for M3 / D4 / S3 against live sources on 2026-06-04 (`modbus_message`
> and `dnp3_application_request_header` against `zeek/zeek` base; `s7comm_read_szl`
> against `cisagov/icsnpp-s7comm`, spike 06). Extending S7 coverage to the general
> S7 header event is a mechanical addition of one more `observe()` call.

## Detection logic — learned state + set membership

The baseline is three sets: `known_talkers`, `known_pairs`, `known_funcs`. It is
supplied two ways (use either or both):

- **Injected (production + the Tier-2 runner).** `redef` the three sets with the
  allow-set computed from a known-good learning period — for Substation, the
  union of tuples observed in the **benign baseline scenarios**
  (`scenarios/*/benign-baseline.yaml`). This is the "learned state" of `PRD.md`
  §5.4: learned once offline, then enforced. The Tier-2 runner derives the
  baseline from the benign PCAPs, redefs it, then runs the anomalous PCAP and
  expects the deviation to fire.
- **Self-learn (optional, standalone).** Set `learn_period` > 0: every tuple seen
  within `learn_period` of the first packet seeds the baseline, and only
  deviations **after** the window alert. Default is `0secs` (off) so X1 relies on
  the injected baseline and never silently "learns away" an attacker that is
  present from the very first packet.

| Knob (`&redef`) | Default | Meaning |
|---|---|---|
| `known_talkers` | `{}` | Learned legitimate originator hosts. |
| `known_pairs` | `{}` | Learned legitimate (src, dst) asset pairs. |
| `known_funcs` | `{}` | Learned legitimate (src, dst, normalized-func) tuples. |
| `learn_period` | `0secs` | Optional self-learning window (0 = rely on injected baseline). |

Every observed tuple is folded into the baseline after it is evaluated, which both
seeds the self-learning window and de-dups alerts (each novel tuple fires once).

> **Status note.** X1 executes in **Tier 2** (containerized Zeek over the PCAP).
> The Tier-2 runner is a Phase-2 `ENGINEERING_CHECKLIST.md` item, so X1's
> fire/quiet test runs there; the harness here still enforces X1's contract
> linkage (rule + doc + ≥1 fire and ≥1 quiet scenario). The rule is authored
> against verified Zeek/ICSNPP APIs.

## Scenarios (spanning protocols)

Quiet, across **all three** protocols (every legitimate tuple is in the injected
baseline):

- [`modbus/benign-baseline.yaml`](../../scenarios/modbus/benign-baseline.yaml)
- [`dnp3/benign-baseline.yaml`](../../scenarios/dnp3/benign-baseline.yaml)
- [`s7/benign-baseline.yaml`](../../scenarios/s7/benign-baseline.yaml)

Fires, across **two** protocols, with **one scenario per deviation class** (each
isolates its class — recall the precedence talker > pair > function, so the class
under test must be the *highest*-precedence novelty in its scenario):

- **New talker** — [`modbus/anomalous-x1-new-talker.yaml`](../../scenarios/modbus/anomalous-x1-new-talker.yaml):
  an unbaselined host (`10.0.0.123`) originates Modbus reads to the PLC alongside
  the baselined HMI/EWS polling. The source is not in `known_talkers`, so it
  reports as a **new talker**.
- **New asset pair** — [`modbus/anomalous-x1-new-pair.yaml`](../../scenarios/modbus/anomalous-x1-new-pair.yaml):
  a **baselined** talker (`hmi-1`) reaches a PLC it has never talked to (`plc-2`).
  Because `hmi-1` *is* in `known_talkers`, the new-talker branch does not fire and
  the highest-precedence novelty is the **new asset pair** — the branch the
  new-talker scenario cannot reach.
- **New function for a known pair** — [`dnp3/anomalous-x1-new-function.yaml`](../../scenarios/dnp3/anomalous-x1-new-function.yaml):
  the **baselined** master/outstation pair, which has only ever read, issues a
  function never seen for that pair: a **new function for a known pair**.

The baseline for the anomalous runs is the union of the benign baselines; the
legitimate background traffic in each anomalous scenario is in that baseline (so it
stays quiet) while the novel tuple is not (so X1 fires).

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Remote System Discovery | **T0846** | Discovery (TA0102) |

A new talker / new asset pair is the network signature of an actor **discovering
and reaching** OT assets it has not legitimately spoken to before — T0846 ("a
listing of other systems by IP address, hostname, or other logical identifier on a
network"). `PRD.md` §5.4 also relates X1 to **Lateral Movement (TA0109)** (the
new-asset-pair class especially); the registry's data model records one verified
tactic per detection, and the verified primary mapping is Discovery/T0846 — the
same already-verified mapping used by M3/D4/S3.

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS
> matrix on 2026-06-04. Sources: <https://attack.mitre.org/techniques/T0846/>,
> tactic <https://attack.mitre.org/tactics/TA0102/>. The Lateral Movement relation
> (TA0109) is noted from `PRD.md` §5.4 and not asserted as the primary mapping.

## False-positive profile

- **Legitimate new equipment / commissioning.** Adding a PLC, an HMI, or a new
  poll target is a genuine new talker / new pair and *will* fire X1 — correctly.
  This is change-management signal, not a bug: re-learn the baseline after
  sanctioned changes (re-derive and re-inject `known_*`). The detection is only as
  good as the freshness of the learned baseline.
- **DHCP / re-addressing.** If OT hosts can change IP, a re-addressed-but-legitimate
  host looks like a new talker. Mitigate by baselining on stable addressing (OT
  segments are typically statically addressed) or by keying the baseline on asset
  identity upstream.
- **Under-learned baseline.** A learning period that missed a rare-but-legitimate
  function (e.g. a quarterly restart, an annual program download) will false-fire
  the first time that function recurs. Mitigate by learning over a window long
  enough to capture the full legitimate function set, or by allow-listing known
  rare-but-legitimate verbs.
- **Why benign baselines stay quiet.** Every talker, pair and function in the
  benign baseline scenarios is, by construction, in the injected baseline, so
  every observation is a set member and X1 says nothing — regardless of how much
  legitimate polling occurs (volume is not part of the signal).
