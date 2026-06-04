# S3 — S7 module-info / SZL enumeration (recon)

A single source reading an anomalously **diverse** set of S7comm SZL system-status
lists (module identity, CPU characteristics, component identification, memory/system
areas, block types, …) — plus block listings and an S7comm-plus `Explore` — against
one PLC within a short window. The reconnaissance/enumeration detection for the S7
slice (`PRD.md` §5.3).

| | |
|---|---|
| **Detection ID** | S3 |
| **Engine** | Zeek (Tier 2, over PCAP via the icsnpp-s7comm plugin) |
| **Rule** | [`detections/zeek/s7comm_s3_enumeration.zeek`](../zeek/s7comm_s3_enumeration.zeek) |
| **Status** | tier2 · **Level** | (notice) |

## Behavior

Before manipulating a PLC, an adversary fingerprints it: the S7comm **Read SZL**
(System Status List) function returns module identification, CPU characteristics,
component identification, memory and system areas, block-type inventories, and more —
each selected by a distinct **SZL-ID**. Sweeping many SZL-IDs (optionally with `List
Blocks` / `Get Block Info` and an S7comm-plus `Explore`) maps the device's identity and
configuration. The signal is **diversity** — the number of *distinct* SZL-IDs one
source requests — deliberately **not** request volume: an engineering tool legitimately
reads module identity on connect, so a volume threshold would fire on normal operation
(`PRD.md` §8).

## Engine choice + rationale

**Zeek (the S7 slice's stateful rail, `PRD.md` §6.5; mirrors Modbus M3 / DNP3 D4).**
Enumeration needs durable **per-source state** — the set of distinct SZL-IDs
accumulated over a window — plus a set-cardinality test. A stateless Sigma field-match
cannot express "this source has now touched ≥ N *distinct* SZL-IDs." The Zeek script
keys on the ICSNPP `s7comm_read_szl` event (`szl_id`, `is_orig`, `c$id$orig_h`),
counts distinct SZL-IDs per (source, PLC) over a 60 s window, and raises one
`S7Enum::Enumeration` notice per episode (window-aligned dedup, the M3/D4 review fix
carried over).

Because Zeek/Suricata detections require their engine, S3 executes in **Tier 2** over
the emitted PCAP (`PRD.md` §6.2). The Tier-1 harness still enforces S3's contract
linkage (a rule, ≥1 fire and ≥1 quiet scenario); its fire/quiet run in the Tier-2
runner.

## Data source

ICSNPP-S7comm `s7comm_read_szl` event over PCAP (Tier 2). Event/field names verified
against `cisagov/icsnpp-s7comm` `scripts/icsnpp/s7comm/main.zeek` on 2026-06-04
(spike 06). The same telemetry appears in the Tier-1 `.jsonl` as
`detail.read_szl.szl_id` / `szl_id_name` (`docs/schema.md`), so the behavior is
inspectable in both tiers.

## Detection logic

```
per (source, PLC) over enum_window (60s):
    accumulate the set of distinct szl_id from s7comm_read_szl requests (is_orig)
fire when:  |distinct szl_id| >= szl_id_threshold (5)
            (one notice per window; resets with the window)
```

## Scenarios

- **Fires:** [`s7-anomalous-s3-enumeration.yaml`](../../scenarios/s7/anomalous-s3-enumeration.yaml)
  — `rogue-1` sweeps **six** distinct module-info SZL-IDs (module identification,
  component identification, CPU characteristics, user memory areas, system areas,
  block types) plus `List Blocks`, `Get Block Info` and an S7comm-plus `Explore`.
  Crosses the diversity threshold → fires (Tier-2 runner).
- **Quiet:** [`s7-benign-baseline.yaml`](../../scenarios/s7/benign-baseline.yaml)
  — the EWS reads a **single** module-identity SZL on connect (one distinct SZL-ID);
  well under the threshold → quiet. Also quiet on the S1/S2 anomalous scenarios
  (neither sweeps SZL-IDs).

## ATT&CK-for-ICS mapping

| | Technique | ID | Tactic |
|---|---|---|---|
| **Primary** | Remote System Information Discovery | **T0888** | Discovery (TA0102) |
| Secondary | Remote System Discovery | **T0846** | Discovery (TA0102) |

Sweeping a PLC's SZL system-status lists to gather its identity, CPU characteristics
and configuration is *Remote System Information Discovery* (T0888); enumerating the
device/block inventory is *Remote System Discovery* (T0846). Both sit under the
Discovery tactic — the same mapping as the DNP3 enumeration detection D4.

> **VERIFY (`CLAUDE.md` gate).** Verified against the **live** ATT&CK-for-ICS matrix
> on 2026-06-04: T0888 *Remote System Information Discovery* and T0846 *Remote System
> Discovery* both exist and are assigned to tactic Discovery (TA0102). Sources:
> <https://attack.mitre.org/techniques/T0888/>,
> <https://attack.mitre.org/techniques/T0846/>, tactic
> <https://attack.mitre.org/tactics/TA0102/>.

## False-positive profile

What benign behavior could trip this, and why it does not here:

- **Engineering tools reading module identity on connect** — TIA Portal and HMIs read
  a small handful of SZLs (often just module identification) when a session opens.
  Handled: the diversity threshold (5 distinct SZL-IDs) sits above a connect-time
  working set, so routine engineering stays quiet. The benign baseline reads one SZL
  and produces no notice.
- **Asset-inventory / monitoring tools** that periodically poll a *fixed, small* set of
  SZLs — stay below the threshold; if a site's legitimate tooling sweeps widely,
  raise `szl_id_threshold` or allow-list the tool's source.
- **Volume of a single SZL** (e.g. fast repeated module-identity polls) — never trips
  S3: the key is **distinct** SZL-IDs, not request count.

**Modelling note.** The 60 s window and the threshold of 5 distinct SZL-IDs are
`&redef`-able tuning knobs; environments with chattier engineering tooling should
tune them against their own baseline.
