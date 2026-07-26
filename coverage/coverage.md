# Substation — ATT&CK-for-ICS coverage map

> **Generated** by `python -m substation.coverage` from `detections/registry.yaml`. Do not hand-edit — rerun the generator (`make coverage-build`). `make ci` fails if this file is out of date.

Detections: **11**. Tier 1 = Sigma-over-JSON (zero-dep headline path); Tier 2 = Zeek/Suricata over PCAP.

Download the [ATT&CK Navigator layer](./navigator-layer.json) and load it directly into the [Navigator](https://mitre-attack.github.io/attack-navigator/) to view this coverage on the live ICS matrix.

## Detections

| Detection | Title | Protocol | Technique(s) | Tactic | Engine | Tier | Status |
|---|---|---|---|---|---|---|---|
| M1 | Unauthorized register/coil write | modbus | T1692.001, T0836 | Impair Process Control (TA0106) | sigma | 1 | validated |
| M2 | Illegal / abnormal function code | modbus | T0888 | Discovery (TA0102) | sigma | 1 | validated |
| M3 | Function-code / unit-ID sweep | modbus | T0846, T0888 | Discovery (TA0102) | zeek | 2 | tier2 |
| D1 | Cold/warm restart from unexpected source | dnp3 | T0816, T0814 | Inhibit Response Function (TA0107) | sigma | 1 | validated |
| D2 | Disable unsolicited responses | dnp3 | T1691.002, T0878 | Inhibit Response Function (TA0107) | sigma | 1 | validated |
| D3 | Unauthorized control (operate/direct-operate) | dnp3 | T1692.001 | Impair Process Control (TA0106) | sigma | 1 | validated |
| D4 | Function-code enumeration / scanning | dnp3 | T0888, T0846 | Discovery (TA0102) | zeek | 2 | tier2 |
| S1 | CPU stop/start from unexpected source | s7comm | T0858 | Execution (TA0104) | sigma | 1 | validated |
| S2 | Program / data-block write or download | s7comm | T0843 | Lateral Movement (TA0109) | sigma | 1 | validated |
| S3 | Enumeration / module-info reads | s7comm | T0888, T0846 | Discovery (TA0102) | zeek | 2 | tier2 |
| X1 | Cross-protocol baseline deviation (new talker / asset pair / function) | cross | T0846 | Discovery (TA0102) | zeek | 2 | tier2 |

## Coverage by tactic (covered vs gap)

**5 of 12** ATT&CK-for-ICS tactics have at least one detection. Tactics are stable (`CLAUDE.md`); the gaps below are candidate areas for new detections, not missing technique IDs.

| Tactic | ID | Detections | Coverage |
|---|---|---|---|
| Initial Access | TA0108 | — | ⬜ gap |
| Execution | TA0104 | S1 | ✅ covered |
| Persistence | TA0110 | — | ⬜ gap |
| Privilege Escalation | TA0111 | — | ⬜ gap |
| Evasion | TA0103 | — | ⬜ gap |
| Discovery | TA0102 | M2, M3, D4, S3, X1 | ✅ covered |
| Lateral Movement | TA0109 | S2 | ✅ covered |
| Collection | TA0100 | — | ⬜ gap |
| Command and Control | TA0101 | — | ⬜ gap |
| Inhibit Response Function | TA0107 | D1, D2 | ✅ covered |
| Impair Process Control | TA0106 | M1, D3 | ✅ covered |
| Impact | TA0105 | — | ⬜ gap |
