<!--
Substation PR template. CI is LOCAL (`make ci`) — there is NO GitHub Actions in
this repo (CLAUDE.md). This file is a PR template only, not a workflow.
Fill in the sections and tick the boxes that apply. Delete the "Adding/changing a
detection" block if your PR has nothing to do with detections.
-->

## What & why

<!-- One or two sentences: what does this PR change and why? Link issues. -->

## Type of change

- [ ] New detection
- [ ] New protocol
- [ ] New / changed scenario
- [ ] Bug fix
- [ ] Docs / coverage / tooling

## Safety invariants (CLAUDE.md — all PRs)

- [ ] **Defensive-only:** no exploit code, weaponization, or payloads against real
      equipment — only the network *signature* of behaviour, for detection.
- [ ] **Files-only simulator preserved:** no sending socket / live-interface
      transmit added (`emit/guard.py` + `tests/test_files_only.py` still pass).
- [ ] **No cloud CI added:** no `.github/workflows/`; `make ci` is the gate.
- [ ] **VERIFY gates honoured:** any ATT&CK technique ID / ICSNPP field is verified
      against the live source, with the source + date recorded (not from memory).

## Adding or changing a detection — Detection Contract (PRD.md §6.6)

<!-- Every box must be ticked for a detection to be "done". Delete if N/A. -->

Detection ID(s): `________`

- [ ] **1. Rule** authored under `detections/<engine>/` (Sigma/Zeek/Suricata).
- [ ] **2. Anomalous scenario(s)** it must fire on (`exercises.fires`), with
      legitimate background traffic so it proves discrimination (PRD.md §8).
- [ ] **3. Benign scenario(s)** it must stay quiet on (`exercises.quiet`).
- [ ] **4. Fire-on-anomaly test passes** (Tier 1) / runs in the Tier-2 runner.
- [ ] **5. Quiet-on-benign test passes.**
- [ ] **6. ATT&CK-for-ICS mapping** with a **verified** technique ID + tactic
      (source + date in the doc/registry).
- [ ] **7. Doc** at `detections/docs/<ID>-*.md` with **engine choice + rationale**,
      **data source**, and a **false-positive profile**.
- [ ] **8. Registry entry** added/updated in `detections/registry.yaml`
      (the coverage-map entry everything is generated from).
- [ ] **Engine choice justified** per the policy (Sigma-first; Zeek only for real
      state; Suricata optional) — PRD.md §6.5.
- [ ] **Coverage regenerated:** `make coverage-build` (committed `docs/coverage/`
      snapshot + Navigator layer up to date; `make coverage-check` passes).

## Validation

- [ ] `make ci` is green locally (format-check, lint, type, tests, schema, coverage).
- [ ] Generated telemetry is **not** committed (`artifacts/`, `*.pcap`, `*.jsonl`
      except golden fixtures under `tests/data/`).

## Notes for reviewers

<!-- Anything reviewers should focus on; friction worth feeding into the docs. -->
