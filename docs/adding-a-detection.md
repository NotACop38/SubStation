# Adding a detection

A **finite, ordered checklist** for adding one detection to an *existing* protocol.
It is the operational form of the **Detection Definition of Done**
(`ENGINEERING_CHECKLIST.md`) / the **Detection Contract** (`PRD.md` §6.6): work the
steps top to bottom and the contract is satisfied by construction. To add a whole
new protocol first, see [`adding-a-protocol.md`](./adding-a-protocol.md).

> **The Detection Contract — a detection is "done" only when it has all of:**
> the authored rule · ≥1 anomalous scenario it fires on · ≥1 benign scenario it
> stays quiet on · a passing fire-on-anomaly test · a passing quiet-on-benign test
> · a verified ATT&CK-for-ICS mapping (technique ID + tactic) · a doc with engine
> rationale, data source and false-positive profile · a coverage-map entry.

Pick a detection ID up front (e.g. `M5`, `D5`, `S4`, or `X2`). Every artifact
below keys off it.

## Ordered checklist

1. **Describe the behaviour and pick the tactic.** Write one sentence: *what
   network behaviour fires this, and why is it credible OT-wise?* Name the
   ATT&CK-for-ICS **tactic** (tactics are stable — `CLAUDE.md`). Sanity-check the
   OT-realism guardrails (`PRD.md` §8): never "any write = bad" or "scanning =
   volume"; key on allow-list / diversity / illegal-code signals.

2. **Choose the engine (and record why).** Per the engine policy (`PRD.md` §6.5):
   - **Sigma (Tier 1)** for a stateless field match over the JSON envelope
     (allow-list source, illegal code, a specific control command). Default here.
   - **Zeek (Tier 2)** only when **real state** is required — learned baselines,
     set membership, multi-log joins, cross-protocol logic (see X1).
   - **Suricata** only for an optional packet-level signature.
   You will justify this choice in the doc (step 8); decide it now.

3. **Author the rule** under `detections/<engine>/`:
   - **Sigma:** `detections/sigma/<proto>_<id>_<slug>.yml`. `logsource.service`
     **must** equal the protocol (`modbus`/`dnp3`/`s7comm`); match over the
     normalized envelope fields (`docs/schema.md`). Tag the tactic and every
     technique (`attack.<taXXXX-shortname>`, `attack.tXXXX`) — the harness asserts
     the rule's `logsource` + tags agree with the registry.
   - **Zeek:** `detections/zeek/<proto>_<id>_<slug>.zeek`. Use only event/field
     names **verified against live sources** (record the verification + date in a
     header comment, as M3/D4/S3/X1 do).

4. **Verify the ATT&CK mapping.** Confirm the **technique ID(s)** against the
   **live** ATT&CK-for-ICS matrix (`CLAUDE.md` VERIFY gate — never from memory).
   Record the ID(s), the tactic, and the verification date + source URLs; you cite
   them in the registry and the doc.

5. **Author scenarios** under `scenarios/<proto>/` (see
   [`scenario-format.md`](./scenario-format.md)). The contract needs **both**:
   - ≥1 **anomalous** (`label: anomalous`) scenario listing your ID under
     `exercises.fires`. Include legitimate background traffic so the detection
     proves it *discriminates* (`PRD.md` §8), not just that it fires.
   - ≥1 **benign** (`label: benign`) scenario listing your ID under
     `exercises.quiet` — usually the protocol's `benign-baseline.yaml` (add your ID
     to its `quiet:` list).
   Make sure your anomalous scenario stays quiet on the *other* detections it
   lists under `quiet:` (the harness tests those too).

6. **Register the detection.** Add an entry to `detections/registry.yaml`
   (`id`, `title`, `protocol`, `engine`, `tier`, `status`, `rule`, `doc`,
   `attack`). The registry is the single metadata source — the coverage map, the
   Navigator layer and the harness all read it. Pick `status`:
   - `validated` — Tier-1 Sigma, fire **and** quiet proven by the harness.
   - `tier2` — Zeek/Suricata; fire/quiet runs in the Tier-2 runner (linkage still
     enforced here).
   - `partial` — quiet proven, fire blocked on an emitter/harness gap (note why).

7. **Run the harness.** `make test` (or `pytest`). The metadata-driven harness
   auto-discovers your detection from the registry. It asserts: rule + doc exist,
   ≥1 fire and ≥1 quiet scenario, `exercises` reference known IDs, Sigma
   `logsource`+tags match the registry, and (Tier 1) fire-on-anomaly +
   quiet-on-benign over real emitted telemetry. Tier-2 fire/quiet is skipped with
   a reason. One deliberate test-code step remains: a **validated Tier-1** fire
   scenario must pin its exact hit indices in `_EXPECTED_FIRE_HITS`
   (`tests/test_detection_contract.py`) — the completeness check tells you the
   missing entry, and the indices come from the failing assertion message. This
   is the over-match regression net: ≥1-hit alone can't catch a rule that also
   fires on events it never meant to.

8. **Write the doc** at `detections/docs/<ID>-<slug>.md` (copy an existing one):
   **engine choice + rationale**, **data source**, **detection logic**, the
   **scenarios** (fires/quiet), the **verified ATT&CK mapping** (with the VERIFY
   note from step 4), and a **false-positive profile** — what benign behaviour
   could trip it and why it does not here. The FP profile is mandatory.

9. **Regenerate the coverage map.** `make coverage-build` rewrites the committed
   snapshot (`docs/coverage/`) and the Navigator layer from the registry. Commit
   it; `make coverage-check` is the drift gate.

10. **Run the full gate once.** `make ci` (format-check, lint, type-check, tests,
    schema, coverage). Green = the Detection Contract is satisfied. Open a PR using
    the PR template, which itemizes every contract element.

## Done when

Every box of the Detection Definition of Done is ticked, `make ci` is green, and
the coverage map shows your new row (and any newly-covered tactic flips from ⬜ gap
to ✅ covered).
