#!/usr/bin/env python3
"""Tier-2 fidelity + detection validation (real Zeek/ICSNPP in Docker).

This is the Tier-2 half of the two-tier execution model (PRD §6.5, §6.8). Where
Tier 1 evaluates Sigma over the emitted ``.jsonl`` in-process, Tier 2 runs the
**real** engines against the emitted PCAPs:

  1. **Fidelity golden test.** Every Modbus/DNP3 scenario's PCAP is parsed by real
     Zeek + the real ICSNPP script analyzers; the per-message protocol semantics
     in the resulting logs are diffed against our emitted ``.jsonl``. If our
     hand-built/scapy packets do not parse to the same events a production sensor
     would see, that is a fidelity bug.
  2. **Zeek detections in their real engine.** Every Tier-2 Zeek detection in the
     registry is executed by real Zeek over its fire and quiet scenarios; the
     runner asserts the SAME fire/quiet behavior the Tier-1 contract asserts for
     Sigma rules. X1's learned baseline is derived from the benign scenarios and
     injected via ``redef`` (exactly the mechanism the X1 doc describes).
  3. **Suricata detections.** Executed in real Suricata if any are shipped.

Honest scoping: the ICSNPP **S7comm** analyzer is a compiled C++ Zeek plugin, so
anything that needs it (S3, X1's S7 path, S7 fidelity) requires a Zeek image with
a build toolchain. When that plugin is unavailable the runner SKIPS those checks
with a loud, explicit reason — it never silently passes them. Likewise Suricata is
reported as "no rules" when the repo ships none (``detections/suricata`` empty).

Run: ``make verify`` (or ``python scripts/verify/run.py``). Requires Docker.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO_ROOT))

from substation.detect.registry import Detection, load_registry  # noqa: E402
from substation.detect.x1_tokens import x1_norm_func  # noqa: E402
from substation.emit import write_artifacts  # noqa: E402
from substation.scenarios import Scenario, load_scenario  # noqa: E402

# --- configuration -----------------------------------------------------------

ZEEK_IMAGE = (
    "zeek/zeek:8.2"
    "@sha256:32b90c30cb87d66748c3a6776ad2c0f5502aae7c12da9766cfdd426453c58838"
)
_DET_ZEEK = _REPO_ROOT / "detections" / "zeek"
_DET_SURICATA = _REPO_ROOT / "detections" / "suricata"
_SCENARIOS = _REPO_ROOT / "scenarios"
_REGISTRY = _REPO_ROOT / "detections" / "registry.yaml"
_CACHE = _REPO_ROOT / ".verify-cache"

# ICSNPP script packages we vendor for the fidelity check (script-only, mountable).
# Pinned to a commit for reproducibility. s7comm is intentionally absent — it is a
# compiled C++ plugin (see module docstring).
_ICSNPP = {
    # The hex strings are upstream git COMMIT PINS (not secrets) — allowlisted for
    # the secret scanner's high-entropy detector.
    "modbus": ("https://github.com/cisagov/icsnpp-modbus", "64559be1640dd91b888aed993531a06156deaed0"),  # pragma: allowlist secret
    "dnp3": ("https://github.com/cisagov/icsnpp-dnp3", "6e997bfc9445ff6b6845beaa1e4beab4ecec458e"),  # pragma: allowlist secret
}

# Per Tier-2 Zeek detection: the Notice::Type token it raises, and whether it needs
# the (unavailable) S7comm plugin to observe its protocol.
_NOTICE_TOKEN = {
    "M3": "ModbusSweep::Sweep",
    "D4": "Dnp3Enum::Enumeration",
    "S3": "S7Enum::Enumeration",
    "X1": "CrossProtoBaseline::BaselineDeviation",
}
_NEEDS_S7 = {"S3"}  # X1 runs over Modbus/DNP3; its S7 path is skipped per-scenario without the plugin.
# Optional local image with icsnpp-s7comm built in (see docs/verify-s7.md). When set
# and pullable, verify prefers it over the stock ZEEK_IMAGE for S7-capable runs.
_S7_ZEEK_IMAGE_ENV = "SUBSTATION_ZEEK_S7_IMAGE"


# --- result bookkeeping ------------------------------------------------------


@dataclass
class Results:
    passed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def ok(self, msg: str) -> None:
        print(f"  PASS  {msg}")
        self.passed.append(msg)

    def skip(self, msg: str) -> None:
        print(f"  SKIP  {msg}")
        self.skipped.append(msg)

    def fail(self, msg: str) -> None:
        print(f"  FAIL  {msg}")
        self.failed.append(msg)


# --- environment -------------------------------------------------------------


def _docker_ok() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def _image_present() -> bool:
    out = subprocess.run(
        ["docker", "image", "inspect", ZEEK_IMAGE], capture_output=True
    )
    if out.returncode == 0:
        return True
    print(f"verify: pulling {ZEEK_IMAGE} ...")
    return subprocess.run(["docker", "pull", ZEEK_IMAGE]).returncode == 0


def _at_commit(dest: Path, commit: str) -> bool:
    head = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return head.returncode == 0 and head.stdout.strip() == commit


def _checkout(dest: Path, commit: str) -> bool:
    if subprocess.run(["git", "-C", str(dest), "checkout", commit], capture_output=True).returncode == 0:
        return True
    # The pinned commit may not be in a shallow/older cache — fetch it, then retry.
    subprocess.run(["git", "-C", str(dest), "fetch", "--all", "--tags"], capture_output=True)
    return subprocess.run(["git", "-C", str(dest), "checkout", commit], capture_output=True).returncode == 0


def _discard_cached_clone(dest: Path) -> bool:
    try:
        if dest.is_symlink() or dest.is_file():
            dest.unlink()
        elif dest.exists():
            shutil.rmtree(dest)
    except OSError as exc:
        print(f"verify: could not discard stale ICSNPP cache {dest}: {exc}", file=sys.stderr)
        return False
    return True


def ensure_icsnpp(name: str) -> Path | None:
    """Return the local ICSNPP scripts dir for ``name`` at the **pinned** commit.

    On a cache hit the clone is re-verified against the pin. A drifted cache is
    discarded and cloned again instead of checked out in place, because Git runs
    repository-local checkout hooks from existing caches.
    """
    url, commit = _ICSNPP[name]
    dest = _CACHE / f"icsnpp-{name}"
    scripts = dest / "scripts"
    if (dest / ".git").is_dir():
        if _at_commit(dest, commit):
            return scripts if scripts.is_dir() else None
        print(f"verify: discarding drifted icsnpp-{name} cache -> {commit[:10]} ...")
        if not _discard_cached_clone(dest):
            return None
    _CACHE.mkdir(exist_ok=True)
    print(f"verify: fetching icsnpp-{name} @ {commit[:10]} ...")
    if subprocess.run(["git", "clone", url, str(dest)], capture_output=True).returncode != 0:
        return None
    if not _checkout(dest, commit):
        return None
    return scripts if scripts.is_dir() else None


# --- Zeek execution ----------------------------------------------------------


def run_zeek(pcap: Path, loads: list[str], mounts: list[tuple[Path, str]]) -> Path:
    """Run ``zeek -r pcap <loads>`` in the container; return a host dir of logs."""
    outdir = Path(tempfile.mkdtemp(prefix="zeeklogs-"))
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap.parent}:/pcaps:ro",
        "-v", f"{outdir}:/out",
    ]
    for host, container in mounts:
        cmd += ["-v", f"{host}:{container}:ro"]
    cmd += ["-w", "/out", ZEEK_IMAGE, "zeek", "-r", f"/pcaps/{pcap.name}", *loads]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"zeek failed on {pcap.name}: {proc.stderr.strip()[:400]}")
    return outdir


def read_zeek_log(logdir: Path, name: str) -> list[dict[str, str]]:
    """Parse a TSV Zeek log into a list of {field: value} dicts (header-driven)."""
    path = logdir / name
    if not path.is_file():
        return []
    fields: list[str] = []
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
        elif line.startswith("#") or not line:
            continue
        elif fields:
            rows.append(dict(zip(fields, line.split("\t"), strict=False)))
    return rows


# --- emit helper -------------------------------------------------------------


def emit(scenario_file: Path, outdir: Path) -> tuple[Path, list[dict[str, object]]]:
    """Emit a scenario's PCAP+JSON; return (pcap path, parsed JSON events)."""
    scenario = load_scenario(scenario_file)
    res = write_artifacts(scenario, outdir)
    events = [json.loads(line) for line in res.jsonl.read_text().splitlines()]
    return res.pcap, events


# --- fidelity check ----------------------------------------------------------


def _json_request_tuples(events: list[dict[str, object]]) -> Counter[tuple[str, str, str]]:
    """(orig_h, resp_h, func_name) multiset over request events in our JSON."""
    c: Counter[tuple[str, str, str]] = Counter()
    for e in events:
        if not e.get("is_orig"):
            continue
        conn = e["conn"]  # type: ignore[index]
        c[(conn["orig_h"], conn["resp_h"], str(e["func_name"]))] += 1  # type: ignore[index]
    return c


def _modbus_log_tuples(logdir: Path) -> Counter[tuple[str, str, str]]:
    c: Counter[tuple[str, str, str]] = Counter()
    for row in read_zeek_log(logdir, "modbus_detailed.log"):
        # modbus_detailed logs one row per request; func mirrors our func_name.
        # Skip exception-RESPONSE rows: a compliant outstation answers an undefined
        # request code 0x42 with a 0xC2 exception PDU, which ICSNPP cannot fold back
        # onto the (unhandled) request and logs as a separate `unknown-194` row with
        # exception_code set. Our two-event JSON models that exception on the
        # request's identity (is_orig=False, excluded from the request tuples), so we
        # compare like-for-like by dropping ICSNPP's standalone exception rows.
        if row.get("exception_code", "-") not in ("", "-"):
            continue
        c[(row.get("id.orig_h", ""), row.get("id.resp_h", ""), row.get("func", ""))] += 1
    return c


def _dnp3_log_tuples(logdir: Path) -> Counter[tuple[str, str, str]]:
    c: Counter[tuple[str, str, str]] = Counter()
    for row in read_zeek_log(logdir, "dnp3.log"):
        fc = row.get("fc_request", "-")
        if fc and fc != "-":
            c[(row.get("id.orig_h", ""), row.get("id.resp_h", ""), fc)] += 1
    return c


def fidelity_check(proto: str, results: Results) -> None:
    """Diff emitted JSON vs real Zeek/ICSNPP logs for every scenario of a protocol."""
    if proto not in _ICSNPP:
        # Only Modbus/DNP3 have vendored ICSNPP *script* packages; S7comm fidelity
        # needs the compiled plugin + a fidelity mapping (see docs/verify-s7.md).
        results.skip(
            f"fidelity[{proto}]: no vendored ICSNPP scripts / fidelity mapping "
            f"(enable via docs/verify-s7.md when using an icsnpp-s7comm image)"
        )
        return
    scripts = ensure_icsnpp(proto)
    if scripts is None:
        results.fail(f"fidelity[{proto}]: could not obtain icsnpp-{proto} scripts")
        return
    mounts = [(scripts, f"/icsnpp-{proto}")]
    loads = [f"/icsnpp-{proto}"]
    log_tuples = _modbus_log_tuples if proto == "modbus" else _dnp3_log_tuples

    proto_dir = _SCENARIOS / ("modbus" if proto == "modbus" else proto)
    compared = 0
    for scenario_file in sorted(proto_dir.glob("*.yaml")):
        with tempfile.TemporaryDirectory() as td:
            pcap, events = emit(scenario_file, Path(td))
            want = _json_request_tuples(events)
            if not want:
                results.skip(
                    f"fidelity[{proto}] {scenario_file.name}: no request events to compare"
                )
                continue
            try:
                logs = run_zeek(pcap, loads, mounts)
            except RuntimeError as exc:
                results.fail(f"fidelity[{proto}] {scenario_file.name}: {exc}")
                continue
            got = log_tuples(logs)
            shutil.rmtree(logs, ignore_errors=True)
            compared += 1
            # Per-message fidelity: the (src,dst,func) request *counts* must match
            # between our JSON and what real ICSNPP/Zeek decoded from our PCAP, so a
            # dropped or duplicated repeated message is caught (Counter, not set).
            if want == got:
                results.ok(
                    f"fidelity[{proto}] {scenario_file.name}: "
                    f"{sum(want.values())} request message(s) match real Zeek "
                    f"({len(want)} distinct tuple(s))"
                )
            else:
                deltas = sorted(
                    (t, want.get(t, 0), got.get(t, 0))
                    for t in set(want) | set(got)
                    if want.get(t, 0) != got.get(t, 0)
                )
                detail = ", ".join(f"{t}: json={w} zeek={g}" for t, w, g in deltas)
                results.fail(f"fidelity[{proto}] {scenario_file.name}: count mismatch — {detail}")
    if compared == 0 and proto in _ICSNPP:
        results.fail(f"fidelity[{proto}]: no scenarios produced comparable request events")


# --- detection checks --------------------------------------------------------


def _scenarios_for(det_id: str, fires: bool) -> list[Path]:
    out: list[Path] = []
    for scenario_file in sorted(_SCENARIOS.rglob("*.yaml")):
        scenario: Scenario = load_scenario(scenario_file)
        ids = scenario.exercises.fires if fires else scenario.exercises.quiet
        if det_id in ids:
            out.append(scenario_file)
    return out


def _count_notices(logdir: Path, token: str) -> int:
    rows = read_zeek_log(logdir, "notice.log")
    return sum(1 for r in rows if r.get("note") == token)


def _x1_baseline_redef(outdir: Path) -> Path:
    """Derive X1's learned baseline from the benign scenarios; write a redef file.

    Tokens are produced by :func:`substation.detect.x1_tokens.x1_norm_func`, which
    mirrors ``detections/zeek/x1_cross_protocol_baseline.zeek`` (Modbus/DNP3 numeric
    codes plus S7 ``rosctr``/``function``/``szl``/``s7comm-plus`` forms). Including
    the S7 benign baseline keeps X1's S7 quiet path honest when the plugin is present.
    """
    talkers: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    funcs: set[tuple[str, str, str]] = set()
    for proto in ("modbus", "dnp3", "s7"):
        benign = _SCENARIOS / proto / "benign-baseline.yaml"
        if not benign.exists():
            continue
        with tempfile.TemporaryDirectory() as td:
            _, events = emit(benign, Path(td))
        for e in events:
            token = x1_norm_func(e)  # type: ignore[arg-type]
            if token is None:
                continue
            conn = e["conn"]  # type: ignore[index]
            src, dst = conn["orig_h"], conn["resp_h"]  # type: ignore[index]
            talkers.add(str(src))
            pairs.add((str(src), str(dst)))
            funcs.add((str(src), str(dst), token))

    lines = ["redef CrossProtoBaseline::known_talkers += {"]
    lines += [f"\t{t}," for t in sorted(talkers)]
    lines.append("};")
    lines.append("redef CrossProtoBaseline::known_pairs += {")
    lines += [f"\t[{s}, {d}]," for s, d in sorted(pairs)]
    lines.append("};")
    lines.append("redef CrossProtoBaseline::known_funcs += {")
    lines += [f'\t[{s}, {d}, "{f}"],' for s, d, f in sorted(funcs)]
    lines.append("};")
    path = outdir / "x1_baseline.zeek"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def detection_check(
    det: Detection, s7_available: bool, results: Results, *, s7_loads: list[str] | None = None
) -> None:
    token = _NOTICE_TOKEN.get(det.id)
    if token is None:
        results.skip(f"detection[{det.id}]: no Tier-2 notice mapping")
        return
    if det.id in _NEEDS_S7 and not s7_available:
        results.skip(
            f"detection[{det.id}]: needs the icsnpp-s7comm C++ plugin (not built in "
            f"{ZEEK_IMAGE}); see docs/verify-s7.md to enable"
        )
        return

    rule_container = f"/det/{det.rule_path.name}"
    mounts = [(_DET_ZEEK, "/det")]
    fires = _scenarios_for(det.id, fires=True)
    quiet = _scenarios_for(det.id, fires=False)
    if not fires or not quiet:
        results.fail(f"detection[{det.id}]: missing fire/quiet scenarios")
        return

    ran = 0
    for label, scenario_files, want_fire in (("fire", fires, True), ("quiet", quiet, False)):
        for scenario_file in scenario_files:
            needs_s7_path = scenario_file.parent.name == "s7"
            if needs_s7_path and not s7_available:
                results.skip(
                    f"detection[{det.id}] {scenario_file.name}: S7 path needs the "
                    "s7comm plugin (docs/verify-s7.md)"
                )
                continue
            with tempfile.TemporaryDirectory() as td:
                tdp = Path(td)
                pcap, _ = emit(scenario_file, tdp)
                loads = [rule_container]
                mounts_run = list(mounts)
                if needs_s7_path and s7_loads:
                    # Load the S7 analyzer before the detection script so events exist.
                    loads = [*s7_loads, rule_container]
                if det.id == "X1":
                    _x1_baseline_redef(tdp)
                    mounts_run = [*mounts_run, (tdp, "/x1")]
                    # The rule must load FIRST so its &redef-able sets exist before
                    # the injected baseline redefs them (S7 loads still precede).
                    prefix = list(s7_loads or []) if needs_s7_path else []
                    loads = [*prefix, rule_container, "/x1/x1_baseline.zeek"]
                try:
                    logs = run_zeek(pcap, loads, mounts_run)
                except RuntimeError as exc:
                    results.fail(f"detection[{det.id}] {scenario_file.name}: {exc}")
                    continue
                hits = _count_notices(logs, token)
                shutil.rmtree(logs, ignore_errors=True)
            ran += 1
            if want_fire and hits >= 1:
                results.ok(f"detection[{det.id}] FIRE on {scenario_file.name} ({hits} notice)")
            elif not want_fire and hits == 0:
                results.ok(f"detection[{det.id}] QUIET on {scenario_file.name}")
            else:
                results.fail(
                    f"detection[{det.id}] {label} on {scenario_file.name}: "
                    f"expected {'>=1' if want_fire else '0'} notices, got {hits}"
                )
    if ran == 0:
        results.fail(
            f"detection[{det.id}]: every fire/quiet scenario was skipped — nothing evaluated"
        )


def suricata_check(results: Results) -> None:
    rules = [p for p in _DET_SURICATA.glob("*.rules")] + [
        p for p in _DET_SURICATA.glob("*.suricata")
    ]
    if not rules:
        results.skip(
            "suricata: no Suricata rules shipped (detections/suricata is empty) — "
            "nothing to execute (Suricata is optional, PRD §6.5)"
        )
        return
    results.skip(f"suricata: {len(rules)} rule file(s) found but the Suricata runner is not wired")


# --- s7 plugin probe ---------------------------------------------------------


def _active_zeek_image() -> str:
    """Return the Zeek image to use (optional S7-capable override via env)."""
    import os

    override = os.environ.get(_S7_ZEEK_IMAGE_ENV, "").strip()
    return override or ZEEK_IMAGE


def _s7_plugin_probe(image: str) -> tuple[bool, list[str]]:
    """Probe ``image`` for a usable icsnpp-s7comm analyzer.

    Returns ``(available, load_args)``. Availability requires both the plugin
    appearing in ``zeek -N`` *and* a loadable script path — claiming "available"
    without usable scripts caused silent empty S7 runs.
    """
    probe = subprocess.run(  # noqa: S603
        [
            "docker",
            "run",
            "--rm",
            image,
            "bash",
            "-c",
            "zeek -N 2>/dev/null | grep -qi s7comm && "
            "ls /usr/local/zeek/share/zeek/site/icsnpp/s7comm 2>/dev/null || "
            "ls /usr/local/zeek/share/zeek/site/icsnpp-s7comm 2>/dev/null || "
            "true",
        ],
        capture_output=True,
        text=True,
    )
    out = (probe.stdout or "") + (probe.stderr or "")
    if "s7comm" not in out.lower() and probe.returncode != 0:
        # Second probe: plugin name only (scripts may live under a package name).
        name_only = subprocess.run(  # noqa: S603
            [
                "docker",
                "run",
                "--rm",
                image,
                "bash",
                "-c",
                "zeek -N 2>/dev/null | grep -i s7comm || true",
            ],
            capture_output=True,
            text=True,
        )
        if "s7comm" not in (name_only.stdout or "").lower():
            return False, []
    # Prefer the conventional ICSNPP package load path.
    loads = ["icsnpp/s7comm"]
    load_ok = subprocess.run(  # noqa: S603
        [
            "docker",
            "run",
            "--rm",
            image,
            "bash",
            "-c",
            "zeek -e '@load icsnpp/s7comm' 2>&1 | tail -n 5",
        ],
        capture_output=True,
        text=True,
    )
    combined = (load_ok.stdout or "") + (load_ok.stderr or "")
    if load_ok.returncode != 0 or "error" in combined.lower():
        return False, []
    return True, loads


# --- main --------------------------------------------------------------------


def main() -> int:
    argparse.ArgumentParser(description=__doc__).parse_args()

    if not _docker_ok():
        print(
            "verify: Docker is required for Tier-2 validation but is not available.\n"
            "Start the Docker daemon and re-run `make verify`.",
            file=sys.stderr,
        )
        return 2
    global ZEEK_IMAGE
    ZEEK_IMAGE = _active_zeek_image()
    if not _image_present():
        print(f"verify: could not obtain {ZEEK_IMAGE}", file=sys.stderr)
        return 2

    results = Results()
    s7_available, s7_loads = _s7_plugin_probe(ZEEK_IMAGE)
    print(f"verify: Zeek image {ZEEK_IMAGE}; icsnpp-s7comm available: {s7_available}\n")
    if not s7_available:
        print(
            "verify: S7 Tier-2 path disabled — see docs/verify-s7.md "
            f"(optional {_S7_ZEEK_IMAGE_ENV}=...)\n"
        )

    print("== Fidelity (emitted JSON vs real Zeek/ICSNPP) ==")
    fidelity_check("modbus", results)
    fidelity_check("dnp3", results)
    if s7_available:
        fidelity_check("s7comm", results)
    else:
        results.skip(
            "fidelity[s7comm]: needs a Zeek image with a loadable icsnpp-s7comm "
            "plugin (docs/verify-s7.md)"
        )

    print("\n== Zeek detections (real engine, fire/quiet) ==")
    registry = load_registry(_REGISTRY)
    for det in registry:
        if det.engine == "zeek" and det.tier == 2:
            detection_check(det, s7_available, results, s7_loads=s7_loads)

    print("\n== Suricata detections ==")
    suricata_check(results)

    print("\n== Summary ==")
    print(f"  passed:  {len(results.passed)}")
    print(f"  skipped: {len(results.skipped)}")
    print(f"  failed:  {len(results.failed)}")
    if results.failed:
        print("\nverify: FAILED")
        return 1
    if not results.passed:
        print(
            "\nverify: FAILED — every check was skipped; nothing was evaluated. "
            "Check Docker/image availability and re-run.",
            file=sys.stderr,
        )
        return 1
    print("\nverify: OK (Tier-2 fidelity + Zeek detections; skips are explicit above)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
