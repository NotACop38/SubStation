"""Versioned site permissions compiled into ordinary, portable Sigma rules."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

import yaml

from substation._yaml import safe_load_strict
from substation.detect.registry import load_registry
from substation.detect.sigma_eval import matching_indices, parse_rule
from substation.schema import SchemaValidationError, iter_jsonl_lines

_CHANNELS = {"D1", "D2", "D3", "S1", "S2"}
_MAX_SELECTORS = 8192
_BASE = {
    "M1": "modbus_write_request",
    "D1": "restart_command",
    "D2": "disable_unsolicited",
    "D3": "output_control",
    "S1": "s7_request and (cpu_stop or cpu_start_stop)",
    "S2": "program_transfer",
}


def _mapping(value: Any, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or value.keys() != keys:
        raise ValueError(f"expected exactly these keys: {sorted(keys)}")
    return value


def _list(value: Any, *, nonempty: bool = False) -> list[Any]:
    if not isinstance(value, list) or len(value) > 128 or (nonempty and not value):
        raise ValueError(
            "expected a list of at most 128 entries" + (" (nonempty)" if nonempty else "")
        )
    return value


def _int(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"expected integer in {minimum}..{maximum}")
    return int(value)


def _ip(value: Any) -> str:
    if not isinstance(value, str) or "%" in value:
        raise ValueError("expected an IP address without a scope identifier")
    return str(ipaddress.ip_address(value))


def _channel(grant: dict[str, Any]) -> dict[str, Any]:
    return {
        "sources": sorted({_ip(v) for v in _list(grant["sources"], nonempty=True)}),
        "destination": _ip(grant["destination"]),
        "port": _int(grant["port"], 1, 65535),
    }


def load_policy(path: str | Path) -> dict[str, Any]:
    """Validate a bounded profile; absent permissions are explicit empty lists."""
    try:
        text = "".join(raw for _, raw in iter_jsonl_lines(path, max_bytes=262144, max_lines=10000))
        data = _mapping(safe_load_strict(text), {"schema", "name", "modbus", "channels"})
        if data["schema"] != "substation-site-policy/v1":
            raise ValueError("unsupported policy schema")
        if not isinstance(data["name"], str) or not re.fullmatch(
            r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}", data["name"]
        ):
            raise ValueError("policy name must be a short filename-safe identifier")
        writes = []
        for raw in _list(_mapping(data["modbus"], {"writes"})["writes"]):
            grant = _mapping(
                raw, {"sources", "destination", "port", "units", "address_space", "ranges"}
            )
            if grant["address_space"] not in ("coil", "holding-register"):
                raise ValueError("address_space must be coil or holding-register")
            ranges = []
            for item in _list(grant["ranges"], nonempty=True):
                span = _mapping(item, {"start", "end"})
                start, end = _int(span["start"], 0, 65535), _int(span["end"], 0, 65535)
                if start > end:
                    raise ValueError("range start exceeds end")
                ranges.append((start, end))
            # Overlapping/adjacent intervals within a grant form one permission.
            merged: list[dict[str, int]] = []
            for start, end in sorted(ranges):
                if merged and start <= merged[-1]["end"] + 1:
                    merged[-1]["end"] = max(end, merged[-1]["end"])
                else:
                    merged.append({"start": start, "end": end})
            writes.append(
                {
                    **_channel(grant),
                    "address_space": grant["address_space"],
                    "units": sorted(
                        {_int(v, 0, 255) for v in _list(grant["units"], nonempty=True)}
                    ),
                    "ranges": merged,
                }
            )
        channels = _mapping(data["channels"], _CHANNELS)
        data = {
            "schema": data["schema"],
            "name": data["name"],
            "modbus": {"writes": writes},
            "channels": {
                key: [
                    _channel(_mapping(g, {"sources", "destination", "port"}))
                    for g in _list(channels[key])
                ]
                for key in sorted(_CHANNELS)
            },
        }
        # Bound expansion before allocating or parsing generated rules.
        if (
            sum(
                min(span["end"] - span["start"] + 1, 1968 if g["address_space"] == "coil" else 123)
                for g in writes
                for span in g["ranges"]
            )
            > _MAX_SELECTORS
        ):
            raise ValueError(f"policy expands beyond {_MAX_SELECTORS} Sigma selectors")
        return data
    except (ValueError, TypeError, RecursionError, yaml.YAMLError) as exc:
        raise SchemaValidationError(f"{path}: invalid site policy: {exc}") from exc


def policy_hash(policy: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _selection(grant: dict[str, Any]) -> dict[str, Any]:
    return {
        "conn.orig_h": grant["sources"],
        "conn.resp_h": grant["destination"],
        "conn.resp_p": grant["port"],
    }


def compile_policy(policy: dict[str, Any]) -> dict[str, str]:
    """Compile validated policy. CLI detection and export share these exact bytes."""
    digest = policy_hash(policy)
    output = {}
    for det in load_registry():
        if det.engine != "sigma" or det.tier != 1:
            continue
        source = det.rule_path.read_text(encoding="utf-8")
        document = yaml.safe_load(source)
        detection = document["detection"]
        if det.id in _BASE:
            base = _BASE[det.id]
            expected = (
                base + " and not (in_policy_write and 1 of allowed_span_*)"
                if det.id == "M1"
                else base + " and not authorized_channel"
            )
            if detection["condition"] != expected:
                raise SchemaValidationError(
                    f"{det.id}: bundled rule changed; review policy compiler"
                )
            detection = {
                key: value
                for key, value in detection.items()
                if key != "condition"
                and key not in {"in_policy_write", "authorized_channel"}
                and not key.startswith("allowed_span_")
            }
            allowed = []
            if det.id == "M1":
                for grant in policy["modbus"]["writes"]:
                    coils = grant["address_space"] == "coil"
                    for span in grant["ranges"]:
                        for quantity in range(
                            1, min(span["end"] - span["start"] + 1, 1968 if coils else 123) + 1
                        ):
                            codes = [5, 15] if coils else [6, 16]
                            allowed.append(
                                {
                                    **_selection(grant),
                                    "detail.unit": grant["units"],
                                    "func_code": codes if quantity == 1 else codes[1],
                                    "detail.quantity": quantity,
                                    "detail.address|gte": span["start"],
                                    "detail.address|lte": span["end"] - quantity + 1,
                                }
                            )
            else:
                allowed = [_selection(grant) for grant in policy["channels"][det.id]]
            detection.update({f"site_allow_{i}": value for i, value in enumerate(allowed)})
            detection["condition"] = base + (" and not 1 of site_allow_*" if allowed else "")
            document["detection"] = detection
            document["falsepositives"] = [
                "Authorized operations missing from the selected site policy."
            ]
        original_id = str(document["id"])
        document["id"] = str(uuid.uuid5(uuid.UUID(original_id), digest))
        document["title"] += f" [{policy['name']}]"
        document["description"] += "\nAuthorization uses the accompanying site-policy manifest.\n"
        document["substation_policy"] = {
            "schema": policy["schema"],
            "name": policy["name"],
            "sha256": digest,
            "base_rule_id": original_id,
            "base_rule_sha256": hashlib.sha256(source.encode()).hexdigest(),
        }
        output[det.id] = yaml.safe_dump(document, sort_keys=False, allow_unicode=True)
        matching_indices(
            parse_rule(output[det.id]), []
        )  # Reject unsupported Sigma even without events.
    return output


def export_policy(policy: dict[str, Any], destination: Path) -> None:
    """Publish a complete new directory; refuse replacing any existing export."""
    rules = compile_policy(policy)
    if destination.exists():
        raise FileExistsError(f"policy export already exists: {destination}")
    staging = Path(tempfile.mkdtemp(prefix=".substation-policy-", dir=destination.parent))
    try:
        for name, content in rules.items():
            (staging / f"{name}.yml").write_text(content, encoding="utf-8")
        manifest = {
            "schema": "substation-policy-export/v1",
            "policy": policy,
            "policy_sha256": policy_hash(policy),
            "rules": {
                f"{name}.yml": hashlib.sha256(content.encode()).hexdigest()
                for name, content in rules.items()
            },
        }
        (staging / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        # An empty destination created concurrently may be replaced; nonempty dirs
        # are protected by rename semantics. No partially populated export is visible.
        os.rename(staging, destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
