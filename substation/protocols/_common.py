"""Helpers shared by the per-protocol semantic modules (PRD §6.1).

Every protocol module (``modbus``/``dnp3``/``s7comm``) and the honeypot needs
the same deterministic plumbing: Zeek-style connection uids, IPv4 validation,
ephemeral-port allocation, function-label normalization, and strict scenario
param checks. Centralizing them here guarantees the protocols cannot drift
apart (same uid derivation, same error phrasing, same bool-vs-int strictness)
and keeps each protocol module focused on protocol semantics only.

Validators take the protocol's error class as a parameter so failures still
surface as that protocol's exception (``ModbusError``/``Dnp3Error``/``S7Error``
— the API contract callers and tests rely on); each module binds it once in a
thin wrapper.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from collections.abc import Mapping

__all__ = [
    "EPHEMERAL_BASE",
    "zeek_uid",
    "normalize_function",
    "ipv4_host",
    "ephemeral_port",
    "check_int",
    "opt_int",
    "opt_str",
    "opt_bool",
]

# IANA dynamic/ephemeral port range start; client ports are assigned from here.
EPHEMERAL_BASE = 49152

_U16 = 0xFFFF
_B62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def zeek_uid(key: str) -> str:
    """Deterministic Zeek-style connection uid (``C`` + 17 base62 chars)."""
    digest = hashlib.blake2b(key.encode("utf-8"), digest_size=13).digest()
    n = int.from_bytes(digest, "big")
    chars: list[str] = []
    for _ in range(17):
        n, rem = divmod(n, 62)
        chars.append(_B62[rem])
    return "C" + "".join(chars)


def normalize_function(name: str) -> str:
    """Collapse a function label to a comparison token (case/separator-insensitive)."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def ipv4_host(host: str, actor_id: str, *, proto: str, error: type[ValueError]) -> str:
    """Validate an actor host as IPv4 (PCAP emission requires it); return it."""
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        raise error(
            f"actor {actor_id!r} host {host!r} is not an IPv4 address "
            f"({proto} PCAP emission requires IPv4)"
        ) from None
    return host


def ephemeral_port(index: int, *, error: type[ValueError]) -> int:
    """The ``index``-th deterministic client port from the ephemeral range."""
    port = EPHEMERAL_BASE + index
    if port > _U16:
        raise error("too many distinct connections for the ephemeral port range")
    return port


def check_int(value: object, where: str, lo: int, hi: int, *, error: type[ValueError]) -> int:
    """A required integer in ``[lo, hi]``; bools are rejected (int subclass)."""
    # bool is an int subclass in Python; an address/count/id is never a bool.
    if isinstance(value, bool) or not isinstance(value, int):
        raise error(f"{where}: expected an integer")
    if not lo <= value <= hi:
        raise error(f"{where}: {value} out of range ({lo}-{hi})")
    return value


def opt_int(
    params: Mapping[str, object],
    key: str,
    where: str,
    lo: int,
    hi: int,
    default: int,
    *,
    error: type[ValueError],
) -> int:
    """An optional integer param in ``[lo, hi]``, defaulting when absent."""
    if key not in params:
        return default
    return check_int(params[key], f"{where}.{key}", lo, hi, error=error)


def opt_str(
    params: Mapping[str, object], key: str, where: str, default: str, *, error: type[ValueError]
) -> str:
    """An optional non-empty string param, defaulting when absent."""
    if key not in params:
        return default
    value = params[key]
    if not isinstance(value, str) or not value:
        raise error(f"{where}.{key}: expected a non-empty string")
    return value


def opt_bool(
    params: Mapping[str, object], key: str, where: str, default: bool, *, error: type[ValueError]
) -> bool:
    """An optional boolean param, defaulting when absent."""
    if key not in params:
        return default
    value = params[key]
    if not isinstance(value, bool):
        raise error(f"{where}.{key}: expected a boolean")
    return value
