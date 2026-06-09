"""Protocol-agnostic helpers shared by the Modbus/DNP3/S7 semantic modules.

Each protocol module mirrors the same connection-bookkeeping shape (PRD §6.1):
deterministic Zeek-style connection uids, IPv4-only actor hosts, and
case/separator-insensitive function-name resolution. Those helpers live here
once so the protocols (and the honeypot, which shares the uid scheme) cannot
drift apart. This module stays pure Python and imports no packet library.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re

__all__ = ["EPHEMERAL_BASE", "ipv4_or_raise", "normalize_function", "zeek_uid"]

# IANA dynamic/ephemeral port range start; simulated client ports are assigned
# sequentially from here, one per distinct connection.
EPHEMERAL_BASE = 49152

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


def ipv4_or_raise(host: str, actor_id: str, proto_label: str, error: type[ValueError]) -> str:
    """Return ``host`` if it is an IPv4 literal, else raise the protocol's error.

    ``proto_label`` names the protocol in the message (e.g. ``Modbus/TCP``);
    ``error`` is the protocol's scenario-encoding error class.
    """
    try:
        ipaddress.IPv4Address(host)
    except ipaddress.AddressValueError:
        raise error(
            f"actor {actor_id!r} host {host!r} is not an IPv4 address "
            f"({proto_label} PCAP emission requires IPv4)"
        ) from None
    return host


def normalize_function(name: str) -> str:
    """Collapse a function label to a comparison token (case/separator-insensitive)."""
    return re.sub(r"[^a-z0-9]", "", name.lower())
