"""Files-only invariant guard (PRD §6.4, CLAUDE.md safety invariant).

The simulator must **only ever write files**: it never opens a sending socket and
never transmits on a live interface. That is a non-negotiable safety boundary, so
we enforce it in code rather than trusting the emitters to behave.

:func:`files_only_guard` is a context manager that, while active, replaces every
socket transmit/connect primitive with one that raises :class:`FilesOnlyViolation`.
Emission runs inside the guard, so any accidental network path — directly or via
scapy, which ultimately transmits through a kernel socket — fails loudly instead
of putting packets on the wire. Writing PCAP/JSON uses ordinary file I/O (``open``),
which the guard leaves untouched.
"""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

__all__ = ["FilesOnlyViolation", "files_only_guard"]


class FilesOnlyViolation(RuntimeError):
    """Raised when guarded code attempts to connect or transmit on a socket."""


# The transmit/connect primitives that would put data on the wire. Blocking these
# on the ``socket.socket`` class covers raw, UDP and TCP sends — and therefore any
# library (scapy included) that ultimately calls down to a kernel socket.
# ``sendfile`` is included because its zero-copy fast path (os.sendfile) transmits
# without routing through ``send``/``sendall``, so it would otherwise be a bypass.
_BLOCKED_METHODS = (
    "connect",
    "connect_ex",
    "send",
    "sendall",
    "sendto",
    "sendmsg",
    "sendfile",
)


def _blocked(name: str) -> Callable[..., Any]:
    def guarded(*_args: Any, **_kwargs: Any) -> Any:
        raise FilesOnlyViolation(
            f"socket.socket.{name}() is forbidden: the Substation simulator is "
            "files-only and must never transmit on a network interface (PRD §6.4)."
        )

    guarded.__name__ = name
    return guarded


@contextmanager
def files_only_guard() -> Iterator[None]:
    """Forbid socket connect/transmit for the duration of the ``with`` block.

    The guard patches ``socket.socket`` **process-wide** and is not thread-safe:
    while it is active, every thread in the process is denied socket transmit,
    and concurrent guards would race on save/restore. Emission is single-threaded
    by design, so this is an intentional simplification — do not run emission
    concurrently with code that legitimately needs a socket (e.g. the opt-in
    honeypot) in one process.
    """
    saved: dict[str, Any] = {}
    for name in _BLOCKED_METHODS:
        if hasattr(socket.socket, name):
            saved[name] = getattr(socket.socket, name)
            setattr(socket.socket, name, _blocked(name))
    try:
        yield
    finally:
        for name, original in saved.items():
            setattr(socket.socket, name, original)
