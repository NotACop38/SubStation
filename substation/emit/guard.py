"""Files-only invariant guard (docs/design.md §6.4, AGENTS.md safety invariant).

The simulator must **only ever write files**: it never opens a sending socket and
never transmits on a live interface. That is a non-negotiable safety boundary, so
we enforce it in code rather than trusting the emitters to behave.

:func:`files_only_guard` is a context manager that, while active, makes every way
of reaching the network raise :class:`FilesOnlyViolation`:

* creating a socket (``socket.socket`` and everything built on it, including
  scapy's layer-2/3 sockets, ``socketpair``, ``fromfd`` and ``create_connection``);
* connecting or transmitting on a socket that already exists;
* starting a process (``subprocess``, ``os.system``, ``os.popen``, ``os.fork``,
  ``os.posix_spawn`` and the ``exec`` family), which could transmit on its behalf.

Emission runs inside the guard, so an accidental network path fails loudly instead
of putting packets on the wire. Writing PCAP/JSON uses ordinary file I/O
(``open``), which the guard leaves untouched.

The guard patches process-wide attributes and is therefore not thread-safe; the
emitters are single-threaded by design, and the complementary static AST scan
(``tests/test_no_raw_socket_send.py``) covers the whole package regardless of
runtime path.
"""

from __future__ import annotations

import os
import socket
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

__all__ = ["FilesOnlyViolation", "files_only_guard"]


class FilesOnlyViolation(RuntimeError):
    """Raised when guarded code attempts to open, connect or transmit on a socket."""


# The socket primitives that would open or use a network path. ``__init__`` blocks
# creation outright (every socket, scapy's included, is constructed through it);
# the rest cover sockets created before the guard. ``sendfile`` is included
# because its zero-copy fast path (os.sendfile) bypasses ``send``/``sendall``.
_BLOCKED_SOCKET_METHODS = (
    "__init__",
    "connect",
    "connect_ex",
    "send",
    "sendall",
    "sendto",
    "sendmsg",
    "sendfile",
)
# Process creation: a child process could transmit on the emitter's behalf.
# os.popen and the other exec variants route through these.
_BLOCKED_OS_FUNCTIONS = ("system", "fork", "posix_spawn", "posix_spawnp", "execv", "execve")


def _blocked(name: str) -> Callable[..., Any]:
    def guarded(*_args: Any, **_kwargs: Any) -> Any:
        raise FilesOnlyViolation(
            f"{name}() is forbidden: the Substation simulator is files-only and must "
            "never open a network path or start a process that could (docs/design.md §6.4)."
        )

    guarded.__name__ = name.rpartition(".")[2]
    return guarded


@contextmanager
def files_only_guard() -> Iterator[None]:
    """Forbid sockets and process creation for the duration of the ``with`` block."""
    targets: list[tuple[Any, str, str]] = [
        (socket.socket, name, f"socket.socket.{name}") for name in _BLOCKED_SOCKET_METHODS
    ]
    targets.append((subprocess.Popen, "__init__", "subprocess.Popen"))
    targets += [(os, name, f"os.{name}") for name in _BLOCKED_OS_FUNCTIONS]
    saved: list[tuple[Any, str, Any]] = []
    try:
        for owner, name, label in targets:
            if hasattr(owner, name):
                saved.append((owner, name, getattr(owner, name)))
                setattr(owner, name, _blocked(label))
        yield
    finally:
        for owner, name, original in reversed(saved):
            setattr(owner, name, original)
