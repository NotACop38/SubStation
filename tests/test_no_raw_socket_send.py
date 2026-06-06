"""Codebase-wide files-only / no-raw-socket-send invariant (static AST scan).

CLAUDE.md's non-negotiable safety invariant: the simulator is *files-only* — it
never opens a sending socket or transmits on a live interface — and the optional
honeypot is *passive* (it only listens/accepts and replies on already-accepted
connections; it never initiates an outbound connection).

``tests/test_files_only.py`` proves the runtime behavior of the emit path. THIS
test is the complementary **static** guarantee over the whole shipped package: it
parses every ``substation/**/*.py`` module and fails if any source would (a)
initiate an outbound connection (``connect`` / ``connect_ex``), (b) create a RAW /
AF_PACKET socket, or (c) call a scapy wire-transmit function (``send`` / ``sendp`` /
``sr`` / ``srp`` / …) or live-sniff. Passive replies on an accepted socket
(``sendall`` on a server-side connection) are allowed — that is the honeypot's
sanctioned behavior — but *initiating* a connection or touching a raw interface is
not. Catching this at the source level means a future edit cannot quietly add a
send path without tripping the gate.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PKG_ROOT = _REPO_ROOT / "substation"

# Outbound-initiation primitives — forbidden as a call however they are spelled
# (``sock.connect(...)`` or a bare ``connect(...)``).
_OUTBOUND_CALLS = {"connect", "connect_ex"}

# ``send`` is also the name of a legitimate *socket method* used by the passive
# honeypot to reply on an already-accepted connection. We only forbid ``send`` /
# ``sendto`` / ``sendmsg`` when they are NOT obviously a method call on a
# connection object — i.e. a bare function call ``send(...)`` (scapy). Method
# calls (``sock.send(...)`` / ``conn.sendall(...)``) on an accepted socket are the
# sanctioned passive-reply path and are allowed.
_SCAPY_BARE_FUNCS = {"send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1", "sniff"}
_SOCKET_TRANSMIT_METHODS = {"send", "sendall", "sendto", "sendmsg", "sendfile"}
_PASSIVE_REPLY_MODULE = _PKG_ROOT / "honeypot" / "modbus.py"

# Raw-socket constants that must never be referenced.
_FORBIDDEN_ATTRS = {"SOCK_RAW", "AF_PACKET"}


def _python_sources() -> list[Path]:
    return sorted(_PKG_ROOT.rglob("*.py"))


def _allows_passive_reply(source: Path) -> bool:
    return source == _PASSIVE_REPLY_MODULE


def _violations(tree: ast.AST, source: Path) -> list[str]:
    found: list[str] = []
    for node in ast.walk(tree):
        # Raw-socket constants (socket.SOCK_RAW / socket.AF_PACKET).
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_ATTRS:
            found.append(f"line {node.lineno}: forbidden raw-socket constant '{node.attr}'")
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # A method/attribute call (``sock.connect(...)``): forbid connect/connect_ex
        # outright. send/sendall/sendto as socket methods (the passive reply path)
        # are allowed.
        if isinstance(func, ast.Attribute) and func.attr in _OUTBOUND_CALLS:
            found.append(f"line {node.lineno}: forbidden outbound '{func.attr}()'")
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in _SOCKET_TRANSMIT_METHODS
            and not _allows_passive_reply(source)
        ):
            found.append(f"line {node.lineno}: forbidden socket transmit method '{func.attr}()'")
        # A bare function call: an outbound connect, or a scapy transmit/capture fn.
        elif isinstance(func, ast.Name) and (
            func.id in _OUTBOUND_CALLS or func.id in _SCAPY_BARE_FUNCS
        ):
            found.append(f"line {node.lineno}: forbidden bare call '{func.id}()'")
    return found


@pytest.mark.parametrize("source", _python_sources(), ids=lambda p: str(p.relative_to(_REPO_ROOT)))
def test_no_outbound_or_raw_socket_calls(source: Path) -> None:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    violations = _violations(tree, source)
    assert not violations, (
        f"{source.relative_to(_REPO_ROOT)} breaks the files-only / no-raw-socket-send "
        f"invariant:\n  " + "\n  ".join(violations)
    )


def test_no_scapy_transmit_imports() -> None:
    """No shipped module may import scapy's transmit/capture entry points."""
    offenders: list[str] = []
    for source in _python_sources():
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("scapy"):
                for alias in node.names:
                    if alias.name in _SCAPY_BARE_FUNCS or alias.name == "sendrecv":
                        offenders.append(
                            f"{source.relative_to(_REPO_ROOT)}:{node.lineno} imports "
                            f"scapy.{node.module}.{alias.name}"
                        )
    assert not offenders, "scapy transmit/capture API imported:\n  " + "\n  ".join(offenders)


def test_method_send_calls_are_forbidden_outside_passive_honeypot() -> None:
    tree = ast.parse("def f(sock):\n    sock.sendall(b'x')\n")

    violations = _violations(tree, _PKG_ROOT / "emit" / "future.py")

    assert violations == ["line 2: forbidden socket transmit method 'sendall()'"]


def test_method_send_calls_are_allowed_in_passive_honeypot() -> None:
    tree = ast.parse("def f(sock):\n    sock.sendall(b'x')\n")

    assert _violations(tree, _PKG_ROOT / "honeypot" / "modbus.py") == []


def test_scan_actually_covers_the_package() -> None:
    """Guard against the glob silently matching nothing (a vacuous green)."""
    sources = _python_sources()
    assert len(sources) >= 15, (
        f"expected the full package to be scanned, found {len(sources)} files"
    )
    # The honeypot (a socket server) must be in scope — it is the one place that
    # legitimately uses sockets, so the scan must actively clear it.
    assert any(p.name == "modbus.py" and "honeypot" in str(p) for p in sources)
