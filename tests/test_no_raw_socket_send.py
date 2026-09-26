"""Codebase-wide files-only / no-raw-socket-send invariant (static AST scan).

CLAUDE.md's non-negotiable safety invariant: the simulator is *files-only* — it
never opens a sending socket or transmits on a live interface — and the optional
honeypot is *passive* (it only listens/accepts and replies on already-accepted
connections; it never initiates an outbound connection).

``tests/test_files_only.py`` proves the runtime behavior of the emit path. THIS
test is the complementary **static** guarantee over the whole shipped package: it
parses every ``substation/**/*.py`` module and fails if any source would (a)
initiate an outbound connection (``connect`` / ``connect_ex``, including through
``getattr``), (b) create a socket anywhere but the honeypot, which may create only
a TCP one, (c) reference a raw-socket constant or scapy's socket factories
(``L2socket`` / ``L3socket``), (d) import or call a scapy wire-transmit or capture
function, however imported or aliased, or (e) start a process (``subprocess``,
``os.system``, ``os.exec*``, ...). Passive replies on an accepted socket
(``sendall`` on a server-side connection) are allowed in the honeypot only.
Catching this at the source level means a future edit cannot quietly add a send
path without tripping the gate.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_PKG_ROOT = _REPO_ROOT / "substation"

# Outbound-initiation primitives — forbidden as a call however they are spelled
# (``sock.connect(...)``, a bare ``connect(...)`` or ``getattr(sock, "connect")``).
_OUTBOUND_CALLS = {"connect", "connect_ex"}

# ``send`` is also the name of a legitimate *socket method* used by the passive
# honeypot to reply on an already-accepted connection. We only forbid ``send`` /
# ``sendto`` / ``sendmsg`` when they are NOT obviously a method call on a
# connection object — i.e. a bare function call ``send(...)`` (scapy). Method
# calls (``sock.send(...)`` / ``conn.sendall(...)``) on an accepted socket are the
# sanctioned passive-reply path and are allowed there only.
_SCAPY_TRANSMIT_FUNCS = {"send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1", "sniff"}
_SOCKET_TRANSMIT_METHODS = {"send", "sendall", "sendto", "sendmsg", "sendfile"}
_PASSIVE_REPLY_MODULE = _PKG_ROOT / "honeypot" / "modbus.py"
# The runtime guard imports subprocess only to disable it during emission.
_GUARD_MODULE = _PKG_ROOT / "emit" / "guard.py"

# Socket constructors. Only the honeypot may create a socket, and only a TCP one.
_SOCKET_FACTORIES = {"socket", "socketpair", "fromfd", "create_connection", "create_server"}

# Names that must never appear: raw-socket constants and scapy's socket factories.
_FORBIDDEN_NAMES = {"SOCK_RAW", "AF_PACKET", "L2socket", "L3socket", "L2listen"}

# Modules whose import alone is a send or spawn path in a files-only package.
_FORBIDDEN_MODULES = {"_socket", "subprocess", "pty", "scapy.sendrecv"}
# Process creation outside subprocess: os.* and asyncio.* spawners.
_SPAWN_CALLS = {
    "system",
    "popen",
    "fork",
    "forkpty",
    "posix_spawn",
    "posix_spawnp",
    "create_subprocess_exec",
    "create_subprocess_shell",
    *(f"{kind}{suffix}" for kind in ("exec", "spawn") for suffix in ("l", "le", "lp", "lpe")),
    *(f"{kind}{suffix}" for kind in ("exec", "spawn") for suffix in ("v", "ve", "vp", "vpe")),
}


def _python_sources() -> list[Path]:
    return sorted(_PKG_ROOT.rglob("*.py"))


def _allows_passive_reply(source: Path) -> bool:
    return source == _PASSIVE_REPLY_MODULE


def _called_name(func: ast.expr, aliases: dict[str, str]) -> str | None:
    """The called name, however it is reached: ``f``, an alias, ``mod.f`` or ``getattr``."""
    if isinstance(func, ast.Name):
        return aliases.get(func.id, func.id)
    if isinstance(func, ast.Attribute):
        return func.attr
    if (
        isinstance(func, ast.Call)
        and isinstance(func.func, ast.Name)
        and func.func.id == "getattr"
        and len(func.args) >= 2
        and isinstance(func.args[1], ast.Constant)
        and isinstance(func.args[1].value, str)
    ):
        return func.args[1].value
    return None


def _is_tcp_socket(node: ast.Call) -> bool:
    """``socket.socket(<family>, socket.SOCK_STREAM)`` with a non-literal family."""
    return (
        len(node.args) == 2
        and not node.keywords
        and not isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[1], ast.Attribute)
        and node.args[1].attr == "SOCK_STREAM"
    )


def _imported_modules(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if isinstance(node, ast.ImportFrom) and node.module:
        return [node.module, *(f"{node.module}.{alias.name}" for alias in node.names)]
    return []


def _violations(tree: ast.AST, source: Path) -> list[str]:
    found: list[str] = []
    passive = _allows_passive_reply(source)
    # ``from m import f as g`` makes a bare ``g(...)`` call ``f``.
    aliases = {
        alias.asname: alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.asname
    }
    for node in ast.walk(tree):
        line = getattr(node, "lineno", 0)
        for module in _imported_modules(node):
            if source == _GUARD_MODULE and module == "subprocess":
                continue
            if module in _FORBIDDEN_MODULES or module.split(".")[0] in _FORBIDDEN_MODULES:
                found.append(f"line {line}: forbidden import '{module}'")
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("scapy"):
            for alias in node.names:
                if alias.name in _SCAPY_TRANSMIT_FUNCS or alias.name in _FORBIDDEN_NAMES:
                    found.append(f"line {line}: forbidden scapy import '{alias.name}'")
        if isinstance(node, ast.Attribute) and node.attr in _FORBIDDEN_NAMES:
            found.append(f"line {line}: forbidden name '{node.attr}'")
        if isinstance(node, ast.Name) and node.id in _FORBIDDEN_NAMES:
            found.append(f"line {line}: forbidden name '{node.id}'")
        if not isinstance(node, ast.Call):
            continue
        name = _called_name(node.func, aliases)
        if name is None:
            continue
        if name in _OUTBOUND_CALLS:
            found.append(f"line {line}: forbidden outbound '{name}()'")
        elif name in _SOCKET_FACTORIES and not (
            passive and name == "socket" and _is_tcp_socket(node)
        ):
            found.append(f"line {line}: forbidden socket creation '{name}()'")
        elif name in _SOCKET_TRANSMIT_METHODS and not (
            passive and isinstance(node.func, ast.Attribute)
        ):
            found.append(f"line {line}: forbidden socket transmit '{name}()'")
        elif name in _SCAPY_TRANSMIT_FUNCS:
            found.append(f"line {line}: forbidden scapy transmit/capture '{name}()'")
        elif name in _SPAWN_CALLS:
            found.append(f"line {line}: forbidden process creation '{name}()'")
    return found


@pytest.mark.parametrize("source", _python_sources(), ids=lambda p: str(p.relative_to(_REPO_ROOT)))
def test_no_outbound_or_raw_socket_calls(source: Path) -> None:
    tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    violations = _violations(tree, source)
    assert not violations, (
        f"{source.relative_to(_REPO_ROOT)} breaks the files-only / no-raw-socket-send "
        f"invariant:\n  " + "\n  ".join(violations)
    )


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("import scapy.all as s\ns.sendp(pkt)\n", "forbidden scapy transmit/capture 'sendp()'"),
        ("from scapy.all import srp1 as ask\n", "forbidden scapy import 'srp1'"),
        ("import scapy.sendrecv\n", "forbidden import 'scapy.sendrecv'"),
        ("from scapy.config import conf\nconf.L2socket(iface='eth0')\n", "'L2socket'"),
        ("import socket\nsocket.socket(17, 3)\n", "forbidden socket creation 'socket()'"),
        ("from socket import socket as s\ns(2, 1)\n", "forbidden socket creation"),
        ("getattr(sock, 'connect')(addr)\n", "forbidden outbound 'connect()'"),
        ("import subprocess\n", "forbidden import 'subprocess'"),
        ("import os\nos.system('tcpreplay x.pcap')\n", "forbidden process creation 'system()'"),
        ("import os\nos.execvp('nc', ['nc'])\n", "forbidden process creation 'execvp()'"),
        ("import _socket\n", "forbidden import '_socket'"),
    ],
)
def test_scan_catches_indirect_send_paths(code: str, expected: str) -> None:
    violations = _violations(ast.parse(code), _PKG_ROOT / "emit" / "future.py")
    assert any(expected in violation for violation in violations), violations


def test_honeypot_may_only_create_a_tcp_socket() -> None:
    honeypot = _PKG_ROOT / "honeypot" / "modbus.py"
    tcp = "import socket\nsocket.socket(family, socket.SOCK_STREAM)\n"
    assert _violations(ast.parse(tcp), honeypot) == []
    for code in (
        "import socket\nsocket.socket(family, socket.SOCK_DGRAM)\n",
        "import socket\nsocket.socket(17, socket.SOCK_STREAM)\n",
        "import socket\nsocket.create_connection(addr)\n",
    ):
        assert _violations(ast.parse(code), honeypot), code


def test_method_send_calls_are_forbidden_outside_passive_honeypot() -> None:
    tree = ast.parse("def f(sock):\n    sock.sendall(b'x')\n")

    violations = _violations(tree, _PKG_ROOT / "emit" / "future.py")

    assert violations == ["line 2: forbidden socket transmit 'sendall()'"]


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
