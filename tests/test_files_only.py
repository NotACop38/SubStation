"""Files-only invariant tests (PRD §6.4, CLAUDE.md safety invariant).

The simulator must only ever write files — it must never open a sending socket or
transmit on an interface. These tests prove two things together: (1) generation
opens **no socket at all**, so no send path is reachable from it; and (2) the
guard that emission runs under actively rejects any connect/transmit attempt.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from substation.emit import write_artifacts
from substation.emit.guard import FilesOnlyViolation, files_only_guard
from substation.scenarios import load_scenario
from substation.schema import iter_jsonl_errors

_REPO_ROOT = Path(__file__).resolve().parent.parent
_EXAMPLE = _REPO_ROOT / "scenarios" / "modbus" / "benign-poll.yaml"


def test_generation_opens_no_socket(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Emission must never even construct a socket — the strongest form of the rule.

    scapy is already imported by the emit package, so replacing ``socket.socket``
    here only affects runtime: if any code on the generation path tried to open a
    socket, this would raise. It does not — generation is pure packet assembly plus
    file I/O — so the artifacts are produced normally.
    """

    def no_sockets(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the files-only simulator must not open a socket")

    monkeypatch.setattr(socket, "socket", no_sockets)

    scenario = load_scenario(_EXAMPLE)
    result = write_artifacts(scenario, tmp_path)

    assert result.pcap.stat().st_size > 24  # a real capture, not just a header
    assert result.event_count > 0
    assert list(iter_jsonl_errors(result.jsonl)) == []


def test_guard_blocks_connect_and_transmit() -> None:
    with files_only_guard():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            with pytest.raises(FilesOnlyViolation):
                sock.connect(("127.0.0.1", 9))
            with pytest.raises(FilesOnlyViolation):
                sock.sendto(b"x", ("127.0.0.1", 9))
            with pytest.raises(FilesOnlyViolation):
                sock.sendall(b"x")
        finally:
            sock.close()


def test_guard_restores_socket_methods_on_exit() -> None:
    original_send = socket.socket.send
    original_connect = socket.socket.connect
    with files_only_guard():
        assert socket.socket.send is not original_send  # patched inside
    assert socket.socket.send is original_send  # restored after
    assert socket.socket.connect is original_connect


def test_guard_restores_even_on_error() -> None:
    original_send = socket.socket.send
    with pytest.raises(ValueError, match="boom"), files_only_guard():
        raise ValueError("boom")
    assert socket.socket.send is original_send
