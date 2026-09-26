"""Local output publication: atomic replacement and durable writes."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def default_mode(base: int = 0o666) -> int:
    """Return the permission bits a new file (``0o666``) or directory gets under the umask."""
    mask = os.umask(0)
    os.umask(mask)
    return base & ~mask


def write_durably(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` and flush it to stable storage."""
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
        stream.flush()
        os.fsync(stream.fileno())


def atomic_write(path: Path, text: str) -> None:
    """Replace one output atomically via a temporary file on the same filesystem.

    The result keeps the permissions of the file it replaces, or gets ordinary
    permissions for the current umask; the temporary file itself is private.
    """
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError:
        mode = default_mode()
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    staging = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        staging.chmod(mode)
        os.replace(staging, path)
    finally:
        staging.unlink(missing_ok=True)
