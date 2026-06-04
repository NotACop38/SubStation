"""Substation: defensive ICS detection-content pack and protocol simulator."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("substation")
except PackageNotFoundError:  # pragma: no cover - source tree without install metadata
    __version__ = "0.0.0"

__all__ = ["__version__"]
