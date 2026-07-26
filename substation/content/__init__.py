"""Resolve shipped detection/scenario content for checkout and wheel installs.

Detection rules and scenarios live at the repo root (``detections/``,
``scenarios/``) for contributor UX. The wheel build copies the same trees under
this package so ``pip install`` works without a git checkout. Callers resolve
paths through :func:`content_root` / :func:`content_path`, which prefer the
packaged copy and fall back to the repo checkout (editable installs).
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

__all__ = ["content_root", "content_path", "ContentError"]


class ContentError(FileNotFoundError):
    """Raised when shipped detections/scenarios cannot be located."""


def content_root() -> Path:
    """Return the directory that contains ``detections/`` and ``scenarios/``.

    Order: (1) packaged data next to this module (wheel / sdist install),
    (2) repo root two levels up (editable checkout).
    """
    packaged = Path(__file__).resolve().parent
    if (packaged / "detections" / "registry.yaml").is_file():
        return packaged

    # Editable install / working tree: content lives at the repo root.
    repo = Path(__file__).resolve().parents[2]
    if (repo / "detections" / "registry.yaml").is_file():
        return repo

    # importlib.resources fallback for zipimport / unusual layouts.
    try:
        traversable = resources.files(__name__)
        registry = traversable.joinpath("detections", "registry.yaml")
        if registry.is_file():
            with resources.as_file(traversable) as root:
                return Path(root)
    except (TypeError, FileNotFoundError, ModuleNotFoundError):
        pass

    raise ContentError(
        "cannot locate Substation detections/scenarios content. Install from a "
        "wheel that bundles content, or run from a repo checkout."
    )


def content_path(*parts: str) -> Path:
    """Join ``parts`` under :func:`content_root` and require the path exists."""
    path = content_root().joinpath(*parts)
    if not path.exists():
        raise ContentError(f"content path not found: {path}")
    return path
