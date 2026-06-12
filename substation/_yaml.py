"""Strict YAML loading shared by every Substation YAML consumer.

PyYAML's default safe loader silently keeps the *last* value when a mapping key
is repeated, so a hand-authored scenario with two ``label:`` blocks (or a
registry entry with two ``attack:`` blocks) could quietly change the Detection
Contract or the coverage map. :func:`safe_load_strict` makes a duplicate key a
parse error instead, while staying exactly as safe as ``yaml.safe_load`` (no
arbitrary object construction).
"""

from __future__ import annotations

import yaml

__all__ = ["safe_load_strict"]


class _StrictLoader(yaml.SafeLoader):
    """A safe YAML loader that rejects duplicate mapping keys."""


def _construct_mapping_no_duplicates(
    loader: _StrictLoader, node: yaml.nodes.MappingNode, deep: bool = False
) -> dict[object, object]:
    loader.flatten_mapping(node)
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_no_duplicates,
)


def safe_load_strict(text: str) -> object:
    """Parse YAML ``text`` safely, rejecting duplicate mapping keys.

    Raises :class:`yaml.YAMLError` (the same family ``yaml.safe_load`` raises)
    on malformed input or a duplicate key.
    """
    # _StrictLoader is a SafeLoader subclass (no arbitrary object construction)
    # that additionally rejects duplicate mapping keys; this is as safe as
    # yaml.safe_load. noqa/nosec silence the ruff/bandit yaml.load heuristics,
    # which only whitelist the loader by name.
    return yaml.load(text, Loader=_StrictLoader)  # noqa: S506  # nosec B506
