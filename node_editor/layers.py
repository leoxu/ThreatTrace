"""
Diagram layers.

Every node carries a ``layer`` property. Nodes without one belong to the base
``model`` layer; review notes default to the ``comment`` layer so a reviewer's
questions can be hidden without deleting them (e.g. before exporting a report
or presenting the design).

A layer is turned off by hiding every item on it — nodes, their slots (child
items, hidden automatically) and any edge with an endpoint on a hidden node.
Hiding is a view state only: nothing is removed from the model.
"""
from __future__ import annotations

from typing import Iterable, List, Set

LAYER_KEY = "layer"

LAYER_MODEL = "model"
LAYER_COMMENT = "comment"

# Layers that always appear in the Layers menu, even when nothing uses them yet.
BUILTIN_LAYERS = (LAYER_MODEL, LAYER_COMMENT)


def node_layer(props: dict) -> str:
    """The layer a node belongs to; nodes without one are on the model layer."""
    value = str(props.get(LAYER_KEY, "")).strip().lower()
    return value or LAYER_MODEL


def scene_layers(scene) -> List[str]:
    """Every layer present in the scene, plus the built-ins, in stable order."""
    from .graphics.items import NodeItem

    found: Set[str] = set()
    for item in scene.items() if scene is not None else []:
        if isinstance(item, NodeItem):
            found.add(node_layer(item.properties()))

    ordered = [l for l in BUILTIN_LAYERS]
    ordered += sorted(l for l in found if l not in BUILTIN_LAYERS)
    return ordered


def apply_visibility(scene, hidden_layers: Iterable[str]) -> int:
    """Show/hide every item according to *hidden_layers*. Returns items hidden.

    Safe to call after any scene rebuild — visibility is derived purely from the
    current node properties.
    """
    from .graphics.items import EdgeItem, NodeItem

    if scene is None:
        return 0
    hidden = {str(l).strip().lower() for l in hidden_layers}
    hidden_nodes = set()
    count = 0

    for item in scene.items():
        if not isinstance(item, NodeItem):
            continue
        invisible = node_layer(item.properties()) in hidden
        item.setVisible(not invisible)
        if invisible:
            hidden_nodes.add(id(item))
            count += 1

    # An edge is only meaningful while both of its endpoints are visible.
    for item in scene.items():
        if not isinstance(item, EdgeItem):
            continue
        endpoints = [item.src, item.dst]
        owners = [s.parentItem() for s in endpoints if s is not None]
        invisible = any(id(o) in hidden_nodes for o in owners)
        for extra in ("source_node", "dest_node"):     # alias edges
            node = getattr(item, extra, None)
            if node is not None and id(node) in hidden_nodes:
                invisible = True
        item.setVisible(not invisible)
        if invisible:
            count += 1

    return count
