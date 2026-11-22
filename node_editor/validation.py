"""
Diagram validation rules.

Entry point:
    validate_scene(scene) -> List[ValidationIssue]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .graphics.items import EdgeItem, NodeItem


# ── classes that must live inside a trust boundary ────────────────────────────
_MUST_BE_IN_BOUNDARY = {
    "security host-app",
    "security process",
    "security dynamic-library",
    "security linux-kmd",
    "security qnx-resmgr",
    "security proxy",
}


# ── severity levels ───────────────────────────────────────────────────────────
SEVERITY_ERROR = "Error"
SEVERITY_WARNING = "Warning"


@dataclass
class ValidationIssue:
    severity: str          # "Error" or "Warning"
    rule: str              # short rule name
    message: str           # human-readable description
    node_id: Optional[str] = None   # highlight target (node)
    edge_id: Optional[str] = None   # highlight target (edge)


def _node_name(node: "NodeItem") -> str:
    return str(node.properties().get("name", node.title))


def _edge_label(edge: "EdgeItem") -> str:
    lbl = edge.label.name if edge.label else ""
    return f'"{lbl}"' if lbl else f"[{edge.edge_id[:8]}…]"


def _edge_type(edge: "EdgeItem", type_by_subtype: Optional[dict]) -> str:
    """Return the type for an edge.

    Prefers the stored 'type' property on the edge; falls back to the
    type_by_subtype lookup for edges saved before type was a stored property.
    """
    etype = str(edge.properties().get("type", "")).strip()
    if not etype and type_by_subtype:
        edge_subtype = str(edge.properties().get("sub-type", "")).strip()
        etype = type_by_subtype.get(edge_subtype, "")
    return etype


def validate_scene(scene, type_by_subtype: Optional[dict] = None) -> List[ValidationIssue]:
    """Run all rules against the live scene and return a list of issues."""
    from .graphics.items import NodeItem, EdgeItem

    nodes: List[NodeItem] = [i for i in scene.items() if isinstance(i, NodeItem)
                             and i.shape_kind != "Boundary"]
    edges: List[EdgeItem] = [i for i in scene.items() if isinstance(i, EdgeItem)]

    issues: List[ValidationIssue] = []

    # ── R1: edge not fully connected ──────────────────────────────────────────
    for edge in edges:
        if edge.src is None or edge.dst is None:
            issues.append(ValidationIssue(
                severity=SEVERITY_ERROR,
                rule="Unconnected Edge",
                message=f"Edge {_edge_label(edge)} has no "
                        f"{'source' if edge.src is None else 'destination'} connection.",
                edge_id=edge.edge_id,
            ))

    # Collect fully-connected edges only for the remaining rules
    connected_edges = [e for e in edges if e.src is not None and e.dst is not None]

    # ── R2: node not inside any trust boundary ────────────────────────────────
    for node in nodes:
        cls = str(node.properties().get("class", ""))
        if cls not in _MUST_BE_IN_BOUNDARY:
            continue
        boundary = getattr(node, "boundary", None)
        if boundary is None:
            issues.append(ValidationIssue(
                severity=SEVERITY_ERROR,
                rule="Node Outside Trust Boundary",
                message=f'"{_node_name(node)}" ({cls}) is not inside any trust boundary.',
                node_id=node.node_id,
            ))

    # ── R3: internal-type edge must not cross a trust boundary ───────────────
    for edge in connected_edges:
        props = edge.properties()
        etype = _edge_type(edge, type_by_subtype)
        if etype != "internal func call":
            continue
        src_node = edge.src.parentItem()
        dst_node = edge.dst.parentItem()
        if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
            continue
        src_boundary = getattr(src_node, "boundary", None)
        dst_boundary = getattr(dst_node, "boundary", None)
        if src_boundary is not dst_boundary:
            boundary_desc = _boundary_desc(src_boundary, dst_boundary)
            edge_subtype = str(props.get("sub-type", "")).strip()
            issues.append(ValidationIssue(
                severity=SEVERITY_ERROR,
                rule="Internal Edge Crosses Trust Boundary",
                message=(
                    f"Edge {_edge_label(edge)} ({edge_subtype!r}) from "
                    f'"{_node_name(src_node)}" to "{_node_name(dst_node)}" '
                    f"must not cross a trust boundary{boundary_desc}. "
                    "Internal calls must stay within the same trust boundary."
                ),
                edge_id=edge.edge_id,
            ))

    # ── R4: resource-type edge not connected to any security node ───────────
    for edge in connected_edges:
        if _edge_type(edge, type_by_subtype) != "Asset Operation":
            continue
        src_node = edge.src.parentItem()
        dst_node = edge.dst.parentItem()
        if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
            continue
        dst_cls = str(dst_node.properties().get("class", ""))
        if not dst_cls.startswith("security"):
            edge_subtype = str(edge.properties().get("sub-type", "")).strip()
            issues.append(ValidationIssue(
                severity=SEVERITY_WARNING,
                rule="Resource Edge to Non-Security Node",
                message=(
                    f"Edge {_edge_label(edge)} ({edge_subtype!r}) from "
                    f'"{_node_name(src_node)}" to "{_node_name(dst_node)}" '
                    "is a resource-access call but the destination is not a security node."
                ),
                edge_id=edge.edge_id,
            ))

    # ── R5: flow-type edge not crossing a trust boundary ─────────────────────
    for edge in connected_edges:
        if _edge_type(edge, type_by_subtype) != "IPC":
            continue
        src_node = edge.src.parentItem()
        dst_node = edge.dst.parentItem()
        if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
            continue
        src_boundary = getattr(src_node, "boundary", None)
        dst_boundary = getattr(dst_node, "boundary", None)
        if src_boundary is dst_boundary:
            edge_subtype = str(edge.properties().get("sub-type", "")).strip()
            issues.append(ValidationIssue(
                severity=SEVERITY_ERROR,
                rule="Flow Edge Within Same Boundary",
                message=(
                    f"Edge {_edge_label(edge)} ({edge_subtype!r}) from "
                    f'"{_node_name(src_node)}" to "{_node_name(dst_node)}" '
                    "must cross a trust boundary. Flow edges carry data between "
                    "different trust levels."
                ),
                edge_id=edge.edge_id,
            ))

    # ── R6: an edge that crosses a trust boundary must target a security asset ─
    for edge in connected_edges:
        etype = _edge_type(edge, type_by_subtype)
        if etype in ("internal func call", "alias", "ownership"):
            continue   # internal: R3; alias: structural; ownership: asset→owner link
        src_node = edge.src.parentItem()
        dst_node = edge.dst.parentItem()
        if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
            continue
        src_boundary = getattr(src_node, "boundary", None)
        dst_boundary = getattr(dst_node, "boundary", None)
        if src_boundary is dst_boundary:
            continue   # does not cross a trust boundary
        dst_cls = str(dst_node.properties().get("class", ""))
        if not dst_cls.startswith("security asset"):
            boundary_desc = _boundary_desc(src_boundary, dst_boundary)
            edge_subtype = str(edge.properties().get("sub-type", "")).strip()
            issues.append(ValidationIssue(
                severity=SEVERITY_ERROR,
                rule="Cross-Boundary Edge Must Target Asset",
                message=(
                    f"Edge {_edge_label(edge)} ({edge_subtype!r}) from "
                    f'"{_node_name(src_node)}" to "{_node_name(dst_node)}" '
                    f"crosses a trust boundary{boundary_desc} but its destination "
                    f'"{_node_name(dst_node)}" ({dst_cls or "no class"}) is not a '
                    "security asset. An edge that crosses a trust boundary must "
                    "target a security asset (its interface)."
                ),
                edge_id=edge.edge_id,
            ))

    # ── R6b: component must satisfy the asset interface's access-class filter ──
    import fnmatch
    for edge in connected_edges:
        # Alias and ownership edges are not interface operations — skip the filter.
        if _edge_type(edge, type_by_subtype) in ("alias", "ownership"):
            continue
        # Identify the asset-interface slot and the component on the other end.
        pairs = ((edge.src, edge.dst), (edge.dst, edge.src))
        for asset_slot, comp_slot in pairs:
            if asset_slot is None or comp_slot is None:
                continue
            asset_node = asset_slot.parentItem()
            comp_node = comp_slot.parentItem()
            if not isinstance(asset_node, NodeItem) or not isinstance(comp_node, NodeItem):
                continue
            if not str(asset_node.properties().get("class", "")).startswith("security asset"):
                continue
            sp = asset_slot.properties() if hasattr(asset_slot, "properties") else {}
            filt = str(sp.get("access-class", "")).strip()
            if not filt:
                continue   # interface declares no restriction
            comp_ac = str(comp_node.properties().get("access-class", "")).strip()
            patterns = [p.strip() for p in filt.split(",") if p.strip()]
            if not any(fnmatch.fnmatch(comp_ac, pat) for pat in patterns):
                iface = str(sp.get("interface", asset_slot.name))
                issues.append(ValidationIssue(
                    severity=SEVERITY_ERROR,
                    rule="Component Not Allowed On Interface",
                    message=(
                        f'"{_node_name(comp_node)}" (access-class '
                        f'{comp_ac or "unset"!r}) is not allowed on interface '
                        f'"{iface}" of "{_node_name(asset_node)}", which requires '
                        f"{filt!r}."
                    ),
                    edge_id=edge.edge_id,
                ))

    # ── R7: edge endpoint slot belongs to a non-node item ────────────────────
    for edge in connected_edges:
        for attr, label in (("src", "source"), ("dst", "destination")):
            slot = getattr(edge, attr)
            if slot is not None and not isinstance(slot.parentItem(), NodeItem):
                issues.append(ValidationIssue(
                    severity=SEVERITY_ERROR,
                    rule="Dangling Slot Reference",
                    message=(
                        f"Edge {_edge_label(edge)} {label} slot "
                        f'"{slot.name}" is not attached to a node.'
                    ),
                    edge_id=edge.edge_id,
                ))

    # ── R8: node with no edges (isolated) ────────────────────────────────────
    for node in nodes:
        cls = str(node.properties().get("class", ""))
        # Only flag security nodes, not generic shapes
        if not cls.startswith("security"):
            continue
        # A security control is never connected by an edge: it is placed *over*
        # the asset interfaces it protects, and its scope is read from that
        # geometry (see mitigation.py). Having no edges is its normal state, not
        # a finding — and a trust boundary contains nodes rather than linking to
        # them.
        if cls.startswith(("security control", "security trust-boundary")):
            continue
        if len(node.edges) == 0:
            issues.append(ValidationIssue(
                severity=SEVERITY_WARNING,
                rule="Isolated Node",
                message=f'"{_node_name(node)}" ({cls}) has no edges.',
                node_id=node.node_id,
            ))

    # ── R9: duplicate edge between same slot pair, type, and sub-type ────────
    seen_pairs: dict = {}
    for edge in connected_edges:
        props = edge.properties()
        key = (id(edge.src), id(edge.dst), props.get("type", ""), props.get("sub-type", ""))
        if key in seen_pairs:
            issues.append(ValidationIssue(
                severity=SEVERITY_WARNING,
                rule="Duplicate Edge",
                message=(
                    f"Edge {_edge_label(edge)} is a duplicate of another edge "
                    f"between the same slots."
                ),
                edge_id=edge.edge_id,
            ))
        else:
            seen_pairs[key] = edge

    return issues


def _boundary_desc(b1, b2) -> str:
    from .graphics.items import NodeItem
    names = []
    for b in (b1, b2):
        if isinstance(b, NodeItem):
            names.append(f'"{b.properties().get("name", "Trust Boundary")}"')
    if names:
        return " (" + " ↔ ".join(names) + ")"
    return ""
