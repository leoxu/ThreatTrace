"""QUndoCommand subclasses for node-editor canvas operations."""
from __future__ import annotations

from typing import List, Tuple, Dict, Any, Optional

from PySide6.QtCore import QPointF
from PySide6.QtGui import QUndoCommand


class AddNodeCommand(QUndoCommand):
    """Record a node that was already added to the scene by the caller.

    push() calls redo() immediately; on the first call we skip re-adding because
    the node is already in the scene.
    """

    def __init__(self, scene, node):
        super().__init__(f"Add {node.title}")
        self._scene = scene
        self._node = node
        self._first = True

    def redo(self):
        if self._first:
            self._first = False
            return
        if self._node.scene() is None:
            self._scene.addItem(self._node)

    def undo(self):
        if self._node.scene() is self._scene:
            self._scene.removeItem(self._node)


class AddEdgeCommand(QUndoCommand):
    """Record an edge that was already added to the scene by the caller."""

    def __init__(self, scene, edge):
        super().__init__("Add Edge")
        self._scene = scene
        self._edge = edge
        self._first = True

    # ------------------------------------------------------------------ helpers
    def _node_edges(self, slot):
        from .graphics.items import NodeItem
        node = slot.parentItem() if slot else None
        return node.edges if isinstance(node, NodeItem) else None

    def _disconnect(self):
        for slot in (self._edge.src, self._edge.dst):
            edges = self._node_edges(slot)
            if edges is not None and self._edge in edges:
                edges.remove(self._edge)

    def _reconnect(self):
        for slot in (self._edge.src, self._edge.dst):
            edges = self._node_edges(slot)
            if edges is not None and self._edge not in edges:
                edges.append(self._edge)

    # --------------------------------------------------------------- QUndoCommand
    def redo(self):
        if self._first:
            self._first = False
            return
        self._reconnect()
        if self._edge.scene() is None:
            self._scene.addItem(self._edge)

    def undo(self):
        self._disconnect()
        if self._edge.scene() is self._scene:
            self._scene.removeItem(self._edge)


class AliasEdgeCommand(QUndoCommand):
    """Add an alias (structural) edge between two nodes. First push is a no-op (edge already in scene)."""

    def __init__(self, scene, edge, source_node, dest_node):
        super().__init__("Link")
        self._scene = scene
        self._edge = edge
        self._source_node = source_node
        self._dest_node = dest_node
        self._first = True

    def _register(self):
        if self._edge not in self._source_node.alias_edges:
            self._source_node.alias_edges.append(self._edge)
        if self._edge not in self._dest_node.alias_edges:
            self._dest_node.alias_edges.append(self._edge)

    def _unregister(self):
        if self._edge in self._source_node.alias_edges:
            self._source_node.alias_edges.remove(self._edge)
        if self._edge in self._dest_node.alias_edges:
            self._dest_node.alias_edges.remove(self._edge)

    def redo(self):
        if self._first:
            self._first = False
            return
        self._register()
        if self._edge.scene() is None:
            self._scene.addItem(self._edge)
        self._edge.update_path()

    def undo(self):
        self._unregister()
        if self._edge.scene() is self._scene:
            self._scene.removeItem(self._edge)


class DeleteItemsCommand(QUndoCommand):
    """Remove a set of nodes and edges from the scene (keeps objects alive for undo)."""

    def __init__(self, scene, nodes, edges, threats_registry: dict, removed_threats: dict):
        super().__init__("Delete")
        self._scene = scene
        self._nodes: list = list(nodes)
        self._edges: list = list(edges)
        self._threats_registry = threats_registry
        self._removed_threats: dict = dict(removed_threats)

        # Cache slot/node references so we can reconnect on undo.
        # Slots are child items of nodes, so they remain valid as long as the
        # node Python object is alive (we never delete the Python objects).
        from .graphics.items import NodeItem
        self._edge_connections: Dict[int, tuple] = {}
        for edge in self._edges:
            src, dst = edge.src, edge.dst
            # For alias edges src/dst are None; fall back to source_node/dest_node
            src_node = src.parentItem() if src else getattr(edge, 'source_node', None)
            dst_node = dst.parentItem() if dst else getattr(edge, 'dest_node', None)
            self._edge_connections[id(edge)] = (src, dst, src_node, dst_node)

    def redo(self):
        from .graphics.items import NodeItem
        self._scene.clearSelection()
        for edge in self._edges:
            src, dst, src_node, dst_node = self._edge_connections[id(edge)]
            if src is None and dst is None:
                # alias edge
                if src_node and edge in getattr(src_node, 'alias_edges', []):
                    src_node.alias_edges.remove(edge)
                if dst_node and edge in getattr(dst_node, 'alias_edges', []):
                    dst_node.alias_edges.remove(edge)
            else:
                if isinstance(src_node, NodeItem) and edge in src_node.edges:
                    src_node.edges.remove(edge)
                if isinstance(dst_node, NodeItem) and edge in dst_node.edges:
                    dst_node.edges.remove(edge)
            if edge.scene() is self._scene:
                self._scene.removeItem(edge)
        for node in self._nodes:
            if node.scene() is self._scene:
                self._scene.removeItem(node)
        for guid in self._removed_threats:
            self._threats_registry.pop(guid, None)

    def undo(self):
        from .graphics.items import NodeItem
        for node in self._nodes:
            if node.scene() is None:
                self._scene.addItem(node)
        for edge in self._edges:
            src, dst, src_node, dst_node = self._edge_connections[id(edge)]
            if src is None and dst is None:
                # alias edge
                if src_node and edge not in getattr(src_node, 'alias_edges', []):
                    src_node.alias_edges.append(edge)
                if dst_node and edge not in getattr(dst_node, 'alias_edges', []):
                    dst_node.alias_edges.append(edge)
            else:
                if isinstance(src_node, NodeItem) and edge not in src_node.edges:
                    src_node.edges.append(edge)
                if isinstance(dst_node, NodeItem) and edge not in dst_node.edges:
                    dst_node.edges.append(edge)
            if edge.scene() is None:
                self._scene.addItem(edge)
        self._threats_registry.update(self._removed_threats)


class MoveNodesCommand(QUndoCommand):
    """Record node position changes caused by a drag operation."""

    def __init__(self, moves: List[Tuple]):
        # moves: list of (node, old_pos: QPointF, new_pos: QPointF)
        super().__init__("Move")
        self._moves = moves

    def undo(self):
        for node, old_pos, _new_pos in self._moves:
            if node.scene() is not None:
                node.setPos(old_pos)

    def redo(self):
        for node, _old_pos, new_pos in self._moves:
            if node.scene() is not None:
                node.setPos(new_pos)


class AutoLayoutCommand(QUndoCommand):
    """Apply a computed layout, fully undoable."""

    def __init__(self, node_items, new_positions: Dict[str, QPointF]):
        super().__init__("Auto Layout")
        self._items = list(node_items)
        self._old: Dict[str, QPointF] = {n.node_id: n.pos() for n in self._items}
        self._new = new_positions

    def redo(self):
        for item in self._items:
            if item.node_id in self._new and item.scene() is not None:
                item.setPos(self._new[item.node_id])

    def undo(self):
        for item in self._items:
            if item.node_id in self._old and item.scene() is not None:
                item.setPos(self._old[item.node_id])


class RetypeAssetsCommand(QUndoCommand):
    """Move every instance of an asset type onto a new type id.

    Renaming a type id is a model edit, not a settings change: the id is the key
    each node stores in ``security-properties.type``, and the schema, the
    operation list and the slot descriptions all resolve through it. Undoing a
    rename has to put the instances back, or the model is left pointing at a type
    that no longer exists.
    """

    def __init__(self, nodes, old_type_id: str, new_type_id: str,
                 project_nodes: Optional[dict] = None):
        super().__init__(f"Rename asset type '{old_type_id}' → '{new_type_id}'")
        self._nodes = list(nodes)
        self._old = old_type_id
        self._new = new_type_id
        # The project registry holds nodes that are not on the active canvas.
        self._project_nodes = project_nodes if project_nodes is not None else {}

    def _apply(self, frm: str, to: str) -> None:
        for node in self._nodes:
            props = dict(node.properties())
            sec = dict(props.get("security-properties") or {})
            if str(sec.get("type", "")) != frm:
                continue
            sec["type"] = to
            props["security-properties"] = sec
            node.set_properties(props)
        for data in self._project_nodes.values():
            sec = (data.get("properties") or {}).get("security-properties")
            if isinstance(sec, dict) and str(sec.get("type", "")) == frm:
                sec["type"] = to

    def redo(self):
        self._apply(self._old, self._new)

    def undo(self):
        self._apply(self._new, self._old)
