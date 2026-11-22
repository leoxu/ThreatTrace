from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from math import cos, sin, pi
from typing import Optional, List, Dict

from PySide6.QtCore import Qt, QPointF, QRectF, QSizeF
from PySide6.QtGui import QBrush, QColor, QPainterPath, QPainterPathStroker, QPen, QPainter, QCursor, QLinearGradient, QRadialGradient
from PySide6.QtWidgets import (
    QGraphicsEllipseItem,
    QGraphicsItem,
    QGraphicsPathItem,
    QGraphicsRectItem,
    QGraphicsSimpleTextItem,
)
from PySide6.QtCore import QTimer


SLOT_SIZE = QSizeF(15, 15)
NODE_PADDING = 12
MIN_BOUNDARY_SIZE = QSizeF(120, 90)
MIN_NODE_SIZE = QSizeF(60, 60)

# Module-level sequence state shared across all EdgeItems (set by app.py)
_seq_registry = None    # SequenceRegistry dict reference
_active_seq_id = None   # currently highlighted sequence id (str or None)
_threat_registry = None # ThreatRegistry dict reference
_edge_routing = "curved"  # "curved" (bezier) | "orthogonal" (right-angle elbows)


def set_edge_routing(style: str) -> None:
    """Set the global edge routing style ('curved' or 'orthogonal')."""
    global _edge_routing
    _edge_routing = style if style in ("curved", "orthogonal") else "curved"


def get_edge_routing() -> str:
    return _edge_routing


def set_sequence_registry(registry) -> None:
    global _seq_registry
    _seq_registry = registry


def set_active_sequence(seq_id) -> None:
    global _active_seq_id
    _active_seq_id = seq_id


def get_sequence_registry():
    return _seq_registry


def _is_owner_component(cls: str) -> bool:
    """A component that can own assets (not an asset/container/boundary/control)."""
    cls = str(cls)
    return cls.startswith("security") and not cls.startswith((
        "security asset", "security container", "security trust-boundary",
        "security control"))


def update_container_ownership(scene) -> None:
    """Derive asset ownership from container co-membership.

    If exactly one owner-component and one or more assets share a container, the
    component becomes the owner of those assets (written to the asset's
    security-properties.owner, else a top-level 'owner' property).
    """
    if scene is None:
        return
    from collections import defaultdict
    by_container = defaultdict(list)
    for item in scene.items():
        if isinstance(item, NodeItem) and getattr(item, "container", None) is not None:
            by_container[item.container].append(item)
    for members in by_container.values():
        comps = [m for m in members if _is_owner_component(m._properties.get("class", ""))]
        assets = [m for m in members
                  if str(m._properties.get("class", "")).startswith("security asset")]
        if len(comps) != 1 or not assets:
            continue
        owner_name = str(comps[0]._properties.get("name", ""))
        for a in assets:
            _set_asset_owner(a, owner_name)


def ensure_owner_slot(node: "NodeItem") -> None:
    """Every security asset gets a single dedicated 'owner' output slot.

    The ownership connection runs from this slot to the owning component.
    Idempotent: does nothing if the asset already has an owner slot.
    """
    if not str(node._properties.get("class", "")).startswith("security asset"):
        return
    for s in node.outputs:
        if s.name == "owner":
            return
    # No fixed side: the owner slot joins the even border distribution so it
    # never overlaps an interface slot; its dark-green colour keeps it distinct.
    node.add_slot("owner", "output",
                  {"owner-slot": True, "color": "#1e8449"})


def _set_asset_owner(asset: "NodeItem", owner_name: str) -> None:
    sec = asset._properties.get("security-properties")
    if isinstance(sec, dict):
        if sec.get("owner") != owner_name:
            new_sec = dict(sec)
            new_sec["owner"] = owner_name
            asset._properties["security-properties"] = new_sec
            asset.update()
    elif asset._properties.get("owner") != owner_name:
        asset._properties["owner"] = owner_name
        asset.update()


def get_active_sequence():
    return _active_seq_id


def set_threat_registry(registry) -> None:
    global _threat_registry
    _threat_registry = registry


def slot_tangent(slot: 'SlotItem') -> QPointF:
    """Return the outward unit tangent direction for a slot (module-level, mirrors EdgeItem._slot_tangent)."""
    parent = slot.parentItem()
    if not isinstance(parent, NodeItem):
        return QPointF(1, 0) if slot.kind == "output" else QPointF(-1, 0)
    slot_scene = slot.center_in_scene()
    if parent.shape_kind in ("Circle", "Ellipse", "Triangle", "Diamond", "Hexagon"):
        center_scene = parent.mapToScene(parent._shape_rect().center())
        dx = slot_scene.x() - center_scene.x()
        dy = slot_scene.y() - center_scene.y()
        length = (dx ** 2 + dy ** 2) ** 0.5
        if length > 0.001:
            return QPointF(dx / length, dy / length)
    slot_local = parent.mapFromScene(slot_scene)
    mid_x = parent._shape_rect().center().x()
    return QPointF(1, 0) if slot_local.x() >= mid_x else QPointF(-1, 0)


def _is_valid(item: Optional[QGraphicsItem]) -> bool:
    try:
        return bool(item) and item.scene() is not None
    except Exception:
        return False


@dataclass
class SlotSpec:
    name: str
    kind: str  # "input" or "output"
    properties: Dict[str, object] = field(default_factory=dict)


class SlotItem(QGraphicsRectItem):
    def __init__(self, name: str, kind: str, parent: QGraphicsItem,
                 properties: Optional[dict] = None):
        super().__init__(parent)
        self.name = name
        self.kind = kind
        self._properties: dict = dict(properties) if properties else {}
        self.setRect(QRectF(0, 0, SLOT_SIZE.width(), SLOT_SIZE.height()))
        # Directional appearance
        self._dir_display = "In" if kind == "input" else "Out"
        if self._dir_display == "In":
            self.base_brush = QBrush(QColor("#29b6f6"))  # sky blue — receiving
            self._base_pen = QPen(QColor("#0277bd"))
            self._base_pen.setWidthF(1.5)
        else:
            self.base_brush = QBrush(QColor("#ff9800"))  # amber — sending
            self._base_pen = QPen(QColor("#e65100"))
            self._base_pen.setWidthF(1.5)
        # Asset interface slots carry their own colour so each interface is
        # visually distinct.
        _slot_color = str(self._properties.get("color", "")).strip()
        if _slot_color:
            c = QColor(_slot_color)
            if c.isValid():
                self.base_brush = QBrush(c)
                self._base_pen = QPen(c.darker(140))
                self._base_pen.setWidthF(1.5)
        self.setBrush(self.base_brush)
        self.setPen(self._base_pen)
        self._highlighted = False
        self.setFlag(QGraphicsItem.ItemSendsScenePositionChanges)
        self.setAcceptHoverEvents(True)
        self.setToolTip(f"{self.name} (Dir: {self._dir_display})")

    @property
    def Dir(self) -> str:
        return self._dir_display

    def properties(self) -> dict:
        return dict(self._properties)

    def set_properties(self, props: dict) -> None:
        self._properties = dict(props)

    def center_in_scene(self) -> QPointF:
        # Use direct center point mapping to avoid heavy polygon conversions
        c = self.rect().center()
        return self.mapToScene(c)

    def hoverEnterEvent(self, event):  # type: ignore[override]
        # Slightly brighten on hover
        c = self.brush().color()
        c = QColor(min(255, int(c.red() * 1.1)), min(255, int(c.green() * 1.1)), min(255, int(c.blue() * 1.1)))
        self.setBrush(QBrush(c))
        return super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):  # type: ignore[override]
        if not self._highlighted:
            self.setBrush(self.base_brush)
        return super().hoverLeaveEvent(event)

    def set_highlight(self, on: bool) -> None:
        self._highlighted = on
        highlight_pen = QPen(QColor("#ffff00"), 2.5)
        self.setPen(highlight_pen if on else self._base_pen)
        self.setBrush(self.base_brush)

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton and self.scene():
            from ..app import NodeGraphicsScene
            scene = self.scene()
            if isinstance(scene, NodeGraphicsScene):
                self._press_scene_pos = event.scenePos()
                self._drag_mode = ""   # undecided until first move
                scene.start_connection(self)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        from ..app import NodeGraphicsScene
        scene = self.scene()
        if not isinstance(scene, NodeGraphicsScene):
            super().mouseMoveEvent(event)
            return

        press_pos = getattr(self, '_press_scene_pos', None)
        drag_mode = getattr(self, '_drag_mode', 'connect')

        # Decide mode on first significant movement
        if drag_mode == "" and press_pos is not None:
            delta = event.scenePos() - press_pos
            if delta.manhattanLength() > 6:
                parent = self.parentItem()
                is_box = (hasattr(parent, 'shape_kind') and
                          parent.shape_kind in ("Box", "Composite", "Subgraph"))
                if (is_box and
                        abs(delta.y()) > abs(delta.x()) * 2.0 and
                        abs(delta.x()) < 15):
                    drag_mode = "reorder"
                    scene.cancel_connection()
                    parent._start_reorder(self)
                    self.setCursor(Qt.SizeVerCursor)
                else:
                    drag_mode = "connect"
                self._drag_mode = drag_mode

        if drag_mode == "reorder":
            parent = self.parentItem()
            if parent is not None:
                local_y = parent.mapFromScene(event.scenePos()).y()
                parent._update_reorder(self, local_y)
            event.accept()
            return

        scene.update_connection(event.scenePos())
        event.accept()

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton and self.scene():
            from ..app import NodeGraphicsScene
            scene = self.scene()
            if isinstance(scene, NodeGraphicsScene):
                drag_mode = getattr(self, '_drag_mode', 'connect')

                if drag_mode == "reorder":
                    parent = self.parentItem()
                    if parent is not None:
                        parent._finish_reorder(self)
                    self._drag_mode = ""
                    self.unsetCursor()
                    event.accept()
                    return

                self._drag_mode = ""
                items = scene.items(event.scenePos())
                target = next((i for i in items if isinstance(i, SlotItem) and i is not self), None)
                press_pos = getattr(self, '_press_scene_pos', None)
                is_click = (
                    target is None and press_pos is not None and
                    (event.scenePos() - press_pos).manhattanLength() < 6
                )
                if is_click:
                    scene.cancel_connection()
                    scene.slotClicked.emit(self)
                else:
                    scene.finish_connection(target)
                event.accept()
                return
        super().mouseReleaseEvent(event)


class LabelHandleItem(QGraphicsRectItem):
    def __init__(self, parent: 'LabelItem'):
        super().__init__(parent)
        self.setRect(QRectF(-6, -6, 12, 12))
        self.setBrush(QBrush(QColor("#e0e0e0")))
        self.setPen(QPen(QColor("#666")))
        self.setZValue(3)
        # We handle dragging manually; don't allow this handle itself to be selected
        self.setFlags(QGraphicsItem.ItemSendsGeometryChanges)
        self._parent_label = parent
        self._dragging = False
        self._press_offset_scene = QPointF(0.0, 0.0)

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            # Select only the parent label when its slot/handle is clicked
            sc = self.scene()
            if sc is not None:
                sc.clearSelection()
            if self._parent_label is not None:
                self._parent_label.setSelected(True)
            origin_scene = self.mapToScene(QPointF(0.0, 0.0))
            self._press_offset_scene = origin_scene - event.scenePos()
            self._dragging = True
            self.setCursor(QCursor(Qt.ClosedHandCursor))
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        if self._dragging and self._parent_label is not None:
            new_origin_scene = event.scenePos() + self._press_offset_scene
            parent = self._parent_label.parentItem()
            new_local = parent.mapFromScene(new_origin_scene) if parent is not None else new_origin_scene
            self._parent_label.setPos(new_local)
            self._parent_label.user_positioned = True
            # Store offset relative to chord midpoint so the label follows nodes
            edge = self._parent_label.edge
            if edge is not None:
                try:
                    if edge.src is not None and edge.dst is not None:
                        a = edge.src.center_in_scene()
                        b = edge.dst.center_in_scene()
                    elif edge.source_node is not None and edge.dest_node is not None:
                        a = edge.dest_node.mapToScene(edge.dest_node._shape_rect().center())
                        b = edge.source_node.mapToScene(edge.source_node._shape_rect().center())
                    else:
                        a = edge.src_pos
                        b = edge.dst_pos
                    chord_mid = QPointF((a.x() + b.x()) / 2, (a.y() + b.y()) / 2)
                    self._parent_label._midpoint_offset = new_origin_scene - chord_mid
                    edge.request_update()
                except Exception:
                    pass
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._dragging:
            self._dragging = False
            event.accept()
            return
        super().mouseReleaseEvent(event)


class LabelItem(QGraphicsItem):
    def __init__(self, text: str = "", edge: Optional['EdgeItem'] = None):
        super().__init__()
        self.setZValue(2)
        self.setFlags(QGraphicsItem.ItemIsSelectable | QGraphicsItem.ItemSendsGeometryChanges)
        self.setAcceptHoverEvents(True)
        self.setAcceptedMouseButtons(Qt.LeftButton)
        self._text_item = QGraphicsSimpleTextItem(text, self)
        # Ensure clicks on text select the label (parent)
        self._text_item.setAcceptedMouseButtons(Qt.NoButton)
        self.user_positioned = False
        self._midpoint_offset = QPointF(0.0, 0.0)  # offset from chord midpoint (a+b)/2
        self.edge: Optional['EdgeItem'] = edge
        self.handle = LabelHandleItem(self)
        self._update_text_layout()

    @property
    def name(self) -> str:
        return self._text_item.text()

    @name.setter
    def name(self, value: str) -> None:
        self.set_text(value)

    def set_text(self, text: str) -> None:
        self._text_item.setText(text)
        self._update_text_layout()
        self.update()

    def set_text_color(self, color: str) -> None:
        from PySide6.QtGui import QBrush
        self._text_item.setBrush(QBrush(QColor(color) if color else QColor("#222222")))

    def _update_text_layout(self) -> None:
        tb = self._text_item.boundingRect()
        self._text_item.setPos(-tb.width() / 2.0, -tb.height())

    def boundingRect(self) -> QRectF:  # type: ignore[override]
        # Keep a stable, small bounding rect around text and handle only
        tb = self._text_item.boundingRect()
        w = max(tb.width(), 12) + 8
        h = tb.height() + 12 + 4
        return QRectF(-w / 2.0, -tb.height() - 4, w, h)

    def shape(self) -> QPainterPath:  # type: ignore[override]
        # Provide a hit shape so clicks select the label even if it doesn't paint
        p = QPainterPath()
        p.addRect(self.boundingRect())
        return p

    def mousePressEvent(self, event):  # type: ignore[override]
        # Ensure clicking the label area selects only it
        sc = self.scene()
        if sc is not None:
            sc.clearSelection()
        self.setSelected(True)
        super().mousePressEvent(event)

    def paint(self, painter, option, widget=None):  # type: ignore[override]
        # Draw a simple selection outline when selected
        if self.isSelected():
            painter.save()
            painter.setRenderHint(QPainter.Antialiasing, True)
            painter.setPen(QPen(QColor("#00e5ff"), 2, Qt.DashLine))
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(self.boundingRect())
            painter.restore()
        # Label no longer draws the arrow; it is drawn by the EdgeItem so it always starts near destination
        pass

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value):  # type: ignore[override]
        if change == QGraphicsItem.ItemPositionHasChanged and self.edge is not None:
            self.edge.update_path()
        return super().itemChange(change, value)


class EdgeItem(QGraphicsPathItem):
    def __init__(self, src: Optional['SlotItem'] = None, dst: Optional['SlotItem'] = None,
                 src_pos: Optional[QPointF] = None, dst_pos: Optional[QPointF] = None,
                 edge_id: Optional[str] = None, properties: Optional[dict] = None):
        super().__init__()
        self.edge_id: str = edge_id if edge_id else str(uuid.uuid4())
        self.threat_guids: set = set()
        self._properties: dict = dict(properties) if properties else {}
        self.src = src
        self.dst = dst
        self.src_pos: QPointF = src_pos or QPointF(0, 0)
        self.dst_pos: QPointF = dst_pos or QPointF(120, 0)
        self.setZValue(100)
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        _etype = self._properties.get("type", "")
        _color_str = str(self._properties.get("color", "")).strip()
        _pen = QPen(QColor(_color_str if _color_str else self._type_color(_etype)), 2)
        if _etype == "alias":
            _pen.setStyle(Qt.DashLine)
        self.setPen(_pen)
        if self._properties.get('sub-type'):
            label_text = self._properties['sub-type']
        elif src and dst:
            slot_type = getattr(src, '_properties', {}).get('type', '')
            label_text = "IPC call" if slot_type == "IPC call" else "func call"
        else:
            label_text = "func call"
        self.label = LabelItem(label_text, edge=self)
        self.label.setParentItem(self)
        self.label.setZValue(1000)
        self.source_node: Optional['NodeItem'] = None  # for alias edges
        self.dest_node: Optional['NodeItem'] = None    # for alias edges
        self._virtual = False                          # display-only owner-op edge
        self._owner_op_edges: List['EdgeItem'] = []    # expanded virtual edges (if any)
        self._update_scheduled = False
        self._arrow_tip: Optional[QPointF] = None
        self._arrow_dir: Optional[QPointF] = None
        self._src_handle = EdgeEndpointHandle(self, "src")
        self._dst_handle = EdgeEndpointHandle(self, "dst")
        self._dragging = False
        self._drag_last_scene = QPointF(0, 0)
        # Orthogonal routing: user-editable interior bend points (scene coords).
        self.ortho_waypoints: List[QPointF] = []
        self._ortho_manual = False       # True once the user has dragged a segment
        self._route_pts: List[QPointF] = []   # last drawn orthogonal polyline
        self._seg_handles: List['EdgeSegmentHandle'] = []
        self._active_seg_drag = False    # True while a segment handle is being dragged
        self.setAcceptHoverEvents(True)
        self.request_update()

    def _slot_tangent(self, slot: SlotItem) -> QPointF:
        """Return outward unit tangent direction for a slot."""
        parent = slot.parentItem()
        if not isinstance(parent, NodeItem):
            return QPointF(1, 0) if slot.kind == "output" else QPointF(-1, 0)
        slot_scene = slot.center_in_scene()
        if parent.shape_kind in ("Circle", "Ellipse", "Triangle", "Diamond", "Hexagon"):
            center_scene = parent.mapToScene(parent._shape_rect().center())
            dx = slot_scene.x() - center_scene.x()
            dy = slot_scene.y() - center_scene.y()
            length = (dx ** 2 + dy ** 2) ** 0.5
            if length > 0.001:
                return QPointF(dx / length, dy / length)
        # Box / Boundary: return outward normal of whichever edge is closest
        slot_local = parent.mapFromScene(slot_scene)
        rect = parent._shape_rect()
        dl = abs(slot_local.x() - rect.left())
        dr = abs(slot_local.x() - rect.right())
        dt = abs(slot_local.y() - rect.top())
        db = abs(slot_local.y() - rect.bottom())
        nearest = min(dl, dr, dt, db)
        if nearest == dl:
            return QPointF(-1, 0)
        if nearest == dr:
            return QPointF(1, 0)
        if nearest == dt:
            return QPointF(0, -1)
        return QPointF(0, 1)

    def properties(self) -> dict:
        return dict(self._properties)

    @staticmethod
    def _type_color(etype: str) -> str:
        return {
            "IPC":               "#e53935",   # red
            "Asset Operation":   "#27ae60",   # green
            "internal func call":"#888888",   # grey
            "syscall":           "#e53935",   # red
            "alias":             "#9e9e9e",   # grey
            "ownership":         "#1e8449",   # dark green
        }.get(etype, "#4a90e2")

    def set_properties(self, props: dict) -> None:
        self._properties = dict(props)
        if self.label is not None and props.get('sub-type'):
            self.label.set_text(props['sub-type'])
        pen = self.pen()
        color_str = str(props.get("color", "")).strip()
        pen.setColor(QColor(color_str if color_str else self._type_color(props.get("type", ""))))
        pen.setStyle(Qt.DashLine if props.get("type") in ("alias", "ownership") else Qt.SolidLine)
        self.setPen(pen)
        if self.label is not None:
            self.label.set_text_color(str(props.get("text-color", "")).strip())
        # If the operation edges are being shown, refresh them so they follow
        # the new sub-type.
        if not self._virtual and self._owner_op_edges:
            self.hide_owner_ops()
            self.show_owner_ops()

    def request_update(self):
        if self._update_scheduled:
            return
        self._update_scheduled = True
        QTimer.singleShot(0, self._perform_update)

    def _perform_update(self):
        self._update_scheduled = False
        self.update_path()

    @staticmethod
    def _snap_axis(t: QPointF) -> QPointF:
        """Snap a tangent to the nearest axis direction (±x or ±y)."""
        if abs(t.x()) >= abs(t.y()):
            return QPointF(1.0 if t.x() >= 0 else -1.0, 0.0)
        return QPointF(0.0, 1.0 if t.y() >= 0 else -1.0)

    @staticmethod
    def _orthogonal_points(a: QPointF, t_src: QPointF, b: QPointF,
                           t_dst: QPointF, stub: float = 22.0) -> list:
        """Return an ordered list of points for a right-angle (Manhattan) route.

        Leaves ``a`` along ``t_src`` and arrives at ``b`` along ``-t_dst`` with a
        short stub at each end, joined by axis-aligned segments.
        """
        ts = EdgeItem._snap_axis(t_src)
        td = EdgeItem._snap_axis(t_dst)
        a1 = QPointF(a.x() + ts.x() * stub, a.y() + ts.y() * stub)
        b1 = QPointF(b.x() + td.x() * stub, b.y() + td.y() * stub)
        pts = [a, a1]
        src_horiz = ts.y() == 0.0
        dst_horiz = td.y() == 0.0

        def _sign(v: float) -> float:
            return 1.0 if v > 0 else (-1.0 if v < 0 else 0.0)

        if src_horiz and dst_horiz:
            # Route through a vertical mid-line only when the stubs face the gap
            # between them; otherwise jog vertically first so neither stub
            # overshoots its node (which reads as a T/hook).
            if _sign(b1.x() - a1.x()) == ts.x() and _sign(a1.x() - b1.x()) == td.x():
                midx = (a1.x() + b1.x()) / 2.0
                pts += [QPointF(midx, a1.y()), QPointF(midx, b1.y())]
            else:
                midy = (a1.y() + b1.y()) / 2.0
                pts += [QPointF(a1.x(), midy), QPointF(b1.x(), midy)]
        elif (not src_horiz) and (not dst_horiz):
            if _sign(b1.y() - a1.y()) == ts.y() and _sign(a1.y() - b1.y()) == td.y():
                midy = (a1.y() + b1.y()) / 2.0
                pts += [QPointF(a1.x(), midy), QPointF(b1.x(), midy)]
            else:
                midx = (a1.x() + b1.x()) / 2.0
                pts += [QPointF(midx, a1.y()), QPointF(midx, b1.y())]
        elif src_horiz and not dst_horiz:
            # Single L-corner; pick the orientation that leaves a1 outward
            # (no horizontal backtrack past the source node).
            if _sign(b1.x() - a1.x()) == ts.x():
                pts.append(QPointF(b1.x(), a1.y()))
            else:
                pts.append(QPointF(a1.x(), b1.y()))
        else:  # src vertical, dst horizontal
            if _sign(b1.y() - a1.y()) == ts.y():
                pts.append(QPointF(a1.x(), b1.y()))
            else:
                pts.append(QPointF(b1.x(), a1.y()))
        pts += [b1, b]
        return EdgeItem._dedupe(pts)

    @staticmethod
    def _polyline_path(pts: list) -> QPainterPath:
        p = QPainterPath()
        if not pts:
            return p
        p.moveTo(pts[0])
        for q in pts[1:]:
            p.lineTo(q)
        return p

    @staticmethod
    def _dedupe(pts: list, eps: float = 0.5) -> list:
        """Drop consecutive points that coincide (removes zero-length segments)."""
        out = []
        for q in pts:
            if not out or abs(out[-1].x() - q.x()) > eps or abs(out[-1].y() - q.y()) > eps:
                out.append(q)
        return out

    @staticmethod
    def _simplify(pts: list, eps: float = 0.5) -> list:
        """Merge redundant vertices: drop coincident points and collapse any
        run of collinear points into a single straight segment.

        Run after every edit so repeated segment drags don't accumulate stray
        collinear bends (which read as extra/T-shaped segments).
        """
        pts = EdgeItem._dedupe(pts, eps)
        changed = True
        while changed and len(pts) > 2:
            changed = False
            out = [pts[0]]
            for i in range(1, len(pts) - 1):
                prev, cur, nxt = out[-1], pts[i], pts[i + 1]
                collinear = (
                    (abs(prev.x() - cur.x()) < eps and abs(cur.x() - nxt.x()) < eps)
                    or (abs(prev.y() - cur.y()) < eps and abs(cur.y() - nxt.y()) < eps)
                )
                if collinear:
                    changed = True          # drop cur; its neighbours are colinear
                    continue
                out.append(cur)
            out.append(pts[-1])
            pts = out
        return pts

    @staticmethod
    def _orthogonalize(pts: list, eps: float = 0.5) -> list:
        """Insert L-corners so every consecutive pair is axis-aligned.

        Idempotent when the input is already orthogonal (no growth), so dragging
        keeps the vertex count stable; a diagonal join (e.g. after a node move)
        gets a single inserted corner.
        """
        if len(pts) < 2:
            return list(pts)
        out = [pts[0]]
        for i in range(1, len(pts)):
            prev, cur = out[-1], pts[i]
            if abs(prev.x() - cur.x()) > eps and abs(prev.y() - cur.y()) > eps:
                out.append(QPointF(cur.x(), prev.y()))   # horizontal-first corner
            out.append(cur)
        return out

    def _refresh_segment_handles(self) -> None:
        """Rebuild (or, during an active drag, just reposition) the segment handles."""
        # Never delete handles mid-drag — that would kill the grabbed handle.
        if self._active_seg_drag:
            self._reposition_segment_handles()
            return
        for h in self._seg_handles:
            if h.scene() is not None:
                h.scene().removeItem(h)
        self._seg_handles = []
        if _edge_routing != "orthogonal" or len(self._route_pts) < 4:
            return
        R = self._route_pts
        vis = self.isSelected()
        # segments whose both endpoints are interior (exclude the two anchor stubs)
        for i in range(1, len(R) - 2):
            p0, p1 = R[i], R[i + 1]
            horiz = abs(p0.y() - p1.y()) <= abs(p0.x() - p1.x())
            h = EdgeSegmentHandle(self, i)
            h.set_orientation("h" if horiz else "v")
            h.setPos(QPointF((p0.x() + p1.x()) / 2.0, (p0.y() + p1.y()) / 2.0))
            h.setVisible(vis)
            self._seg_handles.append(h)

    def _reposition_segment_handles(self) -> None:
        """Move existing handles to their segment midpoints without recreating them."""
        R = self._route_pts
        for h in self._seg_handles:
            i = h.seg_index
            if 0 <= i < len(R) - 1:
                p0, p1 = R[i], R[i + 1]
                horiz = abs(p0.y() - p1.y()) <= abs(p0.x() - p1.x())
                h.set_orientation("h" if horiz else "v")
                h.setPos(QPointF((p0.x() + p1.x()) / 2.0, (p0.y() + p1.y()) / 2.0))

    def begin_segment_drag(self) -> None:
        # Freeze the current auto route into editable waypoints on drag start,
        # so the handle set is fixed for the whole drag.
        if not self._ortho_manual:
            self.ortho_waypoints = [QPointF(p) for p in self._route_pts[1:-1]]
            self._ortho_manual = True
        self._active_seg_drag = True

    def end_segment_drag(self) -> None:
        self._active_seg_drag = False
        self.update_path()   # full re-orthogonalize + rebuild handles

    def move_segment(self, seg_index: int, scene_pos: QPointF) -> None:
        """Drag the segment at ``seg_index`` along its normal (orthogonal edit)."""
        if not self._ortho_manual:
            self.ortho_waypoints = [QPointF(p) for p in self._route_pts[1:-1]]
            self._ortho_manual = True
        self._active_seg_drag = True

        a = self.src.center_in_scene() if (self.src and self.src.scene()) else self.src_pos
        b = self.dst.center_in_scene() if (self.dst and self.dst.scene()) else self.dst_pos
        R = [a] + self.ortho_waypoints + [b]
        if not (1 <= seg_index <= len(R) - 3):
            return
        p0, p1 = R[seg_index], R[seg_index + 1]
        horiz = abs(p0.y() - p1.y()) <= abs(p0.x() - p1.x())
        for idx in (seg_index, seg_index + 1):
            w = idx - 1                     # index into ortho_waypoints
            if 0 <= w < len(self.ortho_waypoints):
                if horiz:
                    self.ortho_waypoints[w].setY(scene_pos.y())
                else:
                    self.ortho_waypoints[w].setX(scene_pos.x())
        self.update_path()

    def reset_waypoints(self) -> None:
        """Clear manual routing and return to the auto orthogonal route."""
        self.ortho_waypoints = []
        self._ortho_manual = False
        self.update_path()

    def _arrowhead_path(self, tip: QPointF, direction: QPointF, size: float = 16.0) -> QPainterPath:
        length = (direction.x() ** 2 + direction.y() ** 2) ** 0.5
        if length < 0.001:
            return QPainterPath()
        ux, uy = direction.x() / length, direction.y() / length
        px, py = -uy, ux  # perpendicular
        base = QPointF(tip.x() - ux * size, tip.y() - uy * size)
        p = QPainterPath()
        p.moveTo(tip)
        p.lineTo(QPointF(base.x() + px * size * 0.45, base.y() + py * size * 0.45))
        p.lineTo(QPointF(base.x() - px * size * 0.45, base.y() - py * size * 0.45))
        p.closeSubpath()
        return p

    def update_path(self):
        if self.scene() is None:
            return
        # Alias edges: cubic bezier from dest node center to source node center
        if self.source_node is not None and self.dest_node is not None:
            try:
                a = self.dest_node.mapToScene(self.dest_node._shape_rect().center())
                b = self.source_node.mapToScene(self.source_node._shape_rect().center())
                dx, dy = b.x() - a.x(), b.y() - a.y()
                dist = (dx * dx + dy * dy) ** 0.5
                self._arrow_tip = b
                self._arrow_dir = QPointF(dx / dist, dy / dist) if dist > 0.001 else QPointF(1, 0)
                chord_mid = QPointF((a.x() + b.x()) / 2, (a.y() + b.y()) / 2)
                p = QPainterPath()
                p.moveTo(a)
                if self.label is not None and self.label.user_positioned:
                    M = chord_mid + self.label._midpoint_offset
                    self.label.setPos(self.mapFromScene(M))
                    dist_am = ((M.x() - a.x()) ** 2 + (M.y() - a.y()) ** 2) ** 0.5
                    dist_mb = ((b.x() - M.x()) ** 2 + (b.y() - M.y()) ** 2) ** 0.5
                    ctrl1 = max(40.0, dist_am * 0.45)
                    ctrl2 = max(40.0, dist_mb * 0.45)
                    chord_len = dist if dist > 0.001 else 1.0
                    tx, ty = dx / chord_len, dy / chord_len
                    ctrl_m = max(30.0, min(dist_am, dist_mb) * 0.35)
                    c1 = QPointF(a.x() + ctrl1, a.y())
                    cm_in  = QPointF(M.x() - tx * ctrl_m, M.y() - ty * ctrl_m)
                    cm_out = QPointF(M.x() + tx * ctrl_m, M.y() + ty * ctrl_m)
                    c2 = QPointF(b.x() - ctrl2, b.y())
                    p.cubicTo(c1, cm_in, M)
                    p.cubicTo(cm_out, c2, b)
                else:
                    ctrl = max(80.0, dist * 0.45)
                    p.cubicTo(QPointF(a.x() + ctrl, a.y()),
                              QPointF(b.x() - ctrl, b.y()),
                              b)
                self.setPath(p)
                if self.label is not None and not self.label.user_positioned:
                    self.label.setPos(self.mapFromScene(p.pointAtPercent(0.5)))
                    self.label._midpoint_offset = QPointF(0.0, 0.0)
                if hasattr(self, '_src_handle'):
                    self._src_handle.update_position()
                    self._dst_handle.update_position()
            except Exception:
                pass
            return
        p = QPainterPath()
        try:
            if self.src is not None and self.src.scene() is not None:
                a = self.src.center_in_scene()
                t_src = self._slot_tangent(self.src)
            else:
                a = self.src_pos
                t_src = QPointF(1, 0)

            if self.dst is not None and self.dst.scene() is not None:
                b = self.dst.center_in_scene()
                t_dst = self._slot_tangent(self.dst)
            else:
                b = self.dst_pos
                t_dst = QPointF(-1, 0)

            dist = ((b.x() - a.x()) ** 2 + (b.y() - a.y()) ** 2) ** 0.5
            # Arrival direction at b is always -t_dst
            self._arrow_tip = b
            self._arrow_dir = QPointF(-t_dst.x(), -t_dst.y())

            chord_mid = QPointF((a.x() + b.x()) / 2, (a.y() + b.y()) / 2)
            if _edge_routing == "orthogonal":
                # Right-angle (Manhattan) route. Auto until the user drags a
                # segment, then it follows the stored waypoints.
                if self._ortho_manual and self.ortho_waypoints:
                    base = [a] + self.ortho_waypoints + [b]
                    if self._active_seg_drag:
                        # Keep vertex indices stable while dragging (no corner
                        # insertion) so the grabbed handle stays valid.
                        pts = base
                    else:
                        # Merge collinear/redundant bends so edits don't pile up.
                        pts = self._simplify(self._orthogonalize(base))
                        self.ortho_waypoints = [QPointF(q) for q in pts[1:-1]]
                else:
                    pts = self._orthogonal_points(a, t_src, b, t_dst)
                self._route_pts = pts
                p = self._polyline_path(pts)
                self.setPath(p)
                if self.label is not None:
                    self.label.setPos(self.mapFromScene(p.pointAtPercent(0.5)))
                    if not self.label.user_positioned:
                        self.label._midpoint_offset = QPointF(0.0, 0.0)
                if hasattr(self, '_src_handle'):
                    self._src_handle.update_position()
                    self._dst_handle.update_position()
                self._refresh_segment_handles()
                self.update()
                return
            self._route_pts = []
            self._refresh_segment_handles()
            p.moveTo(a)
            if self.label is not None and self.label.user_positioned:
                # Two-segment cubic through the label as a smooth waypoint.
                # M is derived from the chord midpoint + stored offset so it
                # follows the nodes when they are moved together.
                M = chord_mid + self.label._midpoint_offset
                self.label.setPos(self.mapFromScene(M))
                dist_am = ((M.x() - a.x()) ** 2 + (M.y() - a.y()) ** 2) ** 0.5
                dist_mb = ((b.x() - M.x()) ** 2 + (b.y() - M.y()) ** 2) ** 0.5
                ctrl1 = max(40.0, dist_am * 0.45)
                ctrl2 = max(40.0, dist_mb * 0.45)
                # Smooth tangent at M: direction of the full chord a→b
                chord_len = dist if dist > 0.001 else 1.0
                tx, ty = (b.x() - a.x()) / chord_len, (b.y() - a.y()) / chord_len
                ctrl_m = max(30.0, min(dist_am, dist_mb) * 0.35)
                c1 = QPointF(a.x() + t_src.x() * ctrl1, a.y() + t_src.y() * ctrl1)
                cm_in  = QPointF(M.x() - tx * ctrl_m, M.y() - ty * ctrl_m)
                cm_out = QPointF(M.x() + tx * ctrl_m, M.y() + ty * ctrl_m)
                c2 = QPointF(b.x() + t_dst.x() * ctrl2, b.y() + t_dst.y() * ctrl2)
                p.cubicTo(c1, cm_in, M)
                p.cubicTo(cm_out, c2, b)
            else:
                ctrl = max(80.0, dist * 0.45)
                c1 = QPointF(a.x() + t_src.x() * ctrl, a.y() + t_src.y() * ctrl)
                c2 = QPointF(b.x() + t_dst.x() * ctrl, b.y() + t_dst.y() * ctrl)
                p.cubicTo(c1, c2, b)

            self.setPath(p)
            if self.label is not None and not self.label.user_positioned:
                mid = p.pointAtPercent(0.5)
                self.label.setPos(self.mapFromScene(mid))
                self.label._midpoint_offset = QPointF(0.0, 0.0)
            if hasattr(self, '_src_handle'):
                self._src_handle.update_position()
                self._dst_handle.update_position()
            self.update()
        except Exception:
            return

    def shape(self) -> QPainterPath:  # type: ignore[override]
        stroker = QPainterPathStroker()
        stroker.setWidth(12)
        return stroker.createStroke(self.path())

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value):  # type: ignore[override]
        if change == QGraphicsItem.ItemSelectedHasChanged:
            visible = bool(value)
            self._src_handle.setVisible(visible)
            self._dst_handle.setVisible(visible)
            for h in self._seg_handles:
                h.setVisible(visible)
            if visible:
                self._src_handle.update_position()
                self._dst_handle.update_position()
            else:
                self._dragging = False
                self.unsetCursor()
            # Deselecting a component↔asset edge hides its operation edges;
            # showing them is driven by the Operation list in the panel.
            if not self._virtual and not visible:
                self.hide_owner_ops()
        return super().itemChange(change, value)

    def hoverEnterEvent(self, event):  # type: ignore[override]
        if self.isSelected():
            self.setCursor(QCursor(Qt.OpenHandCursor))
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):  # type: ignore[override]
        self.unsetCursor()
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, event):  # type: ignore[override]
        # If a slot is under the cursor, let it handle the click instead.
        if event.button() == Qt.LeftButton and self.scene():
            for item in self.scene().items(event.scenePos()):
                if isinstance(item, SlotItem):
                    event.ignore()
                    return
        if event.button() == Qt.LeftButton and self.isSelected():
            self._dragging = True
            self._drag_last_scene = event.scenePos()
            self.setCursor(QCursor(Qt.ClosedHandCursor))
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        if self._dragging:
            delta = event.scenePos() - self._drag_last_scene
            self._drag_last_scene = event.scenePos()
            if self.label is not None:
                self.label._midpoint_offset += delta
                self.label.user_positioned = True
                self.request_update()
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._dragging:
            self._dragging = False
            self.setCursor(QCursor(Qt.OpenHandCursor))
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def _comp_asset_ends(self):
        """If this edge connects a component and a security asset, return
        (component_node, asset_node, asset_slot); else None."""
        if self.src is None or self.dst is None:
            return None
        for asset_slot, comp_slot in ((self.dst, self.src), (self.src, self.dst)):
            a = asset_slot.parentItem()
            c = comp_slot.parentItem()
            if not (isinstance(a, NodeItem) and isinstance(c, NodeItem)):
                continue
            if str(a._properties.get("class", "")).startswith("security asset") \
                    and not str(c._properties.get("class", "")).startswith("security asset"):
                return c, a, asset_slot
        return None

    def is_component_to_asset(self) -> bool:
        return self._comp_asset_ends() is not None

    def _find_owner_node(self, asset_node: 'NodeItem') -> Optional['NodeItem']:
        sc = self.scene()
        if sc is None:
            return None
        # 1) owner-component sharing the asset's container
        cont = getattr(asset_node, "container", None)
        if cont is not None:
            for it in sc.items():
                if isinstance(it, NodeItem) and getattr(it, "container", None) is cont \
                        and _is_owner_component(it._properties.get("class", "")):
                    return it
        # 2) node whose name matches the asset's declared owner
        sec = asset_node._properties.get("security-properties", {})
        owner_name = str(sec.get("owner", "")) if isinstance(sec, dict) else ""
        if owner_name:
            for it in sc.items():
                if isinstance(it, NodeItem) and str(it._properties.get("name", "")) == owner_name:
                    return it
        return None

    def mark_ownership(self) -> None:
        """Style this edge as an ownership link (dashed dark-green, 'owner' label)."""
        pen = self.pen()
        pen.setColor(QColor(self._type_color("ownership")))
        pen.setStyle(Qt.DashLine)
        self.setPen(pen)
        if self.label is not None:
            self.label.set_text(str(self._properties.get("sub-type", "owner")) or "owner")
        self.update()

    def hide_owner_ops(self) -> None:
        """Remove the virtual owner-operation edges (if any are shown)."""
        sc = self.scene()
        for e in self._owner_op_edges:
            if sc is not None and e.scene() is sc:
                sc.removeItem(e)
        self._owner_op_edges = []

    def show_owner_ops(self, op_name: Optional[str] = None,
                       all_ops: bool = False) -> None:
        """Show dotted virtual edges from the component to the asset's owner, one
        per syscall. With ``all_ops`` show every operation's steps; otherwise show
        just ``op_name`` (falling back to the edge's sub-type). Replaces any
        currently shown."""
        self.hide_owner_ops()
        ends = self._comp_asset_ends()
        if ends is None:
            return
        comp, asset, asset_slot = ends
        owner = self._find_owner_node(asset)
        if owner is None or owner is comp:
            return

        sp = asset_slot.properties() if hasattr(asset_slot, "properties") else {}
        op_steps = sp.get("op_steps", {}) if isinstance(sp.get("op_steps"), dict) else {}
        key = op_name or str(self._properties.get("sub-type", ""))
        if not all_ops and key and key in op_steps:
            calls = list(op_steps[key])
        else:
            calls = [c for steps in op_steps.values() for c in steps]
        if not calls:
            return

        sc = self.scene()
        a = comp.mapToScene(comp._shape_rect().center())
        b = owner.mapToScene(owner._shape_rect().center())
        n = len(calls)
        for i, call in enumerate(calls):
            off = (i - (n - 1) / 2.0) * 16.0            # fan the parallel edges
            ve = EdgeItem(
                src_pos=QPointF(a.x(), a.y() + off),
                dst_pos=QPointF(b.x(), b.y() + off),
                properties={"type": "internal func call", "sub-type": call,
                            "color": "#7e57c2"},
            )
            ve._virtual = True
            ve.setZValue(90)
            ve.setFlag(QGraphicsItem.ItemIsSelectable, False)
            pen = ve.pen()
            pen.setStyle(Qt.DotLine)                    # dotted virtual connection
            pen.setWidthF(2.0)
            ve.setPen(pen)
            if ve.label is not None:
                ve.label.set_text(call)
            if sc is not None:
                sc.addItem(ve)
                ve.update_path()
            self._owner_op_edges.append(ve)

    def mouseDoubleClickEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            sc = self.scene()
            if sc:
                views = sc.views()
                if views:
                    win = views[0].window()
                    if hasattr(win, "_raise_properties_dock"):
                        self.setSelected(True)
                        win._raise_properties_dock()
            event.accept()
            return
        super().mouseDoubleClickEvent(event)

    def advance(self, phase: int) -> None:
        if phase == 1:
            self.request_update()

    def paint(self, painter, option, widget=None):  # type: ignore[override]
        # Active sequence glow (drawn under the edge line)
        if _seq_registry and _active_seq_id:
            from ..sequence import edge_sequence_steps as _ess
            if any(sid == _active_seq_id for sid, _ in _ess(_seq_registry, self.edge_id)):
                seq = _seq_registry.get(_active_seq_id)
                if seq:
                    painter.save()
                    painter.setRenderHint(QPainter.Antialiasing, True)
                    glow = QColor(seq.color)
                    glow.setAlpha(110)
                    painter.setPen(QPen(glow, self.pen().widthF() + 7, Qt.SolidLine, Qt.RoundCap))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawPath(self.path())
                    painter.restore()

        if self.isSelected():
            painter.save()
            painter.setRenderHint(QPainter.Antialiasing, True)
            painter.setPen(QPen(QColor("#00e5ff"), self.pen().widthF() + 3, Qt.SolidLine, Qt.RoundCap))
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(self.path())
            painter.restore()
        super().paint(painter, option, widget)
        # Component→asset edges are "special": a small ⊕ badge at the midpoint
        # marks them (select the edge to reveal its operation edges to the owner).
        if not self._virtual and self.path().length() > 0 and self.is_component_to_asset():
            painter.save()
            painter.setRenderHint(QPainter.Antialiasing, True)
            m = self.path().pointAtPercent(0.5)
            r = 6.0
            painter.setBrush(QBrush(QColor("#7e57c2")))
            painter.setPen(QPen(QColor("#ffffff"), 1.4))
            painter.drawEllipse(m, r, r)
            painter.setPen(QPen(QColor("#ffffff"), 1.4))
            painter.drawLine(QPointF(m.x() - 3, m.y()), QPointF(m.x() + 3, m.y()))
            painter.drawLine(QPointF(m.x(), m.y() - 3), QPointF(m.x(), m.y() + 3))
            painter.restore()
        if self._arrow_tip is not None and self._arrow_dir is not None:
            painter.save()
            painter.setRenderHint(QPainter.Antialiasing, True)
            if self._properties.get("type") == "alias":
                # Hollow diamond at destination
                color = self.pen().color()
                tip = self._arrow_tip
                d = self._arrow_dir
                length = (d.x() ** 2 + d.y() ** 2) ** 0.5
                if length > 0.001:
                    nx, ny = d.x() / length, d.y() / length
                    s = 10.0
                    px, py = -ny, nx  # perpendicular
                    p_tip   = tip
                    p_back  = QPointF(tip.x() - nx * s * 1.6, tip.y() - ny * s * 1.6)
                    p_left  = QPointF(tip.x() - nx * s * 0.8 + px * s * 0.5,
                                      tip.y() - ny * s * 0.8 + py * s * 0.5)
                    p_right = QPointF(tip.x() - nx * s * 0.8 - px * s * 0.5,
                                      tip.y() - ny * s * 0.8 - py * s * 0.5)
                    diamond = QPainterPath()
                    diamond.moveTo(p_tip)
                    diamond.lineTo(p_left)
                    diamond.lineTo(p_back)
                    diamond.lineTo(p_right)
                    diamond.closeSubpath()
                    painter.setPen(QPen(color, 1.5))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawPath(diamond)
            else:
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(self.pen().color()))
                painter.drawPath(self._arrowhead_path(self._arrow_tip, self._arrow_dir))
            painter.restore()

        # Sequence step badges — only for the active sequence
        if _seq_registry and _active_seq_id:
            from ..sequence import edge_sequence_steps as _ess
            steps_info = [(sid, idx) for sid, idx in _ess(_seq_registry, self.edge_id)
                          if sid == _active_seq_id]
            if steps_info:
                path = self.path()
                if path.isEmpty():
                    return
                mid = path.pointAtPercent(0.35)  # slightly before label at 0.5
                bw, bh = 26, 18
                gap = 4
                total_w = len(steps_info) * (bw + gap) - gap
                bx0 = mid.x() - total_w / 2
                by = mid.y() - bh - 6  # above the edge

                painter.save()
                painter.setRenderHint(QPainter.Antialiasing, True)
                font = painter.font()
                font.setPointSize(10)
                font.setBold(True)
                painter.setFont(font)

                for i, (seq_id, step_idx) in enumerate(steps_info):
                    seq = _seq_registry.get(seq_id)
                    if seq is None:
                        continue
                    bx = bx0 + i * (bw + gap)
                    rect = QRectF(bx, by, bw, bh)
                    bg = QColor(seq.color)
                    is_active = (seq_id == _active_seq_id)
                    if not is_active:
                        bg.setAlpha(200)
                    painter.setPen(Qt.NoPen)
                    painter.setBrush(QBrush(bg))
                    painter.drawRoundedRect(rect, 3, 3)
                    painter.setPen(QPen(QColor("#ffffff")))
                    painter.drawText(rect, Qt.AlignCenter, str(step_idx))

                painter.restore()

        # Mitigation badge — green "M" circle near arrowhead when all threats are mitigated
        if _threat_registry and self.threat_guids and self._arrow_tip is not None:
            threats = [_threat_registry[g] for g in self.threat_guids if g in _threat_registry]
            if threats and all(t.mitigation_sc_ids for t in threats):
                tip = self._arrow_tip
                painter.save()
                painter.setRenderHint(QPainter.Antialiasing, True)
                painter.setPen(Qt.NoPen)
                painter.setBrush(QBrush(QColor("#27ae60")))
                badge_rect = QRectF(tip.x() + 12, tip.y() - 8, 16, 16)
                painter.drawEllipse(badge_rect)
                painter.setPen(QPen(QColor("#ffffff"), 1.5))
                f = painter.font()
                f.setBold(True)
                f.setPointSize(9)
                painter.setFont(f)
                painter.drawText(badge_rect, Qt.AlignCenter, "M")
                painter.restore()


class EdgeEndpointHandle(QGraphicsRectItem):
    """Draggable endpoint handle shown on a selected EdgeItem.
    Drag to a compatible slot to reconnect that end of the edge."""
    _HS = 8

    def __init__(self, edge: 'EdgeItem', end: str):
        super().__init__(edge)
        self.edge = edge
        self.end = end  # "src" or "dst"
        hs = self._HS
        self.setRect(QRectF(-hs / 2, -hs / 2, hs, hs))
        color = "#ff9800" if end == "src" else "#29b6f6"
        self.setBrush(QBrush(QColor(color)))
        self.setPen(QPen(QColor("#ffffff"), 1.5))
        self.setZValue(150)
        self.setVisible(False)
        self.setCursor(QCursor(Qt.CrossCursor))
        self._dragging = False
        self._temp_path: Optional[QGraphicsPathItem] = None

    def update_position(self) -> None:
        slot = self.edge.src if self.end == "src" else self.edge.dst
        if slot is not None and slot.scene() is not None:
            self.setPos(slot.center_in_scene())
        else:
            self.setPos(self.edge.src_pos if self.end == "src" else self.edge.dst_pos)

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            self._dragging = True
            self._temp_path = QGraphicsPathItem()
            self._temp_path.setZValue(200)
            self._temp_path.setPen(QPen(QColor("#aaaaaa"), 2, Qt.DashLine))
            if self.scene():
                self.scene().addItem(self._temp_path)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        if not self._dragging:
            super().mouseMoveEvent(event)
            return
        fixed_slot = self.edge.dst if self.end == "src" else self.edge.src
        if fixed_slot is not None and fixed_slot.scene() is not None:
            a = fixed_slot.center_in_scene()
        else:
            a = self.edge.dst_pos if self.end == "src" else self.edge.src_pos
        b = event.scenePos()
        dx = (b.x() - a.x()) * 0.5
        p = QPainterPath(a)
        p.cubicTo(QPointF(a.x() + dx, a.y()), QPointF(b.x() - dx, b.y()), b)
        if self._temp_path:
            self._temp_path.setPath(p)
        event.accept()

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if not self._dragging:
            super().mouseReleaseEvent(event)
            return
        self._dragging = False
        sc = self.scene()
        if self._temp_path and sc:
            sc.removeItem(self._temp_path)
        self._temp_path = None
        if sc is None:
            event.accept()
            return

        # Find a compatible slot at the release position
        expected_kind = "output" if self.end == "src" else "input"
        current_slot = self.edge.src if self.end == "src" else self.edge.dst
        target_slot: Optional[SlotItem] = None
        for item in sc.items(event.scenePos()):
            if isinstance(item, SlotItem) and item.kind == expected_kind and item is not current_slot:
                target_slot = item
                break

        if target_slot is not None:
            # Disconnect from old slot's node
            old_node = current_slot.parentItem() if current_slot else None
            if isinstance(old_node, NodeItem) and self.edge in old_node.edges:
                old_node.edges.remove(self.edge)
            # Reconnect to new slot
            if self.end == "src":
                self.edge.src = target_slot
            else:
                self.edge.dst = target_slot
            # Register edge on new slot's node
            new_node = target_slot.parentItem()
            if isinstance(new_node, NodeItem) and self.edge not in new_node.edges:
                new_node.edges.append(self.edge)
        else:
            # Drop on empty space: disconnect from current slot and park as floating
            if current_slot is not None:
                old_node = current_slot.parentItem()
                if isinstance(old_node, NodeItem) and self.edge in old_node.edges:
                    old_node.edges.remove(self.edge)
            if self.end == "src":
                self.edge.src = None
                self.edge.src_pos = event.scenePos()
            else:
                self.edge.dst = None
                self.edge.dst_pos = event.scenePos()

        self.edge.update_path()
        self.update_position()
        event.accept()


class EdgeSegmentHandle(QGraphicsRectItem):
    """Draggable midpoint handle for one segment of an orthogonal edge.

    Dragging moves the whole segment along its normal (vertical for a horizontal
    segment, horizontal for a vertical one), reshaping the right-angle route.
    """
    _HS = 12          # visible handle size
    _HIT = 22         # larger invisible hit area for easy grabbing

    def __init__(self, edge: 'EdgeItem', seg_index: int):
        super().__init__(edge)
        self.edge = edge
        self.seg_index = seg_index
        hs = self._HS
        self.setRect(QRectF(-hs / 2, -hs / 2, hs, hs))
        self.setBrush(QBrush(QColor("#7e57c2")))
        self.setPen(QPen(QColor("#ffffff"), 2.0))
        self.setZValue(170)
        self.setVisible(False)
        self.setAcceptHoverEvents(True)
        self._orient = "h"
        self._drag = False

    def boundingRect(self) -> QRectF:  # type: ignore[override]
        h = self._HIT
        return QRectF(-h / 2, -h / 2, h, h)

    def shape(self) -> QPainterPath:  # type: ignore[override]
        # Bigger hit area than the drawn square so it's easy to grab.
        p = QPainterPath()
        p.addRect(self.boundingRect())
        return p

    def set_orientation(self, orient: str) -> None:
        self._orient = orient
        self.setCursor(QCursor(Qt.SizeVerCursor if orient == "h" else Qt.SizeHorCursor))

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            self._drag = True
            self.edge.begin_segment_drag()
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        if self._drag:
            self.edge.move_segment(self.seg_index, event.scenePos())
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._drag:
            self._drag = False
            self.edge.end_segment_drag()
            sc = self.scene()
            if sc is not None and hasattr(sc, "_notify_edge_edited"):
                sc._notify_edge_edited(self.edge)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def mouseDoubleClickEvent(self, event):  # type: ignore[override]
        # Double-click a segment handle to reset the edge to auto routing.
        self.edge.reset_waypoints()
        event.accept()


class ResizeHandleItem(QGraphicsRectItem):
    """Corner resize handle shown on any NodeItem when selected."""
    _HS = 9  # handle size

    def __init__(self, owner: 'NodeItem', corner: str):
        super().__init__(owner)
        self.owner = owner
        self.corner = corner  # 'nw', 'ne', 'se', 'sw'
        hs = self._HS
        self.setRect(QRectF(-hs / 2, -hs / 2, hs, hs))
        self.setBrush(QBrush(QColor('#ffffff')))
        self.setPen(QPen(QColor('#00e5ff'), 1.5))
        self.setZValue(50)
        self.setVisible(False)
        self.setAcceptHoverEvents(True)
        self.setFlags(QGraphicsItem.ItemIgnoresParentOpacity)
        self.setCursor(QCursor(Qt.SizeFDiagCursor if corner in ('nw', 'se') else Qt.SizeBDiagCursor))
        self._dragging = False
        self._anchor = QPointF()

    def update_position(self) -> None:
        r = self.owner.node_rect()
        corners = {'nw': r.topLeft(), 'ne': r.topRight(), 'se': r.bottomRight(), 'sw': r.bottomLeft()}
        self.setPos(corners[self.corner])

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            r = self.owner.node_rect()
            opposite = {'nw': r.bottomRight(), 'ne': r.bottomLeft(), 'se': r.topLeft(), 'sw': r.topRight()}
            self._anchor = opposite[self.corner]
            self._dragging = True
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        if not self._dragging:
            super().mouseMoveEvent(event)
            return
        new_pt = self.owner.mapFromScene(event.scenePos())
        left  = min(self._anchor.x(), new_pt.x())
        right = max(self._anchor.x(), new_pt.x())
        top   = min(self._anchor.y(), new_pt.y())
        bottom = max(self._anchor.y(), new_pt.y())
        # Enforce minimum size
        if right - left < MIN_NODE_SIZE.width():
            if self.corner in ('nw', 'sw'):
                left = right - MIN_NODE_SIZE.width()
            else:
                right = left + MIN_NODE_SIZE.width()
        if bottom - top < MIN_NODE_SIZE.height():
            if self.corner in ('nw', 'ne'):
                top = bottom - MIN_NODE_SIZE.height()
            else:
                bottom = top + MIN_NODE_SIZE.height()
        # Move node if top-left shifted (left/top are in local coords, bounding rect starts at 0,0)
        if left != 0 or top != 0:
            self.owner.setPos(self.owner.mapToScene(QPointF(left, top)))
        self.owner.prepareGeometryChange()
        self.owner._width = right - left
        self.owner._height = bottom - top
        self.owner._properties["width"] = self.owner._width
        self.owner._properties["height"] = self.owner._height
        self.owner._layout_slots()
        self.owner.update()
        for h in self.owner._resize_handles:
            h.update_position()
        self.owner._reevaluate_children()
        for edge in self.owner.edges:
            edge.request_update()
        event.accept()

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._dragging:
            self._dragging = False
            if self.owner.scene():
                for item in self.owner.scene().items():  # type: ignore
                    if isinstance(item, NodeItem) and item is not self.owner and item.shape_kind != 'Boundary':
                        item._evaluate_boundary_membership()
            event.accept()
            return
        super().mouseReleaseEvent(event)


class BubbleTailHandleItem(QGraphicsEllipseItem):
    """Draggable tip of a speech bubble's tail — points the note at its subject."""
    _HS = 10

    def __init__(self, owner: 'NodeItem'):
        super().__init__(owner)
        self.owner = owner
        hs = self._HS
        self.setRect(QRectF(-hs / 2, -hs / 2, hs, hs))
        self.setBrush(QBrush(QColor('#ffffff')))
        self.setPen(QPen(QColor('#f39c12'), 1.5))
        self.setZValue(50)
        self.setVisible(False)
        self.setAcceptHoverEvents(True)
        self.setFlags(QGraphicsItem.ItemIgnoresParentOpacity)
        self.setCursor(QCursor(Qt.SizeAllCursor))
        self.setToolTip("Drag to point this note at what it comments on")
        self._dragging = False

    def update_position(self) -> None:
        self.setPos(self.owner._tail_anchor_point())

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            self._dragging = True
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        if not self._dragging:
            super().mouseMoveEvent(event)
            return
        self.owner.set_tail_anchor(self.owner.mapFromScene(event.scenePos()))
        self.update_position()
        event.accept()

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._dragging:
            self._dragging = False
            event.accept()
            return
        super().mouseReleaseEvent(event)


class NodeItem(QGraphicsItem):
    Type = QGraphicsItem.UserType + 1

    def __init__(self, title: str, properties: dict, inputs: List[SlotSpec], outputs: List[SlotSpec], shape_kind: str, node_id: str | None = None,
                 inputs_sealed: bool = False, outputs_sealed: bool = False):
        super().__init__()
        self.node_id: str = node_id if node_id else str(uuid.uuid4())
        self.title = title
        self.shape_kind = shape_kind  # "Box", "Circle", "Ellipse", "Boundary"
        self._properties = dict(properties)
        self.inputs: List[SlotItem] = [SlotItem(s.name, "input", self, properties=dict(s.properties)) for s in inputs]
        self.outputs: List[SlotItem] = [SlotItem(s.name, "output", self, properties=dict(s.properties)) for s in outputs]
        self.inputs_sealed: bool = inputs_sealed
        self.outputs_sealed: bool = outputs_sealed
        self.edges: List[EdgeItem] = []
        self.alias_edges: List[EdgeItem] = []
        self._drag_slot: Optional['SlotItem'] = None
        self._drag_slot_y: float = 0.0

        # generic parent/child tracking for movement
        self.children: List['NodeItem'] = []
        self.parent_node: Optional['NodeItem'] = None

        # membership tracking (logical, not parenting)
        self.boundary: Optional['NodeItem'] = None  # if this node is inside a trust boundary
        self.container: Optional['NodeItem'] = None  # if this node is inside an ownership container
        self._boundary_handles_created = False
        self._last_scene_pos = QPointF(0.0, 0.0)
        self._being_moved_by_parent = False  # suppress re-evaluation during parent drag
        self._user_moving = False             # True while the user drags this node
        self._being_resized = False           # suppress child propagation during resize

        # size and z based on shape kind (defaults, overridden by properties below)
        if self.shape_kind == "Boundary":
            self._width = 360
            self._height = 240
            # Defer handle creation until added to scene
        elif self.shape_kind == "Ellipse":
            self._width = 240
            self._height = 160
        else:
            self._width = 180
            self._height = 180
        # Apply width/height from properties if present
        try:
            if "width" in self._properties:
                self._width = float(self._properties["width"])
        except (ValueError, TypeError):
            pass
        try:
            if "height" in self._properties:
                self._height = float(self._properties["height"])
        except (ValueError, TypeError):
            pass

        # Z-order: read from properties, fall back to shape defaults
        default_z = -10 if self.shape_kind == "Boundary" else 1
        self.setZValue(float(self._properties.get("z-order", default_z)))

        self.setFlags(
            QGraphicsItem.ItemIsMovable
            | QGraphicsItem.ItemIsSelectable
            | QGraphicsItem.ItemSendsGeometryChanges
        )

        # Resize handles (hidden until selected)
        self._resize_handles: List[ResizeHandleItem] = [
            ResizeHandleItem(self, corner) for corner in ('nw', 'ne', 'se', 'sw')
        ]
        # Speech bubbles also get a draggable tail tip.
        self._tail_handle: Optional[BubbleTailHandleItem] = (
            BubbleTailHandleItem(self) if shape_kind == "Bubble" else None
        )

        # initial slot layout
        self._layout_slots()

    def type(self) -> int:  # type: ignore[override]
        return NodeItem.Type

    def node_rect(self) -> QRectF:
        """The node's own box — what resize, containment and layout work on.

        Distinct from boundingRect(), which may be larger when a decoration
        (a speech-bubble tail) sticks out of the box.
        """
        return QRectF(0, 0, self._width, self._height)

    def boundingRect(self) -> QRectF:  # type: ignore[override]
        rect = self.node_rect()
        if self.shape_kind == "Bubble":
            apex = self._tail_anchor_point()
            pad = 6.0
            rect = rect.united(QRectF(apex.x() - pad, apex.y() - pad, pad * 2, pad * 2))
        return rect

    def shape(self) -> QPainterPath:  # type: ignore[override]
        path = QPainterPath()
        sr = self._shape_rect()
        if self.shape_kind == "Circle":
            r = min(sr.width(), sr.height())
            path.addEllipse(QRectF(sr.center().x() - r / 2, sr.center().y() - r / 2, r, r))
        elif self.shape_kind == "Ellipse":
            path.addEllipse(sr)
        elif self.shape_kind in ("Triangle", "Diamond", "Hexagon"):
            path = self._polygon_path()
        elif self.shape_kind == "Bubble":
            path = self._bubble_path()
        elif self.shape_kind == "Boundary":
            # Hollow hit region: only the border band is clickable, so clicks in
            # the interior fall through to the nodes contained in the boundary.
            outer = self.boundingRect()
            band = max(float(self._properties.get("border", 3) or 3) + 8.0, 12.0)
            inner = outer.adjusted(band, band, -band, -band)
            if inner.width() > 0 and inner.height() > 0:
                outer_path = QPainterPath()
                outer_path.addRoundedRect(outer, 8, 8)
                inner_path = QPainterPath()
                inner_path.addRoundedRect(inner, 8, 8)
                path = outer_path.subtracted(inner_path)
            else:
                path.addRoundedRect(outer, 8, 8)
        else:
            path.addRoundedRect(self.boundingRect(), 8, 8)
        return path

    def _polygon_path(self) -> QPainterPath:
        sr = self._shape_rect()
        cx, cy = sr.center().x(), sr.center().y()
        p = QPainterPath()
        if self.shape_kind == "Triangle":
            p.moveTo(cx, sr.top())
            p.lineTo(sr.right(), sr.bottom())
            p.lineTo(sr.left(), sr.bottom())
            p.closeSubpath()
        elif self.shape_kind == "Diamond":
            p.moveTo(cx, sr.top())
            p.lineTo(sr.right(), cy)
            p.lineTo(cx, sr.bottom())
            p.lineTo(sr.left(), cy)
            p.closeSubpath()
        elif self.shape_kind == "Hexagon":
            rx, ry = sr.width() / 2, sr.height() / 2
            for i in range(6):
                ang = i * pi / 3  # flat-top: 0°, 60°, 120°, …
                x, y = cx + rx * cos(ang), cy + ry * sin(ang)
                p.moveTo(x, y) if i == 0 else p.lineTo(x, y)
            p.closeSubpath()
        return p

    def set_properties(self, new_props: dict) -> None:
        self._properties = dict(new_props)
        if "z-order" in new_props:
            try:
                self.setZValue(float(new_props["z-order"]))
            except (ValueError, TypeError):
                pass
        if "width" in new_props:
            try:
                self._width = float(new_props["width"])
            except (ValueError, TypeError):
                pass
        if "height" in new_props:
            try:
                self._height = float(new_props["height"])
            except (ValueError, TypeError):
                pass
        self.prepareGeometryChange()
        self._layout_slots()
        if getattr(self, "_tail_handle", None) is not None:
            self._tail_handle.update_position()
        self.update()

    def properties(self) -> dict:
        return dict(self._properties)

    def _shape_rect(self) -> QRectF:
        margin = NODE_PADDING
        return QRectF(
            margin,
            margin,
            self._width - margin * 2,
            self._height - margin * 2,
        )

    def _tail_anchor_point(self) -> QPointF:
        """Where the speech-bubble tail points, in node-local coordinates."""
        from ..review import tail_anchor
        x, y = tail_anchor(self._properties, self._width, self._height)
        return QPointF(x, y)

    def set_tail_anchor(self, point: QPointF) -> None:
        from ..review import with_tail_anchor
        self.prepareGeometryChange()
        self._properties = with_tail_anchor(self._properties, point.x(), point.y())
        self.update()

    def _bubble_radius(self) -> float:
        sr = self._shape_rect()
        return max(4.0, min(12.0, sr.height() / 3.0))

    def _bubble_tail_triangle(self) -> Optional[List[QPointF]]:
        """[base1, base2, apex] for the tail, or None when it points inside.

        The tail leaves the balloon on whichever side the anchor sits, so the
        note can point up, down, left or right at whatever it comments on.
        """
        sr = self._shape_rect()
        apex = self._tail_anchor_point()
        if sr.contains(apex):
            return None            # anchor inside the balloon: no tail to draw

        radius = self._bubble_radius()
        # Keep the base off the rounded corners.
        x = min(max(apex.x(), sr.left() + radius), sr.right() - radius)
        y = min(max(apex.y(), sr.top() + radius), sr.bottom() - radius)
        half = max(6.0, min(18.0, min(sr.width(), sr.height()) * 0.12))

        if apex.y() > sr.bottom() or apex.y() < sr.top():
            edge_y = sr.bottom() - 1.0 if apex.y() > sr.bottom() else sr.top() + 1.0
            x1 = min(max(x - half, sr.left() + radius), sr.right() - radius - 1)
            x2 = min(max(x + half, x1 + 4.0), sr.right() - radius)
            return [QPointF(x1, edge_y), QPointF(x2, edge_y), apex]

        edge_x = sr.right() - 1.0 if apex.x() > sr.right() else sr.left() + 1.0
        y1 = min(max(y - half, sr.top() + radius), sr.bottom() - radius - 1)
        y2 = min(max(y + half, y1 + 4.0), sr.bottom() - radius)
        return [QPointF(edge_x, y1), QPointF(edge_x, y2), apex]

    def _bubble_path(self) -> QPainterPath:
        """Rounded balloon plus the tail, as one outline."""
        sr = self._shape_rect()
        radius = self._bubble_radius()
        balloon = QPainterPath()
        balloon.addRoundedRect(sr, radius, radius)

        points = self._bubble_tail_triangle()
        if points is None:
            return balloon
        tail = QPainterPath()
        tail.moveTo(points[0])
        tail.lineTo(points[1])
        tail.lineTo(points[2])
        tail.closeSubpath()
        return balloon.united(tail)

    def _start_reorder(self, slot: 'SlotItem') -> None:
        """Begin a reorder drag: track the slot and dim it slightly."""
        self._drag_slot = slot
        rect = self._shape_rect()
        self._drag_slot_y = slot.center_in_scene().y() - self.scenePos().y() + self.pos().y()
        # Store original order for potential restore
        if slot.kind == "input":
            self._reorder_original: list = list(self.inputs)
        else:
            self._reorder_original = list(self.outputs)
        slot.setOpacity(0.5)

    def _update_reorder(self, slot: 'SlotItem', local_y: float) -> None:
        """Called on each mouse move during reorder drag."""
        rect = self._shape_rect()
        clamped_y = max(rect.top(), min(rect.bottom(), local_y))
        self._drag_slot_y = clamped_y

        slot_list = self.inputs if slot.kind == "input" else self.outputs
        n = len(slot_list)
        if n > 1:
            cur_idx = slot_list.index(slot)
            h = rect.height()
            # Ideal Y for each index position
            positions = [rect.top() + (i + 1) / (n + 1) * h for i in range(n)]
            new_idx = min(range(n), key=lambda i: abs(positions[i] - clamped_y))
            if new_idx != cur_idx:
                slot_list.pop(cur_idx)
                slot_list.insert(new_idx, slot)

        self._layout_slots()

    def _finish_reorder(self, slot: 'SlotItem') -> None:
        """Finalize the reorder drag: restore opacity and snap to grid."""
        slot.setOpacity(1.0)
        self._drag_slot = None
        self._layout_slots()

    def _layout_slots(self) -> None:
        shape_rect = self._shape_rect()

        def set_center(slot: SlotItem, p: QPointF) -> None:
            slot.setPos(p.x() - SLOT_SIZE.width() / 2.0, p.y() - SLOT_SIZE.height() / 2.0)

        # Interleave: in0, out0, in1, out1, …
        all_slots: list = []
        for i in range(max(len(self.inputs), len(self.outputs))):
            if i < len(self.inputs):
                all_slots.append(self.inputs[i])
            if i < len(self.outputs):
                all_slots.append(self.outputs[i])

        N = len(all_slots)
        if N == 0:
            if self.shape_kind not in ("Box", "Composite", "Subgraph", "Circle", "Ellipse",
                                       "Triangle", "Diamond", "Hexagon"):
                self._ensure_boundary_handles()
                self._update_boundary_handles_positions()
            if self.isSelected():
                for h in self._resize_handles:
                    h.update_position()
            return

        if self.shape_kind in ("Circle", "Ellipse", "Triangle", "Diamond", "Hexagon"):
            cx = shape_rect.center().x()
            cy = shape_rect.center().y()
            if self.shape_kind == "Circle":
                r  = min(shape_rect.width(), shape_rect.height()) / 2.0
                rx = ry = r
            else:
                rx = shape_rect.width()  / 2.0
                ry = shape_rect.height() / 2.0
            # Start at top (−π/2), step clockwise (2π/N per slot)
            for k, slot in enumerate(all_slots):
                ang = -pi / 2.0 + k * (2.0 * pi / N)
                set_center(slot, QPointF(cx + rx * cos(ang), cy + ry * sin(ang)))

        elif self.shape_kind in ("Box", "Composite", "Subgraph"):
            sr = shape_rect
            w, h = sr.width(), sr.height()
            P = 2.0 * (w + h)

            def point_on_perimeter(t: float) -> QPointF:
                """Clockwise from top-left corner; t in [0, 1)."""
                d = (t % 1.0) * P
                if d < w:                        # top edge →
                    return QPointF(sr.left() + d, sr.top())
                d -= w
                if d < h:                        # right edge ↓
                    return QPointF(sr.right(), sr.top() + d)
                d -= h
                if d < w:                        # bottom edge ←
                    return QPointF(sr.right() - d, sr.bottom())
                d -= w                           # left edge ↑
                return QPointF(sr.left(), sr.bottom() - d)

            # Distribute slots evenly around the whole border. Asset slots start
            # at the bottom-centre (t0) and step around; other nodes centre each
            # slot in an equal segment from the top-left.
            if str(self._properties.get("class", "")).startswith("security asset"):
                # Honour a per-slot pinned "side" (top/bottom/left/right); slots
                # without one are auto-distributed around the remaining border.
                sides = {"top": [], "bottom": [], "left": [], "right": []}
                unpinned = []
                for slot in all_slots:
                    s = str(slot._properties.get("side", "")).lower()
                    (sides[s] if s in sides else unpinned).append(slot)

                def _place_edge(slots, side):
                    m = len(slots)
                    for j, slot in enumerate(slots):
                        f = (j + 0.5) / m
                        if side == "top":
                            set_center(slot, QPointF(sr.left() + f * w, sr.top()))
                        elif side == "bottom":
                            set_center(slot, QPointF(sr.left() + f * w, sr.bottom()))
                        elif side == "left":
                            set_center(slot, QPointF(sr.left(), sr.top() + f * h))
                        else:  # right
                            set_center(slot, QPointF(sr.right(), sr.top() + f * h))

                for side, slots in sides.items():
                    if slots:
                        _place_edge(slots, side)
                if unpinned:
                    t0 = (w + h + w / 2.0) / P    # bottom-centre in the param above
                    nu = len(unpinned)
                    for k, slot in enumerate(unpinned):
                        set_center(slot, point_on_perimeter(t0 + k / nu))
            else:
                for k, slot in enumerate(all_slots):
                    t = (k + 0.5) / N            # centre each slot in its segment
                    set_center(slot, point_on_perimeter(t))

        else:
            # Boundary: update resize handles positions
            self._ensure_boundary_handles()
            self._update_boundary_handles_positions()

        # Keep resize handles at corners after any layout change
        if self.isSelected():
            for h in self._resize_handles:
                h.update_position()

    def _draw_shape(self, painter) -> None:
        rect = self._shape_rect()
        props = self.properties()
        color = QColor(props.get("color", "#6fcf97"))
        filled = str(props.get("fill", "true")).lower() not in ("false", "0", "no")
        try:
            border_w = float(props.get("border", 1))
        except (TypeError, ValueError):
            border_w = 1.0
        painter.setRenderHint(QPainter.Antialiasing, True)

        # ── helpers ────────────────────────────────────────────────────────────────────

        def _linear_gradient(r, base):
            """Top-to-bottom linear gradient: lighter top, darker bottom."""
            grad = QLinearGradient(r.topLeft(), r.bottomLeft())
            top = base.lighter(125)
            bot = base.darker(115)
            top.setAlpha(255)
            bot.setAlpha(255)
            grad.setColorAt(0.0, top)
            grad.setColorAt(1.0, bot)
            return grad

        def _radial_gradient(r, base):
            """Radial gradient focal at top-left offset (~-0.25r)."""
            cx = r.center().x()
            cy = r.center().y()
            radius = max(r.width(), r.height()) * 0.65
            fx = cx - r.width() * 0.25
            fy = cy - r.height() * 0.25
            grad = QRadialGradient(cx, cy, radius, fx, fy)
            light = base.lighter(125)
            dark = base.darker(115)
            light.setAlpha(255)
            dark.setAlpha(255)
            grad.setColorAt(0.0, light)
            grad.setColorAt(1.0, dark)
            return grad

        def _faint_brush(base, alpha=20):
            """Semi-transparent tint brush for unfilled nodes."""
            c = QColor(base)
            c.setAlpha(alpha)
            return QBrush(c)

        def _draw_box_shadow(r, rx=8.0):
            """Soft multi-layer drop shadow for rounded rectangles."""
            painter.setPen(Qt.NoPen)
            for dx, dy, alpha in ((2, 2, 25), (3, 3, 18), (4, 4, 10)):
                sc = QColor(0, 0, 0, alpha)
                painter.setBrush(QBrush(sc))
                painter.drawRoundedRect(r.adjusted(dx, dy, dx, dy), rx, rx)

        def _draw_ellipse_shadow(r):
            """Soft multi-layer drop shadow for ellipses."""
            painter.setPen(Qt.NoPen)
            for dx, dy, alpha in ((2, 2, 25), (3, 3, 18), (4, 4, 10)):
                sc = QColor(0, 0, 0, alpha)
                painter.setBrush(QBrush(sc))
                painter.drawEllipse(r.adjusted(dx, dy, dx, dy))

        def _draw_box_highlight(r, rx=8.0):
            """White shine at the top 40% of a rounded-rect shape."""
            shine = QColor(255, 255, 255, 45)
            clip = QPainterPath()
            clip.addRoundedRect(r, rx, rx)
            painter.save()
            painter.setClipPath(clip)
            shine_rect = QRectF(r.x(), r.y(), r.width(), r.height() * 0.4)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(shine))
            painter.drawRoundedRect(shine_rect, rx, rx)
            painter.restore()

        def _draw_ellipse_highlight(r):
            """White shine at the top 40% of an ellipse/circle shape."""
            shine = QColor(255, 255, 255, 45)
            clip = QPainterPath()
            clip.addEllipse(r)
            painter.save()
            painter.setClipPath(clip)
            shine_rect = QRectF(r.x(), r.y(), r.width(), r.height() * 0.4)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(shine))
            painter.drawEllipse(shine_rect)
            painter.restore()

        def _draw_polygon_highlight(path):
            """White shine clipped to an arbitrary polygon path."""
            br = path.boundingRect()
            shine = QColor(255, 255, 255, 45)
            shine_rect = QRectF(br.x(), br.y(), br.width(), br.height() * 0.4)
            painter.save()
            painter.setClipPath(path)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(shine))
            painter.drawRect(shine_rect)
            painter.restore()

        # ── Boundary ───────────────────────────────────────────────────────────────────

        if self.shape_kind == "Boundary":
            faint = QColor(color)
            faint.setAlpha(18)
            painter.setPen(QPen(color, border_w, Qt.DashLine))
            painter.setBrush(QBrush(faint))
            painter.drawRoundedRect(rect, 4, 4)
            return

        # ── Box ─────────────────────────────────────────────────────────────────────────────

        if self.shape_kind == "Box":
            if self.isSelected():
                glow = QColor("#00e5ff")
                for expand, width, alpha in ((7, 8, 70), (4, 5, 150), (2, 2, 255)):
                    gr = rect.adjusted(-expand, -expand, expand, expand)
                    c = QColor(glow)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, width))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawRoundedRect(gr, 7, 7)
            _draw_box_shadow(rect, rx=8.0)
            if filled:
                painter.setBrush(QBrush(_linear_gradient(rect, color)))
                painter.setPen(QPen(color.darker(160), border_w))
            else:
                painter.setBrush(_faint_brush(color, 20))
                painter.setPen(QPen(color, border_w))
            painter.drawRoundedRect(rect, 8, 8)
            if filled:
                _draw_box_highlight(rect, rx=8.0)

        # ── Composite ──────────────────────────────────────────────────────────────────

        elif self.shape_kind == "Composite":
            if self.isSelected():
                glow = QColor("#00e5ff")
                for expand, width, alpha in ((7, 8, 70), (4, 5, 150), (2, 2, 255)):
                    gr = rect.adjusted(-expand, -expand, expand, expand)
                    c = QColor(glow)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, width))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawRoundedRect(gr, 7, 7)
            _draw_box_shadow(rect, rx=8.0)
            if filled:
                painter.setBrush(QBrush(_linear_gradient(rect, color)))
                painter.setPen(QPen(color.darker(160), border_w))
            else:
                painter.setBrush(_faint_brush(color, 20))
                painter.setPen(QPen(color, border_w))
            painter.drawRoundedRect(rect, 8, 8)
            if filled:
                _draw_box_highlight(rect, rx=8.0)
            # Inner border — double-border visual indicator
            inner = rect.adjusted(4, 4, -4, -4)
            painter.setPen(QPen(color.darker(140), border_w))
            painter.setBrush(Qt.NoBrush)
            painter.drawRoundedRect(inner, 3, 3)
            # Small icon at top-right corner
            icon_rect = QRectF(rect.right() - 18, rect.top() + 3, 14, 14)
            painter.setPen(QPen(QColor("#ffffff"), 1.0))
            saved_font = painter.font()
            icon_font = painter.font()
            icon_font.setPointSize(8)
            painter.setFont(icon_font)
            painter.drawText(icon_rect, Qt.AlignCenter, "\u229e")
            painter.setFont(saved_font)

        # ---- Subgraph (placeholder) ----
        elif self.shape_kind == "Subgraph":
            state = str(props.get("security-properties", {}).get("state", "unbound"))
            _badge = {
                "unbound": ("\u25a2", QColor("#9e9e9e")),
                "bound":   ("\u25a3", QColor("#27ae60")),
                "stale":   ("\u26a0", QColor("#e67e22")),
                "missing": ("\u2715", QColor("#e53935")),
            }.get(state, ("\u25a2", QColor("#9e9e9e")))
            badge_glyph, accent = _badge

            if self.isSelected():
                glow = QColor("#00e5ff")
                for expand, width, alpha in ((7, 8, 70), (4, 5, 150), (2, 2, 255)):
                    gr = rect.adjusted(-expand, -expand, expand, expand)
                    c = QColor(glow)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, width))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawRoundedRect(gr, 7, 7)
            _draw_box_shadow(rect, rx=8.0)

            # Unbound placeholders read as "empty": faint fill + dashed border.
            if state == "unbound":
                painter.setBrush(_faint_brush(color, 18))
                pen = QPen(color, border_w)
                pen.setStyle(Qt.DashLine)
                painter.setPen(pen)
            else:
                if filled:
                    painter.setBrush(QBrush(_linear_gradient(rect, color)))
                else:
                    painter.setBrush(_faint_brush(color, 20))
                painter.setPen(QPen(color.darker(160) if filled else color, border_w))
            painter.drawRoundedRect(rect, 8, 8)
            if filled and state != "unbound":
                _draw_box_highlight(rect, rx=8.0)

            saved_font = painter.font()
            gl_font = painter.font()
            gl_font.setPointSize(9)
            painter.setFont(gl_font)
            painter.setPen(QPen(QColor("#ffffff"), 1.0))
            painter.drawText(QRectF(rect.left() + 4, rect.top() + 3, 16, 14),
                             Qt.AlignCenter, "\u25a4")
            badge_rect = QRectF(rect.right() - 18, rect.top() + 3, 14, 14)
            painter.setPen(QPen(accent, 1.2))
            painter.drawText(badge_rect, Qt.AlignCenter, badge_glyph)
            painter.setFont(saved_font)

        # ── Bubble — speech balloon with a tail (review notes) ───────────────────────

        elif self.shape_kind == "Bubble":
            bubble = self._bubble_path()
            if self.isSelected():
                glow = QColor("#00e5ff")
                for width, alpha in ((8, 70), (5, 150), (2, 255)):
                    c = QColor(glow)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, width))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawPath(bubble)
            painter.save()
            painter.translate(3, 4)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(QColor(0, 0, 0, 35)))
            painter.drawPath(bubble)
            painter.restore()
            if filled:
                painter.setBrush(QBrush(_linear_gradient(rect, color)))
                painter.setPen(QPen(color.darker(150), border_w))
            else:
                painter.setBrush(_faint_brush(color, 20))
                painter.setPen(QPen(color, border_w))
            painter.drawPath(bubble)

        # ── Circle ───────────────────────────────────────────────────────────────────

        elif self.shape_kind == "Circle":
            r = min(rect.width(), rect.height())
            cx = rect.center().x() - r / 2
            cy = rect.center().y() - r / 2
            circle_rect = QRectF(cx, cy, r, r)
            if self.isSelected():
                glow = QColor("#00e5ff")
                for expand, width, alpha in ((7, 8, 70), (4, 5, 150), (2, 2, 255)):
                    gr = circle_rect.adjusted(-expand, -expand, expand, expand)
                    c = QColor(glow)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, width))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawEllipse(gr)
            is_sc = str(props.get("class", "")).startswith("security control")
            if is_sc:
                # A security control sits ON TOP of the component it protects, so
                # its interior is fully transparent (no fill, no shadow) — only
                # the red outer / green inner border rings are drawn, letting the
                # protected component show through.
                painter.setPen(QPen(QColor("#e53935"), border_w))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(circle_rect)
                # Inner green border (inset by border_w + 2px gap)
                inset = border_w + 2.0
                inner_rect = circle_rect.adjusted(inset, inset, -inset, -inset)
                painter.setPen(QPen(QColor("#43a047"), max(1.5, border_w - 1)))
                painter.setBrush(Qt.NoBrush)
                painter.drawEllipse(inner_rect)
            else:
                _draw_ellipse_shadow(circle_rect)
                if filled:
                    painter.setBrush(QBrush(_radial_gradient(circle_rect, color)))
                    painter.setPen(QPen(color.darker(160), border_w))
                else:
                    painter.setBrush(_faint_brush(color, 20))
                    painter.setPen(QPen(color.darker(155), border_w))
                painter.drawEllipse(circle_rect)
                if filled:
                    _draw_ellipse_highlight(circle_rect)

        # ── Ellipse ────────────────────────────────────────────────────────────────────

        elif self.shape_kind == "Ellipse":
            if self.isSelected():
                glow = QColor("#00e5ff")
                for expand, width, alpha in ((7, 8, 70), (4, 5, 150), (2, 2, 255)):
                    gr = rect.adjusted(-expand, -expand, expand, expand)
                    c = QColor(glow)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, width))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawEllipse(gr)
            _draw_ellipse_shadow(rect)
            if filled:
                painter.setBrush(QBrush(_radial_gradient(rect, color)))
                painter.setPen(QPen(color.darker(160), border_w))
            else:
                painter.setBrush(_faint_brush(color, 20))
                painter.setPen(QPen(color.darker(155), border_w))
            painter.drawEllipse(rect)
            if filled:
                _draw_ellipse_highlight(rect)

        # ── Triangle / Diamond / Hexagon — polygon shapes ─────────────────────────────────

        else:
            poly = self._polygon_path()
            if self.isSelected():
                glow = QColor("#00e5ff")
                for width, alpha in ((8, 70), (5, 150), (2, 255)):
                    c = QColor(glow)
                    c.setAlpha(alpha)
                    painter.setPen(QPen(c, width))
                    painter.setBrush(Qt.NoBrush)
                    painter.drawPath(poly)
            # Shadow via painter translate
            painter.save()
            painter.translate(3, 4)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QBrush(QColor(0, 0, 0, 35)))
            painter.drawPath(poly)
            painter.restore()
            if filled:
                br = poly.boundingRect()
                painter.setBrush(QBrush(_linear_gradient(br, color)))
                painter.setPen(QPen(color.darker(160), border_w))
            else:
                painter.setBrush(_faint_brush(color, 20))
                painter.setPen(QPen(color, border_w))
            painter.drawPath(poly)
            if filled:
                _draw_polygon_highlight(poly)

    def paint(self, painter, option, widget=None):  # type: ignore[override]
        rect = self.node_rect()

        # Draw dashed resize boundary when selected (all non-Boundary nodes)
        if self.isSelected() and self.shape_kind != "Boundary":
            painter.save()
            painter.setRenderHint(QPainter.Antialiasing, False)
            pen = QPen(QColor("#00e5ff"), 1, Qt.DashLine)
            pen.setDashPattern([4, 3])
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(rect.adjusted(1, 1, -1, -1))
            painter.restore()

        self._draw_shape(painter)
        # removed slot layout from paint to prevent re-entrant updates during drag
        # self._layout_slots()

        name_to_show = str(self._properties.get("name", self.title))
        text_color = QColor(str(self._properties.get("text-color", "#fafafa")))
        if self.shape_kind == "Boundary":
            # Draw name at the top-left inside the boundary
            painter.setPen(QPen(text_color))
            sr = self._shape_rect()
            text_rect = QRectF(sr.left() + 4, sr.top() + 2, sr.width() - 8, 20)
            painter.drawText(text_rect, Qt.AlignLeft | Qt.AlignVCenter, name_to_show)
        else:
            node_class = str(self._properties.get("class", ""))
            painter.setPen(QPen(text_color))
            if node_class.startswith("review comment"):
                self._paint_review_note(painter, text_color)
            elif node_class.startswith("security control"):
                self._paint_control_container(painter, text_color, name_to_show)
            else:
                # Wrap the title onto multiple lines when it doesn't fit on one,
                # keeping a small horizontal inset so text isn't flush to the edge.
                sr = self._shape_rect()
                text_rect = QRectF(sr.left() + 3, sr.top() + 2,
                                   sr.width() - 6, sr.height() - 4)
                painter.drawText(text_rect,
                                 Qt.AlignHCenter | Qt.AlignVCenter | Qt.TextWordWrap,
                                 name_to_show)

    def _paint_control_container(self, painter, text_color: QColor, name: str) -> None:
        """Draw nothing.

        A control circle sits *on top of* the asset interface it protects, so any
        text it draws covers the thing the reader came to look at. The shape and
        its colour already say what the node is; its name and the controls it
        holds are in the properties panel, which is where they are acted on.
        """
        return

    def _paint_review_note(self, painter, text_color: QColor) -> None:
        """Draw a review note: subject, status stripe, latest entry, reply count."""
        from ..review import canvas_text, is_open, read_thread, status, subject

        sr = self._shape_rect()
        open_thread = is_open(self._properties)
        accent = QColor("#f39c12" if open_thread else "#43a047")

        # Status stripe along the top edge, clipped to the balloon so it follows
        # the rounded corners.
        painter.save()
        if self.shape_kind == "Bubble":
            painter.setClipPath(self._bubble_path())
        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(accent))
        painter.drawRect(QRectF(sr.left(), sr.top(), sr.width(), 4))
        painter.restore()

        pad = 6
        y = sr.top() + 4 + 3

        # Subject (bold, single line, elided by the clip rect)
        painter.save()
        f = painter.font()
        f.setBold(True)
        painter.setFont(f)
        painter.setPen(QPen(text_color))
        head_rect = QRectF(sr.left() + pad, y, sr.width() - 2 * pad, 16)
        painter.drawText(head_rect, Qt.AlignLeft | Qt.AlignVCenter, subject(self._properties))
        painter.restore()
        y += 18

        # Footer first so the body knows how much room is left.
        n = len(read_thread(self._properties))
        footer = f"{n} comment{'s' if n != 1 else ''} · {status(self._properties)}"
        footer_h = 14
        footer_rect = QRectF(sr.left() + pad, sr.bottom() - footer_h - 2,
                             sr.width() - 2 * pad, footer_h)

        body_rect = QRectF(sr.left() + pad, y, sr.width() - 2 * pad,
                           max(0.0, footer_rect.top() - y - 2))
        painter.save()
        painter.setPen(QPen(text_color))
        painter.setClipRect(body_rect)
        painter.drawText(body_rect, Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap,
                         self._fit_text(painter, canvas_text(self._properties), body_rect))
        painter.restore()

        painter.save()
        f = painter.font()
        f.setPointSizeF(max(6.0, f.pointSizeF() - 1))
        painter.setFont(f)
        painter.setPen(QPen(accent.darker(140)))
        painter.drawText(footer_rect, Qt.AlignLeft | Qt.AlignVCenter, footer)
        painter.restore()

    @staticmethod
    def _fit_text(painter, text: str, rect: QRectF) -> str:
        """Trim *text* so its wrapped height fits *rect*, ending with an ellipsis."""
        flags = Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap
        metrics = painter.fontMetrics()
        if metrics.boundingRect(rect.toRect(), flags, text).height() <= rect.height():
            return text
        low, high = 0, len(text)
        while low < high:                       # longest prefix that still fits
            mid = (low + high + 1) // 2
            candidate = text[:mid].rstrip() + "…"
            if metrics.boundingRect(rect.toRect(), flags, candidate).height() <= rect.height():
                low = mid
            else:
                high = mid - 1
        return (text[:low].rstrip() + "…") if low else ""

    def add_slot(self, name: str, kind: str, properties: Optional[dict] = None) -> SlotItem:
        slot = SlotItem(name, kind, self, properties=properties)
        if kind == "input":
            self.inputs.append(slot)
        else:
            self.outputs.append(slot)
        self._layout_slots()
        self.update()
        return slot

    def apply_interface(self, interface, rename_map: Optional[dict] = None) -> None:
        """Reconcile this node's slots to a subgraph Interface, preserving edges.

        - Slots renamed via ``rename_map`` keep their identity (and connected
          edges) and are simply relabelled.
        - Slots whose port still exists are kept; ports that are gone have their
          slots (and edges) removed; new ports get new slots.
        - Stores the interface into security-properties and regenerates order.
        """
        rename_map = rename_map or {}
        for slot in list(self.inputs) + list(self.outputs):
            if slot.name in rename_map:
                slot.name = rename_map[slot.name]

        target_in = interface.input_names()
        target_out = interface.output_names()

        for slot in [s for s in list(self.inputs) if s.name not in target_in]:
            self.remove_slot(slot)
        for slot in [s for s in list(self.outputs) if s.name not in target_out]:
            self.remove_slot(slot)

        have_in = {s.name for s in self.inputs}
        have_out = {s.name for s in self.outputs}
        for name in target_in:
            if name not in have_in:
                self.add_slot(name, "input")
        for name in target_out:
            if name not in have_out:
                self.add_slot(name, "output")

        sec = dict(self._properties.get("security-properties", {}))
        sec["interface"] = interface.to_list()
        self._properties["security-properties"] = sec

        self._layout_slots()
        self.update()

    def remove_slot(self, slot: SlotItem) -> None:
        # Remove connected edges first
        for edge in [e for e in list(self.edges) if e.src is slot or e.dst is slot]:
            for node in (edge.src.parentItem() if edge.src else None,
                         edge.dst.parentItem() if edge.dst else None):
                if isinstance(node, NodeItem) and edge in node.edges:
                    node.edges.remove(edge)
            sc = edge.scene()
            if sc:
                sc.removeItem(edge)
        if slot in self.inputs:
            self.inputs.remove(slot)
        elif slot in self.outputs:
            self.outputs.remove(slot)
        sc = slot.scene()
        slot.setParentItem(None)
        if sc:
            sc.removeItem(slot)
        self._layout_slots()
        self.update()

    def _reparent_preserve_scene_pos(self, new_parent: Optional['NodeItem']) -> None:
        scene_pos = self.scenePos()
        self.setParentItem(new_parent)
        if isinstance(new_parent, NodeItem) and new_parent.shape_kind == "Boundary":
            self.setZValue(1)
        if new_parent is None:
            self.setZValue(1)
            self.setPos(scene_pos)
        else:
            self.setPos(new_parent.mapFromScene(scene_pos))

    def _reevaluate_children(self) -> None:
        """Re-evaluate which nodes belong to this node based on its child-classes property.
        Only nodes whose class is listed in child-classes are accepted as children."""
        child_classes = self._properties.get("child-classes", [])
        if not child_classes or not self.scene():
            return
        # Purge children whose class is no longer accepted
        self.children = [c for c in self.children
                         if c._properties.get("class") in child_classes]
        for item in self.scene().items():  # type: ignore
            if isinstance(item, NodeItem) and item._properties.get("class") in child_classes:
                item._evaluate_parent_id()

    def _evaluate_parent_id(self) -> None:
        """Set parent-id to the node that contains this one and lists this node's class
        in its child-classes property. Keeps the parent's children list in sync."""
        my_class = self._properties.get("class")
        if not my_class or not self.scene():
            return
        node_scene_rect = self.mapToScene(self.node_rect()).boundingRect()
        containing: Optional['NodeItem'] = None
        parent_nodes: dict = {}
        for item in self.scene().items():  # type: ignore
            if isinstance(item, NodeItem) and item is not self:
                if my_class in item._properties.get("child-classes", []):
                    parent_nodes[item.node_id] = item
                    # Use shape_rect for circular parents so corners of the bounding
                    # square don't falsely capture assets outside the visible circle.
                    if item.shape_kind in ("Circle", "Ellipse"):
                        parent_rect = item.mapToScene(item._shape_rect()).boundingRect()
                    else:
                        parent_rect = item.mapToScene(item.node_rect()).boundingRect()
                    if parent_rect.contains(node_scene_rect):
                        containing = item

        new_parent_id = containing.node_id if containing else None
        old_parent_id = self._properties.get("parent-id")

        if old_parent_id == new_parent_id:
            return

        # Remove from old parent
        if old_parent_id and old_parent_id in parent_nodes:
            old_parent = parent_nodes[old_parent_id]
            old_children = list(old_parent._properties.get("children", []))
            if self.node_id in old_children:
                old_children.remove(self.node_id)
            old_parent._properties["children"] = old_children
            if self in old_parent.children:
                old_parent.children.remove(self)
            old_parent.update()

        # Add to new parent
        if containing is not None:
            new_children = list(containing._properties.get("children", []))
            if self.node_id not in new_children:
                new_children.append(self.node_id)
            containing._properties["children"] = new_children
            if self not in containing.children:
                containing.children.append(self)
            containing.update()

        self.parent_node = containing
        self._properties["parent-id"] = new_parent_id
        self.update()

    def _evaluate_boundary_membership(self) -> None:
        if self.shape_kind == "Boundary" or not self.scene():
            return
        node_scene_rect = self.mapToScene(self.node_rect()).boundingRect()
        # Track the innermost (smallest-area) containing trust boundary and
        # ownership container separately, distinguished by class.
        best_b: Optional[NodeItem] = None
        best_b_area = None
        best_c: Optional[NodeItem] = None
        best_c_area = None
        for item in self.scene().items():  # type: ignore
            if not (isinstance(item, NodeItem) and item.shape_kind == "Boundary" and item is not self):
                continue
            inner_scene_rect = item.mapToScene(item._shape_rect()).boundingRect()
            if not inner_scene_rect.contains(node_scene_rect):
                continue
            area = inner_scene_rect.width() * inner_scene_rect.height()
            if str(item._properties.get("class", "")).startswith("security container"):
                if best_c_area is None or area < best_c_area:
                    best_c, best_c_area = item, area
            else:  # trust boundary
                if best_b_area is None or area < best_b_area:
                    best_b, best_b_area = item, area
        # Trust-boundary membership (keeps the children list, used elsewhere)
        if best_b is not self.boundary:
            if isinstance(self.boundary, NodeItem) and self in self.boundary.children:
                self.boundary.children.remove(self)
            if isinstance(best_b, NodeItem) and self not in best_b.children:
                best_b.children.append(self)
            self.boundary = best_b
        # Container membership (ownership axis)
        self.container = best_c

    def itemChange(self, change: QGraphicsItem.GraphicsItemChange, value):  # type: ignore[override]
        if change == QGraphicsItem.ItemPositionChange:
            # Snap to grid when enabled (value is the proposed new *local* pos)
            sc = self.scene()
            if sc is not None and getattr(sc, "grid_enabled", False):
                from ..app import GRID_SIZE as _G
                return QPointF(round(value.x() / _G) * _G, round(value.y() / _G) * _G)
        elif change == QGraphicsItem.ItemSelectedHasChanged:
            visible = bool(value)
            for h in list(self._resize_handles) + ([self._tail_handle] if self._tail_handle else []):
                h.setVisible(visible)
                if visible:
                    h.update_position()
        elif change == QGraphicsItem.ItemPositionHasChanged:
            for edge in list(self.edges):
                try:
                    if edge is not None and edge.scene() is not None and edge.src is not None and edge.dst is not None:
                        edge.request_update()
                except Exception:
                    pass
            for edge in list(self.alias_edges):
                try:
                    if edge is not None and edge.scene() is not None:
                        edge.request_update()
                except Exception:
                    pass
            # Generic: propagate movement to all children
            # Security control nodes are visual overlays only — their children move independently.
            is_sc = str(self._properties.get("class", "")).startswith("security control")
            new_scene_pos = self.scenePos()
            delta = new_scene_pos - self._last_scene_pos
            if delta != QPointF(0.0, 0.0) and not self._being_resized and not is_sc:
                for child in list(self.children):
                    try:
                        if child is not None and child.scene() is not None:
                            child._being_moved_by_parent = True
                            child.setPos(child.pos() + delta)
                            child._being_moved_by_parent = False
                    except Exception:
                        if child is not None:
                            child._being_moved_by_parent = False
            # A speech bubble's tail points at something in the diagram, so
            # dragging the note leaves the anchor where it was: compensate the
            # (node-local) anchor by the movement. Only for an interactive move
            # of this note itself — a group/parent move carries the target along,
            # and loading/pasting must not shift a stored anchor.
            if (self.shape_kind == "Bubble" and self._user_moving
                    and not self._being_moved_by_parent
                    and delta != QPointF(0.0, 0.0)):
                apex = self._tail_anchor_point()
                self.set_tail_anchor(QPointF(apex.x() - delta.x(), apex.y() - delta.y()))
                if self._tail_handle is not None:
                    self._tail_handle.update_position()

            self._last_scene_pos = new_scene_pos

            # Update parent-id in real time while dragging (for any node that has a class)
            if self._properties.get("class") and not self._being_moved_by_parent:
                self._evaluate_parent_id()

            # re-layout slots after move
            self._layout_slots()
        elif change == QGraphicsItem.ItemSceneHasChanged:
            # initialize last scene pos when added to scene and ensure handles
            self._last_scene_pos = self.scenePos()
            if self.shape_kind == 'Boundary':
                self._ensure_boundary_handles()
                self._update_boundary_handles_positions()
            # re-layout slots when added to scene
            self._layout_slots()
        return super().itemChange(change, value)

    def mousePressEvent(self, event):  # type: ignore[override]
        # Marks an interactive move, so a bubble's tail anchor can stay put
        # while the note is dragged (see itemChange).
        if event.button() == Qt.LeftButton:
            self._user_moving = True
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        self._user_moving = False
        super().mouseReleaseEvent(event)
        if self.shape_kind == "Boundary":
            if self.scene():
                for item in self.scene().items():  # type: ignore
                    if isinstance(item, NodeItem) and item is not self and item.shape_kind != "Boundary":
                        item._evaluate_boundary_membership()
        else:
            self._evaluate_boundary_membership()

        # Ownership follows container co-membership.
        update_container_ownership(self.scene())

        # Final parent-id snap on drop for any node that has a class
        if self._properties.get("class"):
            self._evaluate_parent_id()

        # Re-evaluate children after a parent node is moved
        if self._properties.get("child-classes"):
            self._reevaluate_children()

    def mouseDoubleClickEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            sc = self.scene()
            if sc:
                views = sc.views()
                if views:
                    win = views[0].window()
                    if self.shape_kind == "Composite" and hasattr(win, "navigate_into"):
                        win.navigate_into(self)
                        event.accept()
                        return
                    if hasattr(win, "_raise_properties_dock"):
                        self.setSelected(True)
                        win._raise_properties_dock()
                        event.accept()
                        return
        super().mouseDoubleClickEvent(event)

    def _ensure_boundary_handles(self) -> None:
        if self.shape_kind != 'Boundary' or getattr(self, '_boundary_handles_created', False):
            return
        self._boundary_handles_created = True
        self.handle_nw = BoundaryHandleItem(self, 'nw')
        self.handle_ne = BoundaryHandleItem(self, 'ne')
        self.handle_se = BoundaryHandleItem(self, 'se')
        self.handle_sw = BoundaryHandleItem(self, 'sw')

    def _update_boundary_handles_positions(self) -> None:
        if self.shape_kind != 'Boundary' or not getattr(self, '_boundary_handles_created', False):
            return
        r = self._shape_rect()
        self.handle_nw.setPos(r.topLeft())
        self.handle_ne.setPos(r.topRight())
        self.handle_se.setPos(r.bottomRight())
        self.handle_sw.setPos(r.bottomLeft())

    def connect(self, out_slot: SlotItem, in_slot: SlotItem) -> Optional[EdgeItem]:
        if out_slot.kind != "output" or in_slot.kind != "input":
            return None
        edge = EdgeItem(out_slot, in_slot)
        if self.scene():
            self.scene().addItem(edge)  # type: ignore
            # label is child of edge; no separate add
        if isinstance(out_slot.parentItem(), NodeItem):
            out_parent: NodeItem = out_slot.parentItem()  # type: ignore
            out_parent.edges.append(edge)
        if isinstance(in_slot.parentItem(), NodeItem):
            in_parent: NodeItem = in_slot.parentItem()  # type: ignore
            in_parent.edges.append(edge)
        edge.update_path()
        return edge


class BoundaryHandleItem(QGraphicsRectItem):
    def __init__(self, owner: NodeItem, corner: str):
        super().__init__(owner)
        self.owner = owner
        self.corner = corner  # 'nw', 'ne', 'se', 'sw'
        self.setRect(QRectF(-7, -7, 14, 14))
        self.setBrush(QBrush(QColor('#ffffff')))
        self.setPen(QPen(QColor('#000000')))
        self.setZValue(100)
        self.setAcceptHoverEvents(True)
        self.setFlags(QGraphicsItem.ItemIsSelectable)
        if self.corner in ('nw', 'se'):
            self.setCursor(QCursor(Qt.SizeFDiagCursor))
        else:
            self.setCursor(QCursor(Qt.SizeBDiagCursor))
        self._dragging = False
        self._anchor_in_owner = QPointF(0.0, 0.0)

    def mousePressEvent(self, event):  # type: ignore[override]
        if event.button() == Qt.LeftButton and self.owner.shape_kind == 'Boundary':
            shape = self.owner._shape_rect()
            if self.corner == 'nw':
                self._anchor_in_owner = shape.bottomRight()
            elif self.corner == 'ne':
                self._anchor_in_owner = shape.bottomLeft()
            elif self.corner == 'se':
                self._anchor_in_owner = shape.topLeft()
            else:  # 'sw'
                self._anchor_in_owner = shape.topRight()
            self._dragging = True
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):  # type: ignore[override]
        if self._dragging and self.owner.shape_kind == 'Boundary':
            # Compute new corner in owner local coords using scenePos
            new_corner_scene = event.scenePos()
            new_corner_owner = self.owner.mapFromScene(new_corner_scene)
            # Clamp to min size relative to anchor
            left = min(self._anchor_in_owner.x(), new_corner_owner.x())
            right = max(self._anchor_in_owner.x(), new_corner_owner.x())
            top = min(self._anchor_in_owner.y(), new_corner_owner.y())
            bottom = max(self._anchor_in_owner.y(), new_corner_owner.y())
            if right - left < MIN_BOUNDARY_SIZE.width():
                if self.corner in ('nw', 'sw'):
                    left = right - MIN_BOUNDARY_SIZE.width()
                else:
                    right = left + MIN_BOUNDARY_SIZE.width()
            if bottom - top < MIN_BOUNDARY_SIZE.height():
                if self.corner in ('nw', 'ne'):
                    top = bottom - MIN_BOUNDARY_SIZE.height()
                else:
                    bottom = top + MIN_BOUNDARY_SIZE.height()
            # Current shape rect
            shape = self.owner._shape_rect()
            # Delta for owner position if top/left moved
            delta_x = left - shape.left()
            delta_y = top - shape.top()
            if delta_x != 0 or delta_y != 0:
                self.owner._being_resized = True
                self.owner.setPos(self.owner.pos() + QPointF(delta_x, delta_y))
                self.owner._being_resized = False
            # Update size
            new_shape_w = right - left
            new_shape_h = bottom - top
            self.owner._width = new_shape_w + NODE_PADDING * 2
            self.owner._height = new_shape_h + NODE_PADDING * 2
            self.owner._properties["width"] = self.owner._width
            self.owner._properties["height"] = self.owner._height
            self.owner.update()
            self.owner._update_boundary_handles_positions()
            # re-layout slots after size change
            self.owner._layout_slots()
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):  # type: ignore[override]
        if self._dragging:
            self._dragging = False
            # Evaluate membership after resize
            if self.owner.scene():
                for item in self.owner.scene().items():  # type: ignore
                    if isinstance(item, NodeItem) and item is not self.owner and item.shape_kind != 'Boundary':
                        item._evaluate_boundary_membership()
                update_container_ownership(self.owner.scene())
            event.accept()
            return
        super().mouseReleaseEvent(event)
