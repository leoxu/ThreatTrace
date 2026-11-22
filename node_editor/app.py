from __future__ import annotations

from pathlib import Path
import logging
import os
from functools import partial
from typing import Optional, List, Dict, Any, Tuple

_LOG = logging.getLogger("node_editor")

from PySide6.QtCore import Qt, QPointF, QRectF, Signal, QThread
from PySide6.QtGui import QAction, QImage, QPainterPath, QPen, QColor, QPainter, QUndoStack
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QDockWidget,
    QGraphicsPathItem,
    QGraphicsScene,
    QGraphicsView,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QProgressDialog,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

import json

from .nodes import NodeSpec, EdgeSpec, PropDef, builtin_nodes, security_nodes, load_toolbox, create_node, load_template, load_edge_template, load_sec_prop_defs
from .graphics.items import NodeItem, EdgeItem, SlotItem, LabelItem, set_sequence_registry, set_active_sequence, set_threat_registry
from .threat import Threat, ThreatRegistry
from .ui.property_editor import PropertyEditor, SHAPE_KEYS
from .sequence import DEFAULT_SEQUENCE_COLOR, Sequence, SequenceRegistry, edge_sequence_steps, new_sequence


GRID_SIZE = 20  # snap/draw granularity in scene units


class _NoCurrentFileError(Exception):
    """Raised by save_project() when no path is given and no file has been opened/saved yet."""


def _pack_shape(props: dict) -> dict:
    """Return a copy of a node's flat properties with shape keys nested under 'shape'.

    Used at save time. Shape keys (color, size, z-order, …) that are present are
    moved into a nested {'shape': {...}} block; all other keys stay top-level.
    """
    result: dict = {}
    shape: dict = {}
    for k, v in props.items():
        if k in SHAPE_KEYS:
            shape[k] = v
        else:
            result[k] = v
    if shape:
        result["shape"] = shape
    return result


def _unpack_shape(stored: dict, shape_defaults: dict) -> dict:
    """Return flat node properties from stored properties that may nest a 'shape' block.

    Used at load time. Any 'shape' sub-block is flattened back to top-level keys.
    For each shape key, precedence is: value in the 'shape' block > legacy flat
    value already present (old files) > default from the node's template. Missing
    keys with no default are simply left out.
    """
    shape_block = stored.get("shape") or {}
    result = {k: v for k, v in stored.items() if k != "shape"}
    for key in SHAPE_KEYS:
        if key in shape_block:
            result[key] = shape_block[key]
        elif key in result:
            continue  # legacy flat value from a pre-'shape' file
        elif key in shape_defaults:
            result[key] = shape_defaults[key]
    return result


class _Tm7ConvertThread(QThread):
    """Runs TM7 → project-JSON conversion off the UI thread."""
    progress = Signal(int, str)   # (0-100, status message)
    converted = Signal(dict)      # project dict on success
    failed = Signal(str)          # error message on failure

    def __init__(self, tm7_path: str, parent=None):
        super().__init__(parent)
        self._tm7_path = tm7_path

    def run(self) -> None:
        try:
            import importlib.util as _ilu

            self.progress.emit(5, "Loading converter…")
            _conv_path = Path(__file__).parent.parent / "tm7" / "tm7_convert.py"
            _spec = _ilu.spec_from_file_location("tm7_convert", _conv_path)
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)

            # Look for a companion .tb7 next to the .tm7, fall back to bundled template
            self.progress.emit(15, "Locating template…")
            tm7_p = Path(self._tm7_path)
            tb7_candidates = list(tm7_p.parent.glob("*.tb7"))
            bundled = Path(__file__).parent.parent / "tm7" / "template.tb7"
            tb7_path = str(tb7_candidates[0]) if tb7_candidates else (
                str(bundled) if bundled.exists() else None
            )

            et_map: dict = {}
            if tb7_path:
                self.progress.emit(30, f"Parsing template {Path(tb7_path).name}…")
                tpl = _mod.parse_template(tb7_path)
                et_map = tpl["element_types"]

            self.progress.emit(55, "Parsing TM7 model…")
            tm7_data = _mod.parse_tm7(self._tm7_path, et_map)

            self.progress.emit(85, "Building project…")
            project = _mod.build_project_json(tm7_data)

            self.progress.emit(100, "Done")
            self.converted.emit(project)
        except Exception as exc:
            self.failed.emit(str(exc))


class NodeGraphicsScene(QGraphicsScene):
    selectionChangedSimplified = Signal(object)
    edgeCreated = Signal(object)  # EdgeItem
    slotClicked = Signal(object)  # SlotItem

    def __init__(self):
        super().__init__()
        self.setItemIndexMethod(QGraphicsScene.NoIndex)
        self._connecting_from: Optional[SlotItem] = None
        self._temp_path: Optional[QGraphicsPathItem] = None
        self._delete_handler = None  # set by MainWindow to route deletion through undo stack
        self.grid_enabled: bool = True  # toggled by View menu
        # forward Qt selectionChanged signal to our simplified variant
        self.selectionChanged.connect(self._on_qt_selection_changed)

    def _on_qt_selection_changed(self) -> None:
        selected = list(self.selectedItems())
        filtered = [it for it in selected if isinstance(it, (NodeItem, LabelItem, EdgeItem))]
        self.selectionChangedSimplified.emit(filtered)

    # Connection helpers
    def start_connection(self, slot: SlotItem) -> None:
        self.cancel_connection()
        self._connecting_from = slot
        self._temp_path = QGraphicsPathItem()
        self._temp_path.setZValue(200)
        pen = QPen(QColor("#aaaaaa"), 2, Qt.DashLine)
        self._temp_path.setPen(pen)
        self.addItem(self._temp_path)

    def update_connection(self, scene_pos: QPointF) -> None:
        if not (self._connecting_from and self._temp_path):
            return
        a = self._connecting_from.center_in_scene()
        b = scene_pos
        p = QPainterPath(a)
        dx = (b.x() - a.x()) * 0.5
        c1 = QPointF(a.x() + dx, a.y())
        c2 = QPointF(b.x() - dx, b.y())
        p.cubicTo(c1, c2, b)
        self._temp_path.setPath(p)

    def finish_connection(self, target: Optional[SlotItem]) -> None:
        if not self._connecting_from:
            self.cancel_connection()
            return
        src = self._connecting_from
        self._connecting_from = None
        if self._temp_path:
            self.removeItem(self._temp_path)
            self._temp_path = None
        if target is None or target is src:
            return
        # normalize direction to output -> input
        if src.kind == "output" and target.kind == "input":
            out_slot, in_slot = src, target
        elif src.kind == "input" and target.kind == "output":
            out_slot, in_slot = target, src
        else:
            return
        # create the edge through either node
        out_node = out_slot.parentItem()
        if isinstance(out_node, NodeItem):
            edge = out_node.connect(out_slot, in_slot)
            if edge is not None:
                self.edgeCreated.emit(edge)

    def cancel_connection(self) -> None:
        self._connecting_from = None
        if self._temp_path:
            self.removeItem(self._temp_path)
            self._temp_path = None

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key_Delete, Qt.Key_Backspace):
            if self._delete_handler is not None:
                self._delete_handler()
            else:
                self._delete_selected()
            event.accept()
            return
        super().keyPressEvent(event)

    def _delete_selected(self) -> None:
        selected = list(self.selectedItems())
        edges_to_remove: set = set()
        nodes_to_remove: set = set()

        for item in selected:
            if isinstance(item, NodeItem):
                nodes_to_remove.add(item)
            elif isinstance(item, EdgeItem):
                edges_to_remove.add(item)
            elif isinstance(item, LabelItem):
                if item.edge is not None:
                    edges_to_remove.add(item.edge)

        # Also collect all edges connected to nodes being deleted
        for node in nodes_to_remove:
            for edge in list(node.edges):
                edges_to_remove.add(edge)

        for edge in edges_to_remove:
            self._remove_edge(edge)

        for node in nodes_to_remove:
            if node.scene() is self:
                self.removeItem(node)

    def _remove_edge(self, edge: 'EdgeItem') -> None:
        src_node = edge.src.parentItem() if edge.src else None
        dst_node = edge.dst.parentItem() if edge.dst else None
        if isinstance(src_node, NodeItem) and edge in src_node.edges:
            src_node.edges.remove(edge)
        if isinstance(dst_node, NodeItem) and edge in dst_node.edges:
            dst_node.edges.remove(edge)
        if edge.scene() is self:
            self.removeItem(edge)

    def snap_to_grid(self, pos: QPointF) -> QPointF:
        if not self.grid_enabled:
            return pos
        g = GRID_SIZE
        return QPointF(round(pos.x() / g) * g, round(pos.y() / g) * g)

    def drawBackground(self, painter: QPainter, rect) -> None:  # type: ignore[override]
        super().drawBackground(painter, rect)
        if not self.grid_enabled:
            return
        g = GRID_SIZE
        left = int(rect.left()) - (int(rect.left()) % g)
        top = int(rect.top()) - (int(rect.top()) % g)
        pen = QPen(QColor("#e8e8e8"), 0)
        painter.setPen(pen)
        x = left
        while x <= rect.right():
            painter.drawLine(int(x), int(rect.top()), int(x), int(rect.bottom()))
            x += g
        y = top
        while y <= rect.bottom():
            painter.drawLine(int(rect.left()), int(y), int(rect.right()), int(y))
            y += g

    def drawForeground(self, painter: QPainter, rect) -> None:  # type: ignore[override]
        super().drawForeground(painter, rect)


class NodeGraphicsView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene):
        super().__init__(scene)
        self.setRenderHints(self.renderHints() | QPainter.Antialiasing)
        self.setDragMode(QGraphicsView.RubberBandDrag)
        self.setViewportUpdateMode(QGraphicsView.FullViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAcceptDrops(True)
        self._space_held = False
        self._pan_last: Optional[QPointF] = None
        self._pre_move_positions: dict = {}  # NodeItem -> QPointF (for move undo)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Space and not event.isAutoRepeat():
            self._space_held = True
            self.setCursor(Qt.OpenHandCursor)
            event.accept()
            return
        if event.key() == Qt.Key_Escape and not event.isAutoRepeat():
            win = self.window()
            if hasattr(win, "_pick_seq_id") and win._pick_seq_id is not None:
                win._cancel_pick_mode()
                event.accept()
                return
            if hasattr(win, "_scene_stack") and win._scene_stack:
                win.navigate_out()
                event.accept()
                return
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event):
        if event.key() == Qt.Key_Space and not event.isAutoRepeat():
            self._space_held = False
            self._pan_last = None
            self.setDragMode(QGraphicsView.RubberBandDrag)
            self.unsetCursor()
            event.accept()
            return
        super().keyReleaseEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MiddleButton:
            self._pan_last = event.position()
            self.setCursor(Qt.ClosedHandCursor)
            event.accept()
            return
        if event.button() == Qt.LeftButton and self._space_held:
            self._pan_last = event.position()
            self.setCursor(Qt.ClosedHandCursor)
            event.accept()
            return
        if event.button() == Qt.LeftButton:
            win = self.window()
            if hasattr(win, "_pick_seq_id") and win._pick_seq_id is not None:
                scene_pos = self.mapToScene(event.pos())
                for it in self.scene().items(scene_pos):
                    if isinstance(it, EdgeItem):
                        win.seq_panel.add_step(it.edge_id)
                        self.scene().update()
                        event.accept()
                        return
                event.accept()
                return
        super().mousePressEvent(event)
        # Capture pre-move positions of all selected nodes for move undo
        if event.button() == Qt.LeftButton and not self._space_held:
            self._pre_move_positions = {
                item: item.pos()
                for item in self.scene().items()
                if isinstance(item, NodeItem) and item.isSelected()
            }

    def _pan_by(self, delta: QPointF) -> None:
        """Pan the view by a viewport-space delta.

        Uses centerOn() so panning works even when all content fits in the
        viewport (scrollbars have zero range).  The view's scene rect is
        expanded on demand so centerOn() is never blocked by the boundary.
        """
        scale = self.transform().m11()
        vr = self.viewport().rect()
        center = self.mapToScene(vr.center())
        new_center = QPointF(center.x() - delta.x() / scale,
                             center.y() - delta.y() / scale)

        # Ensure the view scene rect is large enough to contain the new visible area.
        half_w = vr.width()  / scale / 2.0 + 400
        half_h = vr.height() / scale / 2.0 + 400
        cur = self.sceneRect()
        left   = min(cur.left(),   new_center.x() - half_w)
        top    = min(cur.top(),    new_center.y() - half_h)
        right  = max(cur.right(),  new_center.x() + half_w)
        bottom = max(cur.bottom(), new_center.y() + half_h)
        if left < cur.left() or top < cur.top() or right > cur.right() or bottom > cur.bottom():
            self.setSceneRect(QRectF(left, top, right - left, bottom - top))

        self.centerOn(new_center)

    def mouseMoveEvent(self, event):
        if self._pan_last is not None:
            delta = event.position() - self._pan_last
            self._pan_last = event.position()
            self._pan_by(delta)
            event.accept()
            return
        super().mouseMoveEvent(event)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        win = self.window()
        if hasattr(win, "_minimap") and win._minimap is not None:
            win._minimap.reposition()
            win._minimap.update_viewport()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MiddleButton and self._pan_last is not None:
            self._pan_last = None
            self.unsetCursor()
            event.accept()
            return
        if event.button() == Qt.LeftButton and self._pan_last is not None:
            self._pan_last = None
            self.setCursor(Qt.OpenHandCursor)  # back to open hand while space still held
            event.accept()
            return
        super().mouseReleaseEvent(event)
        # Push a MoveNodes undo command if any selected nodes actually moved
        if event.button() == Qt.LeftButton and self._pre_move_positions:
            moves = []
            for node, old_pos in self._pre_move_positions.items():
                if node.scene() is not None:
                    new_pos = node.pos()
                    if (new_pos - old_pos).manhattanLength() > 0.5:
                        moves.append((node, old_pos, new_pos))
            self._pre_move_positions = {}
            if moves:
                win = self.window()
                if hasattr(win, "_undo_stack"):
                    from .commands import MoveNodesCommand
                    win._undo_stack.push(MoveNodesCommand(moves))
        else:
            self._pre_move_positions = {}

    def dragEnterEvent(self, event) -> None:
        from .ui.toolbox import MIME_EDGE_SPEC
        if event.mimeData().hasText() or event.mimeData().hasFormat(MIME_EDGE_SPEC):
            event.acceptProposedAction()
        else:
            super().dragEnterEvent(event)

    def dragMoveEvent(self, event) -> None:
        from .ui.toolbox import MIME_EDGE_SPEC
        if event.mimeData().hasText() or event.mimeData().hasFormat(MIME_EDGE_SPEC):
            event.acceptProposedAction()
        else:
            super().dragMoveEvent(event)

    def dropEvent(self, event) -> None:
        from .ui.toolbox import MIME_EDGE_SPEC
        if event.mimeData().hasFormat(MIME_EDGE_SPEC):
            edge_name = event.mimeData().data(MIME_EDGE_SPEC).data().decode()
            scene_pos = self.mapToScene(event.position().toPoint())
            win = self.window()
            if hasattr(win, "_drop_edge"):
                win._drop_edge(edge_name, scene_pos)
            event.acceptProposedAction()
        elif event.mimeData().hasText():
            spec_name = event.mimeData().text()
            scene_pos = self.mapToScene(event.position().toPoint())
            win = self.window()
            if hasattr(win, "_drop_node"):
                win._drop_node(spec_name, scene_pos)
            event.acceptProposedAction()
        else:
            super().dropEvent(event)

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        factor = 1.15 if delta > 0 else 1 / 1.15
        self.scale(factor, factor)

    def contextMenuEvent(self, event):
        scene_pos = self.mapToScene(event.pos())
        win = self.window()
        if hasattr(win, "_show_context_menu"):
            win._show_context_menu(scene_pos, event.globalPos())
            return
        super().contextMenuEvent(event)


# The product name, in one place: the window title, the CLI help and the
# generated artefacts all read from here.
APP_NAME = "ThreatTrace"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.resize(1560, 800)

        self.scene = NodeGraphicsScene()
        self.view = NodeGraphicsView(self.scene)
        self._undo_stack = QUndoStack(self)
        self.threats: ThreatRegistry = {}
        self.sequences: SequenceRegistry = {}
        self._highlighted_slot = None
        self._pick_seq_id: Optional[str] = None  # seq_id when in pick-edge mode
        self._selected_edge: Optional[EdgeItem] = None

        # Hook the shared sequence/threat state into EdgeItem rendering
        set_sequence_registry(self.sequences)
        set_threat_registry(self.threats)

        # Navigation stack: each entry = (scene, file_path, threats, crumb_name)
        self._scene_stack: List[Tuple] = []
        self._current_file: Optional[str] = None
        self._clipboard: Optional[Dict[str, Any]] = None
        self._project: List[Dict[str, Any]] = []
        self._active_diag_idx: int = 0
        self._project_nodes: Dict[str, Dict[str, Any]] = {}  # shared node registry
        self._hidden_layers: set = set()   # layer names turned off in View → Layers

        # Central widget: breadcrumb bar + canvas view
        central = QWidget()
        central_vl = QVBoxLayout(central)
        central_vl.setContentsMargins(0, 0, 0, 0)
        central_vl.setSpacing(0)

        self._breadcrumb_bar = QWidget()
        self._breadcrumb_bar.setStyleSheet(
            "background: #1e1e1e; border-bottom: 1px solid #444;"
        )
        self._breadcrumb_layout = QHBoxLayout(self._breadcrumb_bar)
        self._breadcrumb_layout.setContentsMargins(8, 3, 8, 3)
        self._breadcrumb_layout.setSpacing(2)
        self._breadcrumb_bar.hide()

        central_vl.addWidget(self._breadcrumb_bar)
        central_vl.addWidget(self.view, 1)
        self.setCentralWidget(central)

        # Minimap overlay (parented to the viewport so it floats over the canvas)
        from .ui.minimap import MinimapView
        self._minimap = MinimapView(self.scene, self.view,
                                    parent=self.view.viewport())
        self._minimap.show()
        self._minimap.reposition()

        _edge_spec = self._load_edge_spec()
        self._edge_prop_defs: dict = _edge_spec.prop_defs if _edge_spec else {}
        self._edge_default_props: dict = _edge_spec.default_properties() if _edge_spec else {}
        _edge_types = self._load_edge_type_categories()
        self._edge_type_categories: list = _edge_types["categories"]
        self._edge_type_types: dict = _edge_types["types"]
        self._edge_type_all_types: dict = _edge_types["all_types"]
        self._asset_operations: dict = self._load_asset_operations()

        self._sec_prop_defs_by_class: dict = self._load_sec_prop_defs_by_class()

        self._build_menu()
        self._act_minimap.toggled.connect(self._minimap.setVisible)
        self._build_toolbar()
        self._build_toolbox()
        self._build_property_dock()
        self._build_sequence_dock()
        self._build_threat_dock()
        self._build_attack_surface_dock()
        self._build_settings_dock()
        self._build_diagram_dock()
        self._view_menu.addAction(self._as_dock.toggleViewAction())

        self.scene.selectionChangedSimplified.connect(self._on_selection_changed)
        self.scene.edgeCreated.connect(self._on_edge_created)
        self.scene.slotClicked.connect(self._on_slot_clicked)
        self.scene._delete_handler = self._do_delete_selected

        # Minimap: update when main view scrolls
        self.view.horizontalScrollBar().valueChanged.connect(self._minimap.update_viewport)
        self.view.verticalScrollBar().valueChanged.connect(self._minimap.update_viewport)

        self._init_empty_project()

    def _build_menu(self) -> None:
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")

        act_new = QAction("New", self)
        act_new.triggered.connect(self._file_new)
        file_menu.addAction(act_new)

        act_open = QAction("Open...", self)
        act_open.triggered.connect(self._file_open)
        file_menu.addAction(act_open)

        act_save = QAction("Save", self)
        act_save.setShortcut("Ctrl+S")
        act_save.triggered.connect(self._file_save_current)
        file_menu.addAction(act_save)

        act_save_as = QAction("Save As...", self)
        act_save_as.triggered.connect(self._file_save)
        file_menu.addAction(act_save_as)

        file_menu.addSeparator()

        act_export = QAction("Export Selection...", self)
        act_export.triggered.connect(self._export_selection)
        file_menu.addAction(act_export)

        act_export_threats = QAction("Export Threats to CSV...", self)
        act_export_threats.triggered.connect(self._export_threats_csv)
        file_menu.addAction(act_export_threats)

        act_export_png = QAction("Export Diagram as PNG...", self)
        act_export_png.setShortcut("Ctrl+Shift+P")
        act_export_png.triggered.connect(self._export_png)
        file_menu.addAction(act_export_png)

        act_export_svg = QAction("Export Diagram as SVG...", self)
        act_export_svg.setShortcut("Ctrl+Shift+E")
        act_export_svg.triggered.connect(self._export_svg)
        file_menu.addAction(act_export_svg)

        file_menu.addSeparator()

        act_report_md = QAction("Export Report (Markdown)...", self)
        act_report_md.triggered.connect(self._export_report_markdown)
        file_menu.addAction(act_report_md)

        act_report_pdf = QAction("Export Report (PDF)...", self)
        act_report_pdf.triggered.connect(self._export_report_pdf)
        file_menu.addAction(act_report_pdf)

        act_threats_report = QAction("Export Threats Report...", self)
        act_threats_report.setToolTip(
            "The threat register, ranked by risk — Markdown, PDF or CSV"
        )
        act_threats_report.triggered.connect(self._export_threats_report)
        file_menu.addAction(act_threats_report)

        act_design_report = QAction("Export Design Verification Report...", self)
        act_design_report.setToolTip(
            "Diagram, threats and the security controls applied to mitigate them, "
            "with a design-phase verdict"
        )
        act_design_report.triggered.connect(self._export_design_report)
        file_menu.addAction(act_design_report)

        act_import = QAction("Import Nodes...", self)
        act_import.triggered.connect(self._import_nodes)
        file_menu.addAction(act_import)

        edit_menu = menubar.addMenu("Edit")

        act_undo = self._undo_stack.createUndoAction(self, "Undo")
        act_undo.setShortcut("Ctrl+Z")
        edit_menu.addAction(act_undo)

        act_redo = self._undo_stack.createRedoAction(self, "Redo")
        act_redo.setShortcut("Ctrl+Y")
        edit_menu.addAction(act_redo)

        edit_menu.addSeparator()

        act_copy = QAction("Copy", self)
        act_copy.setShortcut("Ctrl+C")
        act_copy.triggered.connect(self._copy_selected)
        edit_menu.addAction(act_copy)

        act_paste = QAction("Paste", self)
        act_paste.setShortcut("Ctrl+V")
        act_paste.triggered.connect(lambda: self._paste_at(self.view.mapToScene(self.view.rect().center())))
        edit_menu.addAction(act_paste)

        act_delete = QAction("Delete", self)
        act_delete.setShortcut("Del")
        act_delete.triggered.connect(self._do_delete_selected)
        edit_menu.addAction(act_delete)

        view_menu = menubar.addMenu("View")

        act_grid = QAction("Show Grid / Snap", self)
        act_grid.setShortcut("Ctrl+G")
        act_grid.setCheckable(True)
        act_grid.setChecked(True)
        act_grid.triggered.connect(self._toggle_grid)
        view_menu.addAction(act_grid)
        self._act_grid = act_grid

        act_ortho = QAction("Orthogonal Edges", self)
        act_ortho.setCheckable(True)
        act_ortho.setChecked(False)
        act_ortho.triggered.connect(self._toggle_edge_routing)
        view_menu.addAction(act_ortho)
        self._act_ortho = act_ortho

        # Layers: one checkable entry per layer, rebuilt each time it opens so
        # layers added since (any custom 'layer' property) show up.
        self._layers_menu = view_menu.addMenu("Layers")
        self._layers_menu.aboutToShow.connect(self._rebuild_layers_menu)

        view_menu.addSeparator()
        # Minimap toggle (minimap created after menu, so wired in __init__)
        self._act_minimap = QAction("Show Minimap", self)
        self._act_minimap.setCheckable(True)
        self._act_minimap.setChecked(True)
        view_menu.addAction(self._act_minimap)

        view_menu.addSeparator()
        # Dock visibility toggles — populated after docks are built
        self._view_menu = view_menu

        tools_menu = menubar.addMenu("Tools")

        act_validate = QAction("Validate Diagram", self)
        act_validate.setShortcut("Ctrl+Shift+V")
        act_validate.triggered.connect(self._run_validation)
        tools_menu.addAction(act_validate)

        act_assets = QAction("Asset Types…", self)
        act_assets.triggered.connect(self._open_asset_manager)
        tools_menu.addAction(act_assets)

        act_diff = QAction("Compare With File…", self)
        act_diff.triggered.connect(self._compare_with_file)
        tools_menu.addAction(act_diff)

        act_diff2 = QAction("Diff Two Files…", self)
        act_diff2.triggered.connect(self._diff_two_files)
        tools_menu.addAction(act_diff2)

        act_import_log = QAction("Import Runtime Log…", self)
        act_import_log.triggered.connect(self._import_runtime_log)
        tools_menu.addAction(act_import_log)

        act_verify_impl = QAction("Verify Against Runtime Log…", self)
        act_verify_impl.triggered.connect(self._verify_against_log)
        tools_menu.addAction(act_verify_impl)

        tools_menu.addSeparator()

        gen_menu = tools_menu.addMenu("Generate Threats")

        act_gen_claude = QAction("From Claude", self)
        act_gen_claude.triggered.connect(lambda: self._on_generate_threats_all_edges("claude"))
        gen_menu.addAction(act_gen_claude)

        act_gen_codex = QAction("From Codex", self)
        act_gen_codex.triggered.connect(lambda: self._on_generate_threats_all_edges("codex"))
        gen_menu.addAction(act_gen_codex)

        act_gen_rules = QAction("From Local Template Rules", self)
        act_gen_rules.triggered.connect(lambda: self._on_generate_threats_all_edges("rules"))
        gen_menu.addAction(act_gen_rules)

        gen_menu.addSeparator()

        act_gen_all = QAction("All Backends", self)
        act_gen_all.setShortcut("Ctrl+Shift+T")
        act_gen_all.triggered.connect(lambda: self._on_generate_threats_all_edges("all"))
        gen_menu.addAction(act_gen_all)

        act_apply_controls = QAction("Apply Security Controls…", self)
        act_apply_controls.setToolTip(
            "Assess every security control against the threats it covers and "
            "link the ones it mitigates"
        )
        act_apply_controls.triggered.connect(self._on_apply_security_controls)
        tools_menu.addAction(act_apply_controls)

        act_static_verify = QAction("Static Verification (Source Code)…", self)
        act_static_verify.setToolTip(
            "Check in the source whether each security control is actually "
            "implemented, with file:line citations"
        )
        act_static_verify.triggered.connect(self._on_static_verification)
        tools_menu.addAction(act_static_verify)

        act_gen_tests = QAction("Generate Runtime Tests…", self)
        act_gen_tests.setToolTip(
            "Write a runtime test per security control — skeletons for the test "
            "harness plus a manifest the results importer reads back")
        act_gen_tests.triggered.connect(self._on_generate_runtime_tests)
        tools_menu.addAction(act_gen_tests)

        act_import_results = QAction("Import Test Results (Runtime)…", self)
        act_import_results.setToolTip(
            "Decide each runtime test from a captured log and record the "
            "evidence on the threats those controls mitigate")
        act_import_results.triggered.connect(self._on_import_test_results)
        tools_menu.addAction(act_import_results)

    # ── layers ────────────────────────────────────────────────────────────────

    def _rebuild_layers_menu(self) -> None:
        from .layers import scene_layers

        self._layers_menu.clear()
        for layer in scene_layers(self.scene):
            act = QAction(layer.capitalize(), self)
            act.setCheckable(True)
            act.setChecked(layer not in self._hidden_layers)
            act.toggled.connect(
                lambda visible, l=layer: self._set_layer_visible(l, visible)
            )
            self._layers_menu.addAction(act)

        self._layers_menu.addSeparator()
        act_all = QAction("Show All Layers", self)
        act_all.triggered.connect(lambda: self._set_hidden_layers(set()))
        self._layers_menu.addAction(act_all)

    def _set_layer_visible(self, layer: str, visible: bool) -> None:
        hidden = set(self._hidden_layers)
        hidden.discard(layer) if visible else hidden.add(layer)
        self._set_hidden_layers(hidden)

    def _set_hidden_layers(self, hidden: set) -> None:
        self._hidden_layers = {str(l).strip().lower() for l in hidden}
        self._apply_layer_visibility()

    def _apply_layer_visibility(self) -> None:
        """Re-apply layer visibility to the current scene (after any rebuild)."""
        from .layers import apply_visibility
        apply_visibility(self.scene, self._hidden_layers)
        self.scene.update()
        if hasattr(self, "_minimap"):
            self._minimap.update_viewport()

    # ── review notes ──────────────────────────────────────────────────────────

    def _on_review_comment_added(self, node: NodeItem, text: str) -> None:
        """Append a comment (question or reply) to a review note's thread."""
        from .review import add_comment
        if node is None or not text.strip():
            return
        node.set_properties(add_comment(node.properties(), text))
        node.update()
        self.prop_editor.set_node(node)      # redraw the thread
        self._sync_active_diagram()

    def _on_review_status_toggled(self, node: NodeItem) -> None:
        from .review import toggle_status
        if node is None:
            return
        node.set_properties(toggle_status(node.properties()))
        node.update()
        self.prop_editor.set_node(node)
        self._sync_active_diagram()

    def _toggle_grid(self, checked: bool) -> None:
        self.scene.grid_enabled = checked
        self.scene.update()

    def _toggle_edge_routing(self, checked: bool) -> None:
        """Switch all edges between curved (bezier) and orthogonal (elbow) routing."""
        from .graphics.items import set_edge_routing
        set_edge_routing("orthogonal" if checked else "curved")
        for item in self.scene.items():
            if isinstance(item, EdgeItem):
                item.update_path()
        self.scene.update()

    def run_validation(self) -> list:
        """Run diagram validation rules and return the list of issues (no dialog)."""
        from .validation import validate_scene
        return validate_scene(self.scene, self._edge_type_types)

    def _run_validation(self) -> None:
        from .ui.validation_dialog import ValidationDialog
        issues = self.run_validation()
        dlg = ValidationDialog(issues, self._navigate_to_item, parent=self)
        dlg.exec()

    def _all_asset_type_entries(self):
        """Return [(AssetType, is_descriptor)] for the manager: descriptors + built-ins."""
        from .asset_registry import descriptor_asset_types
        from .asset_types import asset_type_from_legacy
        entries = []
        descriptors = descriptor_asset_types()
        for at in descriptors.values():
            entries.append((at, True))
        # built-in (legacy) asset types from the toolbox specs, minus descriptors
        for spec in self._toolbox_specs.values():
            props = spec.default_properties
            if not str(props.get("class", "")).startswith("security asset"):
                continue
            sec = props.get("security-properties", {}) if isinstance(props.get("security-properties"), dict) else {}
            type_id = str(sec.get("type", spec.name))
            if type_id in descriptors:
                continue
            schema = self._sec_prop_defs_by_class.get(f"security asset {type_id}") \
                or self._sec_prop_defs_by_class.get("security asset") or {}
            properties = {
                k: ({"default": d.default, "options": d.options} if d.options else d.default)
                for k, d in schema.items()
            }
            at = asset_type_from_legacy(
                spec.name, type_id, {"type": type_id},
                operations=self._asset_operations.get(type_id, []),
                color=str(props.get("color", "#f2994a")), shape=spec.shape_kind,
            )
            if properties:
                at.properties = properties
            entries.append((at, False))
        return entries

    def _asset_type_usage(self, type_id: str) -> int:
        """How many nodes — on the canvas or elsewhere in the project — are of
        this asset type. What deleting or renaming a type would affect."""
        if not type_id:
            return 0
        count = 0
        seen: set = set()
        for item in self.scene.items():
            if not isinstance(item, NodeItem):
                continue
            sec = item.properties().get("security-properties")
            if isinstance(sec, dict) and str(sec.get("type", "")) == type_id:
                seen.add(item.node_id)
                count += 1
        for node_id, data in self._project_nodes.items():
            if node_id in seen:
                continue
            sec = (data.get("properties") or {}).get("security-properties")
            if isinstance(sec, dict) and str(sec.get("type", "")) == type_id:
                count += 1
        return count

    def _retype_asset_instances(self, old_type_id: str, new_type_id: str) -> int:
        """Move every instance from one asset type id to another, undoably."""
        from .commands import RetypeAssetsCommand

        nodes = [i for i in self.scene.items() if isinstance(i, NodeItem)
                 and isinstance(i.properties().get("security-properties"), dict)
                 and str(i.properties()["security-properties"].get("type", "")) == old_type_id]
        affected = self._asset_type_usage(old_type_id)
        if affected:
            self._undo_stack.push(
                RetypeAssetsCommand(nodes, old_type_id, new_type_id, self._project_nodes))
        return affected

    def _open_asset_manager(self) -> None:
        from .ui.asset_editor import AssetManagerDialog
        from .asset_registry import delete_descriptor, descriptor_exists, save_descriptor

        def _save(at, original_id: str = "", rewrite: bool = False):
            # Order matters: rewrite the instances onto the new id first, then
            # drop the old descriptor, then write the new one — so no moment
            # exists where a node points at a type that has no descriptor.
            moved = 0
            if rewrite and original_id and original_id != at.type_id:
                moved = self._retype_asset_instances(original_id, at.type_id)
                delete_descriptor(original_id)
            save_descriptor(at)
            # Re-read schema, operations and toolbox *after* the rewrite, so the
            # property panel renders the moved instances against the new schema.
            self.reload_asset_types()
            selected = [i for i in self.scene.selectedItems() if isinstance(i, NodeItem)]
            if len(selected) == 1:
                self.prop_editor.set_node(selected[0])   # re-render on the new schema
            self.log(f"Asset type '{at.name}' saved"
                     + (f"; {moved} instance(s) moved from '{original_id}'" if moved else ""))

        def _delete(type_id):
            delete_descriptor(type_id)
            self.reload_asset_types()
            self.log(f"Asset type '{type_id}' deleted")

        AssetManagerDialog(self._all_asset_type_entries(), _save, _delete, parent=self,
                           usage=self._asset_type_usage,
                           exists=descriptor_exists).exec()

    def reload_asset_types(self) -> None:
        """Re-read asset descriptors and live-refresh schema, operations, toolbox."""
        self._sec_prop_defs_by_class = self._load_sec_prop_defs_by_class()
        self._asset_operations = self._load_asset_operations()
        self.prop_editor.sec_prop_defs_by_class = self._sec_prop_defs_by_class
        self.prop_editor.asset_operations = self._asset_operations
        self.prop_editor.asset_types_by_id = self._descriptor_asset_types()
        self._build_toolbox()   # reuses the existing dock, replaces its widget

    @staticmethod
    def _descriptor_asset_types() -> dict:
        try:
            from .asset_registry import descriptor_asset_types
            return descriptor_asset_types()
        except Exception:
            return {}

    def _compare_with_file(self) -> None:
        """Diff the current (in-memory) model against a chosen saved project file."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Compare Current Model With…", "", "JSON Files (*.json)"
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                other = json.load(f)
            current = self._serialize_project()
        except Exception as e:
            QMessageBox.critical(self, "Compare Failed", str(e))
            return
        self._show_diff(current, other,
                        Path(self._current_file).name if self._current_file else "current (unsaved)",
                        Path(path).name)

    def _diff_two_files(self) -> None:
        """Diff two chosen saved project files (A → B)."""
        path_a, _ = QFileDialog.getOpenFileName(
            self, "Diff — pick BASE (A)", "", "JSON Files (*.json)"
        )
        if not path_a:
            return
        path_b, _ = QFileDialog.getOpenFileName(
            self, "Diff — pick REVISED (B)", "", "JSON Files (*.json)"
        )
        if not path_b:
            return
        try:
            with open(path_a, "r", encoding="utf-8") as f:
                proj_a = json.load(f)
            with open(path_b, "r", encoding="utf-8") as f:
                proj_b = json.load(f)
        except Exception as e:
            QMessageBox.critical(self, "Diff Failed", str(e))
            return
        self._show_diff(proj_a, proj_b, Path(path_a).name, Path(path_b).name)

    def _show_diff(self, proj_a: dict, proj_b: dict, title_a: str, title_b: str) -> None:
        from .modeldiff import diff_projects
        from .ui.diff_dialog import DiffDialog
        diff = diff_projects(proj_a, proj_b)
        DiffDialog(diff, title_a, title_b, parent=self).exec()

    def _import_runtime_log(self) -> None:
        """Build an implementation-phase model from a runtime syscall capture."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Import Runtime Log", "", "Log Files (*.log *.txt);;All Files (*)"
        )
        if not path:
            return
        self._navigate_to_depth(0)
        try:
            from .implmodel import log_to_project
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                proj = log_to_project(f.read())
            self._load_project(proj)
            self._current_file = None
            self._update_title()
        except Exception as e:
            QMessageBox.critical(self, "Import Log Failed", str(e))
            return
        n_nodes = len(proj.get("nodes", {}))
        n_edges = len(proj.get("diagrams", [{}])[0].get("edges", []))
        QMessageBox.information(
            self, "Runtime Log Imported",
            f"Implementation model built from {Path(path).name}:\n"
            f"{n_nodes} components/assets, {n_edges} observed interactions.\n\n"
            "Use Tools → Verify Against Runtime Log… to check a design model against it."
        )

    # ── static verification ──────────────────────────────────────────────────

    def _diagram_source_root(self) -> str:
        """The source tree this model describes, if the diagram names one."""
        if self._project and 0 <= self._active_diag_idx < len(self._project):
            return str(self._project[self._active_diag_idx].get("source-root", "") or "")
        return ""

    # ── runtime (dynamic) verification ───────────────────────────────────────

    def _on_generate_runtime_tests(self) -> None:
        """Write a runnable stub and a manifest entry per security control.

        The tool stops at specs, skeletons and the manifest: owning an on-target
        harness is a different job. The manifest is the contract that lets the
        results come back in.
        """
        from . import runtime_tests as rt

        specs = rt.build_specs(self.scene, self.threats, self.sequences)
        if not specs:
            missing = rt.control_types_without_tests(
                sorted({c.control_type for _, c in self._control_defs()}))
            extra = ("\n\nNo test template exists for: " + ", ".join(missing)
                     if missing else "")
            self._show_selectable_message(
                QMessageBox.Information, "Generate Runtime Tests",
                "No runtime test applies to this model.\n\nA test is generated "
                "per security control that covers an asset interface, and only "
                "where the test suits that interface's channel type." + extra)
            return

        directory = QFileDialog.getExistingDirectory(
            self, "Where should the tests be written?",
            str(Path(self._current_file).parent) if self._current_file else "")
        if not directory:
            return

        out_dir = Path(directory)
        model_name = Path(self._current_file).name if self._current_file else ""
        try:
            manifest = rt.export_manifest(
                specs, out_dir / "threattrace-tests.manifest.json",
                model_name=model_name)
            written = rt.export_skeletons(specs, out_dir / "tests", harness="shell")
        except OSError as exc:
            QMessageBox.critical(self, "Generate Runtime Tests", str(exc))
            return

        by_control: dict = {}
        for spec in specs:
            by_control.setdefault(spec.control_name, []).append(spec)
        lines = [f"{len(specs)} test(s) for {len(by_control)} control(s):", ""]
        for name, group in sorted(by_control.items()):
            kinds = ", ".join(f"{s.template_id} ({s.kind})" for s in group)
            lines.append(f"  • {name} — {kinds}")
        needs = sorted({r for s in specs for r in s.requires})
        if needs:
            lines += ["", "The target environment must allow: " + ", ".join(needs)]
        lines += ["", f"Manifest: {manifest}", f"Skeletons: {out_dir / 'tests'} "
                  f"({len(written)} file(s))", "",
                  "Fill in the marked steps, run them on target with the syscall "
                  "hook capturing, then use Tools → Import Test Results."]
        self._show_selectable_message(QMessageBox.Information,
                                      "Generate Runtime Tests", "\n".join(lines))
        self.log(f"Runtime tests: wrote {len(written)} skeleton(s) and a manifest "
                 f"to {out_dir}")

    def _control_defs(self) -> list:
        """[(container node, ControlDef)] for every control in the scene."""
        from .controls import read_controls
        from .mitigation import is_security_control

        out = []
        for item in self.scene.items():
            if isinstance(item, NodeItem) and is_security_control(item):
                for control in read_controls(item.properties(), item.node_id):
                    out.append((item, control))
        return out

    def _on_import_test_results(self) -> None:
        """Read a target run back: manifest + captured log → runtime evidence."""
        from . import runtime_tests as rt
        from .ui.runtime_results_dialog import RuntimeResultsDialog

        manifest_path, _ = QFileDialog.getOpenFileName(
            self, "Test manifest", "", "Manifest (*.json);;All files (*)")
        if not manifest_path:
            return
        try:
            specs = rt.load_manifest(manifest_path)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Import Test Results",
                                 f"Could not read the manifest:\n{exc}")
            return
        if not specs:
            QMessageBox.warning(self, "Import Test Results",
                                "That manifest contains no tests.")
            return

        log_path, _ = QFileDialog.getOpenFileName(
            self, "Runtime capture from the test run", "",
            "Logs (*.log *.txt);;All files (*)")
        if not log_path:
            return
        try:
            log_text = Path(log_path).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            QMessageBox.critical(self, "Import Test Results", str(exc))
            return

        results = rt.match_log(specs, log_text)
        counts = rt.summarise(results)
        self.log("Runtime tests: " + ", ".join(f"{k}={v}" for k, v in counts.items() if v))

        def _export(accepted) -> None:
            if not accepted:
                QMessageBox.information(self, "Dynamic Verification",
                                        "No result is selected for the report.")
                return
            default = str(Path(self._current_file or "dynamic-verification").with_suffix(""))
            path, selected = QFileDialog.getSaveFileName(
                self, "Export Dynamic Verification Report",
                default + "-dynamic-verification.pdf",
                "PDF (*.pdf);;Markdown (*.md)")
            if not path:
                return
            kwargs = dict(model_name=Path(self._current_file).name
                          if self._current_file else "",
                          log_name=Path(log_path).name)
            try:
                if path.lower().endswith(".md") or "Markdown" in (selected or ""):
                    out = rt.export_markdown(accepted, Path(path), **kwargs)
                else:
                    out = rt.export_pdf(accepted, Path(path), **kwargs)
            except Exception as exc:
                QMessageBox.critical(self, "Export Failed", str(exc))
                return
            self._show_selectable_message(QMessageBox.Information,
                                          "Dynamic Verification",
                                          f"Report written to:\n{out}")

        dialog = RuntimeResultsDialog(results, on_export=_export, parent=self)
        dialog.exec()
        accepted = dialog.accepted_results()
        updated = rt.apply_results(accepted, self.threats.values(),
                                   asset_of_threat=self._threat_asset_name,
                                   build=Path(log_path).name)
        if updated:
            self._refresh_after_mitigation()
            self.seq_panel.refresh_threats()
            self.log(f"Runtime tests: recorded evidence on {updated} "
                     "threat-control link(s).")

    def _threat_asset_name(self, threat) -> str:
        """The asset this threat's connection ends at, for matching findings."""
        from .graphics.items import NodeItem

        dest = getattr(threat, "dest_guid", "")
        if not dest:
            return ""
        for item in self.scene.items():
            if isinstance(item, NodeItem) and item.node_id == dest:
                return str(item.properties().get("name", ""))
        data = self._project_nodes.get(dest) or {}
        return str((data.get("properties") or {}).get("name", ""))

    def _on_static_verification(self) -> None:
        """Ask the source whether each security control is really there.

        Control → the asset interfaces its circle covers → the code that
        implements them → an agent that must cite file and line. The verdicts are
        reviewed before they reach a report; nothing is written to the model.
        """
        from .codeverify import build_tasks, export_markdown, export_pdf, verify_all
        from .ui.static_verify_dialog import (StaticVerifyResultsDialog,
                                              StaticVerifySetupDialog)

        tasks = build_tasks(self.scene, self.threats, self.sequences)
        if not tasks:
            self._show_selectable_message(
                QMessageBox.Information, "Static Verification",
                "No security control covers an asset interface in this diagram.\n\n"
                "Place a control over the interface it protects, then run this "
                "again — verification follows the same coverage as mitigation.")
            return

        backends = self._configured_backends()
        if "claude" not in backends:
            self._show_selectable_message(
                QMessageBox.Warning, "Static Verification",
                "Static verification needs the Claude CLI: it reads the source "
                "tree with the agent's file tools.\n\nSelect Claude as the "
                "default backend in Settings and run this again.")
            return

        setup = StaticVerifySetupDialog(
            tasks, source_root=self._diagram_source_root(),
            backend_label=f"Claude CLI · {self._configured_claude_model()}",
            parent=self)
        if setup.exec() != QDialog.Accepted:
            return
        root = setup.source_root()
        chosen = setup.selected_tasks()
        if not root or not Path(root).expanduser().is_dir():
            QMessageBox.warning(self, "Static Verification",
                                f"'{root}' is not a directory.")
            return
        if not chosen:
            return

        # Remember it on the diagram, so the next run does not ask again. It is
        # a normal diagram property, saved with the project like any other.
        if self._project and 0 <= self._active_diag_idx < len(self._project):
            self._project[self._active_diag_idx]["source-root"] = root

        model = self._configured_claude_model()
        findings = self._run_generation_with_progress(
            "Static Verification",
            f"Verifying {len(chosen)} control(s) against {root}…",
            lambda progress: verify_all(chosen, root, model=model,
                                        progress_callback=progress),
            len(chosen),
        )
        if findings is None:
            self._cancelled_message("Static Verification")
            return

        from .codeverify import summarise
        counts = summarise(findings)
        self.log("Static Verification: "
                 + ", ".join(f"{k}={v}" for k, v in counts.items() if v))

        def _export(accepted) -> None:
            if not accepted:
                QMessageBox.information(self, "Static Verification",
                                        "No finding is selected for the report.")
                return
            default = str(Path(self._current_file or "static-verification").with_suffix(""))
            path, selected = QFileDialog.getSaveFileName(
                self, "Export Static Verification Report",
                default + "-static-verification.pdf",
                "PDF (*.pdf);;Markdown (*.md)")
            if not path:
                return
            kwargs = dict(model_name=Path(self._current_file).name if self._current_file
                          else (self._project[self._active_diag_idx].get("name", "")
                                if self._project else ""),
                          source_root=root,
                          revision=accepted[0].revision if accepted else "")
            try:
                if path.lower().endswith(".md") or "Markdown" in (selected or ""):
                    out = export_markdown(accepted, Path(path), **kwargs)
                else:
                    out = export_pdf(accepted, Path(path), **kwargs)
            except Exception as exc:
                QMessageBox.critical(self, "Export Failed", str(exc))
                return
            self._show_selectable_message(QMessageBox.Information,
                                          "Static Verification",
                                          f"Report written to:\n{out}")

        dialog = StaticVerifyResultsDialog(findings, on_export=_export, parent=self)
        dialog.exec()

        # Record the verdicts against the threats those controls mitigate: a
        # threat's mitigation is a design claim, and this is the evidence for it.
        from .codeverify import apply_findings
        accepted = dialog.accepted_findings()
        updated = apply_findings(accepted, self.threats.values(),
                                 asset_of_threat=self._threat_asset_name)
        if updated:
            self._refresh_after_mitigation()
            self.seq_panel.refresh_threats()
            self.log(f"Static Verification: recorded evidence on {updated} "
                     "threat-control link(s).")

    def _verify_against_log(self) -> None:
        """Verify the current design model against a chosen runtime log (or impl JSON)."""
        path, _ = QFileDialog.getOpenFileName(
            self, "Verify Against Runtime Log / Impl Model", "",
            "Log or JSON (*.log *.txt *.json);;All Files (*)"
        )
        if not path:
            return
        try:
            design = self._serialize_project()
            if path.lower().endswith(".json"):
                with open(path, "r", encoding="utf-8") as f:
                    impl = json.load(f)
            else:
                from .implmodel import log_to_project
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    impl = log_to_project(f.read())
            from .conformance import verify_conformance
            from .ui.conformance_dialog import ConformanceDialog
            report = verify_conformance(design, impl)
        except Exception as e:
            QMessageBox.critical(self, "Verify Failed", str(e))
            return
        ConformanceDialog(
            report,
            Path(self._current_file).name if self._current_file else "current design",
            Path(path).name, parent=self,
        ).exec()

    def _navigate_to_item(self, node_id, edge_id) -> None:
        """Select the node or edge with the given ID and centre the view on it."""
        target = None
        for item in self.scene.items():
            if node_id and isinstance(item, NodeItem) and item.node_id == node_id:
                target = item
                break
            if edge_id and isinstance(item, EdgeItem) and item.edge_id == edge_id:
                target = item
                break
        if target is None:
            return
        self.scene.clearSelection()
        target.setSelected(True)
        self.view.ensureVisible(target, 60, 60)

    def _build_toolbar(self) -> None:
        toolbar = self.addToolBar("File")
        toolbar.setMovable(False)

        act_new = QAction("New", self)
        act_new.triggered.connect(self._file_new)
        toolbar.addAction(act_new)

        act_open = QAction("Open", self)
        act_open.triggered.connect(self._file_open)
        toolbar.addAction(act_open)

        act_save = QAction("Save", self)
        act_save.triggered.connect(self._file_save_current)
        toolbar.addAction(act_save)

    @staticmethod
    def _merge_descriptor_assets(categories: list) -> list:
        """Append descriptor asset types into the 'Security Assets' toolbox group.

        Descriptor types override a legacy spec with the same name; otherwise
        they are appended. A missing category is created.
        """
        try:
            from .asset_registry import descriptor_asset_specs
            specs = descriptor_asset_specs()
        except Exception:
            specs = []
        by_name = {s.name for s in specs}
        cats = [(name, list(items)) for name, items in categories]
        target = next((c for c in cats if c[0] == "Security Assets"), None)
        if target is None:
            if not specs:
                return categories
            target = ("Security Assets", [])
            cats.append(target)
        # drop legacy specs shadowed by a descriptor of the same name, then append
        existing = [s for s in target[1]
                    if not (isinstance(s, NodeSpec) and s.name in by_name)]
        all_specs = existing + list(specs)

        # Organise the group into subsystem sub-groups (rendered as sub-headers).
        from .ui.toolbox import ToolboxSubHeader

        def _subgroup(spec) -> str:
            n = str(getattr(spec, "name", "")).lower()
            if any(k in n for k in ("memory", "dma-buf", "dma_heap", "shared")):
                return "Memory"
            return "Other"

        order = ["Memory", "Other"]
        buckets: Dict[str, list] = {k: [] for k in order}
        for s in all_specs:
            buckets[_subgroup(s)].append(s)

        grouped: list = []
        multiple = sum(1 for k in order if buckets[k]) > 1
        for k in order:
            items = buckets[k]
            if not items:
                continue
            if multiple:                       # only show sub-headers when it helps
                grouped.append(ToolboxSubHeader(k))
            grouped.extend(items)
        target[1][:] = grouped
        return cats

    def _build_toolbox(self) -> None:
        from .ui.toolbox import NodeToolbox
        from .nodes import EdgeSpec as _EdgeSpec
        categories = load_toolbox()
        categories = self._merge_descriptor_assets(categories)
        toolbox = NodeToolbox(categories, self)
        # Build flat name→spec lookups for drag-drop
        self._toolbox_specs: Dict[str, NodeSpec] = {
            spec.name: spec
            for _, specs in categories
            for spec in specs
            if isinstance(spec, NodeSpec)
        }
        self._toolbox_edge_specs: Dict[str, _EdgeSpec] = {
            spec.name: spec
            for _, specs in categories
            for spec in specs
            if isinstance(spec, _EdgeSpec)
        }
        dock = getattr(self, "_toolbox_dock", None)
        if dock is None:
            dock = QDockWidget("Toolbox", self)
            dock.setObjectName("ToolboxDock")
            dock.setFeatures(
                QDockWidget.DockWidgetMovable | QDockWidget.DockWidgetFloatable
            )
            self.addDockWidget(Qt.LeftDockWidgetArea, dock)
            self._toolbox_dock = dock
        dock.setWidget(toolbox)          # replaces the widget on rebuild
        self.resizeDocks([dock], [180], Qt.Horizontal)

    def _drop_node(self, spec_name: str, pos: QPointF) -> None:
        spec = self._toolbox_specs.get(spec_name)
        if spec:
            self._add_node(spec, pos=self.scene.snap_to_grid(pos))

    def _drop_edge(self, edge_name: str, pos: QPointF) -> None:
        from .commands import AddEdgeCommand
        spec = self._toolbox_edge_specs.get(edge_name)
        if spec:
            props = spec.default_properties()
            edge = EdgeItem(
                src_pos=pos + QPointF(-80, 0),
                dst_pos=pos + QPointF(80, 0),
                properties=props,
            )
            self.scene.addItem(edge)
            self.scene.clearSelection()
            edge.setSelected(True)
            self._undo_stack.push(AddEdgeCommand(self.scene, edge))

    @staticmethod
    def _load_edge_spec():
        from pathlib import Path
        path = Path(__file__).parent.parent / "template" / "security" / "edge.json"
        return load_edge_template(path)

    @staticmethod
    def _load_edge_type_categories() -> dict:
        from pathlib import Path
        path = Path(__file__).parent.parent / "template" / "security" / "edge_types.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                import json
                data = json.load(f)
            categories = data.get("categories", [])
            types = {
                st: cat["type"]
                for cat in categories
                for st in cat.get("sub-types", [])
            }
            # Map each sub-type to ALL types it belongs to (for multi-type sub-types)
            all_types: dict = {}
            for cat in categories:
                for st in cat.get("sub-types", []):
                    all_types.setdefault(st, set()).add(cat["type"])
            return {"categories": categories, "types": types, "all_types": all_types}
        except Exception:
            return {"categories": [], "types": {}, "all_types": {}}

    @staticmethod
    def _load_asset_operations() -> dict:
        """Load the per-asset-type curated operation lists, keyed by asset type

        (i.e. the security-properties.type value, e.g. "shared memory", "file").
        """
        from pathlib import Path
        path = Path(__file__).parent.parent / "template" / "security" / "asset_operations.json"
        ops: dict = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            ops = dict(data.get("operations", {}))
        except Exception:
            ops = {}
        # Descriptor asset types override / extend the legacy list.
        try:
            from .asset_registry import descriptor_operations_by_type
            ops.update(descriptor_operations_by_type())
        except Exception:
            pass
        return ops

    @staticmethod
    def _load_sec_prop_defs_by_class() -> dict:
        from pathlib import Path
        asset_base = Path(__file__).parent.parent / "template" / "security" / "asset"
        elem_base  = Path(__file__).parent.parent / "template" / "security" / "element"
        result = {
            "security asset": load_sec_prop_defs(
                asset_base / "asset_props.json"
            ) or {},
            "security asset file": load_sec_prop_defs(
                asset_base / "file_props.json"
            ) or {},
            "security asset shared memory": load_sec_prop_defs(
                asset_base / "shared_memory_props.json"
            ) or {},
            "security asset register": load_sec_prop_defs(
                asset_base / "register_props.json"
            ) or {},
            "security asset socket": load_sec_prop_defs(
                asset_base / "socket_props.json"
            ) or {},
            "security asset qnx channel": load_sec_prop_defs(
                asset_base / "qnx_channel_props.json"
            ) or {},
            "security control": load_sec_prop_defs(
                elem_base / "security-control_props.json"
            ) or {},
        }
        # Descriptor asset types contribute / override their property schema.
        try:
            from .asset_registry import descriptor_prop_defs_by_class
            result.update(descriptor_prop_defs_by_class())
        except Exception:
            pass
        return result

    @staticmethod
    def _load_property_filter() -> set:
        """Load the set of node property keys hidden by default from property_filter.json."""
        from pathlib import Path
        path = Path(__file__).parent.parent / "template" / "property_filter.json"
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return set(data.get("hidden_node_properties", []))
        except Exception:
            return set()

    @staticmethod
    def _migrate_edge_props(props: dict) -> dict:
        """Migrate edge properties saved under the old schema to the current one.

        Older project files stored the category under 'kind' and the specific
        action under 'type'. The schema was renamed so the category is now
        'type' and the specific action is now 'sub-type'.
        """
        if "kind" not in props:
            return props          # already current schema (or has no type info)
        result = dict(props)
        result["type"] = result.pop("kind")
        if "type" in props:
            result["sub-type"] = props["type"]
        return result

    def _with_type(self, props: dict) -> dict:
        """Return a copy of props with 'type' inserted right before 'sub-type'.

        If the user has explicitly chosen a type that is valid for the selected
        sub-type (i.e. the sub-type belongs to a category of that type), that choice
        is preserved.  Otherwise the default type from the edge_types table is used.
        """
        edge_subtype = props.get("sub-type", "")
        user_type = props.get("type", "")
        valid_types = self._edge_type_all_types.get(edge_subtype, set())
        if user_type and user_type in valid_types:
            etype = user_type          # respect the user's explicit selection
        else:
            etype = self._edge_type_types.get(edge_subtype) or user_type
        result: dict = {}
        for k, v in props.items():
            if k == "type":
                continue          # will be re-inserted in the right position
            if k == "sub-type":
                result["type"] = etype
            result[k] = v
        if "type" not in result:
            result = {"type": etype, **result}
        return result

    def _smart_type(self, edge: EdgeItem, props: dict) -> dict:
        """Override the default edge type/sub-type based on what the endpoints are.

        - to a security asset  -> type "Asset Operation", sub-type = the asset
          interface's first operation
        - otherwise            -> type + sub-type "internal func call"
        """
        def _cls(slot):
            node = slot.parentItem() if slot is not None else None
            return str(node.properties().get("class", "")) if isinstance(node, NodeItem) else None

        def _first_operation(slot) -> str:
            """First operation of the asset interface this slot represents."""
            if slot is None or not hasattr(slot, "properties"):
                return ""
            ops = slot.properties().get("operations")
            if isinstance(ops, list) and ops:
                return str(ops[0])
            # Fallback: the asset type's operation list.
            node = slot.parentItem()
            sec = node.properties().get("security-properties", {}) if isinstance(node, NodeItem) else {}
            tid = str(sec.get("type", "")) if isinstance(sec, dict) else ""
            flat = self._asset_operations.get(tid) if hasattr(self, "_asset_operations") else None
            return str(flat[0]) if isinstance(flat, list) and flat else ""

        src_cls = _cls(edge.src)
        dst_cls = _cls(edge.dst)
        if dst_cls is not None and dst_cls.startswith("security asset"):
            props = dict(props)
            props["type"] = "Asset Operation"
            first_op = _first_operation(edge.dst)
            if first_op:
                props["sub-type"] = first_op
        else:
            # Any non-asset destination is an internal function call.
            props = dict(props)
            props["type"] = "internal func call"
            props["sub-type"] = "internal func call"
        return self._with_type(props)

    def _on_edge_created(self, edge: EdgeItem) -> None:
        from .commands import AddEdgeCommand
        if self._edge_default_props:
            edge.set_properties(self._smart_type(edge, dict(self._edge_default_props)))
        self._undo_stack.push(AddEdgeCommand(self.scene, edge))
        self._apply_ownership(edge)

    def _apply_ownership(self, edge: EdgeItem) -> None:
        """Maintain single-owner ownership for an edge from an asset's owner slot.

        An edge that starts at an asset's dedicated 'owner' slot and ends on a
        component makes that component the asset's owner. An asset has only ONE
        owner: any other edge from the same owner slot is removed (newest wins).
        """
        if edge is None:
            return
        ends = self._ownership_ends(edge)
        if ends is None:
            return
        comp, asset, owner_slot = ends
        # Style + type the ownership edge (dashed dark-green, 'owner' label).
        edge.set_properties(self._with_type({**edge.properties(),
                                             "type": "ownership", "sub-type": "owner"}))
        edge.mark_ownership()
        # Remove any other edge from the same owner slot (newest wins).
        from .commands import DeleteItemsCommand
        stale = [it for it in self.scene.items()
                 if isinstance(it, EdgeItem) and it is not edge
                 and (it.src is owner_slot or it.dst is owner_slot)]
        if stale:
            self._undo_stack.push(
                DeleteItemsCommand(self.scene, [], list(stale), self.threats, {}))
        # Write the owner onto the asset.
        from .graphics.items import _set_asset_owner
        _set_asset_owner(asset, str(comp.properties().get("name", "")))

    @staticmethod
    def _ownership_ends(edge: EdgeItem):
        """(component_node, asset_node, owner_slot) if this edge runs from an
        asset's 'owner' slot to a component; else None."""
        if edge.src is None or edge.dst is None:
            return None
        for owner_slot, other_slot in ((edge.src, edge.dst), (edge.dst, edge.src)):
            a = owner_slot.parentItem() if owner_slot else None
            c = other_slot.parentItem() if other_slot else None
            if not (isinstance(a, NodeItem) and isinstance(c, NodeItem)):
                continue
            if owner_slot.name == "owner" \
                    and str(a.properties().get("class", "")).startswith("security asset") \
                    and not str(c.properties().get("class", "")).startswith("security asset"):
                return (c, a, owner_slot)
        return None

    # ── alias edge helpers ─────────────────────────────────────────────────────

    def _make_alias_edge(self, source_node, dest_node, edge_id=None):
        """Create an alias EdgeItem anchored to two nodes (no slots)."""
        edge = EdgeItem(edge_id=edge_id, properties={"type": "alias", "sub-type": "alias"})
        edge.setZValue(5)  # below nodes (z 10-11) but above boundaries (z -10)
        edge.source_node = source_node
        edge.dest_node = dest_node
        source_node.alias_edges.append(edge)
        dest_node.alias_edges.append(edge)
        if edge.label:
            edge.label.set_text("")
        return edge

    def _alias_edge_between(self, node_a, node_b):
        """Return the alias edge between two nodes, or None."""
        for e in node_a.alias_edges:
            if e.source_node is node_b or e.dest_node is node_b:
                return e
        return None

    def _do_link(self, nodes) -> None:
        from .commands import AliasEdgeCommand
        if len(nodes) != 2:
            return
        # process memory class → dest; other → source
        if nodes[0].properties().get("class") == "process memory":
            dest_node, source_node = nodes[0], nodes[1]
        elif nodes[1].properties().get("class") == "process memory":
            dest_node, source_node = nodes[1], nodes[0]
        else:
            source_node, dest_node = nodes[0], nodes[1]
        edge = self._make_alias_edge(source_node, dest_node)
        self.scene.addItem(edge)
        edge.update_path()
        self._undo_stack.push(AliasEdgeCommand(self.scene, edge, source_node, dest_node))

    def _do_unlink(self, selected_alias, selected_assets) -> None:
        from .commands import DeleteItemsCommand
        edges_to_remove: set = set(selected_alias)
        if not edges_to_remove and len(selected_assets) == 2:
            e = self._alias_edge_between(selected_assets[0], selected_assets[1])
            if e:
                edges_to_remove.add(e)
        if not edges_to_remove:
            return
        self._undo_stack.push(DeleteItemsCommand(self.scene, [], list(edges_to_remove), self.threats, {}))

    def _add_edge(self) -> None:
        from .commands import AddEdgeCommand
        center = self.view.mapToScene(self.view.viewport().rect().center())
        edge = EdgeItem(src_pos=center + QPointF(-80, 0), dst_pos=center + QPointF(80, 0),
                        properties=self._with_type(dict(self._edge_default_props)))
        self.scene.addItem(edge)
        self.scene.clearSelection()
        edge.setSelected(True)
        self._undo_stack.push(AddEdgeCommand(self.scene, edge))

    def _build_property_dock(self) -> None:
        self.prop_editor = PropertyEditor(self)
        self.prop_editor.propertiesChanged.connect(self._on_properties_changed)
        self.prop_editor.edgePropertiesChanged.connect(self._on_edge_properties_changed)
        self.prop_editor.diagramPropertiesChanged.connect(self._on_diagram_properties_changed)
        self.prop_editor.openDiagram.connect(self.navigate_into)
        self.prop_editor.editInterfaceRequested.connect(self._edit_subgraph_interface)
        self.prop_editor.threatAddRequested.connect(self._on_threat_add)
        self.prop_editor.threatEditRequested.connect(self._on_threat_edit)
        self.prop_editor.threatRemoveRequested.connect(self._on_threat_remove)
        self.prop_editor.threatsGenerateRequested.connect(self._on_threats_generate)
        self.prop_editor.threatsUpdateRequested.connect(self._on_edge_threats_update)
        self.prop_editor.threatsDeleteAllRequested.connect(self._on_edge_threats_delete_all)
        self.prop_editor.mitigationCheckRequested.connect(self._on_mitigation_check)
        self.prop_editor.controlAddRequested.connect(self._on_control_add)
        self.prop_editor.controlEditRequested.connect(self._on_control_edit)
        self.prop_editor.controlRemoveRequested.connect(self._on_control_remove)
        self.prop_editor.reviewCommentAdded.connect(self._on_review_comment_added)
        self.prop_editor.reviewStatusToggled.connect(self._on_review_status_toggled)
        self.prop_editor.coverage_fn = self._coverage_scope_for
        self.prop_editor.edge_prop_defs = self._edge_prop_defs
        self.prop_editor.edge_type_categories = self._edge_type_categories
        self.prop_editor.edge_type_types = self._edge_type_types
        self.prop_editor.edge_type_all_types = self._edge_type_all_types
        self.prop_editor.asset_operations = self._asset_operations
        self.prop_editor.asset_types_by_id = self._descriptor_asset_types()
        self.prop_editor.sec_prop_defs_by_class = self._sec_prop_defs_by_class
        self.prop_editor.sequence_registry = self.sequences
        self.prop_editor.hidden_node_props = self._load_property_filter()

        self._prop_dock = QDockWidget("Properties", self)
        self._prop_dock.setWidget(self.prop_editor)
        self._prop_dock.setObjectName("PropertiesDock")
        self._prop_dock.setMinimumWidth(320)
        self.addDockWidget(Qt.RightDockWidgetArea, self._prop_dock)
        self.resizeDocks([self._prop_dock], [360], Qt.Horizontal)

    def _add_node(self, spec: NodeSpec, pos: Optional[QPointF] = None) -> NodeItem:
        from .commands import AddNodeCommand
        node = create_node(spec)
        self.scene.addItem(node)
        center_pos = self.view.mapToScene(self.view.viewport().rect().center())
        node.setPos(pos or center_pos)
        self._undo_stack.push(AddNodeCommand(self.scene, node))
        from .layers import node_layer
        if node_layer(node.properties()) in self._hidden_layers:
            node.setVisible(False)   # dropped onto a layer that is turned off
        return node

    def _do_delete_selected(self) -> None:
        """Delete selected nodes/edges and push an undoable DeleteItemsCommand."""
        from .commands import DeleteItemsCommand
        selected = list(self.scene.selectedItems())
        edges_to_remove: set = set()
        nodes_to_remove: set = set()

        for item in selected:
            if isinstance(item, NodeItem):
                nodes_to_remove.add(item)
            elif isinstance(item, EdgeItem):
                edges_to_remove.add(item)
            elif isinstance(item, LabelItem):
                if item.edge is not None:
                    edges_to_remove.add(item.edge)

        for node in nodes_to_remove:
            for edge in list(node.edges):
                edges_to_remove.add(edge)
            for edge in list(getattr(node, 'alias_edges', [])):
                edges_to_remove.add(edge)

        if not edges_to_remove and not nodes_to_remove:
            return

        # Collect threats that will be removed
        removed_threats = {}
        for edge in edges_to_remove:
            for guid in edge.threat_guids:
                if guid in self.threats:
                    removed_threats[guid] = self.threats[guid]

        cmd = DeleteItemsCommand(
            self.scene,
            list(nodes_to_remove),
            list(edges_to_remove),
            self.threats,
            removed_threats,
        )
        self._undo_stack.push(cmd)

    def _build_sequence_dock(self) -> None:
        from .ui.sequence_panel import SequencePanel
        self.seq_panel = SequencePanel(self.sequences, self)
        self.seq_panel.set_edge_label_fn(self._get_edge_desc)
        self.seq_panel.changed.connect(self._on_sequences_changed)
        self.seq_panel.activeSequenceChanged.connect(self._on_active_sequence_changed)
        self.seq_panel.pickModeChanged.connect(self._on_pick_mode_changed)
        self.seq_panel.stepSelected.connect(self._on_seq_step_selected)
        self.seq_panel.threatsGenerateRequested.connect(self._on_sequence_threats_generate)
        self.seq_panel.threatsUpdateRequested.connect(self._on_sequence_threats_update)
        self.seq_panel.threatsDeleteAllRequested.connect(self._on_sequence_threats_delete_all)
        self.seq_panel.threatAddRequested.connect(self._on_sequence_threat_add)
        self.seq_panel.threatEditRequested.connect(self._on_sequence_threat_edit)
        self.seq_panel.threatRemoveRequested.connect(self._on_sequence_threat_remove)
        self.seq_panel.set_threat_registry(self.threats)
        self.seq_panel.control_names = dict(self._collect_sc_nodes())

        seq_dock = QDockWidget("Sequences", self)
        seq_dock.setWidget(self.seq_panel)
        seq_dock.setObjectName("SequencesDock")
        self.addDockWidget(Qt.RightDockWidgetArea, seq_dock)

        # Group with Properties as tabs; Properties tab shown by default
        self.tabifyDockWidget(self._prop_dock, seq_dock)
        self._prop_dock.raise_()

    def _build_threat_dock(self) -> None:
        from .ui.threat_panel import ThreatPanel
        self.threat_panel = ThreatPanel(self.threats, self)
        self.threat_panel.set_scene(self.scene)
        self.threat_panel.threatEditRequested.connect(self._on_panel_threat_edit)
        self.threat_panel.threatRemoveRequested.connect(self._on_panel_threat_remove)
        self.threat_panel.set_sequence_registry(self.sequences)
        self.threat_panel.threatSelected.connect(
            # Sequence threats carry no edge id — nothing to jump to.
            lambda edge_id: edge_id and self._navigate_to_item(None, edge_id)
        )

        self.threat_panel.set_control_names_provider(self._known_control_names)
        threat_dock = QDockWidget("Threats", self)
        threat_dock.setWidget(self.threat_panel)
        threat_dock.setObjectName("ThreatsDock")
        self.addDockWidget(Qt.RightDockWidgetArea, threat_dock)
        self.tabifyDockWidget(self._prop_dock, threat_dock)
        self._prop_dock.raise_()

    def _build_attack_surface_dock(self) -> None:
        from .ui.attack_surface_panel import AttackSurfacePanel
        self.attack_surface_panel = AttackSurfacePanel(self)
        self.attack_surface_panel.set_scene(self.scene)
        self.attack_surface_panel.set_threats(self.threats)
        self.attack_surface_panel.edgeSelected.connect(
            lambda edge_id: self._navigate_to_item(None, edge_id)
        )
        self._as_dock = QDockWidget("Attack Surface", self)
        self._as_dock.setWidget(self.attack_surface_panel)
        self._as_dock.setObjectName("AttackSurfaceDock")
        self.addDockWidget(Qt.BottomDockWidgetArea, self._as_dock)
        self._as_dock.hide()

    def _build_diagram_dock(self) -> None:
        from .ui.diagram_panel import DiagramPanel
        self._diag_panel = DiagramPanel(self)
        self._diag_panel.diagramActivated.connect(self._switch_diagram)
        self._diag_panel.diagramAdded.connect(self._new_diagram)
        self._diag_panel.diagramDeleted.connect(self._delete_diagram)
        self._diag_panel.diagramRenamed.connect(self._rename_diagram)

        diag_dock = QDockWidget("Diagrams", self)
        diag_dock.setWidget(self._diag_panel)
        diag_dock.setObjectName("DiagramsDock")
        diag_dock.setMinimumWidth(140)
        self.addDockWidget(Qt.LeftDockWidgetArea, diag_dock)

    def _build_settings_dock(self) -> None:
        from .ui.settings_panel import SettingsPanel
        self._settings_panel = SettingsPanel(self)
        self._settings_panel.settingsChanged.connect(self._on_settings_changed)

        settings_dock = QDockWidget("Settings", self)
        settings_dock.setWidget(self._settings_panel)
        settings_dock.setObjectName("SettingsDock")
        self.addDockWidget(Qt.RightDockWidgetArea, settings_dock)
        self.tabifyDockWidget(self._prop_dock, settings_dock)
        self._prop_dock.raise_()

    def _on_settings_changed(self, settings: dict) -> None:
        pass  # future: live-apply model/backend selections

    def _get_edge_desc(self, edge_id: str) -> str:
        for item in self.scene.items():
            if isinstance(item, EdgeItem) and item.edge_id == edge_id:
                src = item.src.parentItem().title if item.src and isinstance(item.src.parentItem(), NodeItem) else "?"
                dst = item.dst.parentItem().title if item.dst and isinstance(item.dst.parentItem(), NodeItem) else "?"
                lbl = item.label.name if item.label else ""
                return f"{src} →[{lbl}]→ {dst}"
        return f"[{edge_id[:8]}…]"

    def _on_sequences_changed(self) -> None:
        self.scene.update()

    def _on_active_sequence_changed(self, seq_id) -> None:
        set_active_sequence(seq_id)
        self.scene.update()

    def _on_pick_mode_changed(self, active: bool) -> None:
        if active:
            self._pick_seq_id = self.seq_panel._active_seq_id
            self.view.setCursor(Qt.CrossCursor)
        else:
            self._pick_seq_id = None
            self.view.unsetCursor()

    def _on_seq_step_selected(self, edge_id: str) -> None:
        for item in self.scene.items():
            if isinstance(item, EdgeItem) and item.edge_id == edge_id:
                self.scene.clearSelection()
                item.setSelected(True)
                break

    def _cancel_pick_mode(self) -> None:
        self._pick_seq_id = None
        self.seq_panel.cancel_pick_mode()
        self.view.unsetCursor()

    def _add_sequence_actions_to_menu(self, menu, edge: EdgeItem) -> None:
        """Append sequence Add/Remove submenus to an existing QMenu for the given edge."""
        from PySide6.QtWidgets import QMenu
        add_menu = menu.addMenu("Add to Sequence")
        for seq_id, seq in self.sequences.items():
            act = QAction(seq.name, self)
            act.triggered.connect(lambda checked=False, sid=seq_id, eid=edge.edge_id: self._seq_add_edge(sid, eid))
            add_menu.addAction(act)
        add_menu.addSeparator()
        new_act = QAction("New Sequence…", self)
        new_act.triggered.connect(lambda: self._seq_add_edge_new(edge.edge_id))
        add_menu.addAction(new_act)

        steps = edge_sequence_steps(self.sequences, edge.edge_id)
        if steps:
            remove_menu = menu.addMenu("Remove from Sequence")
            by_seq: dict = {}
            for sid, idx in steps:
                by_seq.setdefault(sid, []).append(idx)
            for sid, indices in by_seq.items():
                seq = self.sequences.get(sid)
                if seq:
                    label = f"{seq.name} (step {', '.join(str(i) for i in indices)})"
                    act = QAction(label, self)
                    act.triggered.connect(lambda checked=False, sid=sid, eid=edge.edge_id: self._seq_remove_edge(sid, eid))
                    remove_menu.addAction(act)

    def _show_context_menu(self, scene_pos: QPointF, global_pos) -> None:
        from PySide6.QtWidgets import QMenu
        items = self.scene.items(scene_pos)
        clicked_node = next((i for i in items if isinstance(i, NodeItem)), None)
        clicked_edge = next((i for i in items if isinstance(i, EdgeItem)), None)

        # Only change selection when nothing is currently selected
        if not self.scene.selectedItems():
            if clicked_node:
                clicked_node.setSelected(True)
            elif clicked_edge:
                clicked_edge.setSelected(True)

        selected_nodes = [i for i in self.scene.selectedItems() if isinstance(i, NodeItem)]
        selected_items = self.scene.selectedItems()

        menu = QMenu(self)

        act_copy = QAction("Copy", self)
        act_copy.setEnabled(bool(selected_nodes))
        act_copy.triggered.connect(self._copy_selected)
        menu.addAction(act_copy)

        act_paste = QAction("Paste", self)
        act_paste.setEnabled(self._clipboard is not None)
        act_paste.triggered.connect(lambda: self._paste_at(scene_pos))
        menu.addAction(act_paste)

        act_delete = QAction("Delete", self)
        act_delete.setEnabled(bool(selected_items))
        act_delete.triggered.connect(self._do_delete_selected)
        menu.addAction(act_delete)

        menu.addSeparator()

        act_props = QAction("Properties", self)
        act_props.triggered.connect(self._raise_properties_dock)
        menu.addAction(act_props)

        # Link / Unlink for asset nodes
        _asset_classes = {"security asset", "process memory"}
        selected_assets = [n for n in selected_nodes if n.properties().get("class") in _asset_classes]
        selected_alias = [e for e in selected_items if isinstance(e, EdgeItem) and e.properties().get("type") == "alias"]

        can_link = (len(selected_assets) == 2 and
                    not self._alias_edge_between(selected_assets[0], selected_assets[1]))
        can_unlink = bool(selected_alias) or (
            len(selected_assets) == 2 and bool(self._alias_edge_between(selected_assets[0], selected_assets[1]))
        )

        menu.addSeparator()
        act_link = QAction("Link", self)
        act_link.setEnabled(can_link)
        act_link.triggered.connect(lambda: self._do_link(selected_assets))
        menu.addAction(act_link)

        act_unlink = QAction("Unlink", self)
        act_unlink.setEnabled(can_unlink)
        act_unlink.triggered.connect(lambda: self._do_unlink(selected_alias, selected_assets))
        menu.addAction(act_unlink)

        # Add sequence submenu when a non-alias edge is the context target
        edge_target = clicked_edge or (
            selected_items[0] if len(selected_items) == 1 and isinstance(selected_items[0], EdgeItem) else None
        )
        if edge_target and edge_target.properties().get("type") != "alias":
            menu.addSeparator()
            self._add_sequence_actions_to_menu(menu, edge_target)

        # Mitigation coverage for a security control node
        control_target = clicked_node if (
            clicked_node is not None
            and str(clicked_node.properties().get("class", "")).startswith("security control")
        ) else None
        if control_target is None and len(selected_nodes) == 1 and str(
                selected_nodes[0].properties().get("class", "")).startswith("security control"):
            control_target = selected_nodes[0]
        if control_target is not None:
            menu.addSeparator()
            act_cov = QAction("Check Mitigation Coverage…", self)
            act_cov.setToolTip(
                "Assess whether this control mitigates the threats on the "
                "connections it covers"
            )
            act_cov.triggered.connect(
                lambda _=False, n=control_target: self._on_mitigation_check(n)
            )
            menu.addAction(act_cov)

        menu.exec(global_pos)

    def _copy_selected(self) -> None:
        nodes = [i for i in self.scene.selectedItems() if isinstance(i, NodeItem)]
        if not nodes:
            return
        self._sync_active_diagram()  # ensure _project_nodes is current
        data = self._serialize_nodes(nodes)
        data["_source_diag_idx"] = self._active_diag_idx
        data["_node_ids"] = [n.node_id for n in nodes]
        self._clipboard = data

    def _paste_at(self, scene_pos: QPointF) -> None:
        if not self._clipboard:
            return
        source_diag = self._clipboard.get("_source_diag_idx", -1)
        if source_diag == self._active_diag_idx:
            # Same diagram → duplicate with new IDs
            self._deserialize_into_scene(self._clipboard, paste_center=scene_pos)
        else:
            # Different diagram → share the same nodes (same node_ids, new placements)
            self._paste_shared_nodes(self._clipboard, scene_pos)

    def _paste_shared_nodes(self, clipboard: Dict[str, Any], center: QPointF) -> None:
        """Add shared node references to the current diagram at center position."""
        specs = {**builtin_nodes(), **security_nodes()}
        node_ids = clipboard.get("_node_ids", [])

        # Compute centroid of original positions to offset pasted nodes
        positions = [nd.get("pos", [0, 0]) for nd in clipboard.get("nodes", [])
                     if nd.get("id") in node_ids]
        if positions:
            cx = sum(p[0] for p in positions) / len(positions)
            cy = sum(p[1] for p in positions) / len(positions)
            base_offset = center - QPointF(cx, cy)
        else:
            base_offset = QPointF(0.0, 0.0)

        self.scene.clearSelection()
        already_in_scene = {item.node_id for item in self.scene.items() if isinstance(item, NodeItem)}

        for nd in clipboard.get("nodes", []):
            nid = nd.get("id")
            if nid not in node_ids:
                continue
            if nid in already_in_scene:
                # Already placed in this diagram — just select it
                for item in self.scene.items():
                    if isinstance(item, NodeItem) and item.node_id == nid:
                        item.setSelected(True)
                continue

            pn = self._project_nodes.get(nid, nd)
            spec = specs.get(pn.get("type") or nd.get("type", ""))
            if not spec:
                continue

            node = create_node(spec, node_id=nid)
            node.set_properties(dict(pn.get("properties", nd.get("properties", {}))))
            inputs = pn.get("inputs", nd.get("inputs", []))
            outputs = pn.get("outputs", nd.get("outputs", []))
            if inputs or outputs:
                for s in list(node.inputs):
                    node.remove_slot(s)
                for s in list(node.outputs):
                    node.remove_slot(s)
                for entry in inputs:
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "input", properties=sprops)
                for entry in outputs:
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "output", properties=sprops)
            from .graphics.items import ensure_owner_slot
            ensure_owner_slot(node)   # every asset keeps its owner slot

            orig_pos = nd.get("pos", [0, 0])
            node.setPos(QPointF(float(orig_pos[0]), float(orig_pos[1])) + base_offset)
            self.scene.addItem(node)
            node.setSelected(True)
            node._evaluate_parent_id()

    def _raise_properties_dock(self) -> None:
        self._prop_dock.show()
        self._prop_dock.raise_()

    def _seq_add_edge(self, seq_id: str, edge_id: str) -> None:
        if seq_id in self.sequences:
            self.sequences[seq_id].steps.append(edge_id)
            self.seq_panel.refresh()
            self._on_sequences_changed()

    def _seq_add_edge_new(self, edge_id: str) -> None:
        seq = new_sequence(self.sequences)
        seq.steps.append(edge_id)
        self.seq_panel.refresh()
        self._on_sequences_changed()

    def _seq_remove_edge(self, seq_id: str, edge_id: str) -> None:
        if seq_id in self.sequences:
            seq = self.sequences[seq_id]
            seq.steps = [eid for eid in seq.steps if eid != edge_id]
            self.seq_panel.refresh()
            self._on_sequences_changed()

    def _on_selection_changed(self, selected_items: List[QGraphicsItem]):
        self._set_highlighted_slot(None)
        if len(selected_items) == 1:
            item = selected_items[0]
            if isinstance(item, NodeItem):
                self._selected_edge = None
                self.prop_editor.set_node(item)
            elif isinstance(item, LabelItem):
                self._selected_edge = None
                self.prop_editor.set_label(item)
            elif isinstance(item, EdgeItem):
                self._selected_edge = item
                self._refresh_edge_in_prop_editor(item)
            else:
                self._selected_edge = None
                self.prop_editor.set_node(None)
        else:
            self._selected_edge = None
            self._show_diagram_properties()

    def _show_diagram_properties(self) -> None:
        if self._project and 0 <= self._active_diag_idx < len(self._project):
            self.prop_editor.set_diagram(self._project[self._active_diag_idx])
        else:
            self.prop_editor.set_node(None)

    def _on_diagram_properties_changed(self, diag: dict) -> None:
        # diag is the live dict inside _project; name change also updates UI
        if self._project and 0 <= self._active_diag_idx < len(self._project):
            name = diag.get("name", "")
            self._diag_panel.update_name(self._active_diag_idx, name)
            self._update_title()

    def _on_slot_clicked(self, slot) -> None:
        self._set_highlighted_slot(slot)
        self.prop_editor.set_slot(slot)

    def _set_highlighted_slot(self, slot) -> None:
        if self._highlighted_slot is not None and self._highlighted_slot is not slot:
            self._highlighted_slot.set_highlight(False)
        self._highlighted_slot = slot
        if slot is not None:
            slot.set_highlight(True)

    def _on_properties_changed(self, node: NodeItem, new_props: dict):
        if node.scene() is self.scene:
            node.set_properties(new_props)

    def _on_edge_properties_changed(self, edge: EdgeItem, new_props: dict):
        if edge.scene() is self.scene:
            edge.set_properties(self._with_type(new_props))
            self._apply_ownership(edge)

    def _edit_subgraph_interface(self, node: NodeItem) -> None:
        """Open the interface editor for a subgraph placeholder and apply changes."""
        from .subgraph import read_interface
        from .ui.subgraph_dialogs import InterfaceEditorDialog

        dlg = InterfaceEditorDialog(read_interface(node.properties()), parent=self)
        if dlg.exec() != InterfaceEditorDialog.Accepted:
            return
        node.apply_interface(dlg.interface(), dlg.rename_map())
        # Refresh the property panel so the new ports/slots are reflected.
        self.prop_editor.set_node(node)

    # ── threat helpers ────────────────────────────────────────────────────────

    _PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

    def _refresh_edge_in_prop_editor(self, edge: EdgeItem) -> None:
        # edge.threat_guids is a set, so sort for a stable card order — otherwise
        # the cards reshuffle vertically on every rebuild.
        threats = sorted(
            (self.threats[g] for g in edge.threat_guids if g in self.threats),
            key=lambda t: (self._PRIORITY_ORDER.get(t.priority, 3), t.title, t.guid),
        )
        # Refresh the control-id → name map so mitigated threats can name the
        # controls covering them (controls may have been added/renamed since).
        names = dict(self._collect_sc_nodes())
        self.prop_editor.control_names = names
        self.seq_panel.control_names = names
        self.prop_editor.set_edge(edge, threats)

    def _configured_backends(self) -> list:
        """The backends a run should use, from Settings (default: Claude only).

        "rules" means no agent at all — the caller falls back to the local
        rule-based generator.
        """
        from .threat_gen import _backend_names

        panel = getattr(self, "_settings_panel", None)
        choice = panel.get("default_backend", "claude") if panel else "claude"
        if choice == "rules":
            return []
        return _backend_names([choice])

    def _configured_claude_model(self) -> str:
        from .threat_gen import DEFAULT_CLAUDE_MODEL

        panel = getattr(self, "_settings_panel", None)
        return (panel.get("claude_model") if panel else "") or DEFAULT_CLAUDE_MODEL

    def _run_generation_with_progress(self, title: str, label: str, task, total_steps: int = 2):
        """Run an AI-agent task in a worker thread behind a busy dialog.

        The CLI backends block for a minute or more, so the work never runs on
        the GUI thread — the window keeps repainting and shows progress and
        elapsed time while it waits. ``task`` receives a
        ``progress(step, total, text)`` callback.
        """
        from .ui.async_task import run_task_with_progress
        return run_task_with_progress(self, title, label, task, total_steps)

    @staticmethod
    def _format_backend_status_lines(backend_results) -> list[str]:
        lines: list[str] = []
        for item in backend_results:
            if item.error:
                lines.append(f"{item.backend_name}: failed - {item.error}")
            else:
                lines.append(f"{item.backend_name}: {item.threat_count} threat(s)")
        return lines

    def log(self, message: str, level: int = None) -> None:
        """Record a non-blocking notice: status bar + the app log.

        Used where a dialog would interrupt a run for something the user does
        not have to act on — e.g. "no control covers these threats" during an
        update, which is a normal state, not an error.
        """
        import logging

        _LOG.log(level if level is not None else logging.INFO, "%s", message)
        try:
            self.statusBar().showMessage(message, 10000)
        except Exception:
            pass

    def _cancelled_message(self, title: str) -> None:
        """Tell the user the agent was stopped; anything already applied is kept."""
        QMessageBox.information(
            self, title,
            "Cancelled.\n\nThe running agent call was stopped and nothing further "
            "was started. Threats and mitigation links already applied are kept.",
        )

    def _show_selectable_message(self, icon, title: str, text: str) -> None:
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(title)
        box.setText(text)
        box.setTextInteractionFlags(Qt.TextSelectableByMouse)
        box.exec()

    def _collect_sc_nodes(self) -> list:
        """Return [(control id, display name)] for every control in the scene.

        A control container holds several controls, each of which a threat can
        link to on its own, so the unit here is the control definition — the id
        stored in ``Threat.mitigation_sc_ids``.
        """
        from .controls import read_controls

        result = []
        for item in self.scene.items():
            if not isinstance(item, NodeItem):
                continue
            if not str(item.properties().get("class", "")).startswith("security control"):
                continue
            container = str(item.properties().get("name", item.title))
            for c in read_controls(item.properties(), item.node_id):
                label = c.name if c.name == container else f"{container} ▸ {c.name}"
                result.append((c.id, label))
        return sorted(result, key=lambda x: x[1])

    # ── controls inside a container ───────────────────────────────────────────

    def _on_control_add(self, node: NodeItem) -> None:
        from .controls import add_control
        from .ui.control_dialog import ControlDialog

        dlg = ControlDialog(parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        node.set_properties(add_control(node.properties(), dlg.result_control(),
                                        node.node_id))
        self._after_controls_changed(node)

    def _on_control_edit(self, node: NodeItem, control_id: str) -> None:
        from .controls import read_controls, update_control
        from .ui.control_dialog import ControlDialog

        current = next((c for c in read_controls(node.properties(), node.node_id)
                        if c.id == control_id), None)
        if current is None:
            return
        dlg = ControlDialog(control=current, parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        node.set_properties(update_control(node.properties(), dlg.result_control(),
                                           node.node_id))
        self._after_controls_changed(node)

    def _on_control_remove(self, node: NodeItem, control_id: str) -> None:
        from .controls import read_controls, remove_control

        current = next((c for c in read_controls(node.properties(), node.node_id)
                        if c.id == control_id), None)
        if current is None:
            return
        if QMessageBox.question(
            self, "Remove Control",
            f'Remove "{current.name}" from this container?\n\n'
            "Threats linked to it keep the link until you run Update Threats.",
            QMessageBox.Yes | QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        node.set_properties(remove_control(node.properties(), control_id, node.node_id))
        self._after_controls_changed(node)

    def _after_controls_changed(self, node: NodeItem) -> None:
        node.update()
        self.prop_editor.set_node(node)
        self._sync_active_diagram()
        self._refresh_after_mitigation()

    def _on_threat_add(self) -> None:
        edge = self._selected_edge
        if edge is None:
            return
        from .ui.threat_dialogs import ThreatDialog
        dlg = ThreatDialog(parent=self, sc_nodes=self._collect_sc_nodes())
        if dlg.exec() != QDialog.Accepted:
            return
        src_id = edge.src.parentItem().node_id if edge.src and isinstance(edge.src.parentItem(), NodeItem) else ""
        dst_id = edge.dst.parentItem().node_id if edge.dst and isinstance(edge.dst.parentItem(), NodeItem) else ""
        t = dlg.result_threat(source_guid=src_id, dest_guid=dst_id, edge_guid=edge.edge_id)
        self.threats[t.guid] = t
        edge.threat_guids.add(t.guid)
        self._refresh_edge_in_prop_editor(edge)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()

    def _on_threat_edit(self, guid: str) -> None:
        t = self.threats.get(guid)
        edge = self._selected_edge
        if t is None or edge is None:
            return
        from .ui.threat_dialogs import ThreatDialog
        dlg = ThreatDialog(parent=self, threat=t, sc_nodes=self._collect_sc_nodes())
        if dlg.exec() != QDialog.Accepted:
            return
        dlg.apply_to_threat(t)
        self._refresh_edge_in_prop_editor(edge)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()

    def _on_threat_remove(self, guid: str) -> None:
        t = self.threats.get(guid)
        edge = self._selected_edge
        if t is None or edge is None:
            return
        reply = QMessageBox.question(
            self,
            "Delete Threat",
            f"Delete \"{t.title}\"?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self.threats.pop(guid, None)
        edge.threat_guids.discard(guid)
        for seq in self.sequences.values():
            if guid in seq.threat_guids:
                seq.threat_guids.remove(guid)
        self._refresh_edge_in_prop_editor(edge)
        self.seq_panel.refresh_threats()
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()

    # ── sequence-level threats ────────────────────────────────────────────────

    def _on_sequence_threat_add(self, seq_id: str) -> None:
        """Add a threat that belongs to the sequence as a whole (no single edge)."""
        from .ui.threat_dialogs import ThreatDialog
        seq = self.sequences.get(seq_id)
        if seq is None:
            return
        dlg = ThreatDialog(parent=self, sc_nodes=self._collect_sc_nodes())
        if dlg.exec() != QDialog.Accepted:
            return
        src_id, dst_id = self._sequence_end_node_ids(seq)
        t = dlg.result_threat(source_guid=src_id, dest_guid=dst_id, edge_guid="")
        t.sequence_guid = seq_id
        self.threats[t.guid] = t
        seq.threat_guids.append(t.guid)
        self.seq_panel.refresh_threats()
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()

    def _on_sequence_threat_edit(self, guid: str) -> None:
        from .ui.threat_dialogs import ThreatDialog
        t = self.threats.get(guid)
        if t is None:
            return
        dlg = ThreatDialog(parent=self, threat=t, sc_nodes=self._collect_sc_nodes())
        if dlg.exec() != QDialog.Accepted:
            return
        dlg.apply_to_threat(t)
        self.seq_panel.refresh_threats()
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()
        if self._selected_edge is not None:
            self._refresh_edge_in_prop_editor(self._selected_edge)

    def _on_sequence_threat_remove(self, guid: str) -> None:
        t = self.threats.get(guid)
        if t is None:
            return
        if QMessageBox.question(self, "Delete Threat", f'Delete "{t.title}"?',
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self.threats.pop(guid, None)
        for seq in self.sequences.values():
            if guid in seq.threat_guids:
                seq.threat_guids.remove(guid)
        from .graphics.items import EdgeItem
        for item in self.scene.items():
            if isinstance(item, EdgeItem):
                item.threat_guids.discard(guid)
        self.seq_panel.refresh_threats()
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()
        if self._selected_edge is not None:
            self._refresh_edge_in_prop_editor(self._selected_edge)

    def _sequence_end_node_ids(self, seq) -> tuple:
        """(first step's source node id, last step's destination node id)."""
        from .graphics.items import EdgeItem
        edges = {i.edge_id: i for i in self.scene.items() if isinstance(i, EdgeItem)}
        steps = [edges[e] for e in seq.steps if e in edges]
        if not steps:
            return ("", "")

        def _node_id(slot):
            node = slot.parentItem() if slot is not None else None
            return node.node_id if isinstance(node, NodeItem) else ""

        return (_node_id(steps[0].src), _node_id(steps[-1].dst))

    def _on_panel_threat_edit(self, guid: str) -> None:
        t = self.threats.get(guid)
        if t is None:
            return
        from .ui.threat_dialogs import ThreatDialog
        dlg = ThreatDialog(parent=self, threat=t, sc_nodes=self._collect_sc_nodes())
        if dlg.exec() != QDialog.Accepted:
            return
        dlg.apply_to_threat(t)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()
        if self._selected_edge is not None:
            self._refresh_edge_in_prop_editor(self._selected_edge)

    def _on_panel_threat_remove(self, guid: str) -> None:
        t = self.threats.get(guid)
        if t is None:
            return
        reply = QMessageBox.question(
            self, "Delete Threat", f"Delete \"{t.title}\"?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        self.threats.pop(guid, None)
        # Remove from the owning edge
        from .graphics.items import EdgeItem
        for item in self.scene.items():
            if isinstance(item, EdgeItem) and guid in item.threat_guids:
                item.threat_guids.discard(guid)
                if self._selected_edge is item:
                    self._refresh_edge_in_prop_editor(item)
                break
        # …and from any sequence that lists it
        for seq in self.sequences.values():
            if guid in seq.threat_guids:
                seq.threat_guids.remove(guid)
        self.seq_panel.refresh_threats()
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()

    def _on_threats_generate(self, confirm_replace: bool = True) -> None:
        """Generate this connection's threats, replacing whatever it has.

        Generate means "work out this connection's threats from scratch": the
        old set described some earlier version of the connection, so keeping it
        would leave a mixture of two models' findings. Update is the operation
        that preserves threats — see ``_on_edge_threats_update``.

        The replacement happens only once the new threats are accepted, so a
        cancelled run, a failed backend or a rejected review leaves the existing
        threats untouched.
        """
        edge = self._selected_edge
        if edge is None:
            return
        from .threat_gen import (
            build_edge_context, generate_threats_combined_detailed, generate_threats_rules,
            validate_edge_for_generation,
        )
        from .validation import validate_scene
        from .ui.threat_dialogs import ThreatReviewDialog

        # Run full diagram validation and block if this edge has any violations
        edge_issues = [i for i in validate_scene(self.scene, self._edge_type_types)
                       if i.edge_id == edge.edge_id]
        if edge_issues:
            lines = ["This edge has validation violations that must be fixed first:\n"]
            for issue in edge_issues:
                lines.append(f"  [{issue.severity}] {issue.rule}:\n  {issue.message}")
            QMessageBox.warning(self, "Cannot Generate Threats", "\n\n".join(lines))
            return

        error = validate_edge_for_generation(edge, self._edge_type_types)
        if error:
            QMessageBox.warning(self, "Cannot Generate Threats", error)
            return

        ctx = build_edge_context(edge, self.scene, self.threats)
        if ctx is None:
            QMessageBox.warning(self, "Generate Threats", "Edge has no connected nodes.")
            return

        # What this run replaces. Confirmed up front — it is the user's data —
        # but not deleted until the new threats are accepted below.
        existing = {g for g in edge.threat_guids if g in self.threats}
        if existing:
            if confirm_replace and QMessageBox.question(
                self, "Generate Threats",
                f"This connection already has {len(existing)} threat(s).\n\n"
                "Generating replaces them with a fresh analysis of the "
                "connection as it is now. Nothing is deleted unless you accept "
                "the new threats.\n\nTo keep the existing threats and only "
                "re-check their mitigation status, use ↻ Update instead.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
            ) != QMessageBox.Yes:
                return
            # The old threats are on their way out, so the agent must not be
            # told to avoid repeating them — it would omit findings that are
            # about to be deleted.
            ctx.existing_threat_titles = []

        backends = self._configured_backends()
        if backends:
            report = self._run_generation_with_progress(
                "Generate Threats",
                "Preparing AI threat generation...",
                lambda progress: generate_threats_combined_detailed(
                    ctx, claude_model=self._configured_claude_model(),
                    progress_callback=progress, backends=backends),
            )
            if report is None:
                self._cancelled_message("Generate Threats")
                return
            candidates = report.threats
            backend_status_lines = self._format_backend_status_lines(report.backend_results)
            if not candidates and all(item.error for item in report.backend_results):
                QApplication.setOverrideCursor(Qt.WaitCursor)
                candidates = generate_threats_rules(ctx)
                QApplication.restoreOverrideCursor()
                backend_status_lines.append(f"Rule-based: {len(candidates)} threat(s)")
        else:
            # Settings selects the local rules instead of an agent.
            QApplication.setOverrideCursor(Qt.WaitCursor)
            candidates = generate_threats_rules(ctx)
            QApplication.restoreOverrideCursor()
            backend_status_lines = [f"Rule-based: {len(candidates)} threat(s)"]

        if not candidates:
            self._show_selectable_message(
                QMessageBox.Information,
                "Generate Threats",
                "\n".join(["No new threats were generated.", *backend_status_lines]),
            )
            return

        if existing:
            backend_status_lines.append(
                f"Accepting replaces the {len(existing)} existing threat(s) on this "
                "connection.")
        dlg = ThreatReviewDialog(candidates, parent=self, backend_status_lines=backend_status_lines)
        if dlg.exec() != QDialog.Accepted:
            return

        from .threat_sync import context_hash, stamp_context

        accepted = dlg.accepted_threats()
        # Only now, with new threats in hand: swap the old set out.
        replaced = self._delete_threats(existing) if existing else 0

        new_guids = set()
        for t in accepted:
            self.threats[t.guid] = t
            edge.threat_guids.add(t.guid)
            new_guids.add(t.guid)
        # Every threat on this connection now describes the current context.
        stamp_context([self.threats[g] for g in edge.threat_guids if g in self.threats],
                      context_hash(ctx))

        self._refresh_edge_in_prop_editor(edge)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()
        if replaced:
            self.log(f"Generate Threats: replaced {replaced} threat(s) with "
                     f"{len(new_guids)} newly generated one(s).")

        # Generation is only half the loop: go through the security controls and
        # link the ones that mitigate what was just accepted.
        if new_guids:
            self._run_mitigation_pass(new_guids, "Apply Security Controls")

    # ── mitigation coverage ───────────────────────────────────────────────────

    def _coverage_scope_for(self, node: NodeItem):
        """CoverageScope for a security-control node (what its circle covers)."""
        from .mitigation import build_coverage_scope
        return build_coverage_scope(node, self.scene, self.threats, self.sequences)

    def _run_mitigation_pass(self, only_guids: Optional[set] = None,
                             title: str = "Apply Security Controls") -> Optional[int]:
        """Go through every security control and link the threats it mitigates.

        This is the step that follows threat generation: each control's covered
        scope is assessed by the AI agent and the verdicts are reviewed in one
        dialog before anything is linked. ``only_guids`` limits the pass to the
        threats just generated; None assesses every threat in every control's
        scope. Returns the number of threats changed.
        """
        from .mitigation import apply_assessments, assess_scopes, scopes_for_all_controls
        from .ui.mitigation_dialog import MitigationReviewDialog

        # Set when the pass could not assess anything, so the caller can say so
        # in its summary instead of the pass interrupting with a dialog.
        self._last_mitigation_note = ""

        scopes = scopes_for_all_controls(self.scene, self.threats, only_guids,
                                         self.sequences)
        if not scopes:
            # A perfectly normal state — every control may have been moved off
            # the interfaces, or the threats may sit where no control reaches.
            # Not worth a dialog: the caller still prunes the stale links.
            self._last_mitigation_note = (
                "No security control currently covers these threats, so there "
                "was nothing to assess.")
            self.log(f"{title}: {self._last_mitigation_note}")
            # Still a completed check: record that these threats are current
            # under "no control at all", or the next update keeps re-offering it.
            self._stamp_controls_for(only_guids)
            return 0

        results = self._run_generation_with_progress(
            title,
            f"Checking {len(scopes)} security control(s)…",
            lambda progress: assess_scopes(
                scopes, claude_model=self._configured_claude_model(),
                progress_callback=progress,
                backends=self._configured_backends() or ["claude"]),
            len(scopes),
        )
        if results is None:
            self._cancelled_message(title)
            return None

        groups = [(r.scope, r.assessments) for r in results if r.assessments]
        status_lines: list = []
        for r in results:
            name = r.scope.control.name
            if r.used_rules:
                errors = "; ".join(f"{b.backend_name}: {b.error}"
                                   for b in r.backend_results if b.error)
                status_lines.append(f"{name}: rule-based fallback ({errors})")
            else:
                status_lines.append(
                    f"{name}: {len(r.assessments)} verdict(s) from "
                    + ", ".join(b.backend_name for b in r.backend_results if not b.error)
                )

        if not groups:
            self._last_mitigation_note = "No verdicts were produced."
            self.log(f"{title}: {self._last_mitigation_note} "
                     + "; ".join(status_lines))
            self._stamp_controls_for(only_guids)
            return 0

        dlg = MitigationReviewDialog(None, None, parent=self,
                                     backend_status_lines=status_lines, groups=groups)
        if dlg.exec() != QDialog.Accepted:
            return None

        changed = 0
        for scope, accepted in dlg.accepted_by_control():
            changed += apply_assessments(scope.control.node_id, accepted, self.threats)

        # Record the control configuration these verdicts were made under, so a
        # later update knows whether anything moved since.
        self._stamp_controls_for(only_guids)
        self._refresh_after_mitigation()
        return changed

    def _refresh_after_mitigation(self) -> None:
        """Repaint everything that shows mitigation state."""
        if self._selected_edge is not None:
            self._refresh_edge_in_prop_editor(self._selected_edge)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()
        self.scene.update()   # edge mitigation badges

    def update_threats(self, guids: set, title: str) -> None:
        """Re-evaluate existing threats against the security controls as they are now.

        Two halves: drop links the diagram no longer supports (a control was
        deleted, moved off the interface, or the edge rewired) — offline and
        immediate — then re-assess the remaining threats against every control
        that currently covers them, reviewed as usual.
        """
        from .mitigation import prune_stale_links

        if not guids:
            QMessageBox.information(
                self, title,
                "There are no threats here yet.\n\nGenerate threats first, then "
                "update them when the security controls change.",
            )
            return

        removed = prune_stale_links(self.scene, self.threats, self.sequences, guids,
                                    known_names=self._known_control_names())
        if removed:
            self._refresh_after_mitigation()
            self.seq_panel.refresh_threats()

        changed = self._run_mitigation_pass(guids, title)

        lines = [f"{len(guids)} threat(s) checked."]
        if removed:
            lines.append("")
            lines.append(f"Links dropped ({len(removed)}):")
            for link in removed:
                lines.append(f"  • {link.threat_title} — {link.control_name}: {link.reason}")
        else:
            lines.append("No mitigation link had gone stale.")
        if changed:
            lines.append("")
            lines.append(f"{changed} threat(s) updated by the coverage re-assessment.")
        note = getattr(self, "_last_mitigation_note", "")
        if note:
            lines.append("")
            lines.append(note)
        self._show_selectable_message(QMessageBox.Information, title, "\n".join(lines))
        self.seq_panel.refresh_threats()

    def _known_control_names(self) -> dict:
        """{node id: name} for every security control the project knows about.

        Includes controls no longer in the live scene (deleted, or living in
        another diagram), so a dropped link can still name the control.
        """
        from .controls import read_controls

        names: dict = {}
        for nid, nd in self._project_nodes.items():
            props = nd.get("properties", {})
            if not str(props.get("class", "")).startswith("security control"):
                continue
            container = str(props.get("name", ""))
            for c in read_controls(props, nid):
                names[c.id] = c.name if c.name == container else f"{container} ▸ {c.name}"
        names.update(dict(self._collect_sc_nodes()))
        return {k: v for k, v in names.items() if v}

    def _delete_threats(self, guids: set) -> int:
        """Remove threats everywhere they are referenced. Returns how many went.

        A threat is referenced by the registry, by the edge it sits on and by
        any sequence that lists it, so all three have to be cleaned or the
        panels keep showing ghosts.
        """
        from .graphics.items import EdgeItem

        guids = {g for g in guids if g in self.threats}
        if not guids:
            return 0
        for g in guids:
            self.threats.pop(g, None)
        for item in self.scene.items():
            if isinstance(item, EdgeItem):
                item.threat_guids -= guids
        for seq in self.sequences.values():
            seq.threat_guids = [g for g in seq.threat_guids if g not in guids]

        if self._selected_edge is not None:
            self._refresh_edge_in_prop_editor(self._selected_edge)
        self.seq_panel.refresh_threats()
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()
        self.scene.update()          # edge threat/mitigation badges
        self._sync_active_diagram()
        return len(guids)

    def _confirm_delete_threats(self, title: str, what: str, count: int) -> bool:
        if count == 0:
            QMessageBox.information(self, title, f"There are no threats on {what}.")
            return False
        return QMessageBox.question(
            self, title,
            f"Delete all {count} threat(s) on {what}?\n\n"
            "This cannot be undone. Mitigation links and review history for "
            "those threats go with them.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) == QMessageBox.Yes

    def _on_edge_threats_delete_all(self) -> None:
        """Properties panel: delete every threat on the selected connection."""
        edge = self._selected_edge
        if edge is None:
            return
        guids = {g for g in edge.threat_guids if g in self.threats}
        label = str(edge.properties().get("sub-type", "")).strip() or "this connection"
        if not self._confirm_delete_threats("Delete All Threats", f"“{label}”", len(guids)):
            return
        removed = self._delete_threats(guids)
        self._show_selectable_message(
            QMessageBox.Information, "Delete All Threats",
            f"{removed} threat(s) deleted from “{label}”.",
        )

    def _on_sequence_threats_delete_all(self, seq_id: str) -> None:
        """Sequence panel: delete the sequence's threats and its steps' threats."""
        from .graphics.items import EdgeItem

        seq = self.sequences.get(seq_id)
        if seq is None:
            return
        guids = {g for g in seq.threat_guids if g in self.threats}
        step_ids = set(seq.steps)
        for item in self.scene.items():
            if isinstance(item, EdgeItem) and item.edge_id in step_ids:
                guids.update(g for g in item.threat_guids if g in self.threats)
        if not self._confirm_delete_threats(
                "Delete All Threats", f"sequence “{seq.name}” and its steps", len(guids)):
            return
        removed = self._delete_threats(guids)
        self._show_selectable_message(
            QMessageBox.Information, "Delete All Threats",
            f"{removed} threat(s) deleted from “{seq.name}” and its steps.",
        )

    def _edge_scopes(self, edge) -> list:
        """Coverage scopes of the controls that cover this connection."""
        from .mitigation import control_scopes, is_security_control
        from .graphics.items import NodeItem

        scopes = []
        for item in self.scene.items():
            if not isinstance(item, NodeItem) or not is_security_control(item):
                continue
            for scope in control_scopes(item, self.scene, self.threats, self.sequences):
                if any(i.edge_id == edge.edge_id for i in scope.items):
                    scopes.append(scope)
        return scopes

    def _stamp_controls_for(self, guids) -> None:
        """Record, per threat, the control configuration just assessed."""
        from .graphics.items import EdgeItem
        from .threat_sync import controls_hash, stamp_controls

        wanted = set(guids) if guids is not None else set(self.threats)
        for item in self.scene.items():
            if not isinstance(item, EdgeItem):
                continue
            edge_guids = {g for g in item.threat_guids if g in wanted}
            if not edge_guids:
                continue
            value = controls_hash(self._edge_scopes(item))
            stamp_controls([self.threats[g] for g in edge_guids], value)

    def _on_edge_threats_update(self) -> None:
        """Properties panel: bring the selected connection's threats up to date.

        Update never adds or deletes a threat by itself. When the connection is
        unchanged it only re-checks mitigation status against the controls that
        cover it, which is the whole point of having a separate operation from
        Generate. A changed connection is the one case update cannot repair — the
        threats describe a system that no longer exists — so it hands over to
        Generate, which replaces them, and only ever after the user says yes.
        """
        from .threat_gen import build_edge_context
        from .threat_sync import (ACTION_ASSESS, ACTION_GENERATE,
                                  ACTION_NO_THREATS, ACTION_UP_TO_DATE, classify)

        edge = self._selected_edge
        if edge is None:
            return
        title = "Update Threats — Connection"
        guids = {g for g in edge.threat_guids if g in self.threats}
        threats = [self.threats[g] for g in guids]
        ctx = build_edge_context(edge, self.scene, self.threats)
        decision = classify(threats, ctx, self._edge_scopes(edge))
        self.log(f"{title}: {decision.action} — {decision.reason}")

        if decision.action == ACTION_NO_THREATS:
            QMessageBox.information(self, title, decision.reason)
            return

        if decision.action == ACTION_UP_TO_DATE:
            if QMessageBox.question(
                self, title,
                decision.reason + "\n\nRe-check the mitigation status anyway?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            ) != QMessageBox.Yes:
                return
            self.update_threats(guids, title)
            return

        if decision.action == ACTION_GENERATE:
            if QMessageBox.question(
                self, title,
                decision.reason
                + f"\n\nRe-generate threats for the connection as it is now?\n"
                  f"This replaces the {len(guids)} existing threat(s) — they were "
                  "written about the old connection. Nothing is deleted until you "
                  "accept the new ones.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
            ) != QMessageBox.Yes:
                return
            # Generate owns the replacement (and the context stamp); it asks for
            # its own confirmation, which is the same question, so skip that one.
            self._on_threats_generate(confirm_replace=False)
            return

        # ACTION_ASSESS
        self.update_threats(guids, title)

    def _on_sequence_threats_update(self, seq_id: str) -> None:
        """Sequence panel: update this sequence's threats and its steps' threats."""
        from .graphics.items import EdgeItem

        seq = self.sequences.get(seq_id)
        if seq is None:
            return
        guids = {g for g in seq.threat_guids if g in self.threats}
        step_ids = set(seq.steps)
        for item in self.scene.items():
            if isinstance(item, EdgeItem) and item.edge_id in step_ids:
                guids.update(g for g in item.threat_guids if g in self.threats)
        self.update_threats(guids, f"Update Threats — {seq.name}")

    def _on_apply_security_controls(self) -> None:
        """Tools menu: assess every security control against every threat in scope."""
        from .mitigation import prune_stale_links
        removed = prune_stale_links(self.scene, self.threats, self.sequences,
                                    known_names=self._known_control_names())
        if removed:
            self._refresh_after_mitigation()
            self.seq_panel.refresh_threats()

        changed = self._run_mitigation_pass(None, "Apply Security Controls")
        if changed is None:
            if removed:
                self._show_selectable_message(
                    QMessageBox.Information, "Apply Security Controls",
                    "\n".join([f"Links dropped ({len(removed)}):"]
                               + [f"  • {l.threat_title} — {l.control_name}: {l.reason}"
                                  for l in removed]),
                )
            return   # nothing to assess, no verdicts, or the review was cancelled
        note = getattr(self, "_last_mitigation_note", "")
        lines = [f"{changed} threat(s) updated." if changed
                 else (note or "No changes — the verdicts match what is already linked.")]
        if removed:
            lines.append("")
            lines.append(f"Links dropped ({len(removed)}):")
            lines += [f"  • {l.threat_title} — {l.control_name}: {l.reason}" for l in removed]
        self._show_selectable_message(
            QMessageBox.Information, "Apply Security Controls", "\n".join(lines),
        )

    def _on_mitigation_check(self, node: NodeItem) -> None:
        """Check which threats in a security control's scope it mitigates.

        Scope = every threat on the connections attached to the asset interface
        slots the control's circle covers. Each verdict is reviewed by the user
        before it is linked to the threat.
        """
        from .mitigation import apply_assessments, assess_combined_detailed, assess_rules
        from .ui.mitigation_dialog import MitigationReviewDialog

        if node is None or not str(node.properties().get("class", "")).startswith("security control"):
            return

        scope = self._coverage_scope_for(node)
        if not scope.slots:
            QMessageBox.warning(
                self, "Mitigation Coverage",
                f"'{scope.control.name}' does not cover any asset interface.\n\n"
                "Move or resize the control circle so it covers the asset slot(s) "
                "it protects, then run the check again.",
            )
            return
        if not scope.items:
            QMessageBox.information(
                self, "Mitigation Coverage",
                f"'{scope.control.name}' covers {len(scope.slots)} asset interface(s) "
                f"and {scope.edge_count} connection(s), but those connections have "
                "no threats yet.\n\nGenerate threats for them first.",
            )
            return

        run = self._run_generation_with_progress(
            "Mitigation Coverage",
            f"Checking {len(scope.items)} threat(s) against '{scope.control.name}'…",
            lambda progress: assess_combined_detailed(
                scope, claude_model=self._configured_claude_model(),
                progress_callback=progress,
                backends=self._configured_backends() or ["claude"]),
        )
        assessments = run.assessments
        status_lines = [
            f"{r.backend_name}: {r.error}" if r.error
            else f"{r.backend_name}: {r.assessed_count} threat(s) assessed"
            for r in run.backend_results
        ]

        if not assessments:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            assessments = assess_rules(scope)
            QApplication.restoreOverrideCursor()
            status_lines.append(
                f"Rule-based: {len(assessments)} threat(s) assessed"
            )

        if not assessments:
            self._show_selectable_message(
                QMessageBox.Warning, "Mitigation Coverage",
                "\n".join(["No threats could be assessed.", *status_lines]),
            )
            return

        dlg = MitigationReviewDialog(scope, assessments, parent=self,
                                     backend_status_lines=status_lines)
        if dlg.exec() != QDialog.Accepted:
            return

        accepted = dlg.accepted_assessments()
        changed = apply_assessments(scope.control.node_id, accepted, self.threats)
        self._refresh_after_mitigation()

        mitigated = sum(1 for a in accepted if a.mitigated)
        self._show_selectable_message(
            QMessageBox.Information, "Mitigation Coverage",
            f"'{scope.control.name}' now mitigates {mitigated} of "
            f"{len(accepted)} threat(s) in scope ({changed} threat(s) updated).",
        )

    def _on_threats_generate_all(self) -> None:
        self._on_generate_threats_all_edges("all")

    def _on_generate_threats_all_edges(self, backend: str) -> None:
        result = self.generate_threats_all_edges(backend, show_progress=True)
        icon = QMessageBox.Warning if result["skipped_validation"] else QMessageBox.Information
        self._show_selectable_message(icon, result["win_title"], "\n".join(result["lines"]))

    def generate_threats_all_edges(self, backend: str, show_progress: bool = True) -> dict:
        """Generate threats for every eligible edge using the specified backend.

        backend: "claude" | "codex" | "rules" | "all"

        Returns a summary dict with keys: win_title, total_added, backend_summary,
        skipped_no_boundary (list), skipped_validation (list), lines (formatted report).
        Does not show any dialogs; callers are responsible for presenting the result
        (see _on_generate_threats_all_edges for the interactive/GUI presentation).
        """
        from .graphics.items import EdgeItem
        from .threat_gen import (
            build_edge_context, generate_threats, generate_threats_codex,
            generate_threats_combined_detailed, generate_threats_rules,
            validate_edge_for_generation,
        )
        from .validation import validate_scene

        _LABELS = {
            "claude": "Claude",
            "codex":  "Codex",
            "rules":  "Local Template Rules",
            "all":    "All Backends",
        }
        label = _LABELS.get(backend, backend)
        win_title = f"Generate Threats — {label}"

        edges = [i for i in self.scene.items() if isinstance(i, EdgeItem)]
        if not edges:
            return {
                "win_title": win_title, "total_added": 0, "backend_summary": {},
                "skipped_no_boundary": [], "skipped_validation": [],
                "lines": ["No edges in diagram."],
            }

        all_issues = validate_scene(self.scene, self._edge_type_types)
        issues_by_edge: dict = {}
        for issue in all_issues:
            if issue.edge_id:
                issues_by_edge.setdefault(issue.edge_id, []).append(issue)

        skipped_validation: list = []
        skipped_no_boundary: list = []
        total_added = 0
        backend_summary: dict[str, dict] = {}

        # ── phase 1 (GUI thread): pick eligible edges and build their contexts ─
        # Everything that touches scene items happens here; the worker below
        # only ever sees the plain-data EdgeContexts.
        jobs: list = []          # [(edge, ctx, edge_label)]
        for edge in edges:
            if issues_by_edge.get(edge.edge_id):
                skipped_validation.append(edge)
                continue
            if validate_edge_for_generation(edge, self._edge_type_types) is not None:
                skipped_no_boundary.append(edge)
                continue
            ctx = build_edge_context(edge, self.scene, self.threats)
            if ctx is None:
                skipped_no_boundary.append(edge)
                continue
            jobs.append((edge, ctx, edge.properties().get("type", "") or edge.edge_id))

        _rules_file = getattr(self, "_settings_panel", None) and self._settings_panel.get("threat_rules_file") or None

        # ── phase 2 (worker thread): run the backends for every job ───────────
        # "all" uses 2 progress steps per edge (claude + codex); others use 1
        steps_per_edge = 2 if backend == "all" else 1
        total_steps = max(1, len(jobs) * steps_per_edge)

        # Filled as each edge finishes, so a cancelled run keeps what it already
        # generated instead of throwing the whole batch away.
        done_jobs: list = []

        model = self._configured_claude_model()

        def _one_edge(ji: int, ctx, edge_label: str) -> tuple:
            """Generate for a single connection. Returns (ji, candidates, deltas)."""
            from . import cancel

            candidates: list = []
            deltas: list = []
            try:
                if backend == "claude":
                    candidates = generate_threats(ctx, model)
                    for t in candidates:
                        t.ai_backends = ["Claude CLI"]
                    deltas.append(("Claude CLI", len(candidates), 0))

                elif backend == "codex":
                    candidates = generate_threats_codex(ctx)
                    for t in candidates:
                        t.ai_backends = ["Codex CLI"]
                    deltas.append(("Codex CLI", len(candidates), 0))

                elif backend == "rules":
                    candidates = generate_threats_rules(ctx, rules_path=_rules_file or None)
                    deltas.append(("Rule-based", len(candidates), 0))

                else:  # "all"
                    report = generate_threats_combined_detailed(ctx, claude_model=model)
                    candidates = report.threats
                    for item in report.backend_results:
                        deltas.append((item.backend_name, item.threat_count,
                                       1 if item.error else 0))

                    if not candidates and all(r.error for r in report.backend_results):
                        candidates = generate_threats_rules(ctx, rules_path=_rules_file or None)
                        deltas.append(("Rule-based", len(candidates), 0))

            except cancel.CancelledError:
                raise                   # the user stopped; not a backend failure
            except Exception:
                bname = {"claude": "Claude CLI", "codex": "Codex CLI"}.get(backend, backend)
                deltas.append((bname, 0, 1))

            return (ji, candidates, deltas)

        def _work(progress) -> list:
            """Returns [(job_index, candidates, [(backend name, threats, failures)])].

            Connections are independent, so they are generated concurrently
            (bounded by parallel.MAX_PARALLEL_CALLS): a 12-connection model no
            longer takes twelve agent calls end to end. Progress counts
            completions, since there is no single "current" connection any more.
            Each result is recorded as it lands, so a cancelled run keeps the
            connections that finished.
            """
            from .parallel import MAX_PARALLEL_CALLS, run_parallel

            out = done_jobs
            done = 0

            def _tick() -> None:
                nonlocal done
                done += 1
                progress(done * steps_per_edge, total_steps,
                         f"{done} of {len(jobs)} connection(s) done…")

            def _job(ji: int, ctx, edge_label: str):
                result = _one_edge(ji, ctx, edge_label)
                out.append(result)      # append is atomic; order is restored below
                return result

            progress(0, total_steps, f"Generating for {len(jobs)} connection(s)…")
            run_parallel(
                [partial(_job, ji, ctx, label)
                 for ji, (_edge, ctx, label) in enumerate(jobs)],
                MAX_PARALLEL_CALLS, on_done=_tick,
            )
            return sorted(out, key=lambda r: r[0])

        if jobs:
            if show_progress:
                results = self._run_generation_with_progress(
                    win_title, f"Preparing ({label})…", _work, total_steps
                )
                cancelled = results is None
                if cancelled:            # keep the edges that finished before the stop
                    results = list(done_jobs)
            else:
                results = _work(lambda *_args: None)
                cancelled = False
        else:
            results = []
            cancelled = False

        # ── phase 3 (GUI thread): apply the generated threats ─────────────────
        new_guids: set = set()
        for ji, candidates, deltas in results:
            edge = jobs[ji][0]
            for bname, n_threats, n_failures in deltas:
                entry = backend_summary.setdefault(bname, {"threats": 0, "failures": 0})
                entry["threats"] += n_threats
                entry["failures"] += n_failures
            for t in candidates:
                self.threats[t.guid] = t
                edge.threat_guids.add(t.guid)
                new_guids.add(t.guid)
                total_added += 1

        if self._selected_edge is not None:
            self._refresh_edge_in_prop_editor(self._selected_edge)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()

        # Second half of the loop: run every security control against the
        # threats just generated. Interactive runs only — the headless path
        # (show_progress=False) stays a pure generation call.
        mitigated_changed = 0
        if new_guids and show_progress:
            mitigated_changed = self._run_mitigation_pass(new_guids, "Apply Security Controls")

        lines = [f"Threats generated: {total_added}"]
        if cancelled:
            lines.insert(0, f"Cancelled after {len(results)} of {len(jobs)} connection(s).")
        if mitigated_changed:
            lines.append(f"Mitigated by security controls: {mitigated_changed}")
        for bname, data in backend_summary.items():
            line = f"{bname}: {data['threats']} threat(s)"
            if data.get("failures"):
                line += f", {data['failures']} failure(s)"
            lines.append(line)
        if skipped_no_boundary:
            lines.append(f"Skipped (no trust boundary / non-flow): {len(skipped_no_boundary)}")
        if skipped_validation:
            lines.append(f"\nSkipped — validation violations ({len(skipped_validation)} edge(s)):")
            for edge in skipped_validation:
                for issue in issues_by_edge.get(edge.edge_id, []):
                    lines.append(f"  [{issue.severity}] {issue.rule}: {issue.message}")

        return {
            "win_title": win_title, "total_added": total_added,
            "backend_summary": backend_summary,
            "skipped_no_boundary": skipped_no_boundary,
            "skipped_validation": skipped_validation,
            "lines": lines,
        }

    def _on_sequence_threats_generate(self, seq_id: str, seq_name: str, edge_ids: list) -> None:
        """Generate this sequence's threats, replacing the ones it produced before.

        Same rule as a connection: generate re-derives the whole flow's threats,
        so the previous run's findings go. "Previous run's findings" is exact —
        the threats stamped with this sequence's guid, whether they ended up on
        the sequence or pinned to one of its steps. Threats generated per
        connection are not touched, and nothing is deleted until the new set is
        accepted.
        """
        from .threat_gen import build_sequence_context, generate_threats_for_sequence_combined_detailed

        if not edge_ids:
            QMessageBox.information(self, "Generate Sequence Threats", "Sequence has no steps.")
            return

        seq = self.sequences.get(seq_id)
        existing = {g for g, t in self.threats.items() if t.sequence_guid == seq_id}
        if existing:
            if QMessageBox.question(
                self, "Generate Sequence Threats",
                f"“{seq_name}” already has {len(existing)} threat(s) from an earlier "
                "run.\n\nGenerating replaces them with a fresh analysis of the flow "
                "as it is now. Nothing is deleted unless you accept the new threats."
                "\n\nTo keep them and only re-check their mitigation status, use "
                "↻ Update Threats instead.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes,
            ) != QMessageBox.Yes:
                return

        seq_ctx = build_sequence_context(
            seq_id, seq_name, edge_ids, self.scene, self.threats,
            step_props=list(seq.step_props) if seq is not None else None,
            sequence_threat_guids=list(seq.threat_guids) if seq is not None else None,
        )
        if existing:
            # Threats about to be replaced must not appear in the prompt's
            # "already identified" list — the agent would leave them out, and
            # they are on their way to being deleted. Threats generated per
            # connection stay in the list: those survive this run.
            doomed = {self.threats[g].title for g in existing if g in self.threats}
            seq_ctx.existing_threat_titles = [
                t for t in seq_ctx.existing_threat_titles if t not in doomed]
            seq_ctx.existing_sequence_threat_titles = [
                t for t in seq_ctx.existing_sequence_threat_titles if t not in doomed]

        if not seq_ctx.steps:
            QMessageBox.warning(
                self, "Generate Sequence Threats",
                "No eligible steps found (edges may not cross a trust boundary or have validation errors)."
            )
            return

        report = self._run_generation_with_progress(
                "Generate Sequence Threats",
                "Preparing AI threat generation...",
                lambda progress: generate_threats_for_sequence_combined_detailed(
                    seq_ctx, claude_model=self._configured_claude_model(),
                    progress_callback=progress,
                    backends=self._configured_backends() or ["claude"],
                ),
            )
        if report is None:
            self._cancelled_message("Generate Sequence Threats")
            return
        candidates = report.threats
        backend_status_lines = self._format_backend_status_lines(report.backend_results)

        if not candidates:
            self._show_selectable_message(
                QMessageBox.Information,
                "Generate Sequence Threats",
                "\n".join(["No new threats were generated.", *backend_status_lines]),
            )
            return

        # Map edge_id → EdgeItem so we can attach threat_guids
        from .graphics.items import EdgeItem
        edge_item_map: dict = {
            item.edge_id: item
            for item in self.scene.items()
            if isinstance(item, EdgeItem)
        }

        # New threats are in hand and accepted: swap the previous run's set out.
        replaced = self._delete_threats(existing) if existing else 0
        if replaced:
            self.log(f"Generate Sequence Threats: replaced {replaced} threat(s) "
                     f"from an earlier run of “{seq_name}”.")

        new_guids = set()
        for t in candidates:
            self.threats[t.guid] = t
            # Step-pinned threats also belong to their edge; sequence-wide ones
            # (edge_guid == "") are owned by the sequence alone.
            edge = edge_item_map.get(t.edge_guid) if t.edge_guid else None
            if edge is not None:
                edge.threat_guids.add(t.guid)
            if seq is not None and t.guid not in seq.threat_guids:
                seq.threat_guids.append(t.guid)
            new_guids.add(t.guid)
        self.seq_panel.refresh_threats()

        if self._selected_edge is not None:
            self._refresh_edge_in_prop_editor(self._selected_edge)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()

        # Then go through the security controls for the threats just generated.
        mitigated_changed = self._run_mitigation_pass(new_guids, "Apply Security Controls")

        skipped = len(edge_ids) - len(seq_ctx.steps)
        seq_wide = sum(1 for t in candidates if not t.edge_guid)
        lines = [
            f"Threats generated: {len(candidates)} "
            f"({seq_wide} on the sequence, {len(candidates) - seq_wide} on individual steps)",
            *backend_status_lines,
        ]
        if mitigated_changed:
            lines.append(f"Mitigated by security controls: {mitigated_changed}")
        if skipped:
            lines.append(f"Steps skipped (ineligible): {skipped}")
        self._show_selectable_message(QMessageBox.Information, "Generate Sequence Threats", "\n".join(lines))

    # File operations
    # ── project helpers ───────────────────────────────────────────────────────

    def _init_empty_project(self) -> None:
        """Reset to a fresh single-diagram project."""
        import uuid
        self._project_nodes = {}
        diag = {"id": str(uuid.uuid4()), "name": "Diagram 1",
                "description": "", "source-root": "",
                "placements": [], "edges": [], "threats": {}, "sequences": {}}
        self._project = [diag]
        self._active_diag_idx = 0
        self._current_file = None
        self._deserialize_scene(diag)
        self._diag_panel.set_project(self._project, 0)
        self._update_title()

    def _sync_active_diagram(self) -> None:
        """Flush the live scene into _project[_active_diag_idx] and update _project_nodes."""
        if not self._project or not (0 <= self._active_diag_idx < len(self._project)):
            return
        diag = self._project[self._active_diag_idx]
        placements = []
        edges_data = []
        seen_edges: set = set()

        nodes = [item for item in self.scene.items() if isinstance(item, NodeItem)]
        for node in nodes:
            pos = node.scenePos()
            props = node.properties()
            props["width"] = node._width
            props["height"] = node._height
            # Update the shared node registry
            self._project_nodes[node.node_id] = {
                "type": node.shape_kind,
                "properties": dict(props),
                "inputs": [{"name": s.name, "properties": s.properties()} for s in node.inputs],
                "outputs": [{"name": s.name, "properties": s.properties()} for s in node.outputs],
                "inputs_sealed": node.inputs_sealed,
                "outputs_sealed": node.outputs_sealed,
            }
            placements.append({"node_id": node.node_id, "pos": [pos.x(), pos.y()]})

        for node in nodes:
            for e in getattr(node, "edges", []):
                if id(e) in seen_edges:
                    continue
                seen_edges.add(id(e))
                if e.src is None or e.dst is None:
                    continue
                src_node = e.src.parentItem()
                dst_node = e.dst.parentItem()
                if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
                    continue
                lbl_data: dict = {"text": "", "user_positioned": False, "midpoint_offset": None}
                if hasattr(e, "label") and e.label is not None:
                    lbl_data["text"] = e.label.name
                    lbl_data["user_positioned"] = e.label.user_positioned
                    if e.label.user_positioned:
                        mo = e.label._midpoint_offset
                        lbl_data["midpoint_offset"] = [mo.x(), mo.y()]
                edge_dict = {
                    "id": e.edge_id,
                    "from": {"node": src_node.node_id, "slot": e.src.name},
                    "to": {"node": dst_node.node_id, "slot": e.dst.name},
                    "label": lbl_data,
                    "threat_guids": list(e.threat_guids),
                    "properties": e.properties(),
                }
                if getattr(e, "_ortho_manual", False) and e.ortho_waypoints:
                    edge_dict["waypoints"] = [[p.x(), p.y()] for p in e.ortho_waypoints]
                edges_data.append(edge_dict)

        # Also serialize alias edges
        for node in nodes:
            for e in getattr(node, 'alias_edges', []):
                if id(e) in seen_edges:
                    continue
                seen_edges.add(id(e))
                if e.source_node is None or e.dest_node is None:
                    continue
                edges_data.append({
                    "id": e.edge_id,
                    "alias": True,
                    "source_node": e.source_node.node_id,
                    "dest_node": e.dest_node.node_id,
                    "properties": e.properties(),
                })

        diag["placements"] = placements
        diag["edges"] = edges_data
        diag["threats"] = {guid: t.to_dict() for guid, t in self.threats.items()}
        diag["sequences"] = {sid: seq.to_dict() for sid, seq in self.sequences.items()}

    def _serialize_project(self) -> Dict[str, Any]:
        """Sync active diagram then return the full project dict.

        Node properties are written with shape keys nested under a 'shape' block.
        """
        self._sync_active_diagram()
        nodes_out: Dict[str, Any] = {}
        for nid, nd in self._project_nodes.items():
            nd_out = dict(nd)
            nd_out["properties"] = _pack_shape(nd.get("properties", {}))
            nodes_out[nid] = nd_out
        return {
            "version": 2,
            "nodes": nodes_out,
            "diagrams": list(self._project),
            "hidden-layers": sorted(self._hidden_layers),
        }

    def _shape_defaults_for(self, node_type: str) -> dict:
        """Return the default shape-property values for a node type (from its template)."""
        if not hasattr(self, "_shape_defaults_cache"):
            from .nodes import builtin_nodes, security_nodes
            specs = {**builtin_nodes(), **security_nodes()}
            self._shape_defaults_cache: dict = {}
            for spec in specs.values():
                defaults = dict(spec.default_properties)
                self._shape_defaults_cache[spec.shape_kind] = {
                    k: v for k, v in defaults.items() if k in SHAPE_KEYS
                }
        return self._shape_defaults_cache.get(node_type, {})

    def _load_project(self, data: Dict[str, Any]) -> None:
        """Populate _project from a project dict (v2) or a legacy single-diagram dict (v1).

        Node properties may store shape keys nested under a 'shape' block; these
        are flattened back into the in-memory registry, filling any missing shape
        key from the node type's template defaults.
        """
        import uuid

        def _reg_entry(nd: dict) -> dict:
            node_type = nd.get("type")
            return {
                "type": node_type,
                "properties": _unpack_shape(
                    nd.get("properties", {}), self._shape_defaults_for(node_type)
                ),
                "inputs": nd.get("inputs", []),
                "outputs": nd.get("outputs", []),
                **({"inputs_sealed": nd["inputs_sealed"]} if "inputs_sealed" in nd else {}),
                **({"outputs_sealed": nd["outputs_sealed"]} if "outputs_sealed" in nd else {}),
            }

        # Which layers were turned off when the project was saved
        self._hidden_layers = {
            str(l).strip().lower() for l in data.get("hidden-layers", []) if str(l).strip()
        }

        # Load shared node registry (v2 format stores it as a dict)
        raw_nodes = data.get("nodes", {})
        if isinstance(raw_nodes, dict):
            self._project_nodes = {nid: _reg_entry(nd) for nid, nd in raw_nodes.items()}
        else:
            # v1: nodes is a list — build registry from it
            self._project_nodes = {}
            for nd in raw_nodes:
                nid = nd.get("id")
                if nid:
                    self._project_nodes[nid] = _reg_entry(nd)

        if "diagrams" in data:
            diagrams = list(data["diagrams"])
            for d in diagrams:
                d.setdefault("id", str(uuid.uuid4()))
                d.setdefault("name", "Untitled")
                d.setdefault("description", "")
                d.setdefault("source-root", "")
                # Migrate old inline-nodes diagrams to placements format
                if "nodes" in d and "placements" not in d:
                    placements = []
                    for nd in d["nodes"]:
                        nid = nd.get("id")
                        if not nid:
                            continue
                        if nid not in self._project_nodes:
                            self._project_nodes[nid] = _reg_entry(nd)
                        placements.append({"node_id": nid, "pos": nd.get("pos", [0, 0])})
                    d["placements"] = placements
                    del d["nodes"]
        else:
            # v1 single-diagram — wrap it, convert nodes list to placements
            placements = []
            for nd in (raw_nodes if isinstance(raw_nodes, list) else []):
                nid = nd.get("id")
                if nid:
                    placements.append({"node_id": nid, "pos": nd.get("pos", [0, 0])})
            diag = {
                "id": str(uuid.uuid4()),
                "name": "Main",
                "placements": placements,
                "edges": data.get("edges", []),
                "threats": data.get("threats", {}),
                "sequences": data.get("sequences", {}),
            }
            diagrams = [diag]

        if not diagrams:
            diagrams = [{"id": str(uuid.uuid4()), "name": "Diagram 1",
                         "description": "", "source-root": "",
                         "placements": [], "edges": [], "threats": {}, "sequences": {}}]

        self._project = diagrams
        self._active_diag_idx = 0
        self._deserialize_scene(self._project[0])
        self._diag_panel.set_project(self._project, 0)

    def _update_title(self) -> None:
        diag_name = self._project[self._active_diag_idx]["name"] if self._project else ""
        file_part = Path(self._current_file).name if self._current_file else "Untitled"
        name = f"{file_part} — {diag_name}" if diag_name else file_part
        self.setWindowTitle(f"{name} — {APP_NAME}")

    # ── diagram management ────────────────────────────────────────────────────

    def _switch_diagram(self, idx: int) -> None:
        if idx == self._active_diag_idx or not (0 <= idx < len(self._project)):
            return
        self._navigate_to_depth(0)
        self._sync_active_diagram()
        self._active_diag_idx = idx
        self._deserialize_scene(self._project[idx])
        self._diag_panel.set_active(idx)
        self._update_title()

    def _new_diagram(self) -> None:
        import uuid
        self._navigate_to_depth(0)
        self._sync_active_diagram()
        n = len(self._project) + 1
        diag = {"id": str(uuid.uuid4()), "name": f"Diagram {n}",
                "description": "", "source-root": "",
                "nodes": [], "edges": [], "threats": {}, "sequences": {}}
        self._project.append(diag)
        new_idx = len(self._project) - 1
        self._active_diag_idx = new_idx
        self._deserialize_scene(diag)
        self._diag_panel.set_project(self._project, new_idx)
        self._update_title()

    def _delete_diagram(self, idx: int) -> None:
        if len(self._project) <= 1:
            QMessageBox.information(self, "Delete Diagram",
                                    "A project must have at least one diagram.")
            return
        self._navigate_to_depth(0)
        self._project.pop(idx)
        new_idx = min(idx, len(self._project) - 1)
        self._active_diag_idx = new_idx
        self._deserialize_scene(self._project[new_idx])
        self._diag_panel.set_project(self._project, new_idx)
        self._update_title()

    def _rename_diagram(self, idx: int, name: str) -> None:
        if 0 <= idx < len(self._project):
            self._project[idx]["name"] = name
        if idx == self._active_diag_idx:
            self._update_title()

    # ── file operations ───────────────────────────────────────────────────────

    def _file_new(self):
        self._navigate_to_depth(0)
        self._init_empty_project()

    def _file_open(self):
        self._navigate_to_depth(0)
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Project", "",
            "All Supported (*.json *.tm7);;JSON Files (*.json);;TM7 Files (*.tm7)",
        )
        if not path:
            return
        if path.lower().endswith(".tm7"):
            self._open_tm7(path)
        else:
            try:
                self.open_project(path)
            except Exception as e:
                QMessageBox.critical(self, "Open Failed", str(e))

    def open_project(self, path: str) -> None:
        """Load a project file (.json or .tm7) from disk, synchronously.

        Used by automation commands. GUI file-open uses the threaded/progress
        version (_open_tm7) for .tm7 files instead, for UI responsiveness.
        Raises on failure.
        """
        if path.lower().endswith(".tm7"):
            data = self._convert_tm7_sync(path)
            self._load_project(data)
            self._current_file = None
        else:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._load_project(data)
            self._current_file = path
        self._update_title()

    def _convert_tm7_sync(self, path: str) -> dict:
        """Convert a .tm7 file to a project dict synchronously (no thread/progress dialog)."""
        import importlib.util as _ilu

        _conv_path = Path(__file__).parent.parent / "tm7" / "tm7_convert.py"
        _spec = _ilu.spec_from_file_location("tm7_convert", _conv_path)
        _mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_mod)

        tm7_p = Path(path)
        tb7_candidates = list(tm7_p.parent.glob("*.tb7"))
        bundled = Path(__file__).parent.parent / "tm7" / "template.tb7"
        tb7_path = str(tb7_candidates[0]) if tb7_candidates else (
            str(bundled) if bundled.exists() else None
        )

        et_map: dict = {}
        if tb7_path:
            tpl = _mod.parse_template(tb7_path)
            et_map = tpl["element_types"]

        tm7_data = _mod.parse_tm7(path, et_map)
        return _mod.build_project_json(tm7_data)

    def _open_tm7(self, path: str) -> None:
        """Convert a .tm7 file and load the result, showing a progress dialog."""
        dlg = QProgressDialog("Preparing…", None, 0, 100, self)
        dlg.setWindowTitle("Importing TM7")
        dlg.setWindowModality(Qt.WindowModal)
        dlg.setMinimumDuration(0)
        dlg.setAutoClose(False)
        dlg.setAutoReset(False)
        dlg.setValue(0)

        self._tm7_thread = _Tm7ConvertThread(path, parent=self)

        def _on_progress(val: int, msg: str) -> None:
            dlg.setLabelText(msg)
            dlg.setValue(val)

        def _on_converted(data: dict) -> None:
            dlg.close()
            try:
                self._load_project(data)
                # Imported — no JSON file yet; leave _current_file as None
                self._current_file = None
                self._update_title()
                n_diag = len(data.get("diagrams", []))
                n_nodes = len(data.get("nodes", {}))
                QMessageBox.information(
                    self, "TM7 Imported",
                    f"Imported {Path(path).name}\n"
                    f"{n_nodes} nodes, {n_diag} diagram(s).\n\n"
                    "Use File → Save to store as a JSON project.",
                )
            except Exception as exc:
                QMessageBox.critical(self, "Load Failed", str(exc))

        def _on_failed(msg: str) -> None:
            dlg.close()
            QMessageBox.critical(self, "TM7 Import Failed", msg)

        self._tm7_thread.progress.connect(_on_progress)
        self._tm7_thread.converted.connect(_on_converted)
        self._tm7_thread.failed.connect(_on_failed)
        self._tm7_thread.finished.connect(self._tm7_thread.deleteLater)
        self._tm7_thread.start()

    def _file_save(self):
        default = self._current_file or "project.json"
        path, _ = QFileDialog.getSaveFileName(self, "Save Project", default, "JSON Files (*.json)")
        if not path:
            return
        try:
            self.save_project(path)
        except Exception as e:
            QMessageBox.critical(self, "Save Failed", str(e))

    def _file_save_current(self):
        try:
            self.save_project()
        except _NoCurrentFileError:
            self._file_save()
        except Exception as e:
            QMessageBox.critical(self, "Save Failed", str(e))

    def save_project(self, path: Optional[str] = None) -> None:
        """Save the project to `path`, or to the current file if path is None.

        Raises _NoCurrentFileError if path is None and no file has been
        opened/saved yet; raises other exceptions on I/O failure.
        """
        target = path or self._current_file
        if not target:
            raise _NoCurrentFileError("No file path given and no current file is set.")
        data = self._serialize_project()
        with open(target, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        self._current_file = target
        self._update_title()

    def _export_selection(self):
        selected_nodes: List[NodeItem] = [
            item for item in self.scene.selectedItems() if isinstance(item, NodeItem)
        ]
        if not selected_nodes:
            QMessageBox.information(self, "Export Selection", "No nodes selected.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Selection", "selection.json", "JSON Files (*.json)")
        if not path:
            return
        try:
            self.export_selection_to(path, selected_nodes)
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def export_selection_to(self, path: str, nodes: Optional[List[NodeItem]] = None) -> None:
        """Export the given nodes (default: current scene selection) to a JSON file.

        Raises ValueError if no nodes are given/selected, or on I/O failure.
        """
        if nodes is None:
            nodes = [item for item in self.scene.selectedItems() if isinstance(item, NodeItem)]
        if not nodes:
            raise ValueError("No nodes selected.")
        data = self._serialize_nodes(nodes)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _export_threats_csv(self) -> None:
        """Export all threats across all diagrams to a CSV file."""
        if not self.threats:
            QMessageBox.information(self, "Export Threats", "No threats to export.")
            return
        default_name = ""
        if self._current_file:
            default_name = str(Path(self._current_file).with_suffix(".csv"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Threats to CSV", default_name, "CSV Files (*.csv)"
        )
        if not path:
            return
        try:
            self.export_threats_csv_to(path)
            QMessageBox.information(
                self, "Export Threats",
                f"Exported {len(self.threats)} threat(s) to:\n{path}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def export_threats_csv_to(self, path: str) -> None:
        """Write all threats across all diagrams to a CSV file. Raises on failure."""
        import csv

        # Build a node-id → name lookup from _project_nodes
        node_names: Dict[str, str] = {}
        for nid, nd in self._project_nodes.items():
            props = nd.get("properties", {})
            node_names[nid] = str(props.get("name", nid))

        # Also check live scene nodes (covers unsaved edits)
        for item in self.scene.items():
            if isinstance(item, NodeItem):
                node_names[item.node_id] = str(item.properties().get("name", item.title))

        # Build edge-id → label lookup from live scene
        edge_labels: Dict[str, str] = {}
        for item in self.scene.items():
            if isinstance(item, EdgeItem):
                src = item.src.parentItem() if item.src else None
                dst = item.dst.parentItem() if item.dst else None
                src_name = node_names.get(src.node_id, "?") if isinstance(src, NodeItem) else "?"
                dst_name = node_names.get(dst.node_id, "?") if isinstance(dst, NodeItem) else "?"
                edge_labels[item.edge_id] = f"{src_name} → {dst_name}"

        columns = ["title", "category", "priority", "status", "ai_backends",
                   "edge", "source", "destination",
                   "description", "mitigations"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=columns)
            writer.writeheader()
            for threat in sorted(
                self.threats.values(),
                key=lambda t: ({"High": 0, "Medium": 1, "Low": 2}.get(t.priority, 3), t.title),
            ):
                writer.writerow({
                    "title":       threat.title,
                    "category":    threat.category,
                    "priority":    threat.priority,
                    "status":      threat.status,
                    "ai_backends": ", ".join(threat.ai_backends),
                    "edge":        edge_labels.get(threat.edge_guid, threat.edge_guid),
                    "source":      node_names.get(threat.source_guid, threat.source_guid),
                    "destination": node_names.get(threat.dest_guid, threat.dest_guid),
                    "description": threat.description,
                    "mitigations": threat.mitigations,
                })

    def _render_scene_to_image(self, margin: int = 40, scale: float = 2.0) -> QImage:
        bounding = self.scene.itemsBoundingRect().adjusted(-margin, -margin, margin, margin)
        w = max(int(bounding.width() * scale), 1)
        h = max(int(bounding.height() * scale), 1)
        img = QImage(w, h, QImage.Format_ARGB32)
        img.fill(Qt.white)
        p = QPainter(img)
        p.setRenderHint(QPainter.Antialiasing)
        self.scene.render(p, QRectF(0, 0, w, h), bounding)
        p.end()
        return img

    def _export_png(self) -> None:
        default_name = ""
        if self._current_file:
            default_name = str(Path(self._current_file).with_suffix(".png"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Diagram as PNG", default_name, "PNG Images (*.png)"
        )
        if not path:
            return
        try:
            self.export_png_to(path)
            QMessageBox.information(self, "Export PNG", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export PNG", str(e))

    def export_png_to(self, path: str) -> None:
        """Render the current diagram to a PNG file. Raises RuntimeError on failure."""
        img = self._render_scene_to_image()
        if not img.save(path, "PNG"):
            raise RuntimeError(f"Failed to save image to:\n{path}")

    def _export_svg(self) -> None:
        default_name = ""
        if self._current_file:
            default_name = str(Path(self._current_file).with_suffix(".svg"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Diagram as SVG", default_name, "SVG Files (*.svg)"
        )
        if not path:
            return
        try:
            self.export_svg_to(path)
            QMessageBox.information(self, "Export SVG", f"Saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "SVG Export Failed", str(e))

    def export_svg_to(self, path: str) -> None:
        """Render the current diagram to an SVG file. Raises on failure."""
        try:
            from PySide6.QtSvg import QSvgGenerator
        except ImportError as exc:
            raise RuntimeError(
                "PySide6-Addons is required for SVG export.\n"
                "Install it with: pip install PySide6-Addons"
            ) from exc
        bounding = self.scene.itemsBoundingRect().adjusted(-40, -40, 40, 40)
        gen = QSvgGenerator()
        gen.setFileName(path)
        gen.setViewBox(bounding)
        gen.setSize(bounding.size().toSize())
        p = QPainter(gen)
        p.setRenderHint(QPainter.Antialiasing)
        self.scene.render(p, source=bounding)
        p.end()

    def _current_diag_name(self) -> str:
        if 0 <= self._active_diag_idx < len(self._project):
            return self._project[self._active_diag_idx].get("name", "Diagram")
        return "Diagram"

    def _export_report_markdown(self) -> None:
        default_name = ""
        if self._current_file:
            default_name = str(Path(self._current_file).with_suffix(".md"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report (Markdown)", default_name, "Markdown Files (*.md)"
        )
        if not path:
            return
        try:
            self.export_report_markdown_to(path)
            QMessageBox.information(self, "Export Report", f"Report saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def export_report_markdown_to(self, path: str) -> None:
        from .report import export_markdown
        export_markdown(self.scene, self.threats, self._current_diag_name(), Path(path))

    def _export_report_pdf(self) -> None:
        default_name = ""
        if self._current_file:
            default_name = str(Path(self._current_file).with_suffix(".pdf"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Report (PDF)", default_name, "PDF Files (*.pdf)"
        )
        if not path:
            return
        try:
            self.export_report_pdf_to(path)
            QMessageBox.information(self, "Export Report", f"PDF saved to:\n{path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def export_report_pdf_to(self, path: str) -> None:
        from .report import export_pdf
        export_pdf(self.scene, self.threats, self._current_diag_name(), Path(path))

    def _export_threats_report(self) -> None:
        """File menu: the threat register, ranked by risk."""
        from .threats_report import SCOPE_DIAGRAM
        from .ui.threats_report_dialog import ThreatsReportDialog

        self._sync_active_diagram()      # flush the live scene into the project
        names = [str(d.get("name", "Diagram")) for d in self._project]
        dlg = ThreatsReportDialog(names, self._current_diag_name(), parent=self)
        if dlg.exec() != QDialog.Accepted:
            return
        options = dlg.options(source_file=self._current_file or "")

        stem = Path(self._current_file).stem if self._current_file else "threats"
        if options.scope == SCOPE_DIAGRAM:
            stem = f"{stem}-{self._current_diag_name()}"
        # PDF is the format this report is read in; Markdown and CSV stay
        # available for diffing and for spreadsheets.
        default_name = str(Path(self._current_file).with_name(f"{stem}-report.pdf")) \
            if self._current_file else f"{stem}-report.pdf"
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Threats Report", default_name,
            "PDF Files (*.pdf);;Markdown Files (*.md);;CSV Files (*.csv)",
        )
        if not path:
            return
        try:
            written, count = self.export_threats_report_to(path, options)
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))
            return
        note = ("\n\nThe Markdown source is written alongside it."
                if str(written).lower().endswith(".pdf") else "")
        self._show_selectable_message(
            QMessageBox.Information, "Threats Report",
            f"{count} threat(s) written to:\n{written}{note}",
        )

    def export_threats_report_to(self, path: str, options=None) -> tuple:
        """Write the threats report. Format follows the suffix (.md/.pdf/.csv).

        Returns (path written, number of threats in the report).
        """
        from .threats_report import (ReportOptions, collect, export_csv,
                                     export_markdown, export_pdf)

        self._sync_active_diagram()
        if options is None:
            options = ReportOptions(diagram_name=self._current_diag_name(),
                                    source_file=self._current_file or "")
        data = collect(self._project, self._project_nodes, options)

        # PDF unless the caller explicitly asked for Markdown or CSV; a path
        # with no suffix at all becomes a PDF rather than silently dropping the
        # formatting.
        out_path = Path(path)
        if not out_path.suffix:
            out_path = out_path.with_suffix(".pdf")
        writer = {".md": export_markdown, ".markdown": export_markdown,
                  ".csv": export_csv}.get(out_path.suffix.lower(), export_pdf)
        out = writer(data, out_path)
        return str(out), len(data.entries) + len(data.orphaned)

    def _export_design_report(self) -> None:
        """File menu: design phase verification report (Markdown or PDF by suffix)."""
        default_name = ""
        if self._current_file:
            default_name = str(Path(self._current_file).with_name(
                Path(self._current_file).stem + "-design-verification.md"))
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Design Verification Report", default_name,
            "Markdown Files (*.md);;PDF Files (*.pdf)",
        )
        if not path:
            return
        try:
            written = self.export_design_report_to(path)
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))
            return
        self._show_selectable_message(
            QMessageBox.Information, "Design Verification Report",
            f"Report written to:\n{written}",
        )

    def export_design_report_to(self, path: str) -> str:
        """Write the design verification report. PDF when the path ends in .pdf.

        Validation runs as part of the report, so the verdict reflects the model
        as it stands right now. Returns the path written.
        """
        from .design_report import export_markdown, export_pdf
        writer = export_pdf if str(path).lower().endswith(".pdf") else export_markdown
        out = writer(
            self.scene, self.threats, self._current_diag_name(), Path(path),
            issues=self.run_validation(), source_file=self._current_file or "",
            sequences=self.sequences,
        )
        return str(out)

    def _import_nodes(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Nodes", "", "JSON Files (*.json)")
        if not path:
            return
        try:
            self.import_nodes_from(path)
        except Exception as e:
            QMessageBox.critical(self, "Import Failed", str(e))

    def import_nodes_from(self, path: str) -> None:
        """Import nodes/edges from a JSON file into the current scene. Raises on failure."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self._deserialize_into_scene(data)

    def _serialize_nodes(self, nodes: List[NodeItem]) -> Dict[str, Any]:
        """Serialize a subset of nodes and any edges whose both endpoints are in that set."""
        selected_ids = {n.node_id for n in nodes}
        nodes_data: List[Dict[str, Any]] = []
        edges_data: List[Dict[str, Any]] = []

        for n in nodes:
            pos = n.scenePos()
            props = n.properties()
            props["width"] = n._width
            props["height"] = n._height
            nodes_data.append({
                "id": n.node_id,
                "type": n.shape_kind,
                "pos": [pos.x(), pos.y()],
                "properties": props,
                "inputs": [{"name": s.name, "properties": s.properties()} for s in n.inputs],
                "outputs": [{"name": s.name, "properties": s.properties()} for s in n.outputs],
            })

        seen_edges: set = set()
        for n in nodes:
            for e in getattr(n, "edges", []):
                if id(e) in seen_edges:
                    continue
                seen_edges.add(id(e))
                if e.src is None or e.dst is None:
                    continue
                src_node = e.src.parentItem()
                dst_node = e.dst.parentItem()
                if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
                    continue
                if src_node.node_id not in selected_ids or dst_node.node_id not in selected_ids:
                    continue
                edges_data.append({
                    "id": e.edge_id,
                    "from": {"node": src_node.node_id, "slot": e.src.name},
                    "to": {"node": dst_node.node_id, "slot": e.dst.name},
                    "label": {
                        "text": e.label.name if hasattr(e, "label") else "",
                        "pos": [e.label.mapToScene(QPointF(0, 0)).x(), e.label.mapToScene(QPointF(0, 0)).y()] if hasattr(e, "label") else None,
                    },
                    "threat_guids": list(e.threat_guids),
                    "properties": e.properties(),
                })

        threat_guids_in_selection = {g for ed in edges_data for g in ed["threat_guids"]}
        threats_data = {
            guid: t.to_dict()
            for guid, t in self.threats.items()
            if guid in threat_guids_in_selection
        }
        exported_edge_ids = {ed["id"] for ed in edges_data}
        sequences_data = {}
        for sid, seq in self.sequences.items():
            relevant = [eid for eid in seq.steps if eid in exported_edge_ids]
            if relevant:
                sequences_data[sid] = {"name": seq.name, "color": seq.color, "steps": relevant}
        return {"version": 1, "nodes": nodes_data, "edges": edges_data, "threats": threats_data, "sequences": sequences_data}

    def _deserialize_into_scene(self, data: Dict[str, Any], paste_center: Optional[QPointF] = None) -> None:
        """Add nodes from data into the current scene without clearing it. Remaps IDs to avoid conflicts."""
        import uuid
        specs = {**builtin_nodes(), **security_nodes()}
        # Build a mapping from file node IDs to fresh IDs
        id_map: Dict[str, str] = {
            nd["id"]: str(uuid.uuid4())
            for nd in data.get("nodes", [])
            if "id" in nd
        }
        nodes_by_new_id: Dict[str, NodeItem] = {}

        # Compute offset: center pasted nodes on paste_center, or nudge slightly for plain import
        if paste_center is not None:
            positions = [nd.get("pos", [0, 0]) for nd in data.get("nodes", [])]
            if positions:
                cx = sum(p[0] for p in positions) / len(positions)
                cy = sum(p[1] for p in positions) / len(positions)
                offset = paste_center - QPointF(cx, cy)
            else:
                offset = QPointF(0.0, 0.0)
        else:
            offset = QPointF(20.0, 20.0)

        for nd in data.get("nodes", []):
            t = nd.get("type")
            pos = nd.get("pos", [0, 0])
            props = nd.get("properties", {})
            old_id = nd.get("id")
            spec = specs.get(t)
            if not spec:
                continue
            new_id = id_map.get(old_id, str(uuid.uuid4()))
            node = create_node(spec, node_id=new_id)
            node.set_properties(props)
            self.scene.addItem(node)
            node.setPos(QPointF(float(pos[0]), float(pos[1])) + offset)
            if "inputs" in nd or "outputs" in nd:
                for s in list(node.inputs):
                    node.remove_slot(s)
                for s in list(node.outputs):
                    node.remove_slot(s)
                for entry in nd.get("inputs", []):
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "input", properties=sprops)
                for entry in nd.get("outputs", []):
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "output", properties=sprops)
            from .graphics.items import ensure_owner_slot
            ensure_owner_slot(node)   # every asset keeps its owner slot
            nodes_by_new_id[new_id] = node

        edge_id_map: Dict[str, str] = {}  # old_edge_id -> new_edge_id
        for ed in data.get("edges", []):
            try:
                src_id = id_map.get(str(ed["from"]["node"]))
                dst_id = id_map.get(str(ed["to"]["node"]))
                if src_id is None or dst_id is None:
                    continue
                src_slot_name = str(ed["from"]["slot"])
                dst_slot_name = str(ed["to"]["slot"])
                src_node = nodes_by_new_id[src_id]
                dst_node = nodes_by_new_id[dst_id]
                out_slot = next((s for s in src_node.outputs if s.name == src_slot_name), None)
                in_slot = next((s for s in dst_node.inputs if s.name == dst_slot_name), None)
                if out_slot and in_slot:
                    edge = src_node.connect(out_slot, in_slot)
                    if edge:
                        if "properties" in ed:
                            edge.set_properties(self._with_type(self._migrate_edge_props(dict(ed["properties"]))))
                        new_eid = str(uuid.uuid4())
                        if "id" in ed:
                            edge_id_map[str(ed["id"])] = new_eid
                        edge.edge_id = new_eid
                        new_threat_guids = set()
                        for old_tguid in ed.get("threat_guids", []):
                            new_tguid = str(uuid.uuid4())
                            if old_tguid in {t_guid: None for t_guid in data.get("threats", {})}:
                                td = data["threats"][old_tguid]
                                td = dict(td)
                                td["guid"] = new_tguid
                                self.threats[new_tguid] = Threat.from_dict(td)
                            new_threat_guids.add(new_tguid)
                        edge.threat_guids = new_threat_guids
                        if "label" in ed:
                            label = ed["label"]
                            txt = label.get("text", "")
                            if txt:
                                edge.label.set_text(txt)
                            mo = label.get("midpoint_offset")
                            if mo and label.get("user_positioned"):
                                edge.label._midpoint_offset = QPointF(float(mo[0]), float(mo[1]))
                                edge.label.user_positioned = True
                        edge.update_path()
            except Exception:
                continue

        # Import sequences, remapping edge IDs
        for sid, sd in data.get("sequences", {}).items():
            new_sid = str(uuid.uuid4())
            new_steps = [edge_id_map.get(eid, eid) for eid in sd.get("steps", [])
                         if edge_id_map.get(eid) is not None]
            if new_steps:
                self.sequences[new_sid] = Sequence.from_dict(
                    new_sid, {"name": sd.get("name", "Sequence"), "color": sd.get("color", DEFAULT_SEQUENCE_COLOR), "steps": new_steps}
                )
        self.seq_panel.refresh()

        # Select the newly imported nodes so user can see/move them
        self.scene.clearSelection()
        for node in nodes_by_new_id.values():
            node.setSelected(True)
            node._evaluate_parent_id()

    def _serialize_scene(self) -> Dict[str, Any]:
        nodes: List[NodeItem] = [item for item in self.scene.items() if isinstance(item, NodeItem)]
        # Keep a stable order by z/index to make diffs nicer
        nodes = list(reversed(nodes))
        node_to_index: Dict[NodeItem, int] = {n: i for i, n in enumerate(nodes)}
        nodes_data: List[Dict[str, Any]] = []
        edges_data: List[Dict[str, Any]] = []

        for n in nodes:
            pos = n.scenePos()
            props = n.properties()
            props["width"] = n._width
            props["height"] = n._height
            nodes_data.append({
                "id": n.node_id,
                "type": n.shape_kind,
                "pos": [pos.x(), pos.y()],
                "properties": props,
                "inputs": [{"name": s.name, "properties": s.properties()} for s in n.inputs],
                "outputs": [{"name": s.name, "properties": s.properties()} for s in n.outputs],
            })

        seen_edges: set[int] = set()
        for n in nodes:
            for e in getattr(n, "edges", []):
                if id(e) in seen_edges:
                    continue
                seen_edges.add(id(e))
                if e.src is None or e.dst is None:
                    continue
                src_node = e.src.parentItem()
                dst_node = e.dst.parentItem()
                if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
                    continue
                edges_data.append({
                    "id": e.edge_id,
                    "from": {
                        "node": src_node.node_id,
                        "slot": e.src.name,
                    },
                    "to": {
                        "node": dst_node.node_id,
                        "slot": e.dst.name,
                    },
                    "label": {
                        "text": e.label.name if hasattr(e, 'label') else "",
                        "pos": [e.label.mapToScene(QPointF(0,0)).x(), e.label.mapToScene(QPointF(0,0)).y()] if hasattr(e, 'label') else None,
                    },
                    "threat_guids": list(e.threat_guids),
                    "properties": e.properties(),
                })

        threats_data = {guid: t.to_dict() for guid, t in self.threats.items()}
        sequences_data = {sid: seq.to_dict() for sid, seq in self.sequences.items()}
        return {"version": 1, "nodes": nodes_data, "edges": edges_data, "threats": threats_data, "sequences": sequences_data}

    def _deserialize_scene(self, data: Dict[str, Any]) -> None:
        if "placements" in data:
            self._deserialize_from_placements(self.scene, data, self.threats, self.sequences)
        else:
            self._deserialize_into(self.scene, data, self.threats, self.sequences)
        self._show_diagram_properties()
        self.seq_panel.set_registry(self.sequences)
        self._undo_stack.clear()
        self.threat_panel.set_scene(self.scene)
        self.threat_panel.refresh()
        self.attack_surface_panel.refresh()
        self.attack_surface_panel.set_scene(self.scene)
        self.attack_surface_panel.refresh()
        self._apply_layer_visibility()   # layers survive a diagram switch/reload
        self._minimap.update_viewport()

    def _deserialize_from_placements(
        self,
        scene: NodeGraphicsScene,
        data: Dict[str, Any],
        threats: ThreatRegistry,
        sequences: Optional[SequenceRegistry] = None,
    ) -> None:
        """Load a diagram that stores placements (node_id + pos) referencing _project_nodes."""
        scene.clear()
        threats.clear()
        if sequences is not None:
            sequences.clear()

        specs = {**builtin_nodes(), **security_nodes()}
        nodes_by_id: Dict[str, NodeItem] = {}

        for pl in data.get("placements", []):
            nid = pl.get("node_id")
            pos = pl.get("pos", [0, 0])
            nd = self._project_nodes.get(nid)
            if not nd or not nid:
                continue
            spec = specs.get(nd.get("type"))
            if not spec:
                continue
            node = create_node(spec, node_id=nid)
            node.set_properties(dict(nd.get("properties", {})))
            if "inputs_sealed" in nd:
                node.inputs_sealed = bool(nd["inputs_sealed"])
            if "outputs_sealed" in nd:
                node.outputs_sealed = bool(nd["outputs_sealed"])
            if nd.get("inputs") or nd.get("outputs"):
                for s in list(node.inputs):
                    node.remove_slot(s)
                for s in list(node.outputs):
                    node.remove_slot(s)
                for entry in nd.get("inputs", []):
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "input", properties=sprops)
                for entry in nd.get("outputs", []):
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "output", properties=sprops)
            scene.addItem(node)
            node.setPos(QPointF(float(pos[0]), float(pos[1])))
            nodes_by_id[nid] = node

        # Build edges (same logic as _deserialize_into)
        for ed in data.get("edges", []):
            try:
                if ed.get("alias"):
                    src_node = nodes_by_id.get(str(ed.get("source_node", "")))
                    dst_node = nodes_by_id.get(str(ed.get("dest_node", "")))
                    if src_node and dst_node:
                        edge = self._make_alias_edge(src_node, dst_node, edge_id=ed.get("id"))
                        scene.addItem(edge)
                        edge.update_path()
                    continue
                src_id = str(ed["from"]["node"])
                dst_id = str(ed["to"]["node"])
                src_node = nodes_by_id[src_id]
                dst_node = nodes_by_id[dst_id]
                out_slot = next((s for s in src_node.outputs if s.name == str(ed["from"]["slot"])), None)
                in_slot = next((s for s in dst_node.inputs if s.name == str(ed["to"]["slot"])), None)
                if out_slot and in_slot:
                    edge = src_node.connect(out_slot, in_slot)
                    if edge:
                        if "properties" in ed:
                            edge.set_properties(self._with_type(self._migrate_edge_props(dict(ed["properties"]))))
                        if "id" in ed:
                            edge.edge_id = str(ed["id"])
                        edge.threat_guids = set(ed.get("threat_guids", []))
                        wp = ed.get("waypoints")
                        if wp:
                            edge.ortho_waypoints = [QPointF(float(x), float(y)) for x, y in wp]
                            edge._ortho_manual = True
                        if "label" in ed:
                            lbl = ed["label"]
                            txt = lbl.get("text", "")
                            if txt:
                                edge.label.set_text(txt)
                            mo = lbl.get("midpoint_offset")
                            if mo and lbl.get("user_positioned"):
                                edge.label._midpoint_offset = QPointF(float(mo[0]), float(mo[1]))
                                edge.label.user_positioned = True
                        edge.update_path()
            except Exception:
                continue

        for guid, td in data.get("threats", {}).items():
            threats[guid] = Threat.from_dict(td)
        if sequences is not None:
            for sid, sd in data.get("sequences", {}).items():
                sequences[sid] = Sequence.from_dict(sid, sd)
        for node in nodes_by_id.values():
            if node._properties.get("class"):
                node._evaluate_parent_id()
        for node in nodes_by_id.values():
            if node.shape_kind != "Boundary":
                node._evaluate_boundary_membership()
        self._strip_control_slots(nodes_by_id.values())

    @staticmethod
    def _strip_control_slots(nodes) -> int:
        """A security control has no slots: it is placed, not connected.

        Its scope comes from the geometry — which asset interfaces its circle
        covers — so connection points are meaningless on it and only clutter the
        canvas. Models saved before the container refactor carry the four in /
        four out slots the old template shipped; drop them on load.

        A slot that an edge actually uses is kept: an old model that wired
        something to a control would otherwise lose that edge silently. Those
        show up as a validation finding instead.
        """
        removed = 0
        for node in nodes:
            if not str(node.properties().get("class", "")).startswith("security control"):
                continue
            for slot in list(node.inputs) + list(node.outputs):
                if any(e.src is slot or e.dst is slot for e in node.edges):
                    continue
                node.remove_slot(slot)
                removed += 1
        return removed

    def _deserialize_into(self, scene: NodeGraphicsScene, data: Dict[str, Any], threats: ThreatRegistry, sequences: Optional[SequenceRegistry] = None) -> None:
        scene.clear()
        threats.clear()
        if sequences is not None:
            sequences.clear()
        specs = {**builtin_nodes(), **security_nodes()}
        nodes_by_id: Dict[str, NodeItem] = {}
        for nd in data.get("nodes", []):
            t = nd.get("type")
            pos = nd.get("pos", [0, 0])
            props = nd.get("properties", {})
            node_id = nd.get("id")
            spec = specs.get(t)
            if not spec:
                continue
            node = create_node(spec, node_id=node_id)
            node.set_properties(props)
            scene.addItem(node)
            node.setPos(QPointF(float(pos[0]), float(pos[1])))
            # Restore custom slots if present
            if "inputs" in nd or "outputs" in nd:
                for s in list(node.inputs):
                    node.remove_slot(s)
                for s in list(node.outputs):
                    node.remove_slot(s)
                for entry in nd.get("inputs", []):
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "input", properties=sprops)
                for entry in nd.get("outputs", []):
                    name, sprops = (entry["name"], entry.get("properties", {})) if isinstance(entry, dict) else (entry, {})
                    node.add_slot(name, "output", properties=sprops)
            nodes_by_id[node.node_id] = node
        # Build edges
        for ed in data.get("edges", []):
            try:
                if ed.get("alias"):
                    src_node = nodes_by_id.get(str(ed.get("source_node", "")))
                    dst_node = nodes_by_id.get(str(ed.get("dest_node", "")))
                    if src_node and dst_node:
                        edge = self._make_alias_edge(src_node, dst_node, edge_id=ed.get("id"))
                        scene.addItem(edge)
                        edge.update_path()
                    continue
                src_id = str(ed["from"]["node"])
                dst_id = str(ed["to"]["node"])
                src_slot_name = str(ed["from"]["slot"])
                dst_slot_name = str(ed["to"]["slot"])
                src_node = nodes_by_id[src_id]
                dst_node = nodes_by_id[dst_id]
                out_slot = next((s for s in src_node.outputs if s.name == src_slot_name), None)
                in_slot = next((s for s in dst_node.inputs if s.name == dst_slot_name), None)
                if out_slot and in_slot:
                    edge = src_node.connect(out_slot, in_slot)
                    if edge:
                        if "properties" in ed:
                            edge.set_properties(self._with_type(self._migrate_edge_props(dict(ed["properties"]))))
                        if "id" in ed:
                            edge.edge_id = str(ed["id"])
                        edge.threat_guids = set(ed.get("threat_guids", []))
                        wp = ed.get("waypoints")
                        if wp:
                            edge.ortho_waypoints = [QPointF(float(x), float(y)) for x, y in wp]
                            edge._ortho_manual = True
                        if "label" in ed:
                            label = ed["label"]
                            txt = label.get("text", "")
                            if txt:
                                edge.label.set_text(txt)
                            mo = label.get("midpoint_offset")
                            if mo and label.get("user_positioned"):
                                edge.label._midpoint_offset = QPointF(float(mo[0]), float(mo[1]))
                                edge.label.user_positioned = True
                        edge.update_path()
            except Exception:
                continue
        # Restore threats registry
        for guid, td in data.get("threats", {}).items():
            threats[guid] = Threat.from_dict(td)
        # Restore sequences registry
        if sequences is not None:
            for sid, sd in data.get("sequences", {}).items():
                sequences[sid] = Sequence.from_dict(sid, sd)
        # Bootstrap parent/child runtime relationships from loaded properties
        for node in nodes_by_id.values():
            if node._properties.get("class"):
                node._evaluate_parent_id()
        for node in nodes_by_id.values():
            if node.shape_kind != "Boundary":
                node._evaluate_boundary_membership()
        self._strip_control_slots(nodes_by_id.values())

    # Navigation
    def navigate_into(self, node: NodeItem) -> None:
        source = node._properties.get("source", "").strip()
        if not source:
            QMessageBox.warning(
                self, "No Source File",
                "Set the 'source' property on this composite node to a JSON file path first."
            )
            return

        source_path = Path(source)
        if not source_path.is_absolute() and self._current_file:
            source_path = Path(self._current_file).parent / source_path
        source_path = source_path.resolve()

        crumb_name = node._properties.get("name", "?")

        # Push current state onto the stack
        self._scene_stack.append((self.scene, self._current_file, dict(self.threats), crumb_name))

        # Build new scene from source file (or empty if file doesn't exist yet)
        new_scene = NodeGraphicsScene()
        new_threats: ThreatRegistry = {}
        if source_path.exists():
            try:
                with open(source_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._deserialize_into(new_scene, data, new_threats)
            except Exception as e:
                QMessageBox.critical(self, "Open Failed", str(e))
                self._scene_stack.pop()
                return

        self._switch_scene(new_scene, new_threats, str(source_path))

    def navigate_out(self) -> None:
        if not self._scene_stack:
            return

        # Auto-save current sub-diagram
        if self._current_file:
            try:
                data = self._serialize_scene()
                with open(self._current_file, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                QMessageBox.critical(self, "Save Failed", str(e))
                return

        prev_scene, prev_file, prev_threats, _ = self._scene_stack.pop()
        self._switch_scene(prev_scene, prev_threats, prev_file)

    def _navigate_to_depth(self, depth: int) -> None:
        while len(self._scene_stack) > depth:
            self.navigate_out()

    def _switch_scene(self, scene: NodeGraphicsScene, threats: ThreatRegistry, file_path: Optional[str]) -> None:
        try:
            self.scene.selectionChangedSimplified.disconnect(self._on_selection_changed)
            self.scene.edgeCreated.disconnect(self._on_edge_created)
            self.scene.slotClicked.disconnect(self._on_slot_clicked)
        except Exception:
            pass

        self.scene = scene
        self.threats = threats
        self._current_file = file_path
        self.view.setScene(self.scene)

        self.scene.selectionChangedSimplified.connect(self._on_selection_changed)
        self.scene.edgeCreated.connect(self._on_edge_created)
        self.scene.slotClicked.connect(self._on_slot_clicked)
        self.scene._delete_handler = self._do_delete_selected
        self._undo_stack.clear()

        self.prop_editor.set_node(None)
        self._update_breadcrumb()
        self._update_title()

    def _update_breadcrumb(self) -> None:
        # Clear existing widgets
        while self._breadcrumb_layout.count():
            item = self._breadcrumb_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not self._scene_stack:
            self._breadcrumb_bar.hide()
            return

        self._breadcrumb_bar.show()

        _crumb_style = "font-size: 12px; padding: 1px 4px; border: none; background: transparent; color: #aaa;"
        _sep_style = "color: #666; font-size: 12px; padding: 0 2px;"

        # Root button (navigates back to depth 0)
        root_btn = QPushButton("Root")
        root_btn.setFlat(True)
        root_btn.setStyleSheet(_crumb_style)
        root_btn.clicked.connect(lambda: self._navigate_to_depth(0))
        self._breadcrumb_layout.addWidget(root_btn)

        # One entry per level navigated into
        for i, (_, _, _, name) in enumerate(self._scene_stack):
            sep = QLabel(">")
            sep.setStyleSheet(_sep_style)
            self._breadcrumb_layout.addWidget(sep)

            depth = i + 1
            if depth < len(self._scene_stack):
                # Intermediate level — clickable
                btn = QPushButton(name)
                btn.setFlat(True)
                btn.setStyleSheet(_crumb_style)
                btn.clicked.connect(lambda checked=False, d=depth: self._navigate_to_depth(d))
                self._breadcrumb_layout.addWidget(btn)
            else:
                # Current level — bold, not clickable
                lbl = QLabel(name)
                lbl.setStyleSheet("font-size: 12px; padding: 1px 4px; color: #eee; font-weight: bold;")
                self._breadcrumb_layout.addWidget(lbl)

        self._breadcrumb_layout.addStretch()

    # ── automation / scripting ───────────────────────────────────────────────

    _GENERATE_THREATS_BACKENDS = ("claude", "codex", "rules", "all")

    def run_command(self, line: str) -> bool:
        """Execute a single automation command line.

        Supported commands (whitespace-separated, quote paths with spaces):
            new
            open <path>                    (.json or .tm7)
            import <path>
            save
            save-as <path>
            export-selection <path>
            export-png <path>
            export-svg <path>
            export-threats-csv <path>
            export-report-md <path>
            export-report-pdf <path>
            validate
            generate-threats <claude|codex|rules|all>
            diff <fileB>  |  diff <fileA> <fileB>
            import-log <logfile> [<out.json>]
            verify-impl <design.json> <log-or-impl.json>
            quit | exit

        Returns False for 'quit'/'exit' (caller should stop processing further
        commands), True otherwise. Raises on failure (unknown command, missing
        argument, or the underlying operation's own error).
        """
        import shlex

        parts = shlex.split(line)
        if not parts:
            return True
        cmd, args = parts[0].lower(), parts[1:]

        def _need(n: int) -> None:
            if len(args) < n:
                raise ValueError(f"'{cmd}' requires {n} argument(s), got {len(args)}.")

        if cmd == "new":
            self._file_new()
        elif cmd == "open":
            _need(1)
            self.open_project(args[0])
        elif cmd == "import":
            _need(1)
            self.import_nodes_from(args[0])
        elif cmd == "save":
            self.save_project()
        elif cmd in ("save-as", "saveas"):
            _need(1)
            self.save_project(args[0])
        elif cmd == "export-selection":
            _need(1)
            self.export_selection_to(args[0])
        elif cmd == "export-png":
            _need(1)
            self.export_png_to(args[0])
        elif cmd == "export-svg":
            _need(1)
            self.export_svg_to(args[0])
        elif cmd == "export-threats-csv":
            _need(1)
            self.export_threats_csv_to(args[0])
        elif cmd in ("export-report-md", "export-report-markdown"):
            _need(1)
            self.export_report_markdown_to(args[0])
        elif cmd == "export-report-pdf":
            _need(1)
            self.export_report_pdf_to(args[0])
        elif cmd == "validate":
            issues = self.run_validation()
            if issues:
                for issue in issues:
                    print(f"[{issue.severity}] {issue.rule}: {issue.message}")
            else:
                print("Validation: no issues found.")
        elif cmd == "generate-threats":
            _need(1)
            backend = args[0].lower()
            if backend not in self._GENERATE_THREATS_BACKENDS:
                raise ValueError(
                    f"Unknown backend '{backend}' (expected one of {', '.join(self._GENERATE_THREATS_BACKENDS)})."
                )
            result = self.generate_threats_all_edges(backend, show_progress=False)
            for text_line in result["lines"]:
                print(text_line)
        elif cmd == "import-log":
            # import-log <logfile> [<out.json>]
            # Build an implementation-phase model from a runtime capture. With an
            # out path, writes the project JSON; otherwise loads it into the tool.
            _need(1)
            from .implmodel import log_to_project
            with open(args[0], "r", encoding="utf-8", errors="replace") as f:
                proj = log_to_project(f.read())
            if len(args) >= 2:
                with open(args[1], "w", encoding="utf-8") as f:
                    json.dump(proj, f, indent=2)
                print(f"Wrote implementation model to {args[1]}")
            else:
                self._load_project(proj)
                self._current_file = None
                self._update_title()
                n_nodes = len(proj.get("nodes", {}))
                print(f"Loaded implementation model: {n_nodes} nodes.")
        elif cmd == "verify-impl":
            # verify-impl <design.json> <log-or-impl.json>
            # Verify a design model against a runtime capture (or a pre-built
            # implementation project). Prints a conformance report.
            _need(2)
            from .conformance import verify_conformance, format_text
            with open(args[0], "r", encoding="utf-8") as f:
                design = json.load(f)
            if args[1].lower().endswith(".json"):
                with open(args[1], "r", encoding="utf-8") as f:
                    impl = json.load(f)
            else:
                from .implmodel import log_to_project
                with open(args[1], "r", encoding="utf-8", errors="replace") as f:
                    impl = log_to_project(f.read())
            print(format_text(verify_conformance(design, impl)))
        elif cmd == "diff":
            # diff <fileB>            -> current model vs fileB
            # diff <fileA> <fileB>    -> fileA vs fileB
            _need(1)
            from .modeldiff import diff_projects, format_text
            if len(args) >= 2:
                with open(args[0], "r", encoding="utf-8") as f:
                    proj_a = json.load(f)
                with open(args[1], "r", encoding="utf-8") as f:
                    proj_b = json.load(f)
            else:
                proj_a = self._serialize_project()
                with open(args[0], "r", encoding="utf-8") as f:
                    proj_b = json.load(f)
            print(format_text(diff_projects(proj_a, proj_b)))
        elif cmd in ("quit", "exit"):
            return False
        else:
            raise ValueError(f"Unknown command: '{cmd}'")
        return True

    def run_commands(self, lines: List[str]) -> None:
        """Execute a sequence of automation command lines in order.

        Blank lines and lines starting with '#' are ignored. Stops early on
        'quit'/'exit'. A failing command is reported to stderr; the remaining
        commands still run.
        """
        import sys

        for raw_line in lines:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            print(f"> {stripped}")
            try:
                if not self.run_command(stripped):
                    break
            except Exception as e:
                print(f"error: {e}", file=sys.stderr)


def run():
    import argparse
    import shlex
    import sys

    from .diagnostics import install as install_diagnostics

    # Self-diagnosis: `kill -USR1 <pid>` writes every thread's stack and the
    # agent plumbing's state to this file. A wedged window cannot be inspected
    # with a profiler without ptrace privileges, and asking for them after the
    # fact is too late.
    dump = install_diagnostics()
    if dump is not None:
        _LOG.info("stack dump on SIGUSR1 → %s  (kill -USR1 %d)", dump, os.getpid())
        print(f"[diagnostics] kill -USR1 {os.getpid()} → {dump}", flush=True)

    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} — security threat modelling and verification")
    parser.add_argument(
        "project", nargs="?", default=None,
        help="Project file to open on startup (.json or .tm7)",
    )
    parser.add_argument(
        "-c", "--command", action="append", default=[], dest="commands", metavar="CMD",
        help="Automation command to run (repeatable; run in the order given, after --commands-file)",
    )
    parser.add_argument(
        "-f", "--commands-file", default=None, metavar="PATH",
        help="File of automation commands, one per line ('#' comments and blank lines ignored)",
    )
    parser.add_argument(
        "--headless", action="store_true",
        help="Do not show the main window; exit as soon as all commands have run",
    )
    args, qt_args = parser.parse_known_args(sys.argv[1:])

    app = QApplication([sys.argv[0]] + qt_args)
    win = MainWindow()

    commands: List[str] = []
    if args.project:
        commands.append("open " + shlex.quote(args.project))
    if args.commands_file:
        with open(args.commands_file, "r", encoding="utf-8") as f:
            commands.extend(f.readlines())
    commands.extend(args.commands)

    if not args.headless:
        win.show()

    if commands:
        win.run_commands(commands)

    if args.headless:
        sys.exit(0)

    sys.exit(app.exec())
