from __future__ import annotations

from typing import List, Tuple

from PySide6.QtCore import Qt, QPoint, QMimeData
from PySide6.QtGui import QColor, QCursor, QDrag, QFont, QPainter, QPixmap
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..nodes import NodeSpec, EdgeSpec
from .collapsible import CollapsibleSection

# Mime types used to carry spec names from toolbox → canvas
MIME_NODE_SPEC = "application/x-node-spec"
MIME_EDGE_SPEC = "application/x-edge-spec"


def _drag_pixmap(label: str, color: str) -> QPixmap:
    """Render a small rounded rectangle with text for the drag ghost."""
    pix = QPixmap(130, 34)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.NoPen)
    p.drawRoundedRect(1, 1, 128, 32, 6, 6)
    p.setPen(QColor("#ffffff"))
    f = QFont()
    f.setPointSize(9)
    p.setFont(f)
    p.drawText(pix.rect(), Qt.AlignCenter, label)
    p.end()
    return pix


class _NodeTile(QWidget):
    """A single draggable node entry in the toolbox."""

    def __init__(self, spec: NodeSpec, parent: QWidget | None = None):
        super().__init__(parent)
        self._spec = spec
        self._drag_origin: QPoint | None = None

        color = str(spec.default_properties.get("color", "#888888"))

        swatch = QWidget()
        swatch.setFixedSize(12, 12)
        swatch.setStyleSheet(
            f"background: {color}; border-radius: 2px; border: 1px solid rgba(255,255,255,0.2);"
        )

        name_lbl = QLabel(spec.name)
        name_lbl.setStyleSheet("font-size: 12px; color: #000000;")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(8)
        layout.addWidget(swatch)
        layout.addWidget(name_lbl, 1)

        self.setToolTip(f"Drag to canvas to add a {spec.name} node")
        self.setCursor(QCursor(Qt.OpenHandCursor))
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._set_hover(False)

    # ── Hover highlight ────────────────────────────────────────────────────

    def _set_hover(self, active: bool) -> None:
        if active:
            self.setStyleSheet(
                "background: #ffff00; border-radius: 4px;"
            )
        else:
            self.setStyleSheet(
                "background: transparent; border-radius: 4px;"
            )

    def enterEvent(self, event) -> None:
        self._set_hover(True)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._set_hover(False)
        super().leaveEvent(event)

    # ── Drag ───────────────────────────────────────────────────────────────

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._drag_origin = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if (
            self._drag_origin is not None
            and (event.buttons() & Qt.LeftButton)
            and (event.pos() - self._drag_origin).manhattanLength() >= 6
        ):
            self._start_drag()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._drag_origin = None
        super().mouseReleaseEvent(event)

    def _start_drag(self) -> None:
        self._drag_origin = None
        color = str(self._spec.default_properties.get("color", "#888888"))
        pix = _drag_pixmap(self._spec.name, color)

        mime = QMimeData()
        mime.setText(self._spec.name)

        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.setPixmap(pix)
        drag.setHotSpot(QPoint(pix.width() // 2, pix.height() // 2))
        drag.exec(Qt.CopyAction)


class _EdgeTile(QWidget):
    """A single draggable edge entry in the toolbox."""

    def __init__(self, spec: EdgeSpec, parent: QWidget | None = None):
        super().__init__(parent)
        self._spec = spec
        self._drag_origin: QPoint | None = None

        arrow_lbl = QLabel("→")
        arrow_lbl.setStyleSheet("font-size: 14px; color: #555; padding: 0;")

        name_lbl = QLabel(spec.name)
        name_lbl.setStyleSheet("font-size: 12px; color: #000000;")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(10, 5, 10, 5)
        layout.setSpacing(8)
        layout.addWidget(arrow_lbl)
        layout.addWidget(name_lbl, 1)

        self.setToolTip(f"Drag to canvas to add a {spec.name} edge")
        self.setCursor(QCursor(Qt.OpenHandCursor))
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._set_hover(False)

    def _set_hover(self, active: bool) -> None:
        if active:
            self.setStyleSheet("background: #ffff00; border-radius: 4px;")
        else:
            self.setStyleSheet("background: transparent; border-radius: 4px;")

    def enterEvent(self, event) -> None:
        self._set_hover(True)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:
        self._set_hover(False)
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.LeftButton:
            self._drag_origin = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if (
            self._drag_origin is not None
            and (event.buttons() & Qt.LeftButton)
            and (event.pos() - self._drag_origin).manhattanLength() >= 6
        ):
            self._start_drag()
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        self._drag_origin = None
        super().mouseReleaseEvent(event)

    def _start_drag(self) -> None:
        self._drag_origin = None
        pix = _drag_pixmap(self._spec.name, "#666666")

        mime = QMimeData()
        mime.setData(MIME_EDGE_SPEC, self._spec.name.encode())

        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.setPixmap(pix)
        drag.setHotSpot(QPoint(pix.width() // 2, pix.height() // 2))
        drag.exec(Qt.CopyAction)


class _SectionLabel(QLabel):
    """Styled category header inside the toolbox."""

    def __init__(self, text: str):
        super().__init__(text.upper())
        self.setStyleSheet(
            "font-size: 10px; font-weight: bold; color: #000000; "
            "padding: 10px 10px 3px 10px; letter-spacing: 1px;"
        )


class ToolboxSubHeader:
    """Marker inserted into a category's item list to start a sub-group.

    It is not a NodeSpec/EdgeSpec, so drag-drop lookups ignore it; the toolbox
    renders it as an indented sub-heading.
    """

    def __init__(self, name: str):
        self.name = name


class _SubSectionLabel(QLabel):
    """Indented sub-group heading inside a toolbox category."""

    def __init__(self, text: str):
        super().__init__(text)
        self.setStyleSheet(
            "font-size: 9px; font-weight: bold; color: #333333; "
            "padding: 5px 10px 2px 18px; letter-spacing: 1px;"
        )


class _Divider(QFrame):
    def __init__(self):
        super().__init__()
        self.setFrameShape(QFrame.HLine)
        self.setFrameShadow(QFrame.Plain)
        self.setStyleSheet("color: #333;")
        self.setFixedHeight(1)


class NodeToolbox(QWidget):
    """Left-side panel listing node types defined in template/toolbox.json."""

    # Fold state per category name, kept across rebuilds of the toolbox (the
    # palette is recreated when asset descriptors are reloaded).
    _expanded_state: dict = {}

    def set_all_expanded(self, expanded: bool) -> None:
        """Fold or unfold every category."""
        for name, section in self._sections.items():
            section.set_expanded(expanded)
            self._expanded_state[name] = expanded

    def __init__(
        self,
        categories: List[Tuple[str, List[NodeSpec]]],
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setMinimumWidth(150)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(4, 4, 4, 8)
        content_layout.setSpacing(0)

        # Each category folds away, so a long palette can be narrowed down to
        # the groups in use. Fold state is remembered per category for the
        # session.
        self._sections: dict = {}
        for cat_name, specs in categories:
            section = CollapsibleSection(
                cat_name.upper(),
                expanded=self._expanded_state.get(cat_name, True),
            )
            section.toggled.connect(
                lambda expanded, name=cat_name:
                    self._expanded_state.__setitem__(name, expanded)
            )
            for spec in specs:
                if isinstance(spec, ToolboxSubHeader):
                    section.add_widget(_SubSectionLabel(spec.name))
                elif isinstance(spec, EdgeSpec):
                    section.add_widget(_EdgeTile(spec))
                else:
                    section.add_widget(_NodeTile(spec))
            self._sections[cat_name] = section
            content_layout.addWidget(section)
            content_layout.addWidget(_Divider())

        content_layout.addStretch(1)
        scroll.setWidget(content)
        outer.addWidget(scroll)
