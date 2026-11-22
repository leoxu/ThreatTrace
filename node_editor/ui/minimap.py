"""MinimapView — overlay thumbnail of the scene in the bottom-right of the main view."""
from __future__ import annotations

from PySide6.QtCore import Qt, QPoint, QRectF
from PySide6.QtGui import QBrush, QColor, QPainter, QPen
from PySide6.QtWidgets import QGraphicsView


_MARGIN = 8
_W, _H = 180, 130
_DRAG_THRESHOLD = 5   # px — movement beyond this switches from navigate to drag-to-move


class MinimapView(QGraphicsView):
    """Thumbnail view of the scene, overlaid inside the main viewport.

    Left-click: navigate main view to that scene position.
    Left-click + drag (> 5 px): move the minimap overlay itself.
    """

    def __init__(self, scene, main_view: QGraphicsView, parent=None):
        super().__init__(scene, parent)
        self._main_view = main_view
        self._drag_start: QPoint | None = None   # viewport pos where press started
        self._widget_origin: QPoint | None = None # minimap pos at drag start
        self._is_dragging = False

        self.setFixedSize(_W, _H)
        self.setRenderHint(QPainter.Antialiasing, True)
        self.setInteractive(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setStyleSheet(
            "QGraphicsView { border: 1px solid #555; border-radius: 4px;"
            " background: rgba(240,240,240,210); }"
        )
        self.setAttribute(Qt.WA_TranslucentBackground, False)
        self.setCursor(Qt.SizeAllCursor)

    # ── public API ────────────────────────────────────────────────────────────

    def reposition(self) -> None:
        """Move to bottom-right corner of the parent widget (default position)."""
        p = self.parent()
        if p is not None:
            self.move(p.width() - _W - _MARGIN, p.height() - _H - _MARGIN)

    def update_viewport(self) -> None:
        """Fit scene content and refresh the viewport indicator."""
        items_rect = self.scene().itemsBoundingRect()
        if not items_rect.isEmpty():
            self.fitInView(items_rect.adjusted(-40, -40, 40, 40), Qt.KeepAspectRatio)
        self.viewport().update()

    # ── drawing ───────────────────────────────────────────────────────────────

    def drawForeground(self, painter: QPainter, rect: QRectF) -> None:  # type: ignore[override]
        super().drawForeground(painter, rect)

        mv = self._main_view
        tl = mv.mapToScene(mv.viewport().rect().topLeft())
        br = mv.mapToScene(mv.viewport().rect().bottomRight())
        vp_scene_rect = QRectF(tl, br)

        scale = self.transform().m11()
        pw = max(1.5 / scale, 0.5)

        painter.save()
        painter.setPen(QPen(QColor("#00bcd4"), pw))
        painter.setBrush(QBrush(QColor(0, 188, 212, 35)))
        painter.drawRect(vp_scene_rect)
        painter.restore()

    # ── mouse events ──────────────────────────────────────────────────────────
    # Left-click / drag          → navigate main view
    # Ctrl + left-click / drag   → move the minimap widget itself

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            if event.modifiers() & Qt.ControlModifier:
                self._drag_start = self.mapTo(self.parent(), event.pos())
                self._widget_origin = self.pos()
                self._is_dragging = True
                self.setCursor(Qt.ClosedHandCursor)
            else:
                self._drag_start = None
                self._is_dragging = False
                self._main_view.centerOn(self.mapToScene(event.pos()))
        event.accept()

    def mouseMoveEvent(self, event) -> None:  # type: ignore[override]
        if self._is_dragging and self._drag_start is not None and (event.buttons() & Qt.LeftButton):
            current = self.mapTo(self.parent(), event.pos())
            delta = current - self._drag_start
            p = self.parent()
            if p is not None:
                new_x = max(0, min(self._widget_origin.x() + delta.x(), p.width() - _W))
                new_y = max(0, min(self._widget_origin.y() + delta.y(), p.height() - _H))
                self.move(new_x, new_y)
        elif not self._is_dragging and (event.buttons() & Qt.LeftButton):
            self._main_view.centerOn(self.mapToScene(event.pos()))
        event.accept()

    def mouseReleaseEvent(self, event) -> None:  # type: ignore[override]
        if event.button() == Qt.LeftButton:
            self._drag_start = None
            self._widget_origin = None
            self._is_dragging = False
            self.setCursor(Qt.SizeAllCursor)
        event.accept()
