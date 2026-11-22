"""
DiagramPanel — sidebar listing all diagrams in the current project.
"""
from __future__ import annotations

from typing import List, Dict, Any

from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class DiagramPanel(QWidget):
    """Sidebar showing diagram names with add / rename / delete controls."""

    diagramActivated = Signal(int)   # row index selected by user
    diagramAdded = Signal()
    diagramDeleted = Signal(int)
    diagramRenamed = Signal(int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._project: List[Dict[str, Any]] = []
        self._active_idx: int = -1
        self._updating: bool = False

        title = QLabel("Diagrams")
        title.setStyleSheet("font-weight: bold; padding: 2px 4px;")

        self._list = QListWidget()
        self._list.setAlternatingRowColors(True)
        self._list.currentRowChanged.connect(self._on_row_changed)
        self._list.itemDoubleClicked.connect(self._on_double_click)

        btn_add = QPushButton("+")
        btn_add.setFixedWidth(28)
        btn_add.setToolTip("New diagram")
        btn_add.clicked.connect(self.diagramAdded.emit)

        btn_del = QPushButton("✕")
        btn_del.setFixedWidth(28)
        btn_del.setToolTip("Delete selected diagram")
        btn_del.clicked.connect(self._on_delete)

        btn_row = QHBoxLayout()
        btn_row.setContentsMargins(0, 0, 0, 0)
        btn_row.setSpacing(4)
        btn_row.addStretch()
        btn_row.addWidget(btn_add)
        btn_row.addWidget(btn_del)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        layout.addWidget(title)
        layout.addWidget(self._list, 1)
        layout.addLayout(btn_row)

    def set_project(self, diagrams: List[Dict[str, Any]], active_idx: int) -> None:
        """Repopulate the list with a new project's diagrams."""
        self._project = diagrams
        self._updating = True
        self._list.clear()
        for d in diagrams:
            self._list.addItem(d.get("name", "Untitled"))
        self._active_idx = active_idx
        self._list.setCurrentRow(active_idx)
        self._updating = False

    def set_active(self, idx: int) -> None:
        """Update the highlighted row without emitting diagramActivated."""
        self._active_idx = idx
        self._updating = True
        self._list.setCurrentRow(idx)
        self._updating = False

    def update_name(self, idx: int, name: str) -> None:
        """Update a row label in-place (called after rename)."""
        item = self._list.item(idx)
        if item is not None:
            item.setText(name)

    # ----------------------------------------------------------------- slots

    def _on_row_changed(self, row: int) -> None:
        if self._updating or row < 0 or row == self._active_idx:
            return
        self.diagramActivated.emit(row)

    def _on_double_click(self, item: QListWidgetItem) -> None:
        row = self._list.row(item)
        name, ok = QInputDialog.getText(
            self, "Rename Diagram", "Name:", text=item.text()
        )
        if ok and name.strip():
            self.diagramRenamed.emit(row, name.strip())
            item.setText(name.strip())

    def _on_delete(self) -> None:
        row = self._list.currentRow()
        if row >= 0:
            self.diagramDeleted.emit(row)
