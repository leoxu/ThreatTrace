"""Dialogs for the Subgraph placeholder feature (Phase 1: interface editing)."""
from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout,
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from ..subgraph import Interface, Port, PORT_IN, PORT_OUT


class InterfaceEditorDialog(QDialog):
    """Edit a subgraph's interface (ordered list of ports).

    On accept, exposes:
      - ``interface()``  -> the new Interface
      - ``rename_map()`` -> {original_name: new_name} for ports that were renamed,
        so the caller can preserve edges on renamed slots.
    """

    def __init__(self, interface: Interface, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Edit Subgraph Interface")
        self.resize(460, 360)

        layout = QVBoxLayout(self)
        hint = QLabel(
            "Ports are the placeholder's connection points. Names are the contract "
            "used to bind an imported component later — keep them stable."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #aaa; font-size: 11px;")
        layout.addWidget(hint)

        self._table = QTableWidget(0, 3, self)
        self._table.setHorizontalHeaderLabels(["Port name", "Direction", "Expects (optional)"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self._table, 1)

        # Track each row's original port name (None for newly added rows).
        self._orig_names: List[Optional[str]] = []

        for p in interface.ports:
            self._append_row(p, original=p.name)

        # Row action buttons
        btn_row = QHBoxLayout()
        add_in = QPushButton("+ Input")
        add_out = QPushButton("+ Output")
        rm = QPushButton("Remove")
        up = QPushButton("↑")
        down = QPushButton("↓")
        for b in (add_in, add_out, rm, up, down):
            btn_row.addWidget(b)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        add_in.clicked.connect(lambda: self._add_new(PORT_IN))
        add_out.clicked.connect(lambda: self._add_new(PORT_OUT))
        rm.clicked.connect(self._remove_selected)
        up.clicked.connect(lambda: self._move(-1))
        down.clicked.connect(lambda: self._move(1))

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ── row helpers ────────────────────────────────────────────────────────────
    def _append_row(self, port: Port, original: Optional[str]) -> None:
        r = self._table.rowCount()
        self._table.insertRow(r)
        self._table.setItem(r, 0, QTableWidgetItem(port.name))
        combo = QComboBox()
        combo.addItems([PORT_IN, PORT_OUT])
        combo.setCurrentText(port.dir)
        self._table.setCellWidget(r, 1, combo)
        self._table.setItem(r, 2, QTableWidgetItem(port.expects))
        self._orig_names.insert(r, original)

    def _add_new(self, direction: str) -> None:
        base = "in" if direction == PORT_IN else "out"
        existing = set(self._current_names())
        name = base
        n = 2
        while name in existing:
            name = f"{base}-{n}"
            n += 1
        self._append_row(Port(name=name, dir=direction), original=None)
        self._table.selectRow(self._table.rowCount() - 1)

    def _remove_selected(self) -> None:
        r = self._table.currentRow()
        if r >= 0:
            self._table.removeRow(r)
            self._orig_names.pop(r)

    def _move(self, delta: int) -> None:
        r = self._table.currentRow()
        if r < 0:
            return
        t = r + delta
        if not (0 <= t < self._table.rowCount()):
            return
        # Snapshot both rows, then swap their contents (and original-name tracking).
        a = self._read_row(r)
        b = self._read_row(t)
        self._write_row(r, b)
        self._write_row(t, a)
        self._orig_names[r], self._orig_names[t] = self._orig_names[t], self._orig_names[r]
        self._table.selectRow(t)

    def _read_row(self, r: int) -> Port:
        name = self._table.item(r, 0).text().strip() if self._table.item(r, 0) else ""
        combo: QComboBox = self._table.cellWidget(r, 1)  # type: ignore
        direction = combo.currentText() if combo else PORT_IN
        expects = self._table.item(r, 2).text().strip() if self._table.item(r, 2) else ""
        return Port(name=name, dir=direction, expects=expects)

    def _write_row(self, r: int, port: Port) -> None:
        self._table.setItem(r, 0, QTableWidgetItem(port.name))
        combo: QComboBox = self._table.cellWidget(r, 1)  # type: ignore
        if combo:
            combo.setCurrentText(port.dir)
        self._table.setItem(r, 2, QTableWidgetItem(port.expects))

    def _current_names(self) -> List[str]:
        out = []
        for r in range(self._table.rowCount()):
            it = self._table.item(r, 0)
            out.append(it.text().strip() if it else "")
        return out

    # ── validation / result ─────────────────────────────────────────────────────
    def _on_accept(self) -> None:
        names = self._current_names()
        for nm in names:
            if not nm:
                QMessageBox.warning(self, "Invalid Interface", "Port names cannot be empty.")
                return
        if len(set(names)) != len(names):
            QMessageBox.warning(self, "Invalid Interface", "Port names must be unique.")
            return
        self.accept()

    def interface(self) -> Interface:
        return Interface([self._read_row(r) for r in range(self._table.rowCount())])

    def rename_map(self) -> Dict[str, str]:
        """Map original port name -> new name for rows whose name changed."""
        result: Dict[str, str] = {}
        for r in range(self._table.rowCount()):
            orig = self._orig_names[r]
            new = self._read_row(r).name
            if orig is not None and orig != new:
                result[orig] = new
        return result
