"""
AttackSurfacePanel — bottom dock listing all trust-boundary-crossing edges.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Dict, List, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView, QHeaderView, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

if TYPE_CHECKING:
    from ..threat import ThreatRegistry


_THREAT_COUNT_COL = 4   # column index for threat count


@dataclass
class EntryPoint:
    edge_id: str
    edge_label: str
    src_name: str
    dst_name: str
    boundary_name: str
    threat_count: int
    unmitigated: int


def scan_attack_surface(scene, threats: "ThreatRegistry") -> List[EntryPoint]:
    """Return edges that cross a trust boundary (IPC, Asset Operation, syscall types)."""
    from ..graphics.items import EdgeItem, NodeItem

    edge_threat_count: Dict[str, int] = {}
    edge_unmitigated: Dict[str, int] = {}
    for t in threats.values():
        edge_threat_count[t.edge_guid] = edge_threat_count.get(t.edge_guid, 0) + 1
        if not t.mitigation_sc_ids:
            edge_unmitigated[t.edge_guid] = edge_unmitigated.get(t.edge_guid, 0) + 1

    results: List[EntryPoint] = []
    for item in scene.items():
        if not isinstance(item, EdgeItem) or not item.src or not item.dst:
            continue
        src_node = item.src.parentItem()
        dst_node = item.dst.parentItem()
        if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
            continue

        etype = item.properties().get("type", "")
        if etype not in ("IPC", "Asset Operation", "syscall"):
            continue

        # Only include edges that cross a trust boundary
        src_boundary = src_node.boundary
        dst_boundary = dst_node.boundary
        if src_boundary is dst_boundary and src_boundary is not None:
            continue  # same boundary — internal call, not an entry point

        boundary = dst_boundary or src_boundary
        boundary_name = str(boundary.properties().get("name", "External")) if boundary else "External"

        edge_label = item.label.name if item.label and item.label.name else etype
        src_name = str(src_node.properties().get("name", src_node.title))
        dst_name = str(dst_node.properties().get("name", dst_node.title))

        results.append(EntryPoint(
            edge_id=item.edge_id,
            edge_label=edge_label,
            src_name=src_name,
            dst_name=dst_name,
            boundary_name=boundary_name,
            threat_count=edge_threat_count.get(item.edge_id, 0),
            unmitigated=edge_unmitigated.get(item.edge_id, 0),
        ))

    return sorted(results, key=lambda e: (e.boundary_name, e.src_name, e.dst_name))


class AttackSurfacePanel(QWidget):
    """Table of all trust-boundary-crossing edges with threat counts."""

    edgeSelected = Signal(str)   # emits edge_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = None
        self._threats: Optional["ThreatRegistry"] = None

        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)

        header = QHBoxLayout()
        self._count_lbl = QLabel("Attack Surface")
        self._count_lbl.setStyleSheet("font-weight:bold; font-size:13px;")
        header.addWidget(self._count_lbl, 1)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedHeight(22)
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        root.addLayout(header)

        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ["Edge / Kind", "Source", "Destination", "Boundary", "Threats"]
        )
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.horizontalHeader().setStretchLastSection(False)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self._table.cellDoubleClicked.connect(self._on_row_double_clicked)
        root.addWidget(self._table)

        note = QLabel("Double-click a row to select the edge on the canvas.  "
                      "Only IPC / Asset Operation / syscall edges crossing a trust boundary are shown.")
        note.setStyleSheet("color:#888; font-size:11px;")
        note.setWordWrap(True)
        root.addWidget(note)

    # ── public API ────────────────────────────────────────────────────────────

    def set_scene(self, scene) -> None:
        self._scene = scene

    def set_threats(self, threats: "ThreatRegistry") -> None:
        self._threats = threats

    def refresh(self) -> None:
        self._table.setRowCount(0)
        if self._scene is None or self._threats is None:
            return

        entries = scan_attack_surface(self._scene, self._threats)
        n = len(entries)
        self._count_lbl.setText(
            f"Attack Surface — {n} entry point{'s' if n != 1 else ''}"
        )

        for row, ep in enumerate(entries):
            self._table.insertRow(row)

            edge_item = QTableWidgetItem(ep.edge_label)
            edge_item.setData(Qt.UserRole, ep.edge_id)
            self._table.setItem(row, 0, edge_item)
            self._table.setItem(row, 1, QTableWidgetItem(ep.src_name))
            self._table.setItem(row, 2, QTableWidgetItem(ep.dst_name))
            self._table.setItem(row, 3, QTableWidgetItem(ep.boundary_name))

            threat_text = str(ep.threat_count) if ep.threat_count else "0"
            threat_item = QTableWidgetItem(threat_text)
            threat_item.setTextAlignment(Qt.AlignCenter)
            if ep.threat_count > 0 and ep.unmitigated > 0:
                threat_item.setBackground(Qt.red)
                threat_item.setForeground(Qt.white)
                threat_item.setText(f"{ep.unmitigated}/{ep.threat_count} open")
            elif ep.threat_count > 0:
                threat_item.setBackground(Qt.green)
                threat_item.setText(f"{ep.threat_count} mitigated")
            self._table.setItem(row, 4, threat_item)

    # ── internal ──────────────────────────────────────────────────────────────

    def _on_row_double_clicked(self, row: int, _col: int) -> None:
        item = self._table.item(row, 0)
        if item:
            edge_id = item.data(Qt.UserRole)
            if edge_id:
                self.edgeSelected.emit(edge_id)
