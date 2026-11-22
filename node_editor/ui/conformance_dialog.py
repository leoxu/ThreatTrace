"""Dialog presenting a design<->implementation ConformanceReport."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QLabel, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from ..conformance import ConformanceReport

_SEV_COLOR = {
    "High":   QColor("#c62828"),
    "Medium": QColor("#e67e22"),
    "Low":    QColor("#c9a227"),
    "Info":   QColor("#2e7d32"),
}
_STATUS_TITLE = {
    "violation": "Violations (drift from design)",
    "unrealized": "Unrealized (design not exercised)",
    "conform": "Conforming (verified by runtime)",
}


class ConformanceDialog(QDialog):
    def __init__(self, report: ConformanceReport, design_name: str, impl_name: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Design ↔ Implementation Conformance")
        self.resize(760, 600)

        layout = QVBoxLayout(self)
        header = QLabel(f"Design  <b>{design_name}</b>   vs   Runtime  <b>{impl_name}</b>")
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        s = report.summary()
        summary = QLabel(
            f"<span style='color:#c62828'>{s.get('violation',0)} violations</span>   "
            f"<span style='color:#c9a227'>{s.get('unrealized',0)} unrealized</span>   "
            f"<span style='color:#2e7d32'>{s.get('conform',0)} conforming</span>"
        )
        summary.setTextFormat(Qt.RichText)
        layout.addWidget(summary)

        tree = QTreeWidget()
        tree.setHeaderLabels(["Finding", "Detail"])
        tree.setColumnWidth(0, 430)
        tree.setAlternatingRowColors(True)
        layout.addWidget(tree, 1)

        for status in ("violation", "unrealized", "conform"):
            group = report.by_status(status)
            if not group:
                continue
            root = QTreeWidgetItem([f"{_STATUS_TITLE[status]}  ({len(group)})", ""])
            f = root.font(0)
            f.setBold(True)
            root.setFont(0, f)
            tree.addTopLevelItem(root)
            for fnd in group:
                item = QTreeWidgetItem([f"[{fnd.severity}] {fnd.title}", fnd.detail])
                item.setForeground(0, QBrush(_SEV_COLOR.get(fnd.severity, QColor("#333"))))
                item.setForeground(1, QBrush(QColor("#666")))
                root.addChild(item)
            root.setExpanded(status != "conform")   # collapse the (usually long) conform list

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)
