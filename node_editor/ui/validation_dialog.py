"""
ValidationDialog — shows validation results and lets the user navigate to issues.
"""
from __future__ import annotations

from typing import List, Callable, Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QHeaderView,
)

from ..validation import ValidationIssue, SEVERITY_ERROR, SEVERITY_WARNING


def _severity_icon(severity: str) -> str:
    return "✖" if severity == SEVERITY_ERROR else "⚠"


def _severity_color(severity: str) -> QColor:
    return QColor("#e57373") if severity == SEVERITY_ERROR else QColor("#ffb74d")


class ValidationDialog(QDialog):
    """Modal dialog listing all validation issues with jump-to buttons."""

    def __init__(
        self,
        issues: List[ValidationIssue],
        navigate_fn: Callable[[Optional[str], Optional[str]], None],
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("Diagram Validation")
        self.resize(820, 460)
        self._issues = issues
        self._navigate = navigate_fn

        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Summary line
        n_err = sum(1 for i in issues if i.severity == SEVERITY_ERROR)
        n_warn = sum(1 for i in issues if i.severity == SEVERITY_WARNING)
        if not issues:
            summary_text = "✔  No issues found."
        else:
            parts = []
            if n_err:
                parts.append(f"{n_err} error{'s' if n_err != 1 else ''}")
            if n_warn:
                parts.append(f"{n_warn} warning{'s' if n_warn != 1 else ''}")
            summary_text = "  ".join(parts)

        summary = QLabel(summary_text)
        summary.setStyleSheet("font-weight: bold; padding: 4px 2px;")
        layout.addWidget(summary)

        # Table
        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["", "Rule", "Message", "Go"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.verticalHeader().hide()
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        layout.addWidget(self._table, 1)

        self._populate()

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _populate(self) -> None:
        self._table.setRowCount(len(self._issues))
        for row, issue in enumerate(self._issues):
            # Severity icon
            icon_item = QTableWidgetItem(_severity_icon(issue.severity))
            icon_item.setForeground(QBrush(_severity_color(issue.severity)))
            icon_item.setTextAlignment(Qt.AlignCenter)
            icon_item.setToolTip(issue.severity)
            self._table.setItem(row, 0, icon_item)

            # Rule
            self._table.setItem(row, 1, QTableWidgetItem(issue.rule))

            # Message
            self._table.setItem(row, 2, QTableWidgetItem(issue.message))

            # Go button (only when there's a target)
            if issue.node_id or issue.edge_id:
                btn = QPushButton("Select")
                btn.setFixedWidth(60)
                btn.setToolTip("Select and scroll to this item in the diagram")
                btn.clicked.connect(
                    lambda _checked=False, nid=issue.node_id, eid=issue.edge_id:
                        self._on_go(nid, eid)
                )
                self._table.setCellWidget(row, 3, btn)

        self._table.resizeRowsToContents()

    def _on_go(self, node_id: Optional[str], edge_id: Optional[str]) -> None:
        self._navigate(node_id, edge_id)
