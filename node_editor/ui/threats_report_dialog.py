"""
Options for the threats report: what to include before choosing a file.
"""
from __future__ import annotations

from typing import List

from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QVBoxLayout,
)

from ..threats_report import (FILTER_ALL, FILTER_MITIGATED, FILTER_OPEN,
                              RISK_RULE, ReportOptions, SCOPE_DIAGRAM,
                              SCOPE_PROJECT)


class ThreatsReportDialog(QDialog):
    """Scope, filter and minimum priority for the threats report."""

    def __init__(self, diagram_names: List[str], current_diagram: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Threats Report")
        self.setMinimumWidth(460)
        self._current_diagram = current_diagram

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        intro = QLabel(
            "The threat register, ranked by risk: summary, ranking, the full "
            "record of every threat, and the traceability gaps."
        )
        intro.setWordWrap(True)
        layout.addWidget(intro)

        layout.addWidget(QLabel("Scope"))
        self._scope = QComboBox()
        self._scope.addItem(f"Whole project ({len(diagram_names)} diagram(s))",
                            SCOPE_PROJECT)
        self._scope.addItem(f"Current diagram — {current_diagram}", SCOPE_DIAGRAM)
        layout.addWidget(self._scope)

        layout.addWidget(QLabel("Threats to include"))
        self._filter = QComboBox()
        self._filter.addItem("All threats", FILTER_ALL)
        self._filter.addItem("Open only (no control linked)", FILTER_OPEN)
        self._filter.addItem("Mitigated only", FILTER_MITIGATED)
        layout.addWidget(self._filter)

        layout.addWidget(QLabel("Minimum priority"))
        self._priority = QComboBox()
        self._priority.addItem("Any", "")
        self._priority.addItem("Medium and above", "Medium")
        self._priority.addItem("High only", "High")
        layout.addWidget(self._priority)

        rule = QLabel(RISK_RULE)
        rule.setWordWrap(True)
        rule.setStyleSheet("color:#666; font-size:11px;")
        layout.addWidget(rule)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Choose File…")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def options(self, source_file: str = "") -> ReportOptions:
        return ReportOptions(
            scope=self._scope.currentData(),
            threat_filter=self._filter.currentData(),
            min_priority=self._priority.currentData(),
            diagram_name=self._current_diagram,
            source_file=source_file,
        )
