"""
Static verification — setup and results.

Two dialogs. The first asks what to verify and where the code is; the second
shows what the agent found, with every citation visible, and lets the reviewer
drop a finding before it reaches the report. Same principle as threat generation
and mitigation: the agent proposes, a person disposes.
"""
from __future__ import annotations

from typing import Callable, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QPushButton, QScrollArea,
    QVBoxLayout, QWidget,
)

from ..codeverify import (VERDICT_ERROR, VERDICT_IMPLEMENTED,
                          VERDICT_INSUFFICIENT, VERDICT_NOT_IMPLEMENTED,
                          StaticFinding, VerifyTask)

_VERDICT_STYLE = {
    VERDICT_IMPLEMENTED:     ("IMPLEMENTED",           "#27ae60"),
    VERDICT_NOT_IMPLEMENTED: ("NOT IMPLEMENTED",       "#c0392b"),
    VERDICT_INSUFFICIENT:    ("INSUFFICIENT EVIDENCE", "#e67e22"),
    VERDICT_ERROR:           ("ERROR",                 "#7f8c8d"),
}


class StaticVerifySetupDialog(QDialog):
    """Where is the source, and which controls should be checked?"""

    def __init__(self, tasks: List[VerifyTask], source_root: str = "",
                 backend_label: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("Static Verification")
        self.setMinimumWidth(620)
        self._tasks = list(tasks)

        layout = QVBoxLayout(self)
        intro = QLabel(
            "Each control is checked against the source that implements the asset "
            "interfaces its circle covers. The agent must cite file and line for "
            "anything it claims — a verdict it cannot point at is reported as "
            "insufficient evidence."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color:#444; font-size:12px;")
        layout.addWidget(intro)

        row = QHBoxLayout()
        row.addWidget(QLabel("Source root:"))
        self._root = QLineEdit(source_root)
        self._root.setPlaceholderText("/path/to/the/source/tree")
        row.addWidget(self._root, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._on_browse)
        row.addWidget(browse)
        layout.addLayout(row)

        hint = QLabel("Taken from the diagram's Source Root property when set.")
        hint.setStyleSheet("color:#666; font-size:11px;")
        layout.addWidget(hint)

        layout.addWidget(QLabel(f"Controls to verify ({len(self._tasks)}):"))
        self._list = QListWidget()
        for task in self._tasks:
            item = QListWidgetItem(
                f"{task.control_name}  ·  {task.asset_name}"
                + (f"  ({', '.join(task.interfaces)})" if task.interfaces else "")
            )
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked)
            if not task.control_description:
                item.setToolTip("This control has no configuration description — "
                                "the agent has little to judge against.")
            self._list.addItem(item)
        layout.addWidget(self._list, 1)

        if backend_label:
            backend = QLabel(f"Backend: {backend_label}")
            backend.setStyleSheet("color:#666; font-size:11px;")
            layout.addWidget(backend)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Verify")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Source root",
                                                self._root.text().strip() or "")
        if path:
            self._root.setText(path)

    def source_root(self) -> str:
        return self._root.text().strip()

    def selected_tasks(self) -> List[VerifyTask]:
        return [task for i, task in enumerate(self._tasks)
                if self._list.item(i).checkState() == Qt.Checked]


class _FindingCard(QFrame):
    """One verdict, its reasoning and its citations."""

    def __init__(self, finding: StaticFinding, parent=None):
        super().__init__(parent)
        self.finding = finding
        label, colour = _VERDICT_STYLE.get(finding.verdict, ("?", "#555"))
        self.setObjectName("findingCard")
        self.setStyleSheet(
            f"QFrame#findingCard {{ border: 1px solid #ccc; border-left: 4px solid "
            f"{colour}; border-radius: 4px; background: #f7f7f7; margin: 2px 0; }}"
        )
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        header = QHBoxLayout()
        self._accept = QCheckBox()
        self._accept.setChecked(True)
        self._accept.setToolTip("Include this finding in the report")
        header.addWidget(self._accept)
        badge = QLabel(label)
        badge.setStyleSheet(f"background:{colour}; color:white; font-size:11px; "
                            "font-weight:bold; padding:1px 6px; border-radius:3px;")
        header.addWidget(badge)
        if finding.confidence:
            conf = QLabel(f"confidence {finding.confidence:.2f}")
            conf.setStyleSheet("color:#666; font-size:11px;")
            header.addWidget(conf)
        header.addStretch(1)
        outer.addLayout(header)

        title = QLabel(f"{finding.task.control_name} · {finding.task.asset_name}")
        title.setWordWrap(True)
        title.setStyleSheet("font-weight:bold; color:#111; font-size:13px;")
        outer.addWidget(title)

        if finding.task.requirement_id:
            req = QLabel(f"Requirement: {finding.task.requirement_id}")
            req.setStyleSheet("color:#555; font-size:11px;")
            outer.addWidget(req)

        if finding.rationale:
            body = QLabel(finding.rationale)
            body.setWordWrap(True)
            body.setTextInteractionFlags(Qt.TextSelectableByMouse)
            body.setStyleSheet("color:#222; font-size:12px;")
            outer.addWidget(body)

        for citation in finding.citations:
            cite = QLabel(f"📎 {citation.label()}")
            cite.setTextInteractionFlags(Qt.TextSelectableByMouse)
            cite.setStyleSheet("color:#1a6fa8; font-size:11px; "
                               "font-family: monospace;")
            outer.addWidget(cite)
            if citation.excerpt:
                excerpt = QLabel(citation.excerpt.strip()[:300])
                excerpt.setWordWrap(True)
                excerpt.setTextInteractionFlags(Qt.TextSelectableByMouse)
                excerpt.setStyleSheet(
                    "color:#333; font-size:11px; font-family: monospace; "
                    "background:#eee; padding:3px; border-radius:3px;")
                outer.addWidget(excerpt)

        if finding.error:
            err = QLabel(finding.error)
            err.setWordWrap(True)
            err.setStyleSheet("color:#c0392b; font-size:11px;")
            outer.addWidget(err)

    def accepted(self) -> bool:
        return self._accept.isChecked()


class StaticVerifyResultsDialog(QDialog):
    """The findings, worst first, each droppable before it reaches the report."""

    def __init__(self, findings: List[StaticFinding],
                 on_export: Optional[Callable[[List[StaticFinding]], None]] = None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("Static Verification — Results")
        self.setMinimumSize(720, 560)
        self._on_export = on_export
        # Worst first: a gap is what the reader has to act on.
        order = {VERDICT_NOT_IMPLEMENTED: 0, VERDICT_INSUFFICIENT: 1,
                 VERDICT_ERROR: 2, VERDICT_IMPLEMENTED: 3}
        self._findings = sorted(findings, key=lambda f: (order.get(f.verdict, 9),
                                                         f.task.control_name))

        layout = QVBoxLayout(self)
        counts: dict = {}
        for f in self._findings:
            counts[f.verdict] = counts.get(f.verdict, 0) + 1
        summary = "   ".join(
            f"{_VERDICT_STYLE[v][0]}: {counts[v]}"
            for v in (VERDICT_IMPLEMENTED, VERDICT_NOT_IMPLEMENTED,
                      VERDICT_INSUFFICIENT, VERDICT_ERROR) if counts.get(v))
        head = QLabel(f"{len(self._findings)} control(s) checked   ·   {summary}")
        head.setStyleSheet("font-weight:bold; font-size:13px;")
        layout.addWidget(head)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        inner = QVBoxLayout(container)
        inner.setContentsMargins(2, 2, 2, 2)
        inner.setSpacing(6)
        self._cards = [_FindingCard(f) for f in self._findings]
        for card in self._cards:
            inner.addWidget(card)
        inner.addStretch(1)
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        export = QPushButton("Export Report…")
        export.clicked.connect(self._on_export_clicked)
        buttons.addButton(export, QDialogButtonBox.ActionRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accepted_findings(self) -> List[StaticFinding]:
        for card in self._cards:
            card.finding.accepted = card.accepted()
        return [c.finding for c in self._cards if c.accepted()]

    def _on_export_clicked(self) -> None:
        if self._on_export is not None:
            self._on_export(self.accepted_findings())
