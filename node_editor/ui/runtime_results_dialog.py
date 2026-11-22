"""Runtime test results: what ran on target, what held, and what never ran."""
from __future__ import annotations

from typing import Callable, List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel,
    QPushButton, QScrollArea, QVBoxLayout, QWidget,
)

from ..runtime_tests import (RESULT_FAIL, RESULT_NOT_EXERCISED, RESULT_PASS,
                             TestResult)

_STYLE = {
    RESULT_PASS: ("PASS", "#27ae60"),
    RESULT_FAIL: ("FAIL", "#c0392b"),
    # Grey, not red: "the test did not run" is a gap in the run, not a defect in
    # the system, and colouring it like a failure teaches people to ignore it.
    RESULT_NOT_EXERCISED: ("NOT EXERCISED", "#7f8c8d"),
}


class _ResultCard(QFrame):
    def __init__(self, result: TestResult, parent=None):
        super().__init__(parent)
        self.result = result
        label, colour = _STYLE.get(result.result, ("?", "#555"))
        self.setObjectName("runtimeCard")
        self.setStyleSheet(
            f"QFrame#runtimeCard {{ border: 1px solid #ccc; border-left: 4px solid "
            f"{colour}; border-radius: 4px; background: #f7f7f7; margin: 2px 0; }}")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(8, 6, 8, 6)
        outer.setSpacing(4)

        header = QHBoxLayout()
        self._accept = QCheckBox()
        self._accept.setChecked(True)
        self._accept.setToolTip("Include this result in the report and in the "
                                "evidence recorded on the threats")
        header.addWidget(self._accept)
        badge = QLabel(label)
        badge.setStyleSheet(f"background:{colour}; color:white; font-size:11px; "
                            "font-weight:bold; padding:1px 6px; border-radius:3px;")
        header.addWidget(badge)
        kind = QLabel(result.spec.kind)
        kind.setStyleSheet("color:#666; font-size:11px;")
        header.addWidget(kind)
        header.addStretch(1)
        outer.addLayout(header)

        title = QLabel(result.spec.title)
        title.setWordWrap(True)
        title.setStyleSheet("font-weight:bold; color:#111; font-size:13px;")
        outer.addWidget(title)

        meta = QLabel(f"{result.spec.control_name} · {result.spec.asset_name}"
                      + (f" · {result.spec.requirement_id}"
                         if result.spec.requirement_id else ""))
        meta.setWordWrap(True)
        meta.setStyleSheet("color:#555; font-size:11px;")
        outer.addWidget(meta)

        if result.detail:
            detail = QLabel(result.detail)
            detail.setWordWrap(True)
            detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
            detail.setStyleSheet("color:#222; font-size:12px;")
            outer.addWidget(detail)

        if result.evidence_line:
            ev = QLabel(result.evidence_line)
            ev.setWordWrap(True)
            ev.setTextInteractionFlags(Qt.TextSelectableByMouse)
            ev.setStyleSheet("color:#333; font-size:11px; font-family: monospace; "
                             "background:#eee; padding:3px; border-radius:3px;")
            outer.addWidget(ev)

        if result.result == RESULT_NOT_EXERCISED and result.spec.requires:
            needs = QLabel("Needs on target: " + ", ".join(result.spec.requires))
            needs.setStyleSheet("color:#7f8c8d; font-size:11px;")
            outer.addWidget(needs)

    def accepted(self) -> bool:
        return self._accept.isChecked()


class RuntimeResultsDialog(QDialog):
    """Failures first — they are what the reader has to act on."""

    def __init__(self, results: List[TestResult],
                 on_export: Optional[Callable[[List[TestResult]], None]] = None,
                 parent=None):
        super().__init__(parent)
        self.setWindowTitle("Runtime Test Results")
        self.setMinimumSize(720, 560)
        self._on_export = on_export
        order = {RESULT_FAIL: 0, RESULT_NOT_EXERCISED: 1, RESULT_PASS: 2}
        self._results = sorted(results, key=lambda r: (order.get(r.result, 9),
                                                       r.spec.test_id))

        layout = QVBoxLayout(self)
        counts: dict = {}
        for r in self._results:
            counts[r.result] = counts.get(r.result, 0) + 1
        summary = "   ".join(f"{_STYLE[k][0]}: {counts[k]}"
                             for k in (RESULT_PASS, RESULT_FAIL, RESULT_NOT_EXERCISED)
                             if counts.get(k))
        head = QLabel(f"{len(self._results)} test(s)   ·   {summary}")
        head.setStyleSheet("font-weight:bold; font-size:13px;")
        layout.addWidget(head)

        note = QLabel("A negative test passes when the attempt it makes was "
                      "refused. “Not exercised” means the test did not run in "
                      "this capture — it is not a pass.")
        note.setWordWrap(True)
        note.setStyleSheet("color:#555; font-size:11px;")
        layout.addWidget(note)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        container = QWidget()
        inner = QVBoxLayout(container)
        inner.setContentsMargins(2, 2, 2, 2)
        inner.setSpacing(6)
        self._cards = [_ResultCard(r) for r in self._results]
        for card in self._cards:
            inner.addWidget(card)
        inner.addStretch(1)
        scroll.setWidget(container)
        layout.addWidget(scroll, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        export = QPushButton("Export Report…")
        export.clicked.connect(lambda: self._on_export and
                               self._on_export(self.accepted_results()))
        buttons.addButton(export, QDialogButtonBox.ActionRole)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accepted_results(self) -> List[TestResult]:
        for card in self._cards:
            card.result.accepted = card.accepted()
        return [c.result for c in self._cards if c.accepted()]
