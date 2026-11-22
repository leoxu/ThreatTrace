"""
Mitigation coverage review dialog.

Shows, per threat in a security control's scope, whether the control was judged
to mitigate it and why. The user accepts (or rejects) each verdict before it is
linked to the threat — the analysis proposes, the reviewer decides.
"""
from __future__ import annotations

from typing import List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from ..mitigation import CoverageScope, ThreatAssessment

MITIGATED_COLOR = "#27ae60"     # green — control covers this threat
OPEN_COLOR = "#c0392b"          # red   — threat remains open


class _VerdictRow(QFrame):
    """One assessed threat: verdict badge, title, rationale and a check box."""

    def __init__(self, assessment: ThreatAssessment, parent=None):
        super().__init__(parent)
        self.assessment = assessment
        accent = MITIGATED_COLOR if assessment.mitigated else OPEN_COLOR
        self.setFrameShape(QFrame.StyledPanel)
        # Scoped by object name: QLabel is a QFrame, so an unscoped
        # "QFrame { border… }" rule boxes every child label as well.
        self.setObjectName("verdictRow")
        self.setStyleSheet(
            "QFrame#verdictRow { border: 1px solid #777; border-left: 4px solid "
            + accent
            + "; border-radius: 4px; background: #e8e8e8; margin: 1px 0; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        top = QHBoxLayout()
        top.setSpacing(6)

        self._check = QCheckBox()
        self._check.setChecked(assessment.mitigated)
        self._check.setToolTip(
            "Checked: link this control to the threat as a mitigation.\n"
            "Unchecked: leave the threat open (and unlink this control if it "
            "was linked before)."
        )
        top.addWidget(self._check)

        badge = QLabel("MITIGATED" if assessment.mitigated else "NOT MITIGATED")
        badge.setFixedHeight(18)
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(
            f"background:{accent}; color:#fff; font-weight:bold; font-size:10px;"
            "border-radius:3px; padding:0 5px;"
        )
        top.addWidget(badge)

        edge = QLabel(assessment.edge_label)
        edge.setStyleSheet("color:#333; font-size:11px;")
        top.addWidget(edge, 1)

        if assessment.backend:
            backend = QLabel(assessment.backend)
            backend.setStyleSheet("color:#555; font-size:11px;")
            top.addWidget(backend)

        layout.addLayout(top)

        title = QLabel(assessment.threat_title)
        title.setWordWrap(True)
        title.setStyleSheet(
            "font-weight:bold; color:#111; font-size:12px; padding-left:22px;"
        )
        layout.addWidget(title)

        if assessment.rationale:
            rationale = QLabel(assessment.rationale)
            rationale.setWordWrap(True)
            rationale.setStyleSheet("color:#222; font-size:11px; padding-left:22px;")
            layout.addWidget(rationale)

        if assessment.residual_risk:
            residual = QLabel(f"Residual risk: {assessment.residual_risk}")
            residual.setWordWrap(True)
            residual.setStyleSheet(
                f"color:{OPEN_COLOR}; font-size:11px; padding-left:22px;"
            )
            layout.addWidget(residual)

    def is_checked(self) -> bool:
        return self._check.isChecked()

    def set_checked(self, value: bool) -> None:
        self._check.setChecked(value)


class MitigationReviewDialog(QDialog):
    """Review which threats security controls mitigate before linking them.

    Handles one control (the per-control coverage check) or several at once
    (the pass that runs over every control after threat generation), in which
    case each control's verdicts appear under its own heading.
    """

    def __init__(self, scope: CoverageScope, assessments: List[ThreatAssessment],
                 parent=None, backend_status_lines: Optional[List[str]] = None,
                 groups: Optional[List[Tuple[CoverageScope, List[ThreatAssessment]]]] = None):
        super().__init__(parent)
        self._rows: List[_VerdictRow] = []
        self._groups: List[Tuple[CoverageScope, List[_VerdictRow]]] = []

        if groups is None:
            groups = [(scope, assessments)]
        multi = len(groups) > 1

        total_assessed = sum(len(a) for _, a in groups)
        mitigated = sum(1 for _, a in groups for x in a if x.mitigated)
        self.setWindowTitle(
            f"Mitigation Coverage — {len(groups)} controls" if multi
            else f"Mitigation Coverage — {groups[0][0].control.name}"
        )
        self.setMinimumWidth(600)
        self.setMinimumHeight(460)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        if multi:
            info = QLabel(
                f"{len(groups)} security control(s) cover threats in this model. "
                f"{total_assessed} verdict(s) — <b>{mitigated} mitigated</b>.<br>"
                "Confirm the ones to link; unchecked threats stay open."
            )
        else:
            g_scope = groups[0][0]
            slot_names = ", ".join(
                f"{s.asset_name}.{s.slot_name}" for s in g_scope.slots
            ) or "(none)"
            info = QLabel(
                f"<b>{g_scope.control.name}</b> ({g_scope.control.control_type or 'no type'}) "
                f"covers {len(g_scope.slots)} asset interface(s): {slot_names}<br>"
                f"{g_scope.edge_count} connection(s) in scope, {total_assessed} threat(s) "
                f"assessed — <b>{mitigated} mitigated</b>."
            )
        info.setWordWrap(True)
        info.setStyleSheet("font-size:12px;")
        layout.addWidget(info)

        if backend_status_lines:
            status = QLabel("\n".join(backend_status_lines))
            status.setWordWrap(True)
            status.setTextFormat(Qt.PlainText)
            status.setTextInteractionFlags(Qt.TextSelectableByMouse)
            status.setStyleSheet("color:#555; font-size:11px;")
            layout.addWidget(status)

        ctrl_row = QHBoxLayout()
        sel_all = QPushButton("Select All")
        sel_none = QPushButton("Deselect All")
        sel_all.setFixedHeight(24)
        sel_none.setFixedHeight(24)
        sel_all.clicked.connect(lambda: [r.set_checked(True) for r in self._rows])
        sel_none.clicked.connect(lambda: [r.set_checked(False) for r in self._rows])
        ctrl_row.addWidget(sel_all)
        ctrl_row.addWidget(sel_none)
        ctrl_row.addStretch()
        layout.addLayout(ctrl_row)

        list_w = QWidget()
        list_layout = QVBoxLayout(list_w)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(4)
        for g_scope, g_assessments in groups:
            g_rows: List[_VerdictRow] = []
            if multi:
                n_mit = sum(1 for a in g_assessments if a.mitigated)
                head = QLabel(
                    f"{g_scope.control.name} "
                    f"({g_scope.control.control_type or 'no type'}) — "
                    f"{n_mit}/{len(g_assessments)} mitigated"
                )
                head.setWordWrap(True)
                head.setStyleSheet(
                    "font-weight:bold; font-size:12px; color:#111;"
                    "border-bottom:1px solid #bbb; padding:6px 0 2px 0;"
                )
                list_layout.addWidget(head)
            # Mitigated verdicts first — that is what the reviewer is here to confirm.
            for a in sorted(g_assessments, key=lambda x: (not x.mitigated, x.edge_label)):
                row = _VerdictRow(a)
                self._rows.append(row)
                g_rows.append(row)
                list_layout.addWidget(row)
            self._groups.append((g_scope, g_rows))
        list_layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(list_w)
        scroll.setFrameShape(QFrame.NoFrame)
        layout.addWidget(scroll, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Apply Selected")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    @staticmethod
    def _reviewed(row: "_VerdictRow") -> ThreatAssessment:
        a = row.assessment
        return ThreatAssessment(
            threat_guid=a.threat_guid,
            threat_title=a.threat_title,
            edge_label=a.edge_label,
            mitigated=row.is_checked(),
            rationale=a.rationale,
            residual_risk=a.residual_risk,
            backend=a.backend,
        )

    def accepted_assessments(self) -> List[ThreatAssessment]:
        """Every assessment, with ``mitigated`` set to the reviewer's choice.

        Unchecked rows are returned as not-mitigated so applying the result also
        removes a link this control had from an earlier run.
        """
        return [self._reviewed(row) for row in self._rows]

    def accepted_by_control(self) -> List[Tuple[CoverageScope, List[ThreatAssessment]]]:
        """The reviewer's choices grouped per control, for ``apply_assessments``."""
        return [(scope, [self._reviewed(r) for r in rows]) for scope, rows in self._groups]
