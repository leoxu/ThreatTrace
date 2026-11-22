"""
Threat authoring dialogs.

ThreatDialog        — create or edit a single Threat
ThreatReviewDialog  — batch review of AI/rule-generated threat candidates
"""
from __future__ import annotations

import uuid
from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ..threat import Threat
from ..cvss import (ALL_METRICS, METRIC_LABELS, cvss_base_score,
                    cvss_severity, cvss_severity_color, cvss_vector_string)


# ── shared constants ──────────────────────────────────────────────────────────

CATEGORIES = [
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
]

PRIORITIES = ["High", "Medium", "Low"]

STATUSES = ["Open", "Mitigated", "Won't Fix", "Transferred", "Not Applicable"]

_PRIORITY_COLORS = {
    "High":   ("#c0392b", "#fff"),
    "Medium": ("#e67e22", "#fff"),
    "Low":    ("#27ae60", "#fff"),
}

_DIALOG_SS = """
    QDialog      { background: #e8e8e8; }
    QLabel       { color: #111; }
    QLineEdit    { color: #111; background: #f4f4f4;
                   border: 1px solid #bbb; border-radius: 3px; padding: 3px 5px; }
    QComboBox    { color: #111; background: #f4f4f4;
                   border: 1px solid #bbb; border-radius: 3px; padding: 3px 5px; }
    QComboBox QAbstractItemView { color: #111; background: #f4f4f4;
                                  selection-background-color: #ddd; }
    QPlainTextEdit { color: #111; background: #f4f4f4;
                     border: 1px solid #bbb; border-radius: 3px; padding: 3px 5px; }
    QPushButton  { color: #111; }
"""

_LABEL_W = 120


# ── ThreatDialog ──────────────────────────────────────────────────────────────

class ThreatDialog(QDialog):
    """Modal form for creating or editing a single Threat."""

    def __init__(self, parent=None, threat: Optional[Threat] = None,
                 sc_nodes: Optional[list] = None):
        super().__init__(parent)
        self.setWindowTitle("Edit Threat" if threat else "New Threat")
        self.setMinimumWidth(560)
        self.setMinimumHeight(600)
        self.setStyleSheet(_DIALOG_SS)

        outer = QVBoxLayout(self)
        outer.setSpacing(6)
        outer.setContentsMargins(8, 8, 8, 8)

        tabs = QTabWidget()
        outer.addWidget(tabs, 1)

        # ── Details tab ──────────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        tabs.addTab(scroll, "Details")

        form_w = QWidget()
        layout = QVBoxLayout(form_w)
        layout.setSpacing(5)
        layout.setContentsMargins(4, 4, 4, 4)
        scroll.setWidget(form_w)

        def _line(label: str, widget: QWidget) -> QWidget:
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(8)
            lbl = QLabel(label)
            lbl.setFixedWidth(_LABEL_W)
            lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            rl.addWidget(lbl)
            rl.addWidget(widget, 1)
            return row

        def _section(text: str) -> QLabel:
            lbl = QLabel(text)
            lbl.setStyleSheet(
                "font-weight:bold; color:#333; font-size:12px;"
                "padding-top:6px; padding-bottom:2px;"
            )
            return lbl

        def _text(placeholder: str = "", val: str = "", h_min: int = 60, h_max: int = 120) -> QPlainTextEdit:
            w = QPlainTextEdit(val)
            w.setPlaceholderText(placeholder)
            w.setMinimumHeight(h_min)
            w.setMaximumHeight(h_max)
            return w

        # ── Identity ────────────────────────────────────────────────────────
        layout.addWidget(_section("Identity"))

        self._title = QLineEdit(threat.title if threat else "")
        self._title.setPlaceholderText("Short threat title")
        layout.addWidget(_line("Title", self._title))

        self._category = QComboBox()
        self._category.addItems(CATEGORIES)
        if threat and threat.category in CATEGORIES:
            self._category.setCurrentText(threat.category)
        layout.addWidget(_line("Category", self._category))

        self._short_description = QLineEdit(threat.short_description if threat else "")
        self._short_description.setPlaceholderText("One-line summary")
        layout.addWidget(_line("Short Description", self._short_description))

        self._interaction = QLineEdit(threat.interaction if threat else "")
        self._interaction.setPlaceholderText("Data flow / interaction name")
        layout.addWidget(_line("Interaction", self._interaction))

        # ── Details ─────────────────────────────────────────────────────────
        layout.addWidget(_section("Details"))

        self._description = _text("Describe the threat mechanism…", threat.description if threat else "", 80, 140)
        layout.addWidget(QLabel("Description"))
        layout.addWidget(self._description)

        self._justification = _text("Why this threat applies…", threat.justification if threat else "", 50, 100)
        layout.addWidget(QLabel("Justification"))
        layout.addWidget(self._justification)

        self._damage_scenario = _text("Damage scenario…", threat.damage_scenario if threat else "", 50, 100)
        layout.addWidget(QLabel("Damage Scenario"))
        layout.addWidget(self._damage_scenario)

        # ── Classification ───────────────────────────────────────────────────
        layout.addWidget(_section("Classification"))

        ps_row = QWidget()
        ps_l = QHBoxLayout(ps_row)
        ps_l.setContentsMargins(0, 0, 0, 0)
        ps_l.setSpacing(8)

        pri_lbl = QLabel("Priority")
        pri_lbl.setFixedWidth(_LABEL_W)
        pri_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._priority = QComboBox()
        self._priority.addItems(PRIORITIES)
        current_pri = (threat.priority if threat else "") or "Medium"
        if current_pri in PRIORITIES:
            self._priority.setCurrentText(current_pri)

        sta_lbl = QLabel("Status")
        sta_lbl.setFixedWidth(60)
        sta_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        self._status = QComboBox()
        self._status.addItems(STATUSES)
        if threat and threat.status:
            idx = self._status.findText(threat.status)
            if idx >= 0:
                self._status.setCurrentIndex(idx)

        ps_l.addWidget(pri_lbl)
        ps_l.addWidget(self._priority, 1)
        ps_l.addWidget(sta_lbl)
        ps_l.addWidget(self._status, 2)
        layout.addWidget(ps_row)

        self._authorizer = QLineEdit(threat.authorizer if threat else "")
        self._authorizer.setPlaceholderText("Person who authorized risk acceptance")
        layout.addWidget(_line("Authorizer", self._authorizer))

        # ── Asset ────────────────────────────────────────────────────────────
        layout.addWidget(_section("Asset"))

        # Taller than the other free-text fields: a generated path is a single
        # arrow-joined line of 150-250 characters, which wraps to four or five
        # rows at this width. Anything shorter hides the end of the path — and
        # the end is the impact, the part you check first.
        self._attack_path = _text(
            "Steps the attacker takes, in order…",
            threat.attack_path if threat else "", 110, 220,
        )
        layout.addWidget(QLabel("Attack Path"))
        layout.addWidget(self._attack_path)

        self._asset = QLineEdit(threat.asset if threat else "")
        self._asset.setPlaceholderText("Asset name")
        layout.addWidget(_line("Asset", self._asset))

        self._asset_property = QLineEdit(threat.asset_property if threat else "")
        self._asset_property.setPlaceholderText("Asset security property (e.g. Confidentiality)")
        layout.addWidget(_line("Asset Property", self._asset_property))

        # ── Mitigations ───────────────────────────────────────────────────────
        layout.addWidget(_section("Mitigations"))

        self._mitigations = _text("Describe mitigation steps…", threat.mitigations if threat else "", 70, 130)
        layout.addWidget(QLabel("Recommended Mitigations"))
        layout.addWidget(self._mitigations)

        # ── Mitigation Controls ───────────────────────────────────────────────
        self._sc_checks: dict = {}   # node_id → QCheckBox
        already_linked = set(threat.mitigation_sc_ids) if threat else set()
        if sc_nodes:
            layout.addWidget(_section("Mitigation Controls"))
            sc_frame = QFrame()
            # Scoped by object name so the border does not cascade onto the
            # labels and check boxes inside (QLabel is itself a QFrame).
            sc_frame.setObjectName("scBox")
            sc_frame.setStyleSheet(
                "QFrame#scBox { border: 1px solid #bbb; border-radius: 4px;"
                " background: #f0f0f0; }"
            )
            sc_vl = QVBoxLayout(sc_frame)
            sc_vl.setContentsMargins(8, 4, 8, 4)
            sc_vl.setSpacing(3)
            for node_id, name in sc_nodes:
                cb = QCheckBox(name)
                cb.setChecked(node_id in already_linked)
                cb.setStyleSheet("color:#111;")
                self._sc_checks[node_id] = cb
                sc_vl.addWidget(cb)
            layout.addWidget(sc_frame)

        # ── Traceability ──────────────────────────────────────────────────────
        layout.addWidget(_section("Traceability"))

        self._bug_jira_link = QLineEdit(threat.bug_jira_link if threat else "")
        self._bug_jira_link.setPlaceholderText("Bug / Jira ticket URL or ID")
        layout.addWidget(_line("Bug/Jira Link", self._bug_jira_link))

        self._jama_link = QLineEdit(threat.jama_link if threat else "")
        self._jama_link.setPlaceholderText("JAMA requirement ID(s)")
        layout.addWidget(_line("JAMA Req. Link", self._jama_link))

        self._failure_mode_id = QLineEdit(threat.failure_mode_id if threat else "")
        self._failure_mode_id.setPlaceholderText("Failure Mode ID")
        layout.addWidget(_line("Failure Mode ID", self._failure_mode_id))

        self._failure_mode_description = _text(
            "Failure mode threat description…",
            threat.failure_mode_description if threat else "",
            50, 100,
        )
        layout.addWidget(QLabel("Failure Mode Description"))
        layout.addWidget(self._failure_mode_description)

        self._duplicate_threat = QLineEdit(threat.duplicate_threat if threat else "")
        self._duplicate_threat.setPlaceholderText("ID of duplicate threat (if any)")
        layout.addWidget(_line("Duplicate Threat", self._duplicate_threat))

        layout.addStretch()

        # ── Compliance tab ───────────────────────────────────────────────────
        tabs.addTab(self._build_cvss_tab(threat), "CVSS")
        tabs.addTab(self._build_compliance_tab(threat), "Compliance")

        # Dialog buttons (outside tabs)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        outer.addWidget(buttons)

    def _build_cvss_tab(self, threat: Optional[Threat]) -> QWidget:
        """The CVSS metrics, on their own tab.

        Eight combo boxes and a score badge crowded the Details form and pushed
        the fields people fill in on every threat — description, attack path,
        asset — below the fold. Scoring is a separate pass anyway, and often a
        skipped one.
        """
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setSpacing(6)
        vl.setContentsMargins(12, 12, 12, 12)

        heading = QLabel("CVSS v3.1 Score")
        heading.setStyleSheet(
            "font-weight:bold; color:#333; font-size:12px;"
            "padding-top:4px; padding-bottom:2px;"
        )
        vl.addWidget(heading)

        cvss_grid_w = QWidget()
        cvss_grid = QGridLayout(cvss_grid_w)
        cvss_grid.setContentsMargins(0, 0, 0, 0)
        cvss_grid.setHorizontalSpacing(12)
        cvss_grid.setVerticalSpacing(4)

        # Metric order: 4 rows × 2 columns
        _metric_order = [
            ("av", "ac"),
            ("pr", "ui"),
            ("s",  "c"),
            ("i",  "a"),
        ]
        self._cvss_combos: dict = {}
        t_cvss = {
            "av": threat.cvss_av if threat else "",
            "ac": threat.cvss_ac if threat else "",
            "pr": threat.cvss_pr if threat else "",
            "ui": threat.cvss_ui if threat else "",
            "s":  threat.cvss_s  if threat else "",
            "c":  threat.cvss_c  if threat else "",
            "i":  threat.cvss_i  if threat else "",
            "a":  threat.cvss_a  if threat else "",
        }
        for row_idx, (m1, m2) in enumerate(_metric_order):
            for col_idx, metric in enumerate((m1, m2)):
                lbl = QLabel(METRIC_LABELS[metric])
                lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
                lbl.setStyleSheet("color:#333; font-size:11px;")
                combo = QComboBox()
                combo.addItem("—", "")
                for code, label in ALL_METRICS[metric]:
                    combo.addItem(label, code)
                saved = t_cvss[metric]
                for idx in range(combo.count()):
                    if combo.itemData(idx) == saved:
                        combo.setCurrentIndex(idx)
                        break
                combo.currentIndexChanged.connect(self._update_cvss_score)
                self._cvss_combos[metric] = combo
                cvss_grid.addWidget(lbl,   row_idx, col_idx * 2)
                cvss_grid.addWidget(combo, row_idx, col_idx * 2 + 1)

        cvss_grid.setColumnStretch(1, 1)
        cvss_grid.setColumnStretch(3, 1)
        vl.addWidget(cvss_grid_w)

        self._cvss_score_lbl = QLabel("CVSS: not set")
        self._cvss_score_lbl.setAlignment(Qt.AlignCenter)
        self._cvss_score_lbl.setStyleSheet(
            "background:#555; color:#fff; font-weight:bold; font-size:12px;"
            "border-radius:4px; padding:4px 12px;"
        )
        self._cvss_score_lbl.setFixedHeight(28)
        vl.addWidget(self._cvss_score_lbl)
        vl.addStretch(1)
        self._update_cvss_score()
        return w

    def _build_compliance_tab(self, threat: Optional[Threat]) -> QWidget:
        from .compliance_data import OWASP_TOP10_2021
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setSpacing(10)
        vl.setContentsMargins(12, 12, 12, 12)

        def _section(text):
            lbl = QLabel(text)
            lbl.setStyleSheet(
                "font-weight:bold; color:#333; font-size:12px;"
                "padding-top:4px; padding-bottom:2px;"
            )
            return lbl

        # CWE
        vl.addWidget(_section("CWE IDs"))
        hint = QLabel("Comma-separated, e.g.  CWE-79, CWE-89")
        hint.setStyleSheet("color:#888; font-size:11px;")
        vl.addWidget(hint)
        self._cwe_edit = QLineEdit(", ".join(threat.cwe_ids) if threat else "")
        self._cwe_edit.setPlaceholderText("CWE-20, CWE-79, …")
        vl.addWidget(self._cwe_edit)

        # NIST 800-53
        vl.addWidget(_section("NIST 800-53 Controls"))
        hint2 = QLabel("Comma-separated, e.g.  AC-3, SI-10")
        hint2.setStyleSheet("color:#888; font-size:11px;")
        vl.addWidget(hint2)
        self._nist_edit = QLineEdit(", ".join(threat.nist_controls) if threat else "")
        self._nist_edit.setPlaceholderText("AC-3, AU-10, …")
        vl.addWidget(self._nist_edit)

        # OWASP Top 10 2021
        vl.addWidget(_section("OWASP Top 10 (2021)"))
        already = set(threat.owasp_categories) if threat else set()
        owasp_frame = QFrame()
        owasp_frame.setObjectName("owaspBox")
        owasp_frame.setStyleSheet(
            "QFrame#owaspBox { border: 1px solid #bbb; border-radius: 4px;"
            " background: #f0f0f0; }"
        )
        owasp_vl = QVBoxLayout(owasp_frame)
        owasp_vl.setContentsMargins(8, 4, 8, 4)
        owasp_vl.setSpacing(3)
        self._owasp_checks: dict = {}
        for cat in OWASP_TOP10_2021:
            cb = QCheckBox(cat)
            cb.setChecked(cat in already)
            cb.setStyleSheet("color:#111; font-size:12px;")
            self._owasp_checks[cat] = cb
            owasp_vl.addWidget(cb)
        vl.addWidget(owasp_frame)
        vl.addStretch()
        return w

    def _compliance_values(self) -> tuple:
        cwe = [x.strip() for x in self._cwe_edit.text().split(",") if x.strip()]
        nist = [x.strip() for x in self._nist_edit.text().split(",") if x.strip()]
        owasp = [cat for cat, cb in self._owasp_checks.items() if cb.isChecked()]
        return cwe, nist, owasp

    def _cvss_values(self) -> dict:
        return {m: (combo.currentData() or "") for m, combo in self._cvss_combos.items()}

    def _update_cvss_score(self) -> None:
        v = self._cvss_values()
        if any(val == "" for val in v.values()):
            self._cvss_score_lbl.setText("CVSS: not set")
            self._cvss_score_lbl.setStyleSheet(
                "background:#555; color:#fff; font-weight:bold; font-size:12px;"
                "border-radius:4px; padding:4px 12px;"
            )
            return
        score = cvss_base_score(v["av"], v["ac"], v["pr"], v["ui"],
                                v["s"],  v["c"],  v["i"],  v["a"])
        sev   = cvss_severity(score)
        bg, fg = cvss_severity_color(sev)
        self._cvss_score_lbl.setText(f"CVSS  {score:.1f}  —  {sev}")
        self._cvss_score_lbl.setStyleSheet(
            f"background:{bg}; color:{fg}; font-weight:bold; font-size:12px;"
            "border-radius:4px; padding:4px 12px;"
        )

    def _validate_and_accept(self) -> None:
        if not self._title.text().strip():
            self._title.setStyleSheet(
                "color: #111; background: #f4f4f4;"
                "border: 1px solid #c0392b; border-radius: 3px; padding: 3px 5px;"
            )
            self._title.setFocus()
            return
        self._title.setStyleSheet("")
        self.accept()

    def result_threat(
        self,
        source_guid: str,
        dest_guid: str,
        edge_guid: str,
    ) -> Threat:
        """Return a new Threat populated from the form fields."""
        v = self._cvss_values()
        vector = (cvss_vector_string(**v) if all(v.values()) else "")
        cwe, nist, owasp = self._compliance_values()
        return Threat(
            source_guid=source_guid,
            dest_guid=dest_guid,
            edge_guid=edge_guid,
            guid=str(uuid.uuid4()),
            title=self._title.text().strip(),
            category=self._category.currentText(),
            priority=self._priority.currentText(),
            status=self._status.currentText(),
            description=self._description.toPlainText().strip(),
            short_description=self._short_description.text().strip(),
            justification=self._justification.toPlainText().strip(),
            interaction=self._interaction.text().strip(),
            authorizer=self._authorizer.text().strip(),
            bug_jira_link=self._bug_jira_link.text().strip(),
            jama_link=self._jama_link.text().strip(),
            damage_scenario=self._damage_scenario.toPlainText().strip(),
            attack_path=self._attack_path.toPlainText().strip(),
            asset=self._asset.text().strip(),
            asset_property=self._asset_property.text().strip(),
            mitigations=self._mitigations.toPlainText().strip(),
            failure_mode_id=self._failure_mode_id.text().strip(),
            failure_mode_description=self._failure_mode_description.toPlainText().strip(),
            duplicate_threat=self._duplicate_threat.text().strip(),
            cvss_av=v["av"], cvss_ac=v["ac"], cvss_pr=v["pr"], cvss_ui=v["ui"],
            cvss_s=v["s"],   cvss_c=v["c"],   cvss_i=v["i"],   cvss_a=v["a"],
            cvss_vector=vector,
            mitigation_sc_ids=[nid for nid, cb in self._sc_checks.items() if cb.isChecked()],
            cwe_ids=cwe, nist_controls=nist, owasp_categories=owasp,
        )

    def apply_to_threat(self, threat: Threat) -> None:
        """Update an existing Threat in-place from the form fields."""
        threat.title = self._title.text().strip()
        threat.category = self._category.currentText()
        threat.priority = self._priority.currentText()
        threat.status = self._status.currentText()
        threat.description = self._description.toPlainText().strip()
        threat.short_description = self._short_description.text().strip()
        threat.justification = self._justification.toPlainText().strip()
        threat.interaction = self._interaction.text().strip()
        threat.authorizer = self._authorizer.text().strip()
        threat.bug_jira_link = self._bug_jira_link.text().strip()
        threat.jama_link = self._jama_link.text().strip()
        threat.damage_scenario = self._damage_scenario.toPlainText().strip()
        threat.attack_path = self._attack_path.toPlainText().strip()
        threat.asset = self._asset.text().strip()
        threat.asset_property = self._asset_property.text().strip()
        threat.mitigations = self._mitigations.toPlainText().strip()
        threat.failure_mode_id = self._failure_mode_id.text().strip()
        threat.failure_mode_description = self._failure_mode_description.toPlainText().strip()
        threat.duplicate_threat = self._duplicate_threat.text().strip()
        v = self._cvss_values()
        threat.cvss_av = v["av"];  threat.cvss_ac = v["ac"]
        threat.cvss_pr = v["pr"];  threat.cvss_ui = v["ui"]
        threat.cvss_s  = v["s"];   threat.cvss_c  = v["c"]
        threat.cvss_i  = v["i"];   threat.cvss_a  = v["a"]
        threat.cvss_vector = cvss_vector_string(**v) if all(v.values()) else ""
        threat.mitigation_sc_ids = [nid for nid, cb in self._sc_checks.items() if cb.isChecked()]
        cwe, nist, owasp = self._compliance_values()
        threat.cwe_ids = cwe
        threat.nist_controls = nist
        threat.owasp_categories = owasp


# ── ThreatReviewDialog ────────────────────────────────────────────────────────

class _ReviewRow(QFrame):
    """One checkable threat row in the review dialog."""

    def __init__(self, threat: Threat, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setObjectName("reviewRow")
        self.setStyleSheet(
            "QFrame#reviewRow { border: 1px solid #777; border-radius: 4px; "
            "background: #e8e8e8; margin: 1px 0; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(3)

        # Top row: checkbox + priority badge + category
        top = QHBoxLayout()
        top.setSpacing(6)

        self._check = QCheckBox()
        self._check.setChecked(True)
        top.addWidget(self._check)

        pri = threat.priority or "Low"
        bg, fg = _PRIORITY_COLORS.get(pri, ("#555", "#fff"))
        badge = QLabel(pri)
        badge.setFixedHeight(18)
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(
            f"background:{bg}; color:{fg}; font-weight:bold; font-size:10px;"
            "border-radius:3px; padding:0 5px;"
        )
        top.addWidget(badge)

        cat = QLabel(threat.category or "—")
        cat.setStyleSheet("color:#222; font-size:11px;")
        top.addWidget(cat, 1)

        backend_text = ", ".join(threat.ai_backends) if threat.ai_backends else "—"
        backend_lbl = QLabel(f"AI: {backend_text}")
        backend_lbl.setStyleSheet("color:#444; font-size:11px;")
        top.addWidget(backend_lbl)

        layout.addLayout(top)

        # Title
        title_lbl = QLabel(threat.title)
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet(
            "font-weight:bold; color:#111; font-size:12px; padding-left:22px;"
        )
        layout.addWidget(title_lbl)

        # Description (shown by default — reviewers need context to decide)
        if threat.description:
            desc = QLabel(threat.description)
            desc.setWordWrap(True)
            desc.setStyleSheet("color:#222; font-size:11px; padding-left:22px;")
            layout.addWidget(desc)

        # The attack path is the fastest way to spot a threat that does not
        # apply: a step the attacker cannot actually take sinks the whole row.
        if threat.attack_path:
            path = QLabel(threat.attack_path)
            path.setWordWrap(True)
            path.setStyleSheet(
                "color:#444; font-size:11px; padding-left:22px; font-style:italic;"
            )
            layout.addWidget(path)

    def is_checked(self) -> bool:
        return self._check.isChecked()

    def set_checked(self, value: bool) -> None:
        self._check.setChecked(value)


class ThreatReviewDialog(QDialog):
    """Batch-review dialog for AI/rule-generated threat candidates."""

    def __init__(self, threats: List[Threat], parent=None, backend_status_lines: Optional[List[str]] = None):
        super().__init__(parent)
        n = len(threats)
        self.setWindowTitle(f"Review Generated Threats ({n})")
        self.setMinimumWidth(540)
        self.setMinimumHeight(420)

        self._threats = threats
        self._rows: List[_ReviewRow] = []

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        info = QLabel(
            f"{n} threat{'s' if n != 1 else ''} generated. "
            "Uncheck any you do not want to add, then click <b>Add Selected</b>."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color:#aaa; font-size:12px;")
        layout.addWidget(info)

        if backend_status_lines:
            backend_info = QLabel("\n".join(backend_status_lines))
            backend_info.setWordWrap(True)
            backend_info.setTextFormat(Qt.PlainText)
            backend_info.setTextInteractionFlags(Qt.TextSelectableByMouse)
            backend_info.setStyleSheet("color:#555; font-size:11px;")
            layout.addWidget(backend_info)

        # Select all / none controls
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

        # Scrollable list
        list_w = QWidget()
        list_layout = QVBoxLayout(list_w)
        list_layout.setContentsMargins(0, 0, 0, 0)
        list_layout.setSpacing(4)

        for t in threats:
            row = _ReviewRow(t)
            self._rows.append(row)
            list_layout.addWidget(row)
        list_layout.addStretch()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(list_w)
        scroll.setFrameShape(QFrame.NoFrame)
        layout.addWidget(scroll, 1)

        # Dialog buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Add Selected")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def accepted_threats(self) -> List[Threat]:
        """Return only the threats whose checkboxes are checked."""
        return [t for t, r in zip(self._threats, self._rows) if r.is_checked()]
