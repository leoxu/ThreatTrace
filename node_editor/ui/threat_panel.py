"""
ThreatPanel — right-side dock listing all threats in the active diagram.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QCursor
from PySide6.QtWidgets import (
    QComboBox, QFrame, QHBoxLayout, QLabel, QPushButton,
    QScrollArea, QVBoxLayout, QWidget,
)

if TYPE_CHECKING:
    from ..threat import Threat, ThreatRegistry

from .. import verification as _verification
from ..cvss import cvss_base_score, cvss_severity, cvss_severity_color
from .collapsible import CollapsibleSection
from .mitigation_dialog import MITIGATED_COLOR, OPEN_COLOR

_PRIORITY_COLORS = {
    "High":   ("#c0392b", "#fff"),
    "Medium": ("#e67e22", "#fff"),
    "Low":    ("#27ae60", "#fff"),
}
_PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


class _ClickableCard(QFrame):
    """QFrame that emits clicked(edge_guid) when the card body is pressed."""
    clicked = Signal(str)

    def __init__(self, edge_guid: str, parent=None):
        super().__init__(parent)
        self._edge_guid = edge_guid
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self._edge_guid)
        super().mousePressEvent(event)


class ThreatPanel(QWidget):
    """Shows all threats in the active diagram."""

    threatEditRequested = Signal(str)    # emits threat guid
    threatRemoveRequested = Signal(str)  # emits threat guid
    threatSelected = Signal(str)         # emits edge_guid — selects the edge in the diagram

    def __init__(self, threats: "ThreatRegistry", parent=None):
        super().__init__(parent)
        self._threats = threats
        self._scene = None
        self._sc_names: Optional[dict] = None   # control id → name, per-refresh cache
        # Optional resolver from the main window: controls the project knows
        # about but the canvas does not (deleted, legacy, or in another
        # diagram). Without it their badges show a raw uuid.
        self._name_provider = None
        # Which threat groups are unfolded, kept across refreshes.
        self._group_expanded: dict = {"open": True, "mitigated": True}
        self._sequences = None                  # SequenceRegistry, set by the app

        root = QVBoxLayout(self)
        root.setContentsMargins(4, 4, 4, 4)
        root.setSpacing(4)

        header_row = QHBoxLayout()
        header_row.setSpacing(8)
        self._count_lbl = QLabel("No threats")
        self._count_lbl.setStyleSheet(
            "font-weight:bold; font-size:14px; padding:2px 4px;"
        )
        header_row.addWidget(self._count_lbl, 1)

        self._compliance_filter = QComboBox()
        self._compliance_filter.addItems(
            ["All", "No Compliance Tag", "Has CWE", "Has NIST", "Has OWASP"]
        )
        self._compliance_filter.setFixedHeight(22)
        self._compliance_filter.setStyleSheet("font-size:12px;")
        self._compliance_filter.currentIndexChanged.connect(self.refresh)
        header_row.addWidget(self._compliance_filter)

        # All / only what still needs work / only what a control already covers
        self._mitigation_filter = QComboBox()
        self._mitigation_filter.addItems(
            ["All threats", "Unmitigated only", "Mitigated only"]
        )
        self._mitigation_filter.setFixedHeight(22)
        self._mitigation_filter.setStyleSheet("font-size:12px;")
        self._mitigation_filter.setToolTip(
            "Filter by whether a security control is linked to the threat"
        )
        self._mitigation_filter.currentIndexChanged.connect(self.refresh)
        header_row.addWidget(self._mitigation_filter)
        root.addLayout(header_row)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        root.addWidget(scroll)

        self._container = QWidget()
        self._cards_layout = QVBoxLayout(self._container)
        self._cards_layout.setContentsMargins(2, 2, 2, 2)
        self._cards_layout.setSpacing(6)
        self._cards_layout.addStretch()
        scroll.setWidget(self._container)

    # ── public API ────────────────────────────────────────────────────────────

    def set_scene(self, scene) -> None:
        self._scene = scene

    def set_sequence_registry(self, sequences) -> None:
        """Needed to describe threats that belong to a sequence, not an edge."""
        self._sequences = sequences

    def refresh(self) -> None:
        self._sc_names = None   # controls may have been added/renamed/deleted
        layout = self._cards_layout
        # Remove all widgets except the trailing stretch. Taking an item out of
        # a layout does not unparent its widget, and deleteLater() only runs
        # when the event loop next turns — so without setParent(None) the old
        # cards keep painting over the new ones until then.
        while layout.count() > 1:
            item = layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()

        all_threats = list(self._threats.values())

        mf = self._mitigation_filter.currentText()
        cf = self._compliance_filter.currentText()
        threats = all_threats
        if mf == "Unmitigated only":
            threats = [t for t in threats if not t.mitigation_sc_ids]
        elif mf == "Mitigated only":
            threats = [t for t in threats if t.mitigation_sc_ids]
        if cf == "No Compliance Tag":
            threats = [t for t in threats if not t.cwe_ids and not t.nist_controls and not t.owasp_categories]
        elif cf == "Has CWE":
            threats = [t for t in threats if t.cwe_ids]
        elif cf == "Has NIST":
            threats = [t for t in threats if t.nist_controls]
        elif cf == "Has OWASP":
            threats = [t for t in threats if t.owasp_categories]

        total = len(all_threats)
        shown = len(threats)
        mitigated = sum(1 for t in all_threats if t.mitigation_sc_ids)
        label = (f"{total} threat{'s' if total != 1 else ''}" if shown == total
                 else f"{shown} of {total} threats")
        self._count_lbl.setText(f"{label}  ·  {mitigated} mitigated")

        if not all_threats:
            lbl = QLabel("No threats in this diagram.")
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet("color:#888; font-size:13px; padding:12px;")
            layout.insertWidget(0, lbl)
            return
        if not threats:
            if mf == "Unmitigated only":
                text, color = "All threats are mitigated.", "#27ae60"
            elif mf == "Mitigated only":
                text, color = "No threat has a security control linked yet.", "#c0392b"
            else:
                text, color = "No threat matches the current filter.", "#888"
            lbl = QLabel(text)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setStyleSheet(f"color:{color}; font-size:13px; padding:12px;")
            layout.insertWidget(0, lbl)
            return

        def _sort_key(t):
            cvss = 0.0
            if all([t.cvss_av, t.cvss_ac, t.cvss_pr, t.cvss_ui,
                    t.cvss_s, t.cvss_c, t.cvss_i, t.cvss_a]):
                cvss = cvss_base_score(t.cvss_av, t.cvss_ac, t.cvss_pr,
                                       t.cvss_ui, t.cvss_s, t.cvss_c,
                                       t.cvss_i, t.cvss_a)
            return (_PRIORITY_ORDER.get(t.priority, 3), -cvss, t.title)

        threats.sort(key=_sort_key)

        # Mitigated threats are grouped at the end rather than interleaved by
        # priority. They are a different kind of item: the open ones are work to
        # do, the mitigated ones are evidence to review. Sorting them together
        # buries a High that still needs a control among Highs that already have
        # one. Within each group the priority/CVSS order is unchanged.
        open_threats = [t for t in threats if not t.mitigation_sc_ids]
        mitigated_threats = [t for t in threats if t.mitigation_sc_ids]

        row = 0
        for key, group, title, color in (
                ("open", open_threats, "Open", OPEN_COLOR),
                ("mitigated", mitigated_threats, "Mitigated", MITIGATED_COLOR)):
            if not group:
                continue
            section = CollapsibleSection(f"{title} ({len(group)})",
                                         expanded=self._group_expanded.get(key, True))
            section.set_header_color(color)
            # Fold state is the user's, not the refresh's: this panel rebuilds
            # on every threat, control and selection change, and a group that
            # re-opened itself each time would be unusable.
            section.toggled.connect(
                lambda expanded, k=key: self._group_expanded.__setitem__(k, expanded))
            for threat in group:
                section.add_widget(self._make_card(threat))
            layout.insertWidget(row, section)
            row += 1

    # ── internal ──────────────────────────────────────────────────────────────

    def set_control_names_provider(self, provider) -> None:
        """Supply ``{control id: name}`` for controls outside the current scene."""
        self._name_provider = provider
        self._sc_names = None

    def _make_card(self, threat: "Threat") -> QFrame:
        frame = _ClickableCard(threat.edge_guid)
        frame.clicked.connect(self.threatSelected)
        frame.setFrameShape(QFrame.StyledPanel)
        no_compliance = not (threat.cwe_ids or threat.nist_controls or threat.owasp_categories)
        border_color = "#e67e22" if no_compliance else "#777"
        # Mitigated threats get a green left edge so they read differently from
        # the open ones at a glance.
        accent = "#27ae60" if threat.mitigation_sc_ids else border_color
        # Scoped to this frame by object name: QLabel is a QFrame, so an
        # unscoped "QFrame { border… }" draws a box around every child label.
        frame.setObjectName("threatRow")
        frame.setStyleSheet(
            f"QFrame#threatRow {{ border: 1px solid {border_color};"
            f" border-left: 4px solid {accent}; border-radius: 4px;"
            " background: #e8e8e8; margin: 1px 0; }"
            "QFrame#threatRow:hover { background: #d8d8d8; }"
        )
        vl = QVBoxLayout(frame)
        vl.setContentsMargins(8, 6, 8, 6)
        vl.setSpacing(3)

        # Priority badge + category
        header = QHBoxLayout()
        header.setSpacing(6)
        pri = threat.priority or "—"
        bg, fg = _PRIORITY_COLORS.get(pri, ("#555", "#fff"))
        badge = QLabel(pri)
        badge.setFixedHeight(20)
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(
            f"background:{bg}; color:{fg}; font-weight:bold; font-size:12px;"
            "border-radius:3px; padding:0 6px;"
        )
        header.addWidget(badge)

        # CVSS score badge (only when all metrics are set)
        if all([threat.cvss_av, threat.cvss_ac, threat.cvss_pr, threat.cvss_ui,
                threat.cvss_s, threat.cvss_c, threat.cvss_i, threat.cvss_a]):
            score = cvss_base_score(threat.cvss_av, threat.cvss_ac, threat.cvss_pr,
                                    threat.cvss_ui, threat.cvss_s, threat.cvss_c,
                                    threat.cvss_i, threat.cvss_a)
            sev = cvss_severity(score)
            cbg, cfg = cvss_severity_color(sev)
            cvss_badge = QLabel(f"CVSS {score:.1f}")
            cvss_badge.setFixedHeight(20)
            cvss_badge.setAlignment(Qt.AlignCenter)
            cvss_badge.setStyleSheet(
                f"background:{cbg}; color:{cfg}; font-weight:bold; font-size:11px;"
                "border-radius:3px; padding:0 5px;"
            )
            header.addWidget(cvss_badge)

        cat = QLabel(threat.category or "—")
        cat.setStyleSheet("color:#222; font-size:13px;")
        header.addWidget(cat, 1)
        vl.addLayout(header)

        # Title
        if threat.title:
            title_lbl = QLabel(threat.title)
            title_lbl.setWordWrap(True)
            title_lbl.setStyleSheet("font-weight:bold; color:#111; font-size:14px;")
            vl.addWidget(title_lbl)

        # Edge context
        edge_desc = self._edge_desc(threat)
        if edge_desc:
            edge_lbl = QLabel(edge_desc)
            edge_lbl.setStyleSheet("color:#555; font-size:12px; font-style:italic;")
            edge_lbl.setWordWrap(True)
            vl.addWidget(edge_lbl)

        # Short description or interaction context
        if threat.short_description:
            sd_lbl = QLabel(threat.short_description)
            sd_lbl.setWordWrap(True)
            sd_lbl.setStyleSheet("color:#333; font-size:12px; font-style:italic;")
            vl.addWidget(sd_lbl)

        # Asset info
        asset_parts = []
        if threat.asset:
            asset_parts.append(threat.asset)
        if threat.asset_property:
            asset_parts.append(f"({threat.asset_property.strip()})")
        if asset_parts:
            asset_lbl = QLabel("Asset: " + " ".join(asset_parts))
            asset_lbl.setWordWrap(True)
            asset_lbl.setStyleSheet("color:#444; font-size:12px;")
            vl.addWidget(asset_lbl)

        # Status
        if threat.status:
            status_lbl = QLabel(f"Status: {threat.status}")
            status_lbl.setStyleSheet("color:#333; font-size:13px;")
            vl.addWidget(status_lbl)

        if threat.ai_backends:
            backend_lbl = QLabel(f"AI Backends: {', '.join(threat.ai_backends)}")
            backend_lbl.setStyleSheet("color:#333; font-size:12px;")
            backend_lbl.setWordWrap(True)
            vl.addWidget(backend_lbl)

        # Compliance tags
        tag_parts = []
        if threat.cwe_ids:
            tag_parts.append(", ".join(threat.cwe_ids[:2]) + ("…" if len(threat.cwe_ids) > 2 else ""))
        if threat.nist_controls:
            tag_parts.append(", ".join(threat.nist_controls[:2]) + ("…" if len(threat.nist_controls) > 2 else ""))
        if threat.owasp_categories:
            tag_parts.append(threat.owasp_categories[0].split("–")[0].strip()
                             + ("…" if len(threat.owasp_categories) > 1 else ""))
        if tag_parts:
            comp_lbl = QLabel("  ·  ".join(tag_parts))
            comp_lbl.setStyleSheet("color:#555; font-size:11px; font-style:italic;")
            comp_lbl.setWordWrap(True)
            vl.addWidget(comp_lbl)

        # Mitigation indicator
        if threat.mitigation_sc_ids:
            names = self._control_names()
            listed = ", ".join(names.get(i, i) for i in threat.mitigation_sc_ids)
            # The register shows the claim and, next to it, whether it has been
            # verified — a mitigated-but-unverified threat is a different state
            # from a mitigated-and-proven one.
            status = _verification.threat_summary(threat)
            suffix = (f"  ·  {status}"
                      if status and status != _verification.LABEL_NOT_VERIFIED
                      else "  ·  not verified")
            mit_lbl = QLabel(f"Mitigated by {listed}{suffix}")
            mit_lbl.setToolTip("\n\n".join(
                f"{names.get(i, i)}: {note}"
                for i, note in (threat.mitigation_notes or {}).items() if note
            ))
            mit_lbl.setStyleSheet(
                "color:#fff; background:#27ae60; font-size:11px; font-weight:bold;"
                "border-radius:3px; padding:1px 5px;"
            )
            mit_lbl.setFixedHeight(18)
            vl.addWidget(mit_lbl)

        # Edit / Delete buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(4)
        btn_row.addStretch()
        edit_btn = QPushButton("Edit")
        edit_btn.setFixedHeight(22)
        edit_btn.clicked.connect(
            lambda _=False, g=threat.guid: self.threatEditRequested.emit(g)
        )
        btn_row.addWidget(edit_btn)
        del_btn = QPushButton("Delete")
        del_btn.setFixedHeight(22)
        del_btn.setStyleSheet("color: #e57373;")
        del_btn.clicked.connect(
            lambda _=False, g=threat.guid: self.threatRemoveRequested.emit(g)
        )
        btn_row.addWidget(del_btn)
        vl.addLayout(btn_row)

        return frame

    def _control_names(self) -> dict:
        """{control id: display name} for the current scene (cached per refresh).

        The unit is the **control definition**, not the container node: a
        container holds several controls and ``Threat.mitigation_sc_ids`` stores
        the definition's id. Mapping by node id — as this did before controls
        moved inside containers — matched nothing, so the badge fell back to
        showing a raw uuid.
        """
        if self._sc_names is not None:
            return self._sc_names
        names: dict = {}
        if self._name_provider is not None:
            try:
                names.update(self._name_provider())
            except Exception:                       # a badge is not worth a crash
                pass
        if self._scene is not None:
            from ..controls import read_controls
            from ..graphics.items import NodeItem
            for item in self._scene.items():
                if not isinstance(item, NodeItem):
                    continue
                if not str(item.properties().get("class", "")).startswith("security control"):
                    continue
                container = str(item.properties().get("name", item.title))
                for control in read_controls(item.properties(), item.node_id):
                    names[control.id] = (control.name if control.name == container
                                         else f"{container} ▸ {control.name}")
        self._sc_names = names
        return names

    def _edge_desc(self, threat: "Threat") -> str:
        # A threat with no edge belongs to a sequence as a whole.
        if not threat.edge_guid:
            seq = (self._sequences or {}).get(threat.sequence_guid)
            if seq is not None:
                return f"Sequence: {seq.name} ({len(seq.steps)} steps)"
            return "Sequence" if threat.sequence_guid else ""
        if self._scene is None:
            return ""
        from ..graphics.items import EdgeItem, NodeItem
        for item in self._scene.items():
            if isinstance(item, EdgeItem) and item.edge_id == threat.edge_guid:
                src_name = dst_name = ""
                if item.src and isinstance(item.src.parentItem(), NodeItem):
                    src_name = str(item.src.parentItem().properties().get("name", ""))
                if item.dst and isinstance(item.dst.parentItem(), NodeItem):
                    dst_name = str(item.dst.parentItem().properties().get("name", ""))
                if src_name or dst_name:
                    return f"{src_name} \u2192 {dst_name}"
        return ""
