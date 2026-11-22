"""
ThreatCard — the foldable card that shows one Threat.

Shared by the edge properties panel and the sequence panel so a threat looks and
behaves the same wherever it is listed.
"""
from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from .. import verification as _verification
from ..threat import Threat
from .collapsible import invalidate_layout_chain

# How each verification state reads at a glance: verified is green, contradicted
# is red, unverified is simply grey — absent evidence is not a failure.
_VERIFY_ICON = {
    _verification.LABEL_NOT_VERIFIED: "○",
    _verification.LABEL_SOURCE: "◑",
    _verification.LABEL_RUNTIME: "◑",
    _verification.LABEL_BOTH: "●",
    _verification.LABEL_NOT_IN_SOURCE: "✗",
    _verification.LABEL_FAILED_RUNTIME: "✗",
    _verification.LABEL_INCONCLUSIVE: "?",
}
_VERIFY_COLOR = {
    _verification.LABEL_NOT_VERIFIED: "#777",
    _verification.LABEL_SOURCE: "#1a6fa8",
    _verification.LABEL_RUNTIME: "#1a6fa8",
    _verification.LABEL_BOTH: "#27ae60",
    _verification.LABEL_NOT_IN_SOURCE: "#c0392b",
    _verification.LABEL_FAILED_RUNTIME: "#c0392b",
    _verification.LABEL_INCONCLUSIVE: "#e67e22",
}


def _verify_tooltip(threat, control_id: str) -> str:
    """The evidence behind the status: what was found, where, and when."""
    entries = (getattr(threat, "verification", {}) or {}).get(control_id) or {}
    if not entries:
        return ("No verification has been run for this control.\n"
                "Tools → Static Verification checks the source code.")
    lines = []
    for phase in (_verification.PHASE_STATIC, _verification.PHASE_DYNAMIC):
        entry = entries.get(phase)
        if not entry:
            continue
        head = f"{phase.capitalize()}: {entry.get('result', '?')}"
        if entry.get("confidence"):
            head += f" (confidence {entry['confidence']})"
        if entry.get("at"):
            head += f" — {entry['at']}"
        lines.append(head)
        if entry.get("revision"):
            lines.append(f"  revision {entry['revision']}")
        for citation in entry.get("citations", [])[:4]:
            start = citation.get("line_start") or ""
            lines.append(f"  {citation.get('file', '?')}"
                         + (f":{start}" if start else ""))
        if entry.get("rationale"):
            lines.append(f"  {entry['rationale'][:300]}")
    return "\n".join(lines)


# Green accent used everywhere a threat is marked as mitigated by a control.
MITIGATED_COLOR = "#27ae60"

PRIORITY_COLORS = {
    "High":     ("#c0392b", "#fff"),
    "Medium":   ("#e67e22", "#fff"),
    "Low":      ("#27ae60", "#fff"),
}


class ThreatCard(QFrame):
    """Foldable card displaying one Threat.

    Collapsed it is a single line — priority, category, mitigated badge and the
    title — so a connection with a dozen threats stays scannable; expanded it
    shows status, description, recommended mitigations, the linked controls and
    the edit/delete actions.

    ``control_names`` maps a security-control node id to its display name so a
    mitigated threat can name the controls that cover it.
    """

    editRequested = Signal(str)     # threat guid
    removeRequested = Signal(str)   # threat guid

    def __init__(self, threat: Threat, control_names: Optional[dict] = None,
                 expanded: bool = True, subtitle: str = "", parent=None):
        super().__init__(parent)
        self.guid = threat.guid
        self._guid = threat.guid          # kept for existing call sites
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)
        mitigated = bool(threat.mitigation_sc_ids)
        # Mitigated threats are marked with a green accent; open ones stay grey.
        accent = MITIGATED_COLOR if mitigated else "#777"
        # Scoped by object name: a plain "QFrame { … }" rule would cascade onto
        # every child QLabel (QLabel is a QFrame) and box each line of text.
        self.setObjectName("threatCard")
        # Exactly as tall as its contents: it must not soak up the panel's
        # spare height when folded, nor be squeezed when the panel scrolls.
        # heightForWidth must be declared on the policy, or Qt sizes the card
        # from its (taller) width-independent sizeHint when computing the form's
        # minimum, and the surplus turns into gaps between the sections.
        # Minimum (grow, never shrink) + heightForWidth: a Fixed item is sized
        # from sizeHint and the layout ignores hfw, so a card with wrapped text
        # was laid out ~30px short — clipping its content, and leaving the
        # difference as slack the layout centred as a gap around the section.
        policy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)
        self.setStyleSheet(
            "QFrame#threatCard { border: 1px solid #777; border-left: 4px solid "
            + accent
            + "; border-radius: 4px; background: #e8e8e8; margin: 2px 0; }"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(4)

        # ── header row: priority badge + category ──────────────────────────
        header = QHBoxLayout()
        header.setSpacing(6)

        pri = threat.priority or "—"
        bg, fg = PRIORITY_COLORS.get(pri, ("#555", "#fff"))
        badge = QLabel(pri)
        badge.setFixedHeight(20)
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(
            f"background:{bg}; color:{fg}; font-weight:bold; font-size:10px;"
            "border-radius:3px; padding:0 6px;"
        )
        header.addWidget(badge)

        self._toggle = QToolButton()
        self._toggle.setStyleSheet("QToolButton { border: none; color: #333; }")
        self._toggle.setFixedSize(16, 18)
        self._toggle.setCheckable(True)
        self._toggle.setChecked(expanded)
        self._toggle.setToolTip("Show / hide this threat's details")
        self._toggle.clicked.connect(lambda checked: self.set_expanded(checked))
        header.addWidget(self._toggle)

        cat = QLabel(threat.category or "—")
        cat.setStyleSheet("color:#222; font-size:11px;")
        header.addWidget(cat, 1)

        if mitigated:
            mit_badge = QLabel("MITIGATED")
            mit_badge.setFixedHeight(20)
            mit_badge.setAlignment(Qt.AlignCenter)
            mit_badge.setStyleSheet(
                f"background:{MITIGATED_COLOR}; color:#fff; font-weight:bold;"
                "font-size:10px; border-radius:3px; padding:0 6px;"
            )
            header.addWidget(mit_badge)

        layout.addLayout(header)

        # ── title (always visible — the collapsed summary) ──────────────────
        if threat.title:
            title = QLabel(threat.title)
            title.setWordWrap(True)
            title.setStyleSheet("font-weight:bold; color:#111; font-size:12px;")
            title.setCursor(Qt.PointingHandCursor)
            layout.addWidget(title)

        # ── details, hidden when the card is folded ────────────────────────
        self._body = QWidget()
        body_layout = QVBoxLayout(self._body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(4)
        layout.addWidget(self._body)
        layout = body_layout          # everything below goes into the fold body

        # ── caller-supplied line (e.g. a sequence scope) ───────────────────
        if subtitle:
            sub = QLabel(subtitle)
            sub.setWordWrap(True)
            sub.setStyleSheet("color:#555; font-size:10px; font-style:italic;")
            layout.addWidget(sub)

        # ── status ─────────────────────────────────────────────────────────
        if threat.status:
            status = QLabel(f"Status: {threat.status}")
            status.setStyleSheet("color:#333; font-size:11px;")
            layout.addWidget(status)

        if threat.ai_backends:
            backend_names = ", ".join(threat.ai_backends)
            backend = QLabel(f"AI Backends: {backend_names}")
            backend.setStyleSheet("color:#333; font-size:11px;")
            layout.addWidget(backend)

        # ── description ────────────────────────────────────────────────────
        if threat.description and threat.description.strip():
            layout.addWidget(ThreatCard._section("Description", threat.description.strip()))

        # ── attack path ────────────────────────────────────────────────────
        # Between the description and the mitigations on purpose: it is the
        # bridge from "what could go wrong" to "what we do about it".
        if threat.attack_path and threat.attack_path.strip():
            layout.addWidget(ThreatCard._section("Attack path", threat.attack_path.strip()))

        # ── mitigations ────────────────────────────────────────────────────
        if threat.mitigations and threat.mitigations.strip():
            layout.addWidget(ThreatCard._section("Mitigations", threat.mitigations.strip()))

        # ── mitigating security controls (green) ───────────────────────────
        if mitigated:
            names = control_names or {}
            for sc_id in threat.mitigation_sc_ids:
                name = names.get(sc_id, sc_id)
                lbl = QLabel(f"✓ Mitigated by {name}")
                lbl.setWordWrap(True)
                lbl.setStyleSheet(
                    f"color:{MITIGATED_COLOR}; font-size:11px; font-weight:bold;"
                )
                layout.addWidget(lbl)

                # Whether that control was actually found in the built system.
                # "Not verified" is shown too: a design-phase claim with no
                # evidence behind it should look different from a verified one.
                status = _verification.label(threat, sc_id)
                status_lbl = QLabel(f"    {_VERIFY_ICON.get(status, '○')} {status}")
                status_lbl.setWordWrap(True)
                status_lbl.setToolTip(_verify_tooltip(threat, sc_id))
                status_lbl.setStyleSheet(
                    f"color:{_VERIFY_COLOR.get(status, '#777')}; font-size:11px;")
                layout.addWidget(status_lbl)

                note = (threat.mitigation_notes or {}).get(sc_id, "").strip()
                if note:
                    note_lbl = QLabel(note)
                    note_lbl.setWordWrap(True)
                    note_lbl.setStyleSheet("color:#2c6e49; font-size:11px; padding-left:12px;")
                    layout.addWidget(note_lbl)

        # ── actions ────────────────────────────────────────────────────────
        actions = QWidget()
        act_l = QHBoxLayout(actions)
        act_l.setContentsMargins(0, 2, 0, 0)
        act_l.setSpacing(4)
        act_l.addStretch(1)
        edit_btn = QPushButton("Edit")
        edit_btn.setFixedHeight(22)
        edit_btn.clicked.connect(lambda: self.editRequested.emit(self._guid))
        act_l.addWidget(edit_btn)
        del_btn = QPushButton("Delete")
        del_btn.setFixedHeight(22)
        del_btn.setStyleSheet("color: #e57373;")
        del_btn.clicked.connect(lambda: self.removeRequested.emit(self._guid))
        act_l.addWidget(del_btn)
        layout.addWidget(actions)

        self.set_expanded(expanded)

    # ── folding ────────────────────────────────────────────────────────────

    def is_expanded(self) -> bool:
        return self._toggle.isChecked()

    def set_expanded(self, expanded: bool) -> None:
        self._toggle.setChecked(expanded)
        self._toggle.setText("▾" if expanded else "▸")
        self._body.setVisible(expanded)
        # The card is height-for-width and may sit several layouts deep (inside
        # an Open/Mitigated group, inside the Threats section). Without this the
        # outer layouts keep the pre-fold height and the folded card leaves a
        # tall empty slab behind it.
        invalidate_layout_chain(self)

    def mousePressEvent(self, event):  # type: ignore[override]
        # Clicking the card's own surface folds/unfolds it; clicks that land on
        # a child widget (buttons, selectable text) never reach here.
        if event.button() == Qt.LeftButton:
            self.set_expanded(not self.is_expanded())
            event.accept()
            return
        super().mousePressEvent(event)

    @staticmethod
    def _section(heading: str, text: str) -> QWidget:
        w = QWidget()
        vl = QVBoxLayout(w)
        vl.setContentsMargins(0, 2, 0, 0)
        vl.setSpacing(1)
        lbl = QLabel(heading)
        lbl.setStyleSheet("color:#333; font-size:10px; font-weight:bold;")
        body = QLabel(text)
        body.setWordWrap(True)
        body.setStyleSheet("color:#111; font-size:11px;")
        vl.addWidget(lbl)
        vl.addWidget(body)
        return w
