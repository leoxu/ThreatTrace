from __future__ import annotations

from typing import Callable, Optional, List

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QColorDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
    QFrame,
)

from ..sequence import DEFAULT_SEQUENCE_COLOR, Sequence, SequenceRegistry, edge_sequence_steps, new_sequence
from .collapsible import CollapsibleSection
from .mitigation_dialog import MITIGATED_COLOR, OPEN_COLOR
from .threat_card import ThreatCard


class _StepRow(QWidget):
    """A single step row: index + description + reorder + remove buttons."""

    move_up = Signal()
    move_down = Signal()
    remove = Signal()
    selected = Signal()

    def __init__(self, index: int, desc: str, is_first: bool, is_last: bool):
        super().__init__()
        self.setCursor(Qt.PointingHandCursor)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 1, 0, 1)
        layout.setSpacing(4)

        idx_lbl = QLabel(str(index))
        idx_lbl.setFixedWidth(20)
        idx_lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        idx_lbl.setStyleSheet("color: #888; font-size: 11px;")
        layout.addWidget(idx_lbl)

        desc_lbl = QLabel(desc)
        desc_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        desc_lbl.setStyleSheet("font-size: 11px;")
        desc_lbl.setToolTip(desc)
        layout.addWidget(desc_lbl, 1)

        up_btn = QPushButton("↑")
        up_btn.setFixedSize(22, 22)
        up_btn.setEnabled(not is_first)
        up_btn.clicked.connect(self.move_up.emit)
        layout.addWidget(up_btn)

        dn_btn = QPushButton("↓")
        dn_btn.setFixedSize(22, 22)
        dn_btn.setEnabled(not is_last)
        dn_btn.clicked.connect(self.move_down.emit)
        layout.addWidget(dn_btn)

        rm_btn = QPushButton("×")
        rm_btn.setFixedSize(22, 22)
        rm_btn.setStyleSheet("color: #e57373;")
        rm_btn.clicked.connect(self.remove.emit)
        layout.addWidget(rm_btn)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.selected.emit()
        super().mousePressEvent(event)


class _ColorButton(QPushButton):
    colorChanged = Signal(str)

    def __init__(self, color: str):
        super().__init__()
        self.setFixedSize(32, 22)
        self._color = color
        self._apply()

    def _apply(self):
        self.setStyleSheet(
            f"background:{self._color}; border:1px solid #555; border-radius:3px;"
        )

    def color(self) -> str:
        return self._color

    def set_color(self, c: str) -> None:
        self._color = c
        self._apply()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            c = QColorDialog.getColor(QColor(self._color), self, "Pick Sequence Color")
            if c.isValid():
                self._color = c.name()
                self._apply()
                self.colorChanged.emit(self._color)
        else:
            super().mousePressEvent(event)


class _StepPropRow(QWidget):
    """A key + multi-line value row in the step property editor."""
    remove = Signal()

    def __init__(self, key: str, value: str):
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 2, 0, 2)
        outer.setSpacing(2)

        # Top row: key field + remove button
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(4)

        self._key_edit = QLineEdit(key)
        self._key_edit.setPlaceholderText("key")
        top_row.addWidget(self._key_edit, 1)

        rm_btn = QPushButton("×")
        rm_btn.setFixedSize(22, 22)
        rm_btn.setStyleSheet("color: #e57373;")
        rm_btn.clicked.connect(self.remove.emit)
        top_row.addWidget(rm_btn)
        outer.addLayout(top_row)

        # Value: multi-line text edit
        self._val_edit = QPlainTextEdit(value)
        self._val_edit.setPlaceholderText("value")
        self._val_edit.setMinimumHeight(48)
        self._val_edit.setMaximumHeight(120)
        self._val_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        outer.addWidget(self._val_edit)

    def key(self) -> str:
        return self._key_edit.text().strip()

    def value(self) -> str:
        return self._val_edit.toPlainText()

    def set_changed_callback(self, fn: Callable) -> None:
        self._key_edit.editingFinished.connect(fn)
        self._val_edit.textChanged.connect(fn)


class SequencePanel(QWidget):
    """Dock panel for managing sequence data flows."""

    changed = Signal()
    activeSequenceChanged = Signal(object)   # str seq_id or None
    pickModeChanged = Signal(bool)           # True = on, False = off
    stepSelected = Signal(str)              # edge_id
    threatsGenerateRequested = Signal(str, str, list)  # seq_id, seq_name, edge_ids
    threatsUpdateRequested = Signal(str)  # seq_id — re-check against the controls
    threatAddRequested = Signal(str)      # seq_id
    threatEditRequested = Signal(str)     # threat guid
    threatRemoveRequested = Signal(str)   # threat guid
    threatsDeleteAllRequested = Signal(str)  # seq_id — remove all of its threats

    def __init__(self, registry: SequenceRegistry, parent=None):
        super().__init__(parent)
        self._registry = registry
        self._threats = None                  # ThreatRegistry, set by the app
        self.control_names: dict = {}         # {control id: name}, set by the app
        self._active_seq_id: Optional[str] = None
        self._pick_mode = False
        self._edge_label_fn: Callable[[str], str] = lambda eid: eid[:8]
        self._selected_step_idx: Optional[int] = None

        # ── top list ──────────────────────────────────────────────────
        list_header = QHBoxLayout()
        list_header.setContentsMargins(0, 0, 0, 0)
        list_header.addStretch(1)

        self._add_btn = QPushButton("+")
        self._add_btn.setFixedSize(24, 22)
        self._add_btn.setToolTip("New sequence")
        self._add_btn.clicked.connect(self._on_add_sequence)
        list_header.addWidget(self._add_btn)

        self._del_btn = QPushButton("−")
        self._del_btn.setFixedSize(24, 22)
        self._del_btn.setToolTip("Delete selected sequence")
        self._del_btn.setEnabled(False)
        self._del_btn.clicked.connect(self._on_delete_sequence)
        list_header.addWidget(self._del_btn)
        self._list_header_widget = QWidget()
        self._list_header_widget.setLayout(list_header)

        self._list = QListWidget()
        self._list.setMaximumHeight(120)
        self._list.currentItemChanged.connect(self._on_list_selection)
        # NOTE: de-selecting the active sequence is handled in eventFilter() on
        # mouse *press*. Do not also hook itemClicked (emitted on release) — by
        # then the freshly clicked item is already active and it would toggle
        # every selection straight back off.
        self._list.viewport().installEventFilter(self)

        # ── edit area ─────────────────────────────────────────────────
        self._edit_area = QWidget()
        edit_layout = QVBoxLayout(self._edit_area)
        edit_layout.setContentsMargins(0, 4, 0, 4)
        edit_layout.setSpacing(4)

        name_row = QHBoxLayout()
        name_lbl = QLabel("Name")
        name_lbl.setFixedWidth(40)
        self._name_edit = QLineEdit()
        self._name_edit.editingFinished.connect(self._on_name_changed)
        name_row.addWidget(name_lbl)
        name_row.addWidget(self._name_edit, 1)
        edit_layout.addLayout(name_row)

        color_row = QHBoxLayout()
        color_lbl = QLabel("Color")
        color_lbl.setFixedWidth(40)
        self._color_btn = _ColorButton(DEFAULT_SEQUENCE_COLOR)
        self._color_btn.colorChanged.connect(self._on_color_changed)
        color_row.addWidget(color_lbl)
        color_row.addWidget(self._color_btn)
        color_row.addStretch(1)
        edit_layout.addLayout(color_row)

        # ── steps list ────────────────────────────────────────────────
        self._steps_widget = QWidget()
        self._steps_layout = QVBoxLayout(self._steps_widget)
        self._steps_layout.setContentsMargins(0, 0, 0, 0)
        self._steps_layout.setSpacing(1)
        self._steps_layout.addStretch(1)

        steps_scroll = QScrollArea()
        steps_scroll.setWidgetResizable(True)
        steps_scroll.setWidget(self._steps_widget)
        steps_scroll.setFrameShape(QFrame.NoFrame)
        steps_scroll.setMinimumHeight(60)
        # Steps expands to fill the remaining vertical space (Color → bottom).
        steps_scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

        # ── step property editor ───────────────────────────────────────
        self._step_props_frame = QFrame()
        self._step_props_frame.setFrameShape(QFrame.StyledPanel)
        self._step_props_frame.setVisible(False)
        # Step-property editor is fixed-ish (shown only when a step is selected).
        self._step_props_frame.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        self._step_props_frame.setMaximumHeight(200)
        sp_outer = QVBoxLayout(self._step_props_frame)
        sp_outer.setContentsMargins(4, 4, 4, 4)
        sp_outer.setSpacing(2)

        self._step_props_header_lbl = QLabel()
        self._step_props_header_lbl.setStyleSheet("font-weight: bold; font-size: 11px;")
        self._step_props_header_lbl.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self._step_props_header_lbl.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        sp_outer.addWidget(self._step_props_header_lbl)

        self._props_rows_widget = QWidget()
        self._props_rows_layout = QVBoxLayout(self._props_rows_widget)
        self._props_rows_layout.setContentsMargins(0, 0, 0, 0)
        self._props_rows_layout.setSpacing(1)

        props_scroll = QScrollArea()
        props_scroll.setWidgetResizable(True)
        props_scroll.setWidget(self._props_rows_widget)
        props_scroll.setFrameShape(QFrame.NoFrame)
        sp_outer.addWidget(props_scroll, 1)

        add_prop_btn = QPushButton("+ Add Property")
        add_prop_btn.clicked.connect(self._on_add_prop)
        sp_outer.addWidget(add_prop_btn)

        # ── pick mode button ──────────────────────────────────────────
        self._prop_save_timer = QTimer(self)
        self._prop_save_timer.setSingleShot(True)
        self._prop_save_timer.setInterval(300)
        self._prop_save_timer.timeout.connect(self.changed.emit)

        self._pick_btn = QPushButton("⊕  Click Edge to Add Step")
        self._pick_btn.setCheckable(True)
        self._pick_btn.setEnabled(False)
        self._pick_btn.toggled.connect(self._on_pick_toggled)

        # ── threats on this sequence ──────────────────────────────────
        # One compact row, identical in shape to the connection's Threats
        # section: + Add | ⚡ Generate | ↻ Update … 🗑 | ⌃. Same actions, same
        # order, same icons, so the two panels do not have to be learned twice.
        threats_header = QHBoxLayout()
        threats_header.setContentsMargins(0, 0, 0, 0)
        threats_header.setSpacing(4)

        self._threat_add_btn = QPushButton("+ Add")
        self._threat_add_btn.setFixedHeight(22)
        self._threat_add_btn.setToolTip("Add a threat to this sequence manually")
        self._threat_add_btn.setEnabled(False)
        self._threat_add_btn.clicked.connect(self._on_threat_add)

        self._gen_threats_btn = QPushButton("⚡ Generate")
        self._gen_threats_btn.setFixedHeight(22)
        self._gen_threats_btn.setEnabled(False)
        self._gen_threats_btn.setToolTip(
            "Work out this sequence's threats from scratch — the agent is shown "
            "the whole flow, step by step. Threats from an earlier run of this "
            "sequence are replaced; you are asked first, and nothing is deleted "
            "unless you accept the new ones. Use ↻ Update to keep them."
        )
        self._gen_threats_btn.clicked.connect(self._on_generate_threats)

        self._upd_threats_btn = QPushButton("↻ Update")
        self._upd_threats_btn.setFixedHeight(22)
        self._upd_threats_btn.setEnabled(False)
        self._upd_threats_btn.setToolTip(
            "Bring this sequence's threats — and its steps' — up to date without "
            "replacing them. Never adds or deletes a threat: it drops links to "
            "controls that were removed or no longer cover them, then re-checks "
            "mitigation status against the controls as they are now."
        )
        self._upd_threats_btn.clicked.connect(self._on_update_threats)

        self._threat_del_all_btn = QPushButton("🗑")
        self._threat_del_all_btn.setFixedSize(26, 22)
        self._threat_del_all_btn.setToolTip(
            "Delete every threat on this sequence and on its steps")
        self._threat_del_all_btn.setEnabled(False)
        self._threat_del_all_btn.setStyleSheet("color: #c0392b;")
        self._threat_del_all_btn.clicked.connect(self._on_threats_delete_all)

        self._threat_fold_btn = QPushButton("⌃")
        self._threat_fold_btn.setFixedSize(26, 22)
        self._threat_fold_btn.setToolTip("Fold or unfold every threat on this sequence")
        self._threat_fold_btn.setEnabled(False)
        self._threat_fold_btn.clicked.connect(self._on_toggle_all_threat_cards)

        threats_header.addWidget(self._threat_add_btn)
        threats_header.addWidget(self._gen_threats_btn)
        threats_header.addWidget(self._upd_threats_btn)
        threats_header.addStretch(1)
        threats_header.addWidget(self._threat_del_all_btn)
        threats_header.addWidget(self._threat_fold_btn)
        self._threats_header_widget = QWidget()
        self._threats_header_widget.setLayout(threats_header)

        # Threat cards, same widget the properties panel uses.
        self._threat_cards: List[ThreatCard] = []
        self._threat_expanded: dict = {}          # guid -> unfolded?
        # Open/Mitigated group folds, kept across refreshes.
        self._threat_group_expanded: dict = {"open": True, "mitigated": True}
        self._threats_widget = QWidget()
        self._threats_layout = QVBoxLayout(self._threats_widget)
        self._threats_layout.setContentsMargins(0, 0, 0, 0)
        self._threats_layout.setSpacing(2)
        self._threats_layout.addStretch(1)
        self._threat_scroll = QScrollArea()
        self._threat_scroll.setWidgetResizable(True)
        self._threat_scroll.setWidget(self._threats_widget)
        self._threat_scroll.setFrameShape(QFrame.NoFrame)
        self._threat_scroll.setMinimumHeight(80)
        self._threats_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)

        # ── assemble ──────────────────────────────────────────────────
        root = QVBoxLayout(self)
        root.setContentsMargins(6, 6, 6, 6)
        root.setSpacing(4)
        # The panel reads like the Properties tab: a stack of foldable
        # sections, with the selected sequence's identity fields ungrouped
        # between them.
        self._sequences_section = CollapsibleSection("Sequences")
        self._sequences_section.add_widget(self._list_header_widget)
        self._sequences_section.add_widget(self._list)
        root.addWidget(self._sequences_section)

        # Name + Color: fixed height, aligned to top.
        self._edit_area.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
        root.addWidget(self._edit_area)
        # Steps and Threats each fold away, so a long flow or a long threat
        # list can be collapsed to get the other one on screen.
        self._steps_section = CollapsibleSection("Steps")
        self._steps_section.add_widget(steps_scroll, 1)      # expands with the panel
        self._steps_section.add_widget(self._step_props_frame)
        self._steps_section.add_widget(self._pick_btn)
        self._steps_section.toggled.connect(self._on_steps_section_toggled)
        root.addWidget(self._steps_section, 1)
        self._root_layout = root

        self._threats_section = CollapsibleSection("Threats")
        self._threats_section.add_widget(self._threats_header_widget)
        self._threats_section.add_widget(self._threat_scroll, 1)
        self._threats_section.toggled.connect(self._on_threats_section_toggled)
        root.addWidget(self._threats_section, 1)

        # Trailing spacer (factor 0): while Steps is open it takes the slack
        # (factor 1); once folded the slack collects here instead of leaving a
        # gap in the middle of the panel — same arrangement as the Properties tab.
        root.addStretch(0)

        self._edit_area.setEnabled(False)
        self.refresh()

    # ------------------------------------------------------------------ public

    def set_registry(self, registry: SequenceRegistry) -> None:
        self._registry = registry
        self._active_seq_id = None
        self._selected_step_idx = None
        self._pick_mode = False
        self._pick_btn.setChecked(False)
        self.refresh()

    def set_edge_label_fn(self, fn: Callable[[str], str]) -> None:
        self._edge_label_fn = fn

    def set_threat_registry(self, threats) -> None:
        """Give the panel the threat registry so it can list a sequence's threats."""
        self._threats = threats
        self.refresh_threats()

    def refresh_threats(self) -> None:
        """Rebuild the threat cards for the active sequence."""
        while self._threats_layout.count() > 1:          # keep the trailing stretch
            item = self._threats_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.setParent(None)
                w.deleteLater()
        self._threat_cards = []

        seq = self._registry.get(self._active_seq_id) if self._active_seq_id else None
        threats = []
        if seq is not None and self._threats is not None:
            # Drop guids whose threat was deleted elsewhere.
            seq.threat_guids = [g for g in seq.threat_guids if g in self._threats]
            threats = [self._threats[g] for g in seq.threat_guids]

        self._threats_section.set_title(f"Threats ({len(threats)})")

        if not threats:
            empty = QLabel("No threat on this sequence yet." if seq is not None
                           else "Select a sequence to see its threats.")
            empty.setWordWrap(True)
            empty.setStyleSheet("color:#333; font-size:11px;")
            self._threats_layout.insertWidget(0, empty)
        else:
            def _card(t) -> ThreatCard:
                # A threat with no edge spans the whole sequence; one with an
                # edge was pinned to a single step.
                scope = "whole sequence" if not t.edge_guid else "one step"
                card = ThreatCard(t, self.control_names,
                                  expanded=self._threat_expanded.get(t.guid, True),
                                  subtitle=f"Scope: {scope}")
                card.editRequested.connect(self.threatEditRequested.emit)
                card.removeRequested.connect(self.threatRemoveRequested.emit)
                card._toggle.clicked.connect(
                    lambda checked, g=t.guid: self._threat_expanded.__setitem__(g, checked))
                self._threat_cards.append(card)
                return card

            # Grouped like the Threats panel and the connection's Threats
            # section: open threats are work to do, mitigated ones are evidence
            # to review, and each group folds on its own.
            open_threats = [t for t in threats if not t.mitigation_sc_ids]
            mitigated_threats = [t for t in threats if t.mitigation_sc_ids]

            row = 0
            if open_threats and mitigated_threats:
                for key, group, title, color in (
                        ("open", open_threats, "Open", OPEN_COLOR),
                        ("mitigated", mitigated_threats, "Mitigated", MITIGATED_COLOR)):
                    section = CollapsibleSection(
                        f"{title} ({len(group)})",
                        expanded=self._threat_group_expanded.get(key, True))
                    section.set_header_color(color)
                    section.toggled.connect(
                        lambda expanded, k=key:
                        self._threat_group_expanded.__setitem__(k, expanded))
                    for t in group:
                        section.add_widget(_card(t))
                    section.add_stretch()
                    self._threats_layout.insertWidget(row, section)
                    row += 1
            else:
                # Nothing to divide — one flat list, as before.
                for t in threats:
                    self._threats_layout.insertWidget(row, _card(t))
                    row += 1

        self._threat_add_btn.setEnabled(seq is not None)
        self._threat_fold_btn.setEnabled(bool(threats))
        self._threat_del_all_btn.setEnabled(bool(threats))
        self._sync_threat_fold_button()

    def _on_threats_delete_all(self) -> None:
        if self._active_seq_id:
            self.threatsDeleteAllRequested.emit(self._active_seq_id)

    def _on_toggle_all_threat_cards(self) -> None:
        """Collapse every threat card, or expand them all when all are folded."""
        if not self._threat_cards:
            return
        expand = not any(c.is_expanded() for c in self._threat_cards)
        for card in self._threat_cards:
            card.set_expanded(expand)
            self._threat_expanded[card.guid] = expand
        self._sync_threat_fold_button()

    def _sync_threat_fold_button(self) -> None:
        folded = bool(self._threat_cards) and not any(
            c.is_expanded() for c in self._threat_cards)
        self._threat_fold_btn.setText("⌄" if folded else "⌃")
        self._threat_fold_btn.setToolTip(("Unfold" if folded else "Fold")
                                         + " every threat on this sequence")

    def _on_threat_add(self) -> None:
        if self._active_seq_id:
            self.threatAddRequested.emit(self._active_seq_id)

    def _update_sequences_title(self) -> None:
        n = len(self._registry)
        self._sequences_section.set_title(f"Sequences ({n})")

    def refresh(self) -> None:
        """Rebuild UI from current registry state."""
        current_id = self._active_seq_id
        self._update_sequences_title()

        self._list.blockSignals(True)
        self._list.clear()
        for seq_id, seq in self._registry.items():
            item = QListWidgetItem()
            item.setData(Qt.UserRole, seq_id)
            self._update_list_item(item, seq)
            self._list.addItem(item)
            if seq_id == current_id:
                self._list.setCurrentItem(item)
        self._list.blockSignals(False)

        if current_id and current_id in self._registry:
            self._select_sequence(current_id)
        else:
            self._active_seq_id = None
            self._edit_area.setEnabled(False)
            self._pick_btn.setEnabled(False)
            self._gen_threats_btn.setEnabled(False)
            self._upd_threats_btn.setEnabled(False)
            self._clear_steps()
            self._step_props_frame.setVisible(False)
            self.refresh_threats()
            self.activeSequenceChanged.emit(None)

    def add_step(self, edge_id: str) -> None:
        """Append edge_id as next step to the active sequence. Called by app in pick mode."""
        if self._active_seq_id and self._active_seq_id in self._registry:
            seq = self._registry[self._active_seq_id]
            seq.steps.append(edge_id)
            seq.step_props.append({})
            self._rebuild_steps()
            self.changed.emit()

    def cancel_pick_mode(self) -> None:
        self._pick_mode = False
        self._pick_btn.blockSignals(True)
        self._pick_btn.setChecked(False)
        self._pick_btn.blockSignals(False)
        self.pickModeChanged.emit(False)

    # ----------------------------------------------------------------- private

    def _update_list_item(self, item: QListWidgetItem, seq: Sequence) -> None:
        item.setText(f"  {seq.name}  ({len(seq.steps)} steps)")
        item.setForeground(QColor(seq.color))

    def _select_sequence(self, seq_id: str) -> None:
        self._active_seq_id = seq_id
        seq = self._registry[seq_id]

        self._edit_area.setEnabled(True)
        self._pick_btn.setEnabled(True)
        self._gen_threats_btn.setEnabled(True)
        self._upd_threats_btn.setEnabled(True)
        self._del_btn.setEnabled(True)

        self._name_edit.blockSignals(True)
        self._name_edit.setText(seq.name)
        self._name_edit.blockSignals(False)

        self._color_btn.set_color(seq.color)
        self._rebuild_steps()
        self.refresh_threats()
        self.activeSequenceChanged.emit(seq_id)

    def _set_section_stretch(self, section, expanded: bool) -> None:
        """Only an open section claims the panel's spare height.

        Steps and Threats both scroll, so while both are open they share what
        is left; folded, a section must not hold space it cannot use.
        """
        index = self._root_layout.indexOf(section)
        if index >= 0:
            self._root_layout.setStretch(index, 1 if expanded else 0)

    def _on_threats_section_toggled(self, expanded: bool) -> None:
        self._set_section_stretch(self._threats_section, expanded)

    def _on_steps_section_toggled(self, expanded: bool) -> None:
        self._set_section_stretch(self._steps_section, expanded)

        # The step-property editor belongs to the Steps section; hide it with
        # the section and restore it only when a step is actually selected.
        if not expanded:
            self._step_props_frame.setVisible(False)
        elif self._selected_step_idx is not None:
            self._step_props_frame.setVisible(True)

    def _update_steps_title(self) -> None:
        seq = self._registry.get(self._active_seq_id) if self._active_seq_id else None
        n = len(seq.steps) if seq is not None else 0
        self._steps_section.set_title(f"Steps ({n})")

    def _clear_steps(self) -> None:
        while self._steps_layout.count() > 1:
            item = self._steps_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)

    def _rebuild_steps(self) -> None:
        self._clear_steps()
        self._update_steps_title()
        if not self._active_seq_id or self._active_seq_id not in self._registry:
            return
        seq = self._registry[self._active_seq_id]
        seq._sync_step_props()
        steps = seq.steps
        for i, edge_id in enumerate(steps):
            desc = self._edge_label_fn(edge_id)
            row = _StepRow(i, desc, is_first=(i == 0), is_last=(i == len(steps) - 1))
            idx = i
            eid = edge_id
            row.move_up.connect(lambda _i=idx: self._move_step(_i, -1))
            row.move_down.connect(lambda _i=idx: self._move_step(_i, 1))
            row.remove.connect(lambda _i=idx: self._remove_step(_i))
            row.selected.connect(lambda _i=idx, _e=eid: self._on_step_selected(_i, _e))
            self._steps_layout.insertWidget(i, row)

        if self._selected_step_idx is not None:
            self._rebuild_step_props()

    def _rebuild_step_props(self) -> None:
        # Clear existing rows
        while self._props_rows_layout.count():
            item = self._props_rows_layout.takeAt(0)
            w = item.widget()
            if w:
                w.setParent(None)

        if self._selected_step_idx is None or not self._active_seq_id:
            self._step_props_frame.setVisible(False)
            return

        seq = self._registry.get(self._active_seq_id)
        if seq is None or self._selected_step_idx >= len(seq.steps):
            self._step_props_frame.setVisible(False)
            return

        seq._sync_step_props()
        props = seq.step_props[self._selected_step_idx]
        desc = self._edge_label_fn(seq.steps[self._selected_step_idx])
        self._step_props_header_lbl.setText(f"Step {self._selected_step_idx}: {desc}")
        self._step_props_frame.setVisible(True)

        for key, val in props.items():
            row = _StepPropRow(key, str(val))
            row.set_changed_callback(self._on_prop_row_changed)
            row.remove.connect(lambda r=row: self._remove_prop(r.key()))
            self._props_rows_layout.addWidget(row)

    def _collect_props(self) -> dict:
        """Read current key-value rows into a dict."""
        result = {}
        for i in range(self._props_rows_layout.count()):
            w = self._props_rows_layout.itemAt(i).widget()
            if isinstance(w, _StepPropRow) and w.key():
                result[w.key()] = w.value()
        return result

    def _on_step_selected(self, idx: int, edge_id: str) -> None:
        self._selected_step_idx = idx
        self._rebuild_step_props()
        self.stepSelected.emit(edge_id)

    def _on_prop_row_changed(self) -> None:
        if self._selected_step_idx is None or not self._active_seq_id:
            return
        seq = self._registry.get(self._active_seq_id)
        if seq is None:
            return
        seq._sync_step_props()
        seq.step_props[self._selected_step_idx] = self._collect_props()
        self._prop_save_timer.start()

    def _on_add_prop(self) -> None:
        if self._selected_step_idx is None or not self._active_seq_id:
            return
        seq = self._registry.get(self._active_seq_id)
        if seq is None:
            return
        seq._sync_step_props()
        props = seq.step_props[self._selected_step_idx]
        # Find a unique default key name
        key = "property"
        n = 1
        while key in props:
            key = f"property{n}"
            n += 1
        props[key] = ""
        self._rebuild_step_props()
        self.changed.emit()

    def _remove_prop(self, key: str) -> None:
        if self._selected_step_idx is None or not self._active_seq_id:
            return
        seq = self._registry.get(self._active_seq_id)
        if seq is None:
            return
        seq._sync_step_props()
        seq.step_props[self._selected_step_idx].pop(key, None)
        self._rebuild_step_props()
        self.changed.emit()

    def _move_step(self, idx: int, delta: int) -> None:
        if not self._active_seq_id:
            return
        seq = self._registry[self._active_seq_id]
        new_idx = idx + delta
        if 0 <= new_idx < len(seq.steps):
            seq.steps[idx], seq.steps[new_idx] = seq.steps[new_idx], seq.steps[idx]
            seq._sync_step_props()
            seq.step_props[idx], seq.step_props[new_idx] = seq.step_props[new_idx], seq.step_props[idx]
            if self._selected_step_idx == idx:
                self._selected_step_idx = new_idx
            elif self._selected_step_idx == new_idx:
                self._selected_step_idx = idx
            self._rebuild_steps()
            self.changed.emit()

    def _remove_step(self, idx: int) -> None:
        if not self._active_seq_id:
            return
        seq = self._registry[self._active_seq_id]
        if 0 <= idx < len(seq.steps):
            seq.steps.pop(idx)
            seq.step_props.pop(idx)
            if self._selected_step_idx == idx:
                self._selected_step_idx = None
            elif self._selected_step_idx is not None and self._selected_step_idx > idx:
                self._selected_step_idx -= 1
            self._rebuild_steps()
            if self._selected_step_idx is None:
                self._step_props_frame.setVisible(False)
            self.changed.emit()

    def eventFilter(self, obj, event) -> bool:
        from PySide6.QtCore import QEvent
        if obj is self._list.viewport() and event.type() == QEvent.MouseButtonPress:
            self._pre_click_seq_id = self._active_seq_id
            item = self._list.itemAt(event.pos())
            if item is not None and item.data(Qt.UserRole) == self._pre_click_seq_id:
                self._list.clearSelection()
                self._list.setCurrentItem(None)
                return True  # consume the event — prevents re-selection
        return super().eventFilter(obj, event)

    def _on_list_selection(self, current: Optional[QListWidgetItem], _prev) -> None:
        if current is None:
            self._active_seq_id = None
            self._selected_step_idx = None
            self._edit_area.setEnabled(False)
            self._pick_btn.setEnabled(False)
            self._gen_threats_btn.setEnabled(False)
            self._del_btn.setEnabled(False)
            self._clear_steps()
            self._step_props_frame.setVisible(False)
            self.refresh_threats()
            self.activeSequenceChanged.emit(None)
            return
        seq_id = current.data(Qt.UserRole)
        if seq_id in self._registry:
            self._selected_step_idx = None
            self._step_props_frame.setVisible(False)
            self._select_sequence(seq_id)

    def _on_add_sequence(self) -> None:
        seq = new_sequence(self._registry)
        item = QListWidgetItem()
        item.setData(Qt.UserRole, seq.seq_id)
        self._update_list_item(item, seq)
        self._list.addItem(item)
        self._list.setCurrentItem(item)
        self.changed.emit()

    def _on_delete_sequence(self) -> None:
        if not self._active_seq_id:
            return
        self._registry.pop(self._active_seq_id, None)
        self._active_seq_id = None
        self._selected_step_idx = None
        self.activeSequenceChanged.emit(None)
        self.changed.emit()
        self.refresh()

    def _on_name_changed(self) -> None:
        if not self._active_seq_id or self._active_seq_id not in self._registry:
            return
        new_name = self._name_edit.text().strip() or "Sequence"
        self._registry[self._active_seq_id].name = new_name
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item and item.data(Qt.UserRole) == self._active_seq_id:
                self._update_list_item(item, self._registry[self._active_seq_id])
                break
        self.changed.emit()

    def _on_color_changed(self, color: str) -> None:
        if not self._active_seq_id or self._active_seq_id not in self._registry:
            return
        self._registry[self._active_seq_id].color = color
        for i in range(self._list.count()):
            item = self._list.item(i)
            if item and item.data(Qt.UserRole) == self._active_seq_id:
                self._update_list_item(item, self._registry[self._active_seq_id])
                break
        self.changed.emit()

    def _on_pick_toggled(self, checked: bool) -> None:
        self._pick_mode = checked
        self.pickModeChanged.emit(checked)

    def _on_update_threats(self) -> None:
        if self._active_seq_id:
            self.threatsUpdateRequested.emit(self._active_seq_id)

    def _on_generate_threats(self) -> None:
        if not self._active_seq_id or self._active_seq_id not in self._registry:
            return
        seq = self._registry[self._active_seq_id]
        self.threatsGenerateRequested.emit(self._active_seq_id, seq.name, list(seq.steps))
