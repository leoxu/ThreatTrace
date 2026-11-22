from __future__ import annotations

from typing import Optional, Dict, List

from PySide6.QtCore import Signal, Qt
from PySide6.QtGui import QColor, QFont, QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QColorDialog,
    QCompleter,
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ..graphics.items import NodeItem, LabelItem, SlotItem, EdgeItem
from ..threat import Threat
from .collapsible import CollapsibleSection as _CollapsibleSection
from .mitigation_dialog import OPEN_COLOR as _OPEN_COLOR
from .threat_card import (MITIGATED_COLOR as _MITIGATED_COLOR,
                          PRIORITY_COLORS as _PRIORITY_COLORS,
                          ThreatCard as _ThreatCard)

RESERVED_KEYS = {"color", "text-color", "name", "class"}
SEC_PROPS_KEY = "security-properties"

# One shared row geometry: the key column, the outer insets and the gap between
# a value field and the panel edge. Property rows, template rows and the widget
# sections all use these, so every field lines up in a single column.
_KEY_COLUMN_W = 90
_ROW_LEFT = 4
_ROW_RIGHT = 24
_ROW_SPACING = 6

SHAPE_KEYS = ["color", "text-color", "border", "thickness", "fill", "width", "height", "z-order", "label"]

# Sections that start folded (the user can still expand them; state is remembered).
_COLLAPSED_BY_DEFAULT = {"Shape"}


class _Divider(QFrame):
    def __init__(self):
        super().__init__()
        self.setFrameShape(QFrame.HLine)
        self.setFrameShadow(QFrame.Sunken)


class _PropRow(QWidget):
    """A single key/value row in the property list."""
    removed = Signal()

    def __init__(self, key: str, value: str, removable: bool = True):
        super().__init__()
        self._reserved = not removable  # reserved = name/color

        # Key column width and the trailing gutter match _TemplatePropRow, so
        # plain rows line up with template rows and with the widget sections.
        if self._reserved:
            # Fixed label for reserved keys
            self.key_widget: QWidget = QLabel(key)
            self.key_widget.setFixedWidth(_KEY_COLUMN_W)
            self.key_widget.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            f = self.key_widget.font()
            f.setBold(True)
            self.key_widget.setFont(f)
        else:
            # Editable field for custom keys
            self.key_widget = QLineEdit(key)
            self.key_widget.setFixedWidth(_KEY_COLUMN_W)
            self.key_widget.setPlaceholderText("key")

        if key in ("color", "text-color"):
            self._color_value = value
            self.val_widget: QWidget = QPushButton()
            self.val_widget.setFixedHeight(24)
            self._set_color_swatch(value)
            self.val_widget.clicked.connect(self._pick_color)
        else:
            self.val_widget = QLineEdit(value)
            self.val_widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            self.val_widget.setPlaceholderText("value")

        row = QHBoxLayout(self)
        row.setContentsMargins(_ROW_LEFT, 1, 0, 1)
        row.setSpacing(_ROW_SPACING)
        row.addWidget(self.key_widget)
        row.addWidget(self.val_widget, 1)

        # The remove button (or its placeholder) plus the layout spacing before
        # it add up to the template rows' right margin, so both end level.
        trailing = _ROW_RIGHT - _ROW_SPACING
        if removable:
            rm = QPushButton("✕")
            rm.setFixedWidth(trailing)
            rm.setFixedHeight(24)
            rm.setToolTip("Remove this property")
            rm.clicked.connect(self.removed.emit)
            row.addWidget(rm)
        else:
            spacer = QWidget()
            spacer.setFixedWidth(trailing)
            row.addWidget(spacer)

    def _set_color_swatch(self, hex_color: str) -> None:
        self._color_value = hex_color
        c = QColor(hex_color)
        text_color = "#000" if c.lightnessF() > 0.5 else "#fff"
        self.val_widget.setText(hex_color)
        self.val_widget.setStyleSheet(
            f"background-color: {hex_color}; color: {text_color}; "
            f"border: 1px solid #888; border-radius: 3px;"
        )

    def _pick_color(self) -> None:
        new = QColorDialog.getColor(QColor(self._color_value), self, "Select Color")
        if new.isValid():
            self._set_color_swatch(new.name())
            editor = self._find_editor()
            if editor:
                editor._commit()

    def _find_editor(self) -> Optional["PropertyEditor"]:
        p = self.parent()
        while p is not None:
            if isinstance(p, PropertyEditor):
                return p
            p = p.parent()
        return None

    def current_key(self) -> str:
        if self._reserved:
            return self.key_widget.text()
        return self.key_widget.text().strip()

    def current_value(self) -> str:
        if isinstance(self.val_widget, QPushButton):  # color
            return self._color_value
        return self.val_widget.text().strip()

    def connect_changed(self, slot) -> None:
        if not isinstance(self.val_widget, QPushButton):
            self.val_widget.editingFinished.connect(slot)
        if not self._reserved:
            self.key_widget.editingFinished.connect(slot)


class _TemplatePropRow(QWidget):
    """Key/value row whose widget type (combo vs text) is driven by a PropDef.

    Used for both slot and edge template properties — no widget logic is
    hardcoded in Python; all choices come from the JSON template files.
    """

    def __init__(self, key: str, value: str, prop_def=None,
                 label_width: int = _KEY_COLUMN_W,
                 margins=(_ROW_LEFT, 0, _ROW_RIGHT, 0)):
        super().__init__()
        self._key = key

        lbl = QLabel(key)
        lbl.setFixedWidth(label_width)
        lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        lbl.setStyleSheet("color: #000; font-size: 11px; padding-right: 4px;")

        if prop_def is not None and prop_def.has_options:
            self._combo = QComboBox()
            self._combo.addItems(prop_def.options)
            idx = self._combo.findText(value)
            self._combo.setCurrentIndex(idx if idx >= 0 else 0)
            self._combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            self._combo.setStyleSheet("font-size: 11px;")
            val_widget = self._combo
            self._line = None
        else:
            self._combo = None
            self._line = QLineEdit(value)
            self._line.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            self._line.setStyleSheet("font-size: 11px;")
            val_widget = self._line

        row = QHBoxLayout(self)
        row.setContentsMargins(*margins)
        row.setSpacing(6)
        row.addWidget(lbl)
        row.addWidget(val_widget, 1)

    def current_key(self) -> str:
        return self._key

    def connect_changed(self, slot) -> None:
        if self._combo is not None:
            self._combo.currentIndexChanged.connect(lambda _: slot())
        else:
            self._line.editingFinished.connect(slot)

    def current_value(self) -> str:
        if self._combo is not None:
            return self._combo.currentText()
        return self._line.text().strip()


class _SecPropRow(_TemplatePropRow):
    """A _TemplatePropRow for security-properties (combo or plain text)."""

    def __init__(self, key: str, value: str, prop_def=None):
        # Same geometry as every other row (was a narrower 70px key column).
        super().__init__(key, value, prop_def=prop_def)


class _EdgePropRow(_TemplatePropRow):
    """Template property row for an edge."""

    def __init__(self, key: str, value: str, prop_def=None):
        super().__init__(key, value, prop_def=prop_def)


_TYPE_COLORS = {
    "IPC":               ("#c62828", "#fff"),   # red   — data crosses boundaries, generates threats
    "Asset Operation":   ("#1e8449", "#fff"),   # green — asset access
    "internal func call":("#777777", "#fff"),   # grey  — stays within boundary
    "syscall":           ("#c62828", "#fff"),   # red   — direct system call
}


class _TypeSelectRow(QWidget):
    """Interactive type selector for edges: IPC / Asset Operation / internal func call / syscall."""

    type_changed = Signal(str)
    _TYPE_OPTIONS = ["IPC", "Asset Operation", "internal func call", "syscall", "ownership"]

    def __init__(self, etype: str, locked: bool = False, parent=None,
                 options: Optional[list] = None):
        super().__init__(parent)

        lbl = QLabel("type")
        lbl.setFixedWidth(_KEY_COLUMN_W)
        lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        lbl.setStyleSheet("color: #000; font-size: 11px; padding-right: 4px;")

        self._combo = QComboBox()
        self._combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._combo.setStyleSheet("font-size: 11px;")
        self._combo.addItems(options if options else self._TYPE_OPTIONS)

        cur = self._combo.findText(etype)
        self._combo.setCurrentIndex(cur if cur >= 0 else 0)

        if locked:
            # Type is determined by what the edge connects (asset vs two
            # components) and is not user-editable.
            self._combo.setEnabled(False)
            self._combo.setToolTip(
                "Type is fixed by the edge's endpoints: 'Asset Operation' when it "
                "connects a security asset, 'internal func call' between two components."
            )
        else:
            self._combo.currentIndexChanged.connect(
                lambda _: self.type_changed.emit(self._combo.currentText())
            )

        row = QHBoxLayout(self)
        row.setContentsMargins(_ROW_LEFT, 2, _ROW_RIGHT, 2)
        row.setSpacing(6)
        row.addWidget(lbl)
        row.addWidget(self._combo, 1)

    def set_value(self, etype: str) -> None:
        """Set type without emitting type_changed."""
        self._combo.blockSignals(True)
        idx = self._combo.findText(etype)
        if idx >= 0:
            self._combo.setCurrentIndex(idx)
        self._combo.blockSignals(False)

    def current_key(self) -> str:
        return "type"

    def current_value(self) -> str:
        return self._combo.currentText()

    def connect_changed(self, slot) -> None:
        self.type_changed.connect(lambda _k: slot())


class _SearchableSubTypeRow(QWidget):
    """Edge 'sub-type' row: categorised dropdown + search-as-you-type + free-text custom values.

    ``categories`` is a list of dicts: [{"name": str, "type": str, "sub-types": [str]}, ...]
    ``type_filter`` restricts the shown categories to the given type ("" = all).

    ``operations`` (optional), if given and non-empty, is a curated flat list of
    sub-types (e.g. the destination asset's allowed operations) that replaces the
    categorised list entirely and is not affected by ``type_filter``/``set_type_filter``.
    """

    def __init__(self, key: str, value: str, categories: list,
                 type_filter: str = "", operations: Optional[list] = None,
                 locked: bool = False, parent=None):
        super().__init__(parent)
        self._key = key
        self._categories = categories
        self._operations = list(operations) if operations else None

        lbl = QLabel(key)
        lbl.setFixedWidth(_KEY_COLUMN_W)
        lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        lbl.setStyleSheet("color: #000; font-size: 11px; padding-right: 4px;")

        self._combo = QComboBox()
        self._combo.setEditable(True)
        self._combo.setInsertPolicy(QComboBox.NoInsert)
        self._combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self._combo.setStyleSheet("font-size: 11px;")

        self._build_model(type_filter)

        # Restore the saved value (may be a custom sub-type not in the list).
        # When bound to a curated operations list, only accept a saved value that
        # is actually one of those operations; otherwise keep the default first
        # operation that _build_model already selected (never leave it blank).
        if value and (self._operations is None or value in self._operations):
            self._combo.setCurrentText(value)

        if locked:
            # Fixed sub-type (e.g. an internal func call between two components).
            self._combo.setEditable(False)
            self._combo.setEnabled(False)
            idx = self._combo.findText(value)
            if idx >= 0:
                self._combo.setCurrentIndex(idx)

        row = QHBoxLayout(self)
        row.setContentsMargins(_ROW_LEFT, 0, _ROW_RIGHT, 0)
        row.setSpacing(_ROW_SPACING)
        row.addWidget(lbl)
        row.addWidget(self._combo, 1)

    def _build_model(self, type_filter: str) -> None:
        """Rebuild the dropdown model, optionally filtered to a specific type."""
        current_text = self._combo.currentText() if self._combo.count() > 0 else ""
        model = QStandardItemModel()
        flat: list = []

        if self._operations:
            # Curated asset-specific operation list — flat, no category grouping.
            for func in self._operations:
                model.appendRow(QStandardItem(func))
                flat.append(func)
        else:
            for cat in self._categories:
                cat_name = cat.get("name", "")
                etype = cat.get("type", "")
                if type_filter and etype != type_filter:
                    continue
                color = _TYPE_COLORS.get(etype, ("#888888", "#fff"))[0]

                header = QStandardItem(f"  {cat_name}")
                header.setEnabled(False)
                header.setSelectable(False)
                header.setForeground(QColor(color))
                hf = header.font()
                hf.setBold(True)
                hf.setItalic(True)
                header.setFont(hf)
                model.appendRow(header)

                for func in cat.get("sub-types", []):
                    model.appendRow(QStandardItem(func))
                    flat.append(func)

        self._combo.setModel(model)

        # Contains-matching completer for fast lookup across all sub-types
        completer = QCompleter(flat, self._combo)
        completer.setFilterMode(Qt.MatchContains)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        completer.setCompletionMode(QCompleter.PopupCompletion)
        self._combo.setCompleter(completer)

        # Restore text if it is still present in the new model
        if current_text and current_text in flat:
            self._combo.setCurrentText(current_text)
        elif flat:
            self._combo.setCurrentText(flat[0])

    def set_type_filter(self, etype: str) -> None:
        """Filter visible sub-types to the given type and reset to first available sub-type.

        No-op when a curated asset-specific operation list is in effect.
        """
        if self._operations:
            return
        self._build_model(etype)

    def current_key(self) -> str:
        return self._key

    def current_value(self) -> str:
        return self._combo.currentText().strip()

    def connect_changed(self, slot) -> None:
        self._combo.activated.connect(lambda _: slot())
        line = self._combo.lineEdit()   # None when locked (non-editable)
        if line is not None:
            line.editingFinished.connect(slot)


class _CompositeSourceRow(QWidget):
    """Source path row for Composite nodes: text field + Browse button."""
    browse_clicked = Signal()

    def __init__(self, value: str):
        super().__init__()
        lbl = QLabel("source")
        lbl.setFixedWidth(70)
        lbl.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        f = lbl.font()
        f.setBold(True)
        lbl.setFont(f)

        self.val_edit = QLineEdit(value)
        self.val_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.val_edit.setPlaceholderText("path/to/diagram.json")

        browse_btn = QPushButton("…")
        browse_btn.setFixedWidth(28)
        browse_btn.setFixedHeight(24)
        browse_btn.setToolTip("Browse for source file")
        browse_btn.clicked.connect(self.browse_clicked.emit)

        row = QHBoxLayout(self)
        row.setContentsMargins(0, 1, 0, 1)
        row.setSpacing(6)
        row.addWidget(lbl)
        row.addWidget(self.val_edit, 1)
        row.addWidget(browse_btn)
        # Spacer to match _PropRow's remove button width
        spacer = QWidget()
        spacer.setFixedWidth(24)
        row.addWidget(spacer)

    def current_key(self) -> str:
        return "source"

    def current_value(self) -> str:
        return self.val_edit.text().strip()

    def connect_changed(self, slot) -> None:
        self.val_edit.editingFinished.connect(slot)


class PropertyEditor(QWidget):
    propertiesChanged = Signal(NodeItem, dict)
    edgePropertiesChanged = Signal(EdgeItem, dict)
    diagramPropertiesChanged = Signal(dict)   # emitted when diagram fields are edited
    openDiagram = Signal(object)         # NodeItem
    editInterfaceRequested = Signal(object)  # NodeItem (subgraph)
    threatAddRequested = Signal()
    threatEditRequested = Signal(str)    # threat guid
    threatRemoveRequested = Signal(str)  # threat guid
    threatsGenerateRequested = Signal()
    threatsUpdateRequested = Signal()          # re-check threats against the controls
    threatsDeleteAllRequested = Signal()       # remove every threat on this edge
    mitigationCheckRequested = Signal(object)  # NodeItem (security control)
    controlAddRequested = Signal(object)          # NodeItem (container)
    controlEditRequested = Signal(object, str)    # NodeItem, control id
    controlRemoveRequested = Signal(object, str)  # NodeItem, control id
    reviewCommentAdded = Signal(object, str)   # NodeItem (review note), text
    reviewStatusToggled = Signal(object)       # NodeItem (review note)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._node: Optional[NodeItem] = None
        self._label: Optional[LabelItem] = None
        self._edge: Optional[EdgeItem] = None
        self._slot_item: Optional[SlotItem] = None
        self._edge_threats: List[Threat] = []
        self._diag_data: Optional[dict] = None   # current diagram dict (live reference)
        self.edge_prop_defs: dict = {}
        self.edge_type_categories: list = []
        self.edge_type_types: dict = {}
        self.edge_type_all_types: dict = {}
        self.asset_operations: dict = {}
        self.asset_types_by_id: dict = {}   # {type_id: AssetType} for the interface view
        self.sec_prop_defs_by_class: dict = {}
        self.control_names: dict = {}  # {security-control node id: name}, set by app
        self.coverage_fn = None        # set by app: NodeItem -> CoverageScope
        self.sequence_registry = None  # set by app after construction
        self.hidden_node_props: set = set()  # loaded from property_filter.json
        self._show_hidden: bool = False      # toggled by the button below
        self._section_expanded: Dict[str, bool] = {}  # per-section fold state, by title
        self._edge_steps_list = None                   # edge Steps list widget
        self._edge_op_steps: dict = {}                 # {op name: [calls]} current edge
        self._subtype_row = None                       # edge sub-type row (the operation)
        self._threat_cards: list = []                  # foldable cards on the current edge
        self._threat_expanded: Dict[str, bool] = {}    # threat guid -> unfolded?
        # Open/Mitigated group folds, kept across panel rebuilds.
        self._threat_group_expanded: Dict[str, bool] = {"open": True, "mitigated": True}
        self._iface_list = None                        # asset Interfaces list widget
        self._iface_ops_list = None                    # asset Operations list widget
        self._iface_steps_list = None                  # asset Steps list widget
        self._ifaces_by_name: dict = {}                # {iface name: Interface} current asset

        # Header
        self.title_label = QLabel("No selection")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(title_font.pointSize() + 1)
        self.title_label.setFont(title_font)
        self.title_label.setAlignment(Qt.AlignCenter)
        self.title_label.setContentsMargins(0, 4, 0, 4)

        # Rows container inside a scroll area
        self._rows_widget = QWidget()
        # Two things this policy has to say:
        #  • no shrink flag — QScrollArea sizes a resizable child with
        #    qSmartMinSize, which ignores minimumSizeHint for a shrinkable
        #    widget, and the form was squeezed instead of scrolling;
        #  • heightForWidth — rows wrap, so the form's height depends on its
        #    width. Without it the scroll area sizes the form from
        #    width-independent hints, and the surplus is centred inside the
        #    tallest section, appearing as a gap above and below it.
        rows_policy = QSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        rows_policy.setHeightForWidth(True)
        self._rows_widget.setSizePolicy(rows_policy)
        self._rows_layout = QVBoxLayout(self._rows_widget)
        self._rows_layout.setContentsMargins(6, 4, 6, 4)
        self._rows_layout.setSpacing(2)
        self._rows_layout.addStretch(1)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(self._rows_widget)
        scroll.setFrameShape(QFrame.NoFrame)
        # Always reserve the scrollbar: the viewport width then never changes
        # when a section folds or the content grows past the panel, so the
        # wrapped rows are measured at the width they are laid out at (and the
        # form no longer shifts sideways when the bar appears).
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        # Add property
        self._add_btn = QPushButton("+ Add Property")
        self._add_btn.setEnabled(False)
        self._add_btn.clicked.connect(self._add_custom_row)

        # Toggle to reveal shape/layout properties hidden by the filter
        self._toggle_hidden_btn = QPushButton("Show layout properties")
        self._toggle_hidden_btn.setCheckable(True)
        self._toggle_hidden_btn.setVisible(False)
        self._toggle_hidden_btn.setStyleSheet("font-size: 11px; color: #666;")
        self._toggle_hidden_btn.toggled.connect(self._on_toggle_hidden)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)
        layout.addWidget(self.title_label)
        layout.addWidget(_Divider())
        layout.addWidget(scroll, 1)
        layout.addWidget(self._add_btn)
        layout.addWidget(self._toggle_hidden_btn)

    # ------------------------------------------------------------------ public

    def set_node(self, node: Optional[NodeItem]) -> None:
        self._node = node
        self._label = None
        self._edge = None
        self._slot_item = None
        self._edge_threats = []
        self._diag_data = None
        self._rebuild()

    def set_label(self, label: Optional[LabelItem]) -> None:
        self._label = label
        self._node = None
        self._edge = None
        self._slot_item = None
        self._edge_threats = []
        self._diag_data = None
        self._rebuild()

    def set_slot(self, slot: SlotItem) -> None:
        self._slot_item = slot
        self._node = None
        self._label = None
        self._edge = None
        self._edge_threats = []
        self._diag_data = None
        self._rebuild()

    def set_edge(self, edge: EdgeItem, threats: List[Threat]) -> None:
        self._edge = edge
        self._edge_threats = threats
        self._node = None
        self._label = None
        self._slot_item = None
        self._diag_data = None
        self._rebuild()

    def set_diagram(self, diag: dict) -> None:
        """Show diagram-level properties (name, guid, description, source-root)."""
        self._diag_data = diag
        self._node = None
        self._label = None
        self._edge = None
        self._slot_item = None
        self._edge_threats = []
        self._rebuild()

    def _on_toggle_hidden(self, checked: bool) -> None:
        self._show_hidden = checked
        self._toggle_hidden_btn.setText(
            "Hide layout properties" if checked else "Show layout properties"
        )
        self._rebuild()

    # ----------------------------------------------------------------- private

    def _clear_rows(self) -> None:
        self._edge_steps_list = None   # old edge Steps widget is about to be destroyed
        self._edge_op_steps = {}
        self._subtype_row = None
        self._threat_cards = []
        self._iface_list = None
        self._iface_ops_list = None
        self._iface_steps_list = None
        self._ifaces_by_name = {}
        while self._rows_layout.count() > 1:
            item = self._rows_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.hide()
                w.deleteLater()

    def _rebuild(self) -> None:
        self._clear_rows()

        if self._slot_item is not None:
            self._toggle_hidden_btn.setVisible(False)
            self._rebuild_slot()
            return

        if self._label is not None:
            self.title_label.setText("Edge Label")
            row = _PropRow("name", self._label.name, removable=False)
            row.connect_changed(self._commit_label)
            self._rows_layout.insertWidget(0, row)
            self._add_btn.setEnabled(False)
            self._toggle_hidden_btn.setVisible(False)
            return

        if self._edge is not None:
            self._toggle_hidden_btn.setVisible(False)
            self._rebuild_edge()
            return

        if self._diag_data is not None:
            self._toggle_hidden_btn.setVisible(False)
            self._rebuild_diagram()
            return

        if self._node is None:
            self.title_label.setText("No selection")
            self._add_btn.setEnabled(False)
            self._toggle_hidden_btn.setVisible(False)
            return

        self.title_label.setText(self._node.title)
        self._add_btn.setEnabled(True)

        props = self._node.properties()

        # Determine which keys to suppress (shape/layout properties from property_filter.json)
        effective_hidden = self.hidden_node_props if not self._show_hidden else set()

        # Keys managed elsewhere / not shown as plain rows
        from ..review import MANAGED_KEYS as _REVIEW_KEYS
        _hidden_skip = ({SEC_PROPS_KEY, "parent-id", "children"}
                        | _REVIEW_KEYS | effective_hidden)
        if self._node.shape_kind == "Composite":
            _hidden_skip = _hidden_skip | {"source"}

        # Identity fields — always visible, ungrouped, at the top
        for key in ("name", "class"):
            if key not in props:
                continue
            row = _PropRow(key, str(props[key]), removable=False)
            row.connect_changed(self._commit)
            idx = self._rows_layout.count() - 1  # before the stretch
            self._rows_layout.insertWidget(idx, row)

        # Security group — rendered first (built before Shape/Other)
        sec_props = props.get(SEC_PROPS_KEY)
        if isinstance(sec_props, dict):
            node_class = props.get("class", "")
            asset_type = sec_props.get("type", "") if isinstance(sec_props, dict) else ""
            # Try specific class+type key first (e.g. "security asset file"),
            # fall back to the generic class key (e.g. "security asset").
            specific_key = f"{node_class} {asset_type}".strip() if asset_type else ""
            sec_defs = (
                self.sec_prop_defs_by_class.get(specific_key)
                or self.sec_prop_defs_by_class.get(node_class)
                or {}
            )

            # For subgraph placeholders the interface/state/source keys are shown
            # in a dedicated Subgraph section, so keep them out of the raw
            # Security key/value list.
            from ..subgraph import is_subgraph as _is_subgraph
            _subgraph_managed = (
                {"interface", "state", "source", "source-hash", "bound-at", "mode"}
                if _is_subgraph(props) else set()
            )
            from ..controls import CONTROLS_KEY as _CONTROLS_KEY
            sec_rows = []
            for k, v in sec_props.items():
                if k in _subgraph_managed:
                    continue
                if k == _CONTROLS_KEY:
                    continue      # rendered by the Security Controls section
                row = _SecPropRow(k, str(v), prop_def=sec_defs.get(k))
                row.connect_changed(self._commit)
                sec_rows.append(row)
            self._add_section("Security", sec_rows)

            # Interfaces (read-only): show a security asset's interfaces + their
            # operations / steps, authored in the Asset Editor.
            if str(node_class).startswith("security asset"):
                self._add_asset_interfaces_section(str(asset_type))

            # A control container holds any number of controls; they share its
            # coverage. Listed here, with the coverage section below.
            if str(node_class).startswith("security control"):
                self._add_controls_section(props)
                self._add_mitigation_coverage_section()

        # Review thread (reviewer question + author replies)
        from ..review import is_review_node as _is_review_node
        if _is_review_node(props):
            self._add_review_section(props)

        # Shape group: visual/layout properties
        shape_rows = []
        for key in SHAPE_KEYS:
            if key in _hidden_skip or key not in props:
                continue
            row = _PropRow(key, str(props[key]), removable=key not in RESERVED_KEYS)
            row.connect_changed(self._commit)
            row.removed.connect(lambda _row=row: self._remove_row(_row))
            shape_rows.append(row)
        self._add_section("Shape", shape_rows)

        # Show the toggle button only when there are hidden props that apply to this node
        has_hidden = bool(self.hidden_node_props & set(props.keys()))
        self._toggle_hidden_btn.setVisible(has_hidden)

        # ── Composite diagram section ───────────────────────────
        if self._node.shape_kind == "Composite":
            source_row = _CompositeSourceRow(str(props.get("source", "")))
            source_row.connect_changed(self._commit)
            source_row.browse_clicked.connect(self._browse_source)

            open_btn = QPushButton("Open Diagram")
            open_btn.setToolTip("Double-click the node on canvas, or click here")
            open_btn.clicked.connect(self._open_diagram)

            self._add_section("Composite Diagram", [source_row, open_btn], inset=True)

        # ── Subgraph section ────────────────────────────────────
        if self._node.shape_kind == "Subgraph":
            from ..subgraph import read_interface, PORT_IN
            sec = props.get(SEC_PROPS_KEY, {}) if isinstance(props.get(SEC_PROPS_KEY), dict) else {}
            iface = read_interface(props)
            rows: List[QWidget] = []

            state = str(sec.get("state", "unbound"))
            state_lbl = QLabel(f"State: {state}")
            state_lbl.setStyleSheet("font-size: 11px; color: #000;")
            rows.append(state_lbl)

            # Read-only summary of the interface ports
            if iface.ports:
                for p in iface.ports:
                    arrow = "→ in " if p.dir == PORT_IN else "← out"
                    hint = f"  ({p.expects})" if p.expects else ""
                    port_lbl = QLabel(f"  {arrow}  {p.name}{hint}")
                    port_lbl.setStyleSheet("font-size: 11px; color: #000;")
                    rows.append(port_lbl)
            else:
                empty_lbl = QLabel("  (no ports defined)")
                empty_lbl.setStyleSheet("font-size: 11px; color: #333;")
                rows.append(empty_lbl)

            edit_btn = QPushButton("Edit Interface…")
            edit_btn.setToolTip("Add, rename, remove or re-direction the placeholder's ports")
            edit_btn.clicked.connect(
                lambda: self.editInterfaceRequested.emit(self._node)
            )
            rows.append(edit_btn)

            self._add_section("Subgraph", rows, inset=True)

        # Any other/custom properties not covered by the groups above — rendered last
        other_keys = sorted(
            k for k in props
            if k not in _hidden_skip and k not in SHAPE_KEYS and k not in ("name", "class")
        )
        other_rows = []
        for key in other_keys:
            row = _PropRow(key, str(props[key]), removable=key not in RESERVED_KEYS)
            row.connect_changed(self._commit)
            row.removed.connect(lambda _row=row: self._remove_row(_row))
            other_rows.append(row)
        self._add_section("Other", other_rows)

    # Property rows carry their own horizontal insets (label column on the
    # left, room for the scrollbar on the right). Sections built from plain
    # widgets — lists, cards, button bars — get the same insets applied to the
    # section body so every section lines up with the rows above it.
    _WIDGET_SECTION_MARGINS = (_ROW_LEFT, 0, _ROW_RIGHT, 0)

    def _add_section(self, title: str, rows: list, state_key: str = "",
                     inset: bool = False) -> None:
        """Wrap `rows` in a collapsible, titled section and insert it before the trailing stretch.

        Does nothing if `rows` is empty. The section's fold state is remembered
        across rebuilds/selection changes via self._section_expanded, keyed by
        `state_key` when the visible title carries a changing count. Pass
        `inset=True` for sections whose rows are plain widgets rather than
        property rows, so their left/right edges match the property fields.
        """
        if not rows:
            return
        key = state_key or title
        # Some sections are collapsed by default (until the user expands them).
        default_expanded = key not in _COLLAPSED_BY_DEFAULT
        section = _CollapsibleSection(title, expanded=self._section_expanded.get(key, default_expanded))
        if inset:
            section._body_layout.setContentsMargins(*self._WIDGET_SECTION_MARGINS)
        for row in rows:
            section.add_widget(row)
        section.toggled.connect(lambda expanded, k=key: self._section_expanded.__setitem__(k, expanded))
        idx = self._rows_layout.count() - 1  # before the stretch
        self._rows_layout.insertWidget(idx, section)

    @staticmethod
    def _build_interface_tree(interfaces, single_iface: bool = False) -> QTreeWidget:
        """Build a collapsible Interface → Operations → Steps tree.

        ``interfaces`` is an iterable of descriptor ``Interface`` objects. Level 1
        is each interface (with its path/direction as a dim second column), level 2
        is each operation, level 3 is each compound operation's syscall steps.
        """
        C_IFACE, C_OP, C_STEP = "#0d47a1", "#1b5e20", "#333"
        tree = QTreeWidget()
        tree.setColumnCount(2)
        tree.setHeaderHidden(True)
        tree.setRootIsDecorated(True)
        tree.setUniformRowHeights(True)
        tree.setSelectionMode(QTreeWidget.NoSelection)
        tree.setFocusPolicy(Qt.NoFocus)
        tree.setStyleSheet(
            "QTreeWidget { font-size: 11px; color: #000; border: 1px solid #cfcfcf; }"
            "QTreeWidget::item { padding: 1px 0; }"
        )
        tree.setColumnWidth(0, 190)

        def _item(parent, text, color, bold=False, col2="", tip=""):
            it = QTreeWidgetItem(parent, [text, col2])
            f = it.font(0)
            f.setBold(bold)
            f.setPointSize(9)
            it.setFont(0, f)
            it.setForeground(0, QColor(color))
            if col2:
                it.setForeground(1, QColor("#777"))
                cf = it.font(1); cf.setPointSize(8); it.setFont(1, cf)
            if tip:
                it.setToolTip(0, tip)
            return it

        for iface in interfaces:
            meta = " · ".join(x for x in (iface.direction, iface.access_class) if x)
            iface_it = _item(tree, iface.name, C_IFACE, bold=True,
                             col2=iface.path or "", tip=iface.path or "")
            if meta:
                iface_it.setToolTip(0, f"{iface.path}\n{meta}" if iface.path else meta)
            if not iface.operations:
                _item(iface_it, "(no operations)", C_STEP)
            for op in iface.operations:
                calls = op.calls()
                compound = len(calls) > 1
                # Leaf op (single call == its own name) needs no children.
                op_it = _item(iface_it, op.name, C_OP, bold=compound,
                              col2=("" if compound else (calls[0] if calls and calls[0] != op.name else "")))
                if compound:
                    for step in op.steps:
                        role = getattr(step, "role", "") or ""
                        badge = "◆ " if role == "acquire" else "· "
                        _item(op_it, badge + step.call, C_STEP,
                              tip=f"role: {role}" if role else "")
            iface_it.setExpanded(True)
        # For a single-interface asset, also expand each operation so its steps show.
        if single_iface:
            for i in range(tree.topLevelItemCount()):
                top = tree.topLevelItem(i)
                for j in range(top.childCount()):
                    top.child(j).setExpanded(True)
        # Size the tree to its contents so the section isn't a tiny scroll box.
        rows_est = 0
        def _count(item):
            nonlocal rows_est
            rows_est += 1
            if item.isExpanded():
                for k in range(item.childCount()):
                    _count(item.child(k))
        for i in range(tree.topLevelItemCount()):
            _count(tree.topLevelItem(i))
        tree.setMinimumHeight(min(max(rows_est, 1) * 20 + 6, 340))
        return tree

    def _add_asset_interfaces_section(self, asset_type_id: str) -> None:
        """Add the Interfaces + Operations sections for a security asset.

        Interfaces are shown as a selectable list; selecting one populates a
        separate Operations list (operation name → its syscall step chain).
        Falls back to a flat operation list for legacy assets.
        """
        at = self.asset_types_by_id.get(asset_type_id)
        if at is not None and getattr(at, "interfaces", None):
            self._ifaces_by_name = {i.name: i for i in at.interfaces}

            iface_list = QListWidget()
            iface_list.setStyleSheet(
                "QListWidget { font-size: 11px; color: #000; border: 1px solid #cfcfcf; }"
                "QListWidget::item:selected { background: #d1e3fb; color: #000; }")
            iface_list.setMaximumHeight(130)
            for i in at.interfaces:
                it = QListWidgetItem(f"▸ {i.name}")
                if i.path:
                    it.setToolTip(i.path)
                it.setData(Qt.UserRole, i.name)
                iface_list.addItem(it)
            iface_list.currentRowChanged.connect(self._on_interface_selected)
            self._iface_list = iface_list

            ops_list = QListWidget()
            ops_list.setStyleSheet(
                "QListWidget { font-size: 11px; color: #000; border: 1px solid #cfcfcf; }"
                "QListWidget::item:selected { background: #d1c4e9; color: #000; }")
            ops_list.setMaximumHeight(150)
            ops_list.currentRowChanged.connect(self._on_operation_step_selected)
            self._iface_ops_list = ops_list

            steps_list = QListWidget()
            steps_list.setStyleSheet(
                "QListWidget { font-size: 11px; color: #000; border: 1px solid #cfcfcf; }")
            steps_list.setMaximumHeight(150)
            self._iface_steps_list = steps_list

            self._add_section("Interfaces", [iface_list], inset=True)
            self._add_section("Operations", [ops_list], inset=True)
            self._add_section("Steps", [steps_list], inset=True)
            # Pre-select the first interface so Operations isn't empty.
            if at.interfaces:
                iface_list.setCurrentRow(0)
            return

        # Legacy fallback: flat operation names in a simple Operations list.
        ops = self.asset_operations.get(asset_type_id) or []
        if not ops:
            return
        ops_list = QListWidget()
        ops_list.setStyleSheet("QListWidget { font-size: 11px; color: #000; "
                               "border: 1px solid #cfcfcf; }")
        for name in ops:
            ops_list.addItem(QListWidgetItem(str(name)))
        ops_list.setMaximumHeight(200)
        self._add_section("Operations", [ops_list])

    def _on_toggle_all_threat_cards(self) -> None:
        """Collapse every threat card, or expand them all when all are folded."""
        cards = [c for c in self._threat_cards if c is not None]
        if not cards:
            return
        expand = not any(c.is_expanded() for c in cards)
        for card in cards:
            card.set_expanded(expand)
            self._threat_expanded[card._guid] = expand
        self._sync_threat_fold_button()

    def _sync_threat_fold_button(self) -> None:
        btn = getattr(self, "_threat_fold_btn", None)
        if btn is None:
            return
        cards = [c for c in self._threat_cards if c is not None]
        folded = bool(cards) and not any(c.is_expanded() for c in cards)
        btn.setText("⌄" if folded else "⌃")
        btn.setToolTip(("Unfold" if folded else "Fold")
                       + " every threat on this connection")

    def _add_review_section(self, props: dict) -> None:
        """The review thread: existing comments + a reply box + resolve toggle."""
        from ..review import ROLE_AUTHOR, is_open, read_thread

        rows: list = []
        thread = read_thread(props)

        if not thread:
            empty = QLabel("No comment yet — write the question below.")
            empty.setStyleSheet("color:#333; font-size:11px;")
            rows.append(empty)
        for c in thread:
            card = QFrame()
            accent = "#1565c0" if c.role == ROLE_AUTHOR else "#ef6c00"
            card.setObjectName("reviewCard")
            card.setStyleSheet(
                "QFrame#reviewCard { border: 1px solid #bbb; border-left: 3px solid "
                + accent + "; border-radius: 3px; background: #f4f4f4; }"
            )
            cl = QVBoxLayout(card)
            cl.setContentsMargins(6, 4, 6, 4)
            cl.setSpacing(2)
            head = QLabel(c.header())
            head.setStyleSheet(f"color:{accent}; font-size:10px; font-weight:bold;")
            cl.addWidget(head)
            body = QLabel(c.text)
            body.setWordWrap(True)
            body.setTextInteractionFlags(Qt.TextSelectableByMouse)
            body.setStyleSheet("color:#111; font-size:11px;")
            cl.addWidget(body)
            rows.append(card)

        reply = QPlainTextEdit()
        reply.setPlaceholderText(
            "Write a question…" if not thread else "Write a reply…"
        )
        reply.setFixedHeight(70)
        reply.setStyleSheet("font-size: 11px; color: #000; background: #fff;")
        self._review_reply = reply
        rows.append(reply)

        bar = QWidget()
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(0, 2, 0, 2)
        bl.setSpacing(4)
        send_btn = QPushButton("Add Comment" if not thread else "Reply")
        send_btn.setFixedHeight(24)
        send_btn.clicked.connect(self._on_review_reply)
        status_btn = QPushButton("Resolve" if is_open(props) else "Reopen")
        status_btn.setFixedHeight(24)
        status_btn.setToolTip("Mark this review thread resolved / reopen it")
        status_btn.clicked.connect(self._on_review_toggle_status)
        bl.addWidget(send_btn)
        bl.addWidget(status_btn)
        bl.addStretch(1)
        rows.append(bar)

        title = "Review Thread" + ("" if is_open(props) else " (resolved)")
        self._add_section(title, rows, inset=True)

    def _on_review_reply(self) -> None:
        box = getattr(self, "_review_reply", None)
        if self._node is None or box is None:
            return
        text = box.toPlainText().strip()
        if not text:
            return
        box.clear()
        self.reviewCommentAdded.emit(self._node, text)

    def _on_review_toggle_status(self) -> None:
        if self._node is not None:
            self.reviewStatusToggled.emit(self._node)

    def _add_controls_section(self, props: dict) -> None:
        """The controls held in this container: one row each, plus add/edit/remove.

        Several controls on the same asset used to mean several overlapping
        circles; now they live in one container and are listed here.
        """
        from ..controls import read_controls

        if self._node is None:
            return
        node = self._node
        controls = read_controls(props, node.node_id)

        rows: list = []
        if not controls:
            empty = QLabel(
                "No control defined yet. Add the controls this circle applies "
                "to the asset interfaces it covers."
            )
            empty.setWordWrap(True)
            empty.setStyleSheet("color:#333; font-size:11px;")
            rows.append(empty)

        for c in controls:
            card = QFrame()
            # Scoped by object name: an unscoped "QFrame { … }" rule cascades
            # onto every child QLabel (QLabel is a QFrame) and boxes each line.
            card.setObjectName("controlCard")
            card.setStyleSheet(
                "QFrame#controlCard { border: 1px solid #bbb;"
                " border-left: 3px solid #e53935;"
                " border-radius: 3px; background: #f4f4f4; }"
            )
            cl = QVBoxLayout(card)
            cl.setContentsMargins(6, 4, 6, 4)
            cl.setSpacing(2)

            head = QHBoxLayout()
            head.setSpacing(4)
            title = QLabel(c.name)
            title.setWordWrap(True)
            title.setStyleSheet("color:#111; font-size:11px; font-weight:bold;")
            head.addWidget(title, 1)
            edit_btn = QPushButton("✎")
            edit_btn.setFixedSize(22, 20)
            edit_btn.setToolTip("Edit this control")
            edit_btn.clicked.connect(
                lambda _=False, n=node, cid=c.id: self.controlEditRequested.emit(n, cid))
            head.addWidget(edit_btn)
            del_btn = QPushButton("−")
            del_btn.setFixedSize(22, 20)
            del_btn.setStyleSheet("color:#e57373;")
            del_btn.setToolTip("Remove this control")
            del_btn.clicked.connect(
                lambda _=False, n=node, cid=c.id: self.controlRemoveRequested.emit(n, cid))
            head.addWidget(del_btn)
            cl.addLayout(head)

            meta = c.control_type or "(no type)"
            if c.requirement_id:
                meta += f"  ·  {c.requirement_id}"
            meta_lbl = QLabel(meta)
            meta_lbl.setStyleSheet("color:#555; font-size:10px;")
            cl.addWidget(meta_lbl)

            if c.description:
                # Configuration text can run to a paragraph; show the opening of
                # it and keep the whole thing in the tooltip (and in the editor).
                brief = " ".join(c.description.split())
                if len(brief) > 150:
                    brief = brief[:149].rstrip() + "…"
                desc = QLabel(brief)
                desc.setWordWrap(True)
                desc.setStyleSheet("color:#222; font-size:11px;")
                desc.setToolTip(c.description)
                cl.addWidget(desc)
            rows.append(card)

        add_btn = QPushButton("+ Add Control")
        add_btn.setFixedHeight(24)
        add_btn.setToolTip("Add another control to this container")
        add_btn.clicked.connect(lambda _=False, n=node: self.controlAddRequested.emit(n))
        rows.append(add_btn)

        self._add_section(f"Security Controls ({len(controls)})", rows, inset=True)

    def _add_mitigation_coverage_section(self) -> None:
        """What this security control's circle covers + the AI coverage check.

        The scope (covered asset interfaces, connections and threats in range)
        is computed by the app through ``coverage_fn``; without it the section
        still offers the check button.
        """
        if self._node is None:
            return

        rows: list = []
        scope = None
        if callable(self.coverage_fn):
            try:
                scope = self.coverage_fn(self._node)
            except Exception:
                scope = None

        if scope is None:
            summary = QLabel("Coverage information is not available.")
        elif not scope.slots:
            summary = QLabel(
                "This control does not cover any asset interface. Move the "
                "circle so it covers the asset slot(s) it protects."
            )
        else:
            covered = "\n".join(
                f"  • {s.asset_name}.{s.slot_name}" for s in scope.slots
            )
            mitigated = sum(1 for i in scope.items if i.already_mitigated)
            summary = QLabel(
                f"Covers {len(scope.slots)} asset interface(s):\n{covered}\n"
                f"{scope.edge_count} connection(s) in scope, "
                f"{len(scope.items)} threat(s) — {mitigated} already linked to "
                "this control."
            )
        summary.setWordWrap(True)
        summary.setStyleSheet("color:#222; font-size:11px;")
        rows.append(summary)

        btn = QPushButton("⚡ Check Mitigation Coverage")
        btn.setFixedHeight(24)
        btn.setToolTip(
            "Ask the AI backends whether this control mitigates each threat on "
            "the connections it covers, then review the verdicts."
        )
        btn.setEnabled(bool(scope and scope.items))
        if scope is not None and not scope.items:
            btn.setToolTip("No threats on the connections covered by this control.")
        btn.clicked.connect(
            lambda _=False, n=self._node: self.mitigationCheckRequested.emit(n)
        )
        rows.append(btn)

        self._add_section("Mitigation Coverage", rows, inset=True)

    def _on_interface_selected(self, _row: int) -> None:
        """Populate the Operations list from the interface selected in the list."""
        lst = getattr(self, "_iface_ops_list", None)
        il = getattr(self, "_iface_list", None)
        if lst is None or il is None:
            return
        lst.clear()
        item = il.currentItem()
        if item is None:
            return
        iface = self._ifaces_by_name.get(item.data(Qt.UserRole))
        if iface is None:
            return
        steps = getattr(self, "_iface_steps_list", None)
        if steps is not None:
            steps.clear()
        if not iface.operations:
            lst.addItem(QListWidgetItem("(no operations)"))
            return
        for op in iface.operations:
            n = len(op.steps)
            label = op.name + (f"  ({n} steps)" if n > 1 else "")
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, op)         # carry the Operation for the Steps list
            lst.addItem(item)
        # Pre-select the first operation so Steps isn't empty.
        if iface.operations:
            lst.setCurrentRow(0)

    def _on_operation_step_selected(self, _row: int) -> None:
        """Populate the Steps list from the operation selected in the Operations list."""
        steps = getattr(self, "_iface_steps_list", None)
        ol = getattr(self, "_iface_ops_list", None)
        if steps is None or ol is None:
            return
        steps.clear()
        item = ol.currentItem()
        if item is None:
            return
        op = item.data(Qt.UserRole)
        if op is None or not getattr(op, "steps", None):
            return
        for idx, st in enumerate(op.steps, 1):
            role = getattr(st, "role", "") or ""
            badge = "◆" if role == "acquire" else "·"
            it = QListWidgetItem(f"{idx}. {badge} {st.call}")
            if role:
                it.setToolTip(f"role: {role}")
            steps.addItem(it)

    def _rebuild_slot(self) -> None:
        slot = self._slot_item
        assert slot is not None
        self._add_btn.setEnabled(False)

        kind_label = "Input" if slot.kind == "input" else "Output"
        self.title_label.setText(f"{kind_label}: {slot.name}")

        def ins(w):
            self._rows_layout.insertWidget(self._rows_layout.count() - 1, w)

        name_row = _PropRow("name", slot.name, removable=False)
        name_row.connect_changed(lambda: self._commit_slot_name(slot, name_row))
        ins(name_row)

        # For a security-asset slot, offer Top/Bottom/Left/Right placement.
        node = slot.parentItem()
        if node is not None and hasattr(node, "properties") \
                and str(node.properties().get("class", "")).startswith("security asset"):
            self._add_slot_position_controls(slot)

        # If this slot is an asset interface, show the interface details.
        self._add_slot_interface_detail(slot)

    def _add_slot_position_controls(self, slot: SlotItem) -> None:
        """Buttons to pin an asset slot to an edge; swaps if the edge is taken."""
        bar = QWidget()
        grid = QHBoxLayout(bar)
        grid.setContentsMargins(0, 2, 0, 2)
        grid.setSpacing(4)
        cur = str(slot._properties.get("side", "")).lower()
        for side, glyph in (("top", "↑ Top"), ("bottom", "↓ Bottom"),
                            ("left", "← Left"), ("right", "→ Right")):
            b = QPushButton(glyph)
            b.setStyleSheet("QPushButton { font-size: 11px; color: #000; padding: 2px 6px; }")
            b.setCheckable(True)
            if side == cur:
                b.setChecked(True)
            b.clicked.connect(lambda _c=False, s=side, sl=slot: self._move_slot_to_side(sl, s))
            grid.addWidget(b)
        grid.addStretch(1)
        self._add_section("Position", [bar], inset=True)

    def _move_slot_to_side(self, slot: SlotItem, side: str) -> None:
        """Pin ``slot`` to ``side``; if another slot already holds that side, swap."""
        node = slot.parentItem()
        if node is None:
            return
        prev = str(slot._properties.get("side", "")).lower()
        if prev == side:
            return
        # Find a sibling already pinned to the target side → swap positions.
        for other in list(getattr(node, "inputs", [])) + list(getattr(node, "outputs", [])):
            if other is slot:
                continue
            if str(other._properties.get("side", "")).lower() == side:
                op = other.properties()
                if prev:
                    op["side"] = prev
                else:
                    op.pop("side", None)
                other.set_properties(op)
                break
        sp = slot.properties()
        sp["side"] = side
        slot.set_properties(sp)
        node._layout_slots()
        # Redraw edges attached to the moved slots.
        if node.scene() is not None:
            for it in node.scene().items():
                if isinstance(it, EdgeItem):
                    it.request_update()
        # Route through the normal change signal so the project is marked dirty.
        self.propertiesChanged.emit(node, node.properties())
        self._rebuild()

    def _add_slot_interface_detail(self, slot: SlotItem) -> None:
        node = slot.parentItem()
        if node is None or not hasattr(node, "properties"):
            return
        if not str(node.properties().get("class", "")).startswith("security asset"):
            return

        def _label(text, indent=0, muted=False, bold=False):
            lbl = QLabel(("    " * indent) + text)
            lbl.setTextInteractionFlags(Qt.TextSelectableByMouse)
            style = "font-size: 11px; color: #000;"
            if muted:
                style += " color: #333;"
            if bold:
                style += " font-weight: bold;"
            lbl.setStyleSheet(style)
            return lbl

        rows: List[QWidget] = []
        sp = slot.properties() if hasattr(slot, "properties") else {}

        # Full detail from the descriptor interface, if available.
        type_id = str(node.properties().get(SEC_PROPS_KEY, {}).get("type", "")) \
            if isinstance(node.properties().get(SEC_PROPS_KEY), dict) else ""
        at = self.asset_types_by_id.get(type_id)
        iface = at.interface_for_slot(slot.name) if at is not None else None

        if iface is not None:
            for k, v in (("path", iface.path), ("actor", iface.actor),
                         ("direction", iface.direction),
                         ("access-class", iface.access_class)):
                if v:
                    rows.append(_label(f"{k}: {v}", muted=True))
            # Operations (and compound steps) as an expanded tree for this one
            # interface — consistent with the node-level Interfaces view.
            rows.append(self._build_interface_tree([iface], single_iface=True))
        else:
            # Fallback: whatever the slot itself carries.
            for k in ("path", "access-class"):
                if sp.get(k):
                    rows.append(_label(f"{k}: {sp.get(k)}", muted=True))
            ops = sp.get("operations") or self.asset_operations.get(type_id) or []
            if ops:
                rows.append(_label("Operations", bold=True))
                for name in ops:
                    rows.append(_label(str(name), indent=1))

        self._add_section("Interface", rows, inset=True)

    def _commit_slot_name(self, slot: SlotItem, row: '_PropRow') -> None:
        name = row.current_value()
        if name:
            slot.name = name
            slot.setToolTip(f"{name} (Dir: {slot.Dir})")
            self.title_label.setText(
                f"{'Input' if slot.kind == 'input' else 'Output'}: {name}"
            )

    def _rebuild_diagram(self) -> None:
        assert self._diag_data is not None
        diag = self._diag_data
        self.title_label.setText("Diagram")
        self._add_btn.setEnabled(False)

        # Fields: (label, dict-key, placeholder, read-only)
        fields = [
            ("Name",        "name",        "Diagram name",            False),
            ("ID",          "id",          "",                        True),
            ("Description", "description", "Model description",       False),
            ("Source Root", "source-root", "Path to source code root",False),
        ]

        for idx, (label, key, placeholder, readonly) in enumerate(fields):
            value = str(diag.get(key, ""))
            row_label = QLabel(label)
            row_label.setFixedWidth(80)
            row_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            f = row_label.font()
            f.setBold(True)
            row_label.setFont(f)

            edit = QLineEdit(value)
            edit.setPlaceholderText(placeholder)
            if readonly:
                edit.setReadOnly(True)
                edit.setStyleSheet("color: #222; background: #f0f0f0;")
            else:
                edit.editingFinished.connect(self._commit_diagram)

            container = QWidget()
            row_layout = QHBoxLayout(container)
            row_layout.setContentsMargins(0, 1, 24, 1)
            row_layout.setSpacing(6)
            row_layout.addWidget(row_label)
            row_layout.addWidget(edit, 1)
            # store reference so _commit_diagram can read it
            container._key = key          # type: ignore[attr-defined]
            container._edit = edit        # type: ignore[attr-defined]
            container._readonly = readonly # type: ignore[attr-defined]

            self._rows_layout.insertWidget(idx, container)

    def _commit_diagram(self) -> None:
        if self._diag_data is None:
            return
        # Walk all inserted rows and collect field values
        for i in range(self._rows_layout.count() - 1):  # -1 for stretch
            item = self._rows_layout.itemAt(i)
            if item is None:
                continue
            w = item.widget()
            if w is None or not hasattr(w, "_key"):
                continue
            if not w._readonly:                         # type: ignore[attr-defined]
                self._diag_data[w._key] = w._edit.text().strip()  # type: ignore[attr-defined]
        self.diagramPropertiesChanged.emit(self._diag_data)

    def _connected_asset_operations(self) -> Optional[list]:
        """Return the operation list for a security asset connected by this edge.

        Checks both endpoints. The type/operations are taken from the specific
        connected **slot** (interface) first — a slot may carry its interface's
        own ``operations`` — and fall back to the asset-type-level operation list
        when the slot declares none. Returns None when the edge is not bound to a
        security asset.
        """
        if self._edge is None:
            return None
        for slot in (self._edge.dst, self._edge.src):
            if slot is None:
                continue
            node = slot.parentItem()
            if node is None or not hasattr(node, "properties"):
                continue
            if not str(node.properties().get("class", "")).startswith("security asset"):
                continue
            # Per-interface: prefer the connected slot's own operation list.
            if hasattr(slot, "properties"):
                sp = slot.properties()
                if isinstance(sp, dict):
                    slot_ops = sp.get("operations")
                    if isinstance(slot_ops, list) and slot_ops:
                        return [str(o) for o in slot_ops]
            # Fall back to the asset-type-level list.
            sec_props = node.properties().get(SEC_PROPS_KEY, {})
            if isinstance(sec_props, dict):
                ops = self.asset_operations.get(str(sec_props.get("type", "")))
                if ops:
                    return ops
        return None

    def _edge_op_steps_map(self) -> dict:
        """{operation name: [syscall calls]} for the asset this edge connects to.

        Prefers the asset slot's ``op_steps`` (interface operation → syscalls),
        else falls back to a flat operation list. Empty if not an asset edge.
        """
        if self._edge is None:
            return {}
        for slot in (self._edge.dst, self._edge.src):
            if slot is None:
                continue
            node = slot.parentItem()
            if node is None or not hasattr(node, "properties"):
                continue
            if not str(node.properties().get("class", "")).startswith("security asset"):
                continue
            sp = slot.properties() if hasattr(slot, "properties") else {}
            if isinstance(sp.get("op_steps"), dict) and sp["op_steps"]:
                return sp["op_steps"]
            flat = sp.get("operations")
            if not isinstance(flat, list) or not flat:
                atype = str(node.properties().get(SEC_PROPS_KEY, {}).get("type", "")) \
                    if isinstance(node.properties().get(SEC_PROPS_KEY), dict) else ""
                flat = self.asset_operations.get(atype) or []
            if flat:
                return {str(o): [str(o)] for o in flat}
        return {}

    def _edge_steps_rows(self, props: dict) -> list:
        """The Steps for the connection's operation (its sub-type) + sequence controls.

        The operation itself is the edge's sub-type (chosen in Classification), so
        there is no separate operation list here — just its steps, which refresh
        when the sub-type changes.
        """
        # Ownership links have no operation/steps.
        if self._edge is not None and str(self._edge.properties().get("type", "")) == "ownership":
            return []
        op_steps = self._edge_op_steps_map()
        self._edge_op_steps = op_steps
        if not op_steps:
            return []

        sl = QListWidget()
        sl.setStyleSheet("QListWidget { font-size: 11px; color: #000; "
                         "border: 1px solid #cfcfcf; }")
        sl.setMaximumHeight(160)
        self._edge_steps_list = sl
        self._refresh_edge_steps()

        # Sequence controls: show/hide the dotted owner-operation edges.
        bar = QWidget()
        row = QHBoxLayout(bar)
        row.setContentsMargins(0, 2, 0, 2)
        row.setSpacing(4)
        btn_style = "QPushButton { font-size: 11px; color: #000; padding: 2px 8px; }"
        b_sel = QPushButton("Show Sequence")
        b_all = QPushButton("Show All")
        b_hide = QPushButton("Hide")
        for b in (b_sel, b_all, b_hide):
            b.setStyleSheet(btn_style)
        b_sel.setToolTip("Show the dotted sequence for this operation (sub-type)")
        b_all.setToolTip("Show the dotted sequences for every operation")
        b_hide.setToolTip("Hide all sequence connections")
        b_sel.clicked.connect(self._on_show_selected)
        b_all.clicked.connect(self._on_show_all)
        b_hide.clicked.connect(self._on_hide_ops)
        for b in (b_sel, b_all, b_hide):
            row.addWidget(b)
        row.addStretch(1)
        return [sl, bar]

    def _current_edge_subtype(self) -> str:
        """The connection's current operation = its sub-type (live row, else props)."""
        sr = getattr(self, "_subtype_row", None)
        if sr is not None:
            v = sr.current_value()
            if v:
                return v
        if self._edge is not None:
            return str(self._edge.properties().get("sub-type", "")).strip()
        return ""

    def _refresh_edge_steps(self) -> None:
        """Repopulate the edge Steps list from the current sub-type's operation."""
        sl = getattr(self, "_edge_steps_list", None)
        if sl is None:
            return
        sl.clear()
        name = self._current_edge_subtype()
        calls = self._edge_op_steps.get(name) or []
        if not calls:
            sl.addItem(QListWidgetItem("(no steps)"))
            return
        for idx, call in enumerate(calls, 1):
            sl.addItem(QListWidgetItem(f"{idx}. {call}"))

    def _on_show_selected(self) -> None:
        """Show the owner-operation sequence for the connection's operation (sub-type)."""
        if self._edge is None:
            return
        name = self._current_edge_subtype()
        self._edge.show_owner_ops(op_name=name or None)

    def _on_show_all(self) -> None:
        """Show the owner-operation sequences for every operation of the asset."""
        if self._edge is None:
            return
        self._edge.show_owner_ops(all_ops=True)

    def _on_hide_ops(self) -> None:
        """Hide all owner-operation sequence connections for this edge."""
        if self._edge is None:
            return
        self._edge.hide_owner_ops()

    def _is_internal_component_edge(self) -> bool:
        """True when the edge connects two regular components (neither is a

        security asset). Such edges are always 'internal func call'.
        """
        if self._edge is None or self._edge.src is None or self._edge.dst is None:
            return False
        for slot in (self._edge.src, self._edge.dst):
            node = slot.parentItem()
            if node is None or not hasattr(node, "properties"):
                return False
            if str(node.properties().get("class", "")).startswith("security asset"):
                return False
        return True

    def _rebuild_edge(self) -> None:
        assert self._edge is not None
        self._add_btn.setEnabled(False)

        def ins(w):
            self._rows_layout.insertWidget(self._rows_layout.count() - 1, w)

        # Alias edges: simplified read-only view (source node / dest node only)
        if self._edge.properties().get("type") == "alias":
            self.title_label.setText("Alias Link")
            src_node = getattr(self._edge, 'source_node', None)
            dst_node = getattr(self._edge, 'dest_node', None)
            src_name = src_node.properties().get("name", "?") if src_node else "?"
            dst_name = dst_node.properties().get("name", "?") if dst_node else "?"
            for key, val in (("source", src_name), ("dest", dst_name)):
                row = _PropRow(key, val, removable=False)
                row.val_widget.setReadOnly(True)
                row.val_widget.setStyleSheet("color: #222; background: #f0f0f0;")
                ins(row)
            return

        src_name = self._edge.src.name if self._edge.src else "—"
        dst_name = self._edge.dst.name if self._edge.dst else "—"
        label_text = self._edge.label.name if self._edge.label else ""
        self.title_label.setText(label_text or "Edge")

        # Read-only connection info
        for key, val in (("from", src_name), ("to", dst_name)):
            row = _PropRow(key, val, removable=False)
            row.val_widget.setReadOnly(True)
            row.val_widget.setStyleSheet("color: #222; background: #f0f0f0;")
            ins(row)

        # Editable properties loaded from the edge template, grouped into sections
        props = self._edge.properties()
        if props:
            # Build type and sub-type rows together so they can reference each other
            _type_row: Optional[_TypeSelectRow] = None
            _subtype_row: Optional[_SearchableSubTypeRow] = None

            # When this edge connects a security asset, bind it to that asset's
            # scope: type is fixed to "Asset Operation" and locked, and sub-type
            # is restricted to the asset's curated operation list.
            asset_operations = self._connected_asset_operations()
            asset_bound = asset_operations is not None
            # Edges between two regular (non-asset) components default to
            # 'internal func call', but stay editable — the same pair of
            # components can also talk over IPC or a syscall.
            internal_bound = (not asset_bound) and self._is_internal_component_edge()

            locked_type = "Asset Operation" if asset_bound else None
            type_locked = locked_type is not None
            default_type = str(props.get("type", "")) or (
                "internal func call" if internal_bound else "")

            classification_rows = []
            shape_rows = []
            details_rows = []

            for key, value in props.items():
                if key == "type":
                    type_val = locked_type if type_locked else (str(value) or default_type)
                    _type_row = _TypeSelectRow(type_val, locked=type_locked)
                    classification_rows.append(_type_row)
                elif key == "sub-type" and self.edge_type_categories:
                    _subtype_row = _SearchableSubTypeRow(
                        key, str(value), self.edge_type_categories,
                        type_filter=locked_type if type_locked else default_type,
                        operations=asset_operations,
                    )
                    classification_rows.append(_subtype_row)
                    self._subtype_row = _subtype_row
                elif key in ("color", "text-color"):
                    row = _PropRow(key, str(value), removable=False)
                    row.connect_changed(self._commit_edge)
                    shape_rows.append(row)
                else:
                    row = _EdgePropRow(key, str(value), prop_def=self.edge_prop_defs.get(key))
                    row.connect_changed(self._commit_edge)
                    details_rows.append(row)

            # Wire type ↔ sub-type interactions. When the type is locked
            # (asset-bound) only the sub-type commits.
            if type_locked and _subtype_row is not None:
                def _locked_subtype_changed() -> None:
                    self._commit_edge()
                    self._refresh_edge_steps()   # sub-type IS the operation
                _subtype_row.connect_changed(_locked_subtype_changed)
            elif _type_row is not None and _subtype_row is not None:
                def _on_type_row_changed(t: str, sr=_subtype_row) -> None:
                    sr.set_type_filter(t)
                    self._commit_edge()

                def _on_subtype_changed(tr=_type_row, sr=_subtype_row) -> None:
                    new_subtype = sr.current_value()
                    current_type = tr.current_value()
                    valid_types = self.edge_type_all_types.get(new_subtype, set())
                    if valid_types and current_type not in valid_types:
                        # Current type is not valid for this sub-type — switch to default
                        new_type = self.edge_type_types.get(new_subtype, "")
                        if new_type:
                            tr.set_value(new_type)
                    self._commit_edge()
                    self._refresh_edge_steps()

                _type_row.type_changed.connect(_on_type_row_changed)
                _subtype_row.connect_changed(_on_subtype_changed)
            elif _type_row is not None:
                _type_row.connect_changed(self._commit_edge)
            elif _subtype_row is not None:
                _subtype_row.connect_changed(self._commit_edge)

            self._add_section("Classification", classification_rows)
            self._add_section("Steps", self._edge_steps_rows(props), inset=True)
            self._add_section("Details", details_rows)
            self._add_section("Shape", shape_rows)

            # Persist the rendered type (forced for asset-bound edges, defaulted
            # for component-to-component ones) + a valid sub-type so a freshly
            # connected edge doesn't stay blank or keep a stale type until the
            # user interacts with the dropdown.
            if _type_row is not None and (type_locked or internal_bound):
                shown_type = locked_type if type_locked else _type_row.current_value()
                stored_subtype = str(props.get("sub-type", ""))
                subtype_changed = (_subtype_row is not None
                                   and _subtype_row.current_value() != stored_subtype)
                if props.get("type") != shown_type or subtype_changed:
                    self._commit_edge()

        # ── Threats: one foldable section, with a foldable card per threat ──
        threats_rows: list = []

        # Header row: actions + expand/collapse all
        threats_hdr = QWidget()
        threats_hdr.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
        threats_hdr_l = QHBoxLayout(threats_hdr)
        threats_hdr_l.setContentsMargins(0, 0, 0, 0)
        threats_hdr_l.setSpacing(4)
        count = len(self._edge_threats)
        add_t_btn = QPushButton("+ Add")
        add_t_btn.setFixedHeight(22)
        add_t_btn.setToolTip("Add a threat manually")
        add_t_btn.clicked.connect(self.threatAddRequested.emit)
        gen_t_btn = QPushButton("⚡ Generate")
        gen_t_btn.setFixedHeight(22)
        gen_t_btn.setToolTip(
            "Work out this connection's threats from scratch. Any threats it "
            "already has are replaced — you are asked first, and nothing is "
            "deleted unless you accept the new ones. Use ↻ Update to keep them."
        )
        gen_t_btn.clicked.connect(self.threatsGenerateRequested.emit)
        upd_t_btn = QPushButton("↻ Update")
        upd_t_btn.setFixedHeight(22)
        upd_t_btn.setToolTip(
            "Bring these threats up to date without replacing them. Never adds "
            "or deletes a threat: it drops links to controls that were removed "
            "or no longer cover them, then re-checks mitigation status against "
            "the controls as they are now. If the connection itself changed, it "
            "says so and offers to re-generate instead."
        )
        upd_t_btn.setEnabled(count > 0)
        upd_t_btn.clicked.connect(self.threatsUpdateRequested.emit)
        # Compact toggle: four full-width buttons in one row need ~330px, which
        # overflows the dock once the vertical scrollbar appears and pushes the
        # whole form wider than the rows above it.
        del_all_btn = QPushButton("🗑")
        del_all_btn.setFixedSize(26, 22)
        del_all_btn.setToolTip("Delete every threat on this connection")
        del_all_btn.setEnabled(count > 0)
        del_all_btn.setStyleSheet("color: #c0392b;")
        del_all_btn.clicked.connect(self.threatsDeleteAllRequested.emit)

        fold_btn = QPushButton("⌃")
        fold_btn.setFixedSize(26, 22)
        fold_btn.setToolTip("Fold or unfold every threat on this connection")
        fold_btn.setEnabled(count > 0)
        fold_btn.clicked.connect(self._on_toggle_all_threat_cards)
        self._threat_fold_btn = fold_btn
        threats_hdr_l.addWidget(add_t_btn)
        threats_hdr_l.addWidget(gen_t_btn)
        threats_hdr_l.addWidget(upd_t_btn)
        threats_hdr_l.addStretch(1)
        threats_hdr_l.addWidget(del_all_btn)
        threats_hdr_l.addWidget(fold_btn)
        threats_rows.append(threats_hdr)

        self._threat_cards = []
        if count == 0:
            none_lbl = QLabel("No threats associated with this edge.")
            none_lbl.setStyleSheet("color: #333; font-size: 11px;")
            threats_rows.append(none_lbl)
        else:
            def _card(threat: "Threat") -> _ThreatCard:
                # Remember each card's fold state across rebuilds (an edit or a
                # coverage run rebuilds the whole panel).
                card = _ThreatCard(
                    threat, self.control_names,
                    expanded=self._threat_expanded.get(threat.guid, True),
                )
                card.editRequested.connect(self.threatEditRequested.emit)
                card.removeRequested.connect(self.threatRemoveRequested.emit)
                card._toggle.clicked.connect(
                    lambda checked, g=threat.guid: self._threat_expanded.__setitem__(g, checked)
                )
                self._threat_cards.append(card)
                return card

            # Same grouping as the Threats panel: open threats are work to do,
            # mitigated ones are evidence to review, so they get their own
            # foldable group instead of being interleaved by priority.
            open_threats = [t for t in self._edge_threats if not t.mitigation_sc_ids]
            mitigated_threats = [t for t in self._edge_threats if t.mitigation_sc_ids]

            if open_threats and mitigated_threats:
                for key, group, title, color in (
                        ("open", open_threats, "Open", _OPEN_COLOR),
                        ("mitigated", mitigated_threats, "Mitigated", _MITIGATED_COLOR)):
                    group_section = _CollapsibleSection(
                        f"{title} ({len(group)})",
                        expanded=self._threat_group_expanded.get(key, True))
                    group_section.set_header_color(color)
                    group_section.toggled.connect(
                        lambda expanded, k=key:
                        self._threat_group_expanded.__setitem__(k, expanded))
                    for threat in group:
                        group_section.add_widget(_card(threat))
                    group_section.add_stretch()   # cards keep their own height
                    threats_rows.append(group_section)
            else:
                # Nothing to divide — one flat list, as before.
                for threat in self._edge_threats:
                    threats_rows.append(_card(threat))

        self._add_section(f"Threats ({count})", threats_rows, state_key="Threats",
                          inset=True)
        self._sync_threat_fold_button()

        # Sequences membership section
        if self.sequence_registry:
            from ..sequence import edge_sequence_steps
            steps_info = edge_sequence_steps(self.sequence_registry, self._edge.edge_id)
            if steps_info:
                ins(_Divider())
                seq_count = len({sid for sid, _ in steps_info})
                seq_hdr = QLabel(f"Sequences ({seq_count})")
                seq_hdr.setStyleSheet("font-weight: bold;")
                ins(seq_hdr)
                # Group by sequence
                by_seq: dict = {}
                for sid, step_idx in steps_info:
                    by_seq.setdefault(sid, []).append(step_idx)
                for sid, indices in by_seq.items():
                    seq = self.sequence_registry.get(sid)
                    if seq is None:
                        continue
                    step_str = ", ".join(f"step {i}" for i in indices)
                    lbl = QLabel(f"  {seq.name}: {step_str}")
                    lbl.setStyleSheet(
                        f"color: {seq.color}; font-size: 11px; padding-left: 4px;"
                    )
                    ins(lbl)

    def _iter_row_widgets(self):
        """Yield every row widget in the properties list, including rows nested

        inside collapsible sections (e.g. Geometry, Security).
        """
        for i in range(self._rows_layout.count() - 1):
            w = self._rows_layout.itemAt(i).widget()
            if isinstance(w, _CollapsibleSection):
                for j in range(w._body_layout.count()):
                    item = w._body_layout.itemAt(j)
                    bw = item.widget() if item else None
                    if bw is not None:
                        yield bw
            elif w is not None:
                yield w

    def _collect(self) -> dict:
        # Seed with hidden properties so they survive any commit without being dropped.
        # When _show_hidden=True all props are in the layout and are read directly.
        if self._node is not None and not self._show_hidden:
            result: dict = {
                k: v for k, v in self._node.properties().items()
                if k in self.hidden_node_props
            }
        else:
            result: dict = {}
        # The review thread is managed by the Review section, never rendered as
        # plain rows — carry it through untouched so an edit elsewhere in the
        # panel cannot drop or stringify it.
        if self._node is not None:
            from ..review import MANAGED_KEYS as _REVIEW_KEYS
            for key in _REVIEW_KEYS:
                if key in self._node.properties():
                    result[key] = self._node.properties()[key]

        # Seed security-properties with the node's current values so nested/
        # non-rendered keys (e.g. a subgraph's 'interface' list, managed 'state')
        # survive an edit; rendered rows override their own scalar keys below.
        sec: dict = {}
        if self._node is not None:
            existing_sec = self._node.properties().get(SEC_PROPS_KEY)
            if isinstance(existing_sec, dict):
                sec = dict(existing_sec)
        for w in self._iter_row_widgets():
            if isinstance(w, _SecPropRow):
                k = w.current_key()
                if k:
                    sec[k] = w.current_value()
            elif isinstance(w, (_PropRow, _CompositeSourceRow)):
                k = w.current_key()
                if k:
                    result[k] = w.current_value()
        if sec:
            result[SEC_PROPS_KEY] = sec
        return result

    def _commit(self) -> None:
        if self._node is None:
            return
        self.propertiesChanged.emit(self._node, self._collect())

    def _commit_edge(self) -> None:
        if self._edge is None:
            return
        props: dict = {}
        for w in self._iter_row_widgets():
            if isinstance(w, (_EdgePropRow, _SearchableSubTypeRow, _TypeSelectRow, _PropRow)):
                k = w.current_key()
                if k and k not in ("id", "from", "to"):
                    props[k] = w.current_value()
        self.edgePropertiesChanged.emit(self._edge, props)

    def _commit_label(self) -> None:
        if self._label is None:
            return
        for i in range(self._rows_layout.count() - 1):
            w = self._rows_layout.itemAt(i).widget()
            if isinstance(w, _PropRow) and w.current_key() == "name":
                self._label.name = w.current_value()
                break

    def _remove_row(self, row: "_PropRow") -> None:
        if self._node is None:
            return
        self._rows_layout.removeWidget(row)
        row.hide()
        row.deleteLater()
        self.propertiesChanged.emit(self._node, self._collect())

    def _add_custom_row(self) -> None:
        if self._node is None:
            return
        key = "new_key"
        existing = self._collect()
        n = 1
        while key in existing:
            key = f"new_key_{n}"
            n += 1
        row = _PropRow(key, "", removable=True)
        row.connect_changed(self._commit)
        row.removed.connect(lambda _row=row: self._remove_row(_row))
        idx = self._rows_layout.count() - 1
        self._rows_layout.insertWidget(idx, row)
        row.key_widget.setFocus()
        row.key_widget.selectAll()

    def _browse_source(self) -> None:
        if self._node is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Select Diagram Source File", "", "JSON Files (*.json)"
        )
        if not path:
            return
        for w in self._iter_row_widgets():
            if isinstance(w, _CompositeSourceRow):
                w.val_edit.setText(path)
                self._commit()
                break

    def _open_diagram(self) -> None:
        if self._node is not None:
            self.openDiagram.emit(self._node)
