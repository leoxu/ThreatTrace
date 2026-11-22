"""Asset Editor UI — author asset types (interfaces + operations + schema).

See doc/asset-editor-ui-design.md. Built on node_editor/asset_types.py.
"""
from __future__ import annotations

import copy
import re
from typing import Callable, List, Optional, Tuple

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QGridLayout,
    QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit,
    QListWidget, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from ..interface_categories import (all_categories, get as get_category,
                                    problems as category_problems,
                                    prune as prune_category_fields)
from ..asset_types import (
    AssetType, Interface, Operation, OpStep,
    DIR_IN, DIR_OUT, DIR_BIDIR, ROLE_ACQUIRE, ROLE_OPERATE,
)

_HEX_COLOR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

_DIRECTIONS = [DIR_IN, DIR_OUT, DIR_BIDIR]
_ROLES = [ROLE_ACQUIRE, ROLE_OPERATE]


def _op_summary(op: Operation) -> str:
    if op.is_compound:
        return " → ".join(op.calls())
    return "(leaf)"


class OperationEditorDialog(QDialog):
    """Edit one operation: a name + ordered {call, role} steps."""

    def __init__(self, operation: Optional[Operation] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Operation")
        self.resize(420, 300)
        op = operation or Operation(name="NewOp", steps=[OpStep("open", ROLE_ACQUIRE)])

        layout = QVBoxLayout(self)
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Name"))
        self._name = QLineEdit(op.name)
        name_row.addWidget(self._name, 1)
        layout.addLayout(name_row)

        self._table = QTableWidget(0, 2, self)
        self._table.setHorizontalHeaderLabels(["call (syscall)", "role"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self._table, 1)
        for st in op.steps:
            self._add_step(st)

        btns = QHBoxLayout()
        for text, fn in (("+ Step", self._add_blank), ("−", self._remove),
                         ("↑", lambda: self._move(-1)), ("↓", lambda: self._move(1))):
            b = QPushButton(text); b.clicked.connect(fn); btns.addWidget(b)
        btns.addStretch()
        layout.addLayout(btns)

        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._on_ok); bb.rejected.connect(self.reject)
        layout.addWidget(bb)

    def _add_step(self, st: OpStep) -> None:
        r = self._table.rowCount(); self._table.insertRow(r)
        self._table.setItem(r, 0, QTableWidgetItem(st.call))
        combo = QComboBox(); combo.addItems(_ROLES); combo.setCurrentText(st.role)
        self._table.setCellWidget(r, 1, combo)

    def _add_blank(self):
        self._add_step(OpStep("", ROLE_OPERATE)); self._table.selectRow(self._table.rowCount() - 1)

    def _remove(self):
        r = self._table.currentRow()
        if r >= 0:
            self._table.removeRow(r)

    def _move(self, d: int):
        r = self._table.currentRow(); t = r + d
        if r < 0 or not (0 <= t < self._table.rowCount()):
            return
        a = self._read_step(r); b = self._read_step(t)
        self._write_step(r, b); self._write_step(t, a); self._table.selectRow(t)

    def _read_step(self, r: int) -> OpStep:
        call = self._table.item(r, 0).text().strip() if self._table.item(r, 0) else ""
        combo: QComboBox = self._table.cellWidget(r, 1)  # type: ignore
        return OpStep(call=call, role=combo.currentText() if combo else ROLE_OPERATE)

    def _write_step(self, r: int, st: OpStep):
        self._table.setItem(r, 0, QTableWidgetItem(st.call))
        combo: QComboBox = self._table.cellWidget(r, 1)  # type: ignore
        if combo:
            combo.setCurrentText(st.role)

    def _on_ok(self):
        if not self._name.text().strip():
            QMessageBox.warning(self, "Operation", "Name is required."); return
        steps = [self._read_step(r) for r in range(self._table.rowCount())]
        if not steps or any(not s.call for s in steps):
            QMessageBox.warning(self, "Operation", "Every step needs a syscall."); return
        self.accept()

    def operation(self) -> Operation:
        steps = [self._read_step(r) for r in range(self._table.rowCount())]
        return Operation(name=self._name.text().strip(), steps=steps)


class AssetTypeEditorDialog(QDialog):
    """Add / edit one asset type: identity, interfaces (+operations), schema."""

    def __init__(self, asset_type: Optional[AssetType] = None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Asset Type")
        self.resize(760, 620)
        at = copy.deepcopy(asset_type) if asset_type else AssetType(
            name="New Asset", type_id="new asset",
            interfaces=[Interface(name="interface", direction=DIR_IN)],
            properties={"type": {"default": "new asset", "readonly": True}},
        )
        self._interfaces: List[Interface] = at.interfaces or [Interface(name="interface")]
        self._loading = False

        layout = QVBoxLayout(self)

        # ── Identity ──
        idbox = QGroupBox("Identity"); idg = QGridLayout(idbox)
        self._name = QLineEdit(at.name)
        self._type_id = QLineEdit(at.type_id)
        self._shape = QComboBox(); self._shape.addItems(["Box", "Circle", "Ellipse"])
        self._shape.setCurrentText(at.shape or "Box")
        self._color = QLineEdit(at.color or "#f2994a")
        idg.addWidget(QLabel("Name"), 0, 0); idg.addWidget(self._name, 0, 1)
        idg.addWidget(QLabel("Type id"), 0, 2); idg.addWidget(self._type_id, 0, 3)
        idg.addWidget(QLabel("Shape"), 1, 0); idg.addWidget(self._shape, 1, 1)
        idg.addWidget(QLabel("Colour"), 1, 2); idg.addWidget(self._color, 1, 3)
        layout.addWidget(idbox)

        # ── Interfaces + Operations ──
        mid = QHBoxLayout()
        ibox = QGroupBox("Interfaces"); iv = QVBoxLayout(ibox)
        self._iface_list = QListWidget()
        self._iface_list.currentRowChanged.connect(self._on_iface_changed)
        iv.addWidget(self._iface_list, 1)
        ib = QHBoxLayout()
        for text, fn in (("+", self._add_iface), ("−", self._del_iface),
                         ("↑", lambda: self._move_iface(-1)), ("↓", lambda: self._move_iface(1))):
            b = QPushButton(text); b.setFixedWidth(30); b.clicked.connect(fn); ib.addWidget(b)
        ib.addStretch(); iv.addLayout(ib)
        # interface fields
        fg = QGridLayout()
        self._if_name = QLineEdit(); self._if_path = QLineEdit(); self._if_actor = QLineEdit()
        self._if_access = QLineEdit(); self._if_color = QLineEdit()
        self._if_dir = QComboBox(); self._if_dir.addItems(_DIRECTIONS)
        # How the channel works. Picking one fills in the fields it needs — an
        # ioctl channel wants a device node, a CAN channel an interface and ids.
        self._if_category = QComboBox()
        self._if_category.addItem("(none)", "")
        last_group = None
        for cat in all_categories():
            if cat.group != last_group:
                self._if_category.insertSeparator(self._if_category.count())
                last_group = cat.group
            self._if_category.addItem(cat.label, cat.id)
        self._if_category.currentIndexChanged.connect(self._on_category_changed)
        for w in (self._if_name, self._if_path, self._if_actor, self._if_access, self._if_color):
            w.editingFinished.connect(self._commit_iface_fields)
        self._if_dir.currentIndexChanged.connect(self._commit_iface_fields)
        self._if_access.setPlaceholderText("e.g. software.*  or  hardware.device")
        self._if_color.setPlaceholderText("#hex (blank = auto)")
        fg.addWidget(QLabel("Name"), 0, 0); fg.addWidget(self._if_name, 0, 1)
        fg.addWidget(QLabel("Category"), 1, 0); fg.addWidget(self._if_category, 1, 1)
        fg.addWidget(QLabel("Path"), 2, 0); fg.addWidget(self._if_path, 2, 1)
        self._if_path_label = fg.itemAtPosition(2, 0).widget()
        fg.addWidget(QLabel("Actor"), 3, 0); fg.addWidget(self._if_actor, 3, 1)
        fg.addWidget(QLabel("Direction"), 4, 0); fg.addWidget(self._if_dir, 4, 1)
        fg.addWidget(QLabel("Access-class"), 5, 0); fg.addWidget(self._if_access, 5, 1)
        fg.addWidget(QLabel("Slot colour"), 6, 0); fg.addWidget(self._if_color, 6, 1)
        iv.addLayout(fg)

        # Category-specific fields, rebuilt whenever the category changes.
        self._cat_help = QLabel(); self._cat_help.setWordWrap(True)
        self._cat_help.setStyleSheet("color:#666; font-size:11px;")
        iv.addWidget(self._cat_help)
        self._cat_form = QGridLayout()
        self._cat_edits: dict = {}
        iv.addLayout(self._cat_form)
        mid.addWidget(ibox, 1)

        obox = QGroupBox("Operations (of selected interface)"); ov = QVBoxLayout(obox)
        self._op_table = QTableWidget(0, 2)
        self._op_table.setHorizontalHeaderLabels(["operation", "steps"])
        self._op_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._op_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._op_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        ov.addWidget(self._op_table, 1)
        ob = QHBoxLayout()
        for text, fn in (("+ Op", self._add_leaf_op), ("+ Compound", self._add_compound_op),
                         ("Edit", self._edit_op), ("−", self._del_op)):
            b = QPushButton(text); b.clicked.connect(fn); ob.addWidget(b)
        ob.addStretch(); ov.addLayout(ob)
        mid.addWidget(obox, 1)
        layout.addLayout(mid, 1)

        # ── Properties schema ──
        pbox = QGroupBox("Properties (schema)"); pv = QVBoxLayout(pbox)
        self._prop_table = QTableWidget(0, 3)
        self._prop_table.setHorizontalHeaderLabels(["field", "default", "options (comma)"])
        self._prop_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._prop_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._prop_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        pv.addWidget(self._prop_table, 1)
        pb = QHBoxLayout()
        addf = QPushButton("+ Field"); addf.clicked.connect(self._add_field)
        delf = QPushButton("−"); delf.clicked.connect(lambda: self._prop_table.removeRow(self._prop_table.currentRow()))
        pb.addWidget(addf); pb.addWidget(delf); pb.addStretch(); pv.addLayout(pb)
        layout.addWidget(pbox)
        self._load_properties(at.properties)

        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._on_save); bb.rejected.connect(self.reject)
        layout.addWidget(bb)

        self._refresh_iface_list(select=0)

    # ── interfaces ──
    def _refresh_iface_list(self, select: int = -1):
        self._loading = True
        self._iface_list.clear()
        for iface in self._interfaces:
            self._iface_list.addItem(f"{iface.name}  ({iface.direction})")
        self._loading = False
        if self._interfaces:
            self._iface_list.setCurrentRow(max(0, min(select, len(self._interfaces) - 1)))

    def _cur_iface(self) -> Optional[Interface]:
        r = self._iface_list.currentRow()
        return self._interfaces[r] if 0 <= r < len(self._interfaces) else None

    def _on_iface_changed(self, row: int):
        if self._loading:
            return
        iface = self._interfaces[row] if 0 <= row < len(self._interfaces) else None
        self._loading = True
        self._if_name.setText(iface.name if iface else "")
        self._if_path.setText(iface.path if iface else "")
        self._if_actor.setText(iface.actor if iface else "")
        self._if_dir.setCurrentText(iface.direction if iface else DIR_IN)
        self._if_access.setText(iface.access_class if iface else "")
        self._if_color.setText(iface.color if iface else "")
        wanted = iface.category if iface else ""
        index = self._if_category.findData(wanted)
        self._if_category.setCurrentIndex(index if index >= 0 else 0)
        self._loading = False
        self._rebuild_category_fields()
        self._reload_ops()

    def _rebuild_category_fields(self) -> None:
        """Replace the category field rows with the current category's."""
        while self._cat_form.count():
            item = self._cat_form.takeAt(0)
            widget = item.widget()          # read once: setParent(None) clears it
            if widget is not None:
                widget.setParent(None)
                widget.deleteLater()
        self._cat_edits = {}

        # Reset the shared row first: not every category maps a field onto the
        # path, and a stale "Device node *" label on a CAN interface is a lie.
        self._if_path_label.setText("Path")
        self._if_path.setPlaceholderText("")
        self._if_path.setToolTip("")

        iface = self._cur_iface()
        cat = get_category(iface.category) if iface else None
        if cat is None:
            self._cat_help.setText("")
            return

        self._cat_help.setText(cat.description)
        row = 0
        for f in cat.fields:
            if f.maps_to == "path":
                # Kept in the interface's own path field — relabel it instead of
                # asking for the same thing twice.
                self._if_path_label.setText(f.label + (" *" if f.required else ""))
                self._if_path.setPlaceholderText(f.placeholder)
                self._if_path.setToolTip(f.help)
                continue
            edit = QLineEdit(str(iface.category_fields.get(f.name, "")))
            edit.setPlaceholderText(f.placeholder)
            if f.help:
                edit.setToolTip(f.help)
            edit.editingFinished.connect(self._commit_iface_fields)
            self._cat_form.addWidget(QLabel(f.label + (" *" if f.required else "")), row, 0)
            self._cat_form.addWidget(edit, row, 1)
            self._cat_edits[f.name] = edit
            row += 1

    def _on_category_changed(self) -> None:
        if self._loading:
            return
        iface = self._cur_iface()
        if iface is None:
            return
        new_id = self._if_category.currentData() or ""
        if new_id == iface.category:
            return
        iface.category = new_id
        cat = get_category(new_id)
        if cat is not None:
            # Defaults, never overwrites: an access-class or an operation list the
            # author already chose is theirs.
            if cat.access_class and not iface.access_class:
                iface.access_class = cat.access_class
                self._if_access.setText(cat.access_class)
            if cat.default_operations and not iface.operations:
                iface.operations = [Operation.from_json(o) for o in cat.default_operations]
                self._reload_ops()
        iface.category_fields = prune_category_fields(new_id, iface.category_fields)
        self._rebuild_category_fields()

    def _commit_iface_fields(self):
        if self._loading:
            return
        iface = self._cur_iface()
        if iface is None:
            return
        iface.name = self._if_name.text().strip() or iface.name
        iface.path = self._if_path.text().strip()
        iface.actor = self._if_actor.text().strip()
        iface.direction = self._if_dir.currentText()
        iface.access_class = self._if_access.text().strip()
        iface.color = self._if_color.text().strip()
        for name, edit in self._cat_edits.items():
            iface.category_fields[name] = edit.text().strip()
        iface.category_fields = prune_category_fields(iface.category, iface.category_fields)
        row = self._iface_list.currentRow()
        self._loading = True
        self._iface_list.item(row).setText(f"{iface.name}  ({iface.direction})")
        self._loading = False

    def _add_iface(self):
        self._interfaces.append(Interface(name=f"interface-{len(self._interfaces)+1}", direction=DIR_IN))
        self._refresh_iface_list(select=len(self._interfaces) - 1)

    def _del_iface(self):
        r = self._iface_list.currentRow()
        if 0 <= r < len(self._interfaces):
            del self._interfaces[r]
            self._refresh_iface_list(select=min(r, len(self._interfaces) - 1))

    def _move_iface(self, d: int):
        r = self._iface_list.currentRow(); t = r + d
        if 0 <= r < len(self._interfaces) and 0 <= t < len(self._interfaces):
            self._interfaces[r], self._interfaces[t] = self._interfaces[t], self._interfaces[r]
            self._refresh_iface_list(select=t)

    # ── operations ──
    def _reload_ops(self):
        self._op_table.setRowCount(0)
        iface = self._cur_iface()
        if not iface:
            return
        for op in iface.operations:
            r = self._op_table.rowCount(); self._op_table.insertRow(r)
            self._op_table.setItem(r, 0, QTableWidgetItem(op.name))
            self._op_table.setItem(r, 1, QTableWidgetItem(_op_summary(op)))

    def _add_leaf_op(self):
        iface = self._cur_iface()
        if not iface:
            return
        call, ok = QInputDialog.getText(self, "Add Operation", "Syscall (e.g. ioctl:MYDEV_IOC_FREE):")
        if ok and call.strip():
            iface.operations.append(Operation.from_json(call.strip()))
            self._reload_ops()

    def _add_compound_op(self):
        iface = self._cur_iface()
        if not iface:
            return
        dlg = OperationEditorDialog(parent=self)
        if dlg.exec() == QDialog.Accepted:
            iface.operations.append(dlg.operation()); self._reload_ops()

    def _edit_op(self):
        iface = self._cur_iface(); r = self._op_table.currentRow()
        if not iface or not (0 <= r < len(iface.operations)):
            return
        dlg = OperationEditorDialog(iface.operations[r], parent=self)
        if dlg.exec() == QDialog.Accepted:
            iface.operations[r] = dlg.operation(); self._reload_ops()

    def _del_op(self):
        iface = self._cur_iface(); r = self._op_table.currentRow()
        if iface and 0 <= r < len(iface.operations):
            del iface.operations[r]; self._reload_ops()

    # ── properties schema ──
    def _load_properties(self, properties: dict):
        for name, defn in (properties or {}).items():
            if isinstance(defn, dict):
                default = str(defn.get("default", ""))
                options = ", ".join(str(o) for o in defn.get("options", []))
            else:
                default, options = str(defn), ""
            self._add_field(name, default, options)

    def _add_field(self, name="", default="", options=""):
        r = self._prop_table.rowCount(); self._prop_table.insertRow(r)
        self._prop_table.setItem(r, 0, QTableWidgetItem(name or "field"))
        self._prop_table.setItem(r, 1, QTableWidgetItem(default))
        self._prop_table.setItem(r, 2, QTableWidgetItem(options))

    def _collect_properties(self) -> dict:
        out: dict = {}
        for r in range(self._prop_table.rowCount()):
            name = self._prop_table.item(r, 0).text().strip() if self._prop_table.item(r, 0) else ""
            if not name:
                continue
            default = self._prop_table.item(r, 1).text() if self._prop_table.item(r, 1) else ""
            opt_raw = self._prop_table.item(r, 2).text() if self._prop_table.item(r, 2) else ""
            options = [o.strip() for o in opt_raw.split(",") if o.strip()]
            if options:
                out[name] = {"default": default, "options": options}
            elif default:
                out[name] = {"default": default}
            else:
                out[name] = ""
        return out

    # ── save ──
    def _problems(self) -> List[str]:
        """Everything wrong with the form, so Save reports it in one go.

        A descriptor that reaches disk malformed is worse than an awkward dialog:
        it loads as a half-broken type and the failure surfaces far from here.
        """
        out: List[str] = []
        name, type_id = self._name.text().strip(), self._type_id.text().strip()
        if not name:
            out.append("Name is required.")
        if not type_id:
            out.append("Type id is required.")
        elif not re.sub(r"[^a-z0-9]+", "", type_id.lower()):
            # The descriptor filename is slugged from the type id; a type id of
            # punctuation alone would collide with every other such type.
            out.append(f"Type id '{type_id}' has no letters or digits to name a file with.")

        iface_names = [i.name.strip() for i in self._interfaces]
        if not self._interfaces:
            out.append("An asset needs at least one interface.")
        if any(not n for n in iface_names):
            out.append("Interface names cannot be empty.")
        dupes = {n for n in iface_names if n and iface_names.count(n) > 1}
        if dupes:
            out.append("Interface names must be unique — repeated: "
                       + ", ".join(sorted(dupes)))

        for iface in self._interfaces:
            op_names = [o.name.strip() for o in iface.operations]
            op_dupes = {n for n in op_names if n and op_names.count(n) > 1}
            if op_dupes:
                out.append(f"Interface '{iface.name}': duplicate operation(s) "
                           + ", ".join(sorted(op_dupes)))
            if any(not n for n in op_names):
                out.append(f"Interface '{iface.name}': an operation has no name.")
            for problem in category_problems(iface.category, iface.category_fields,
                                             iface.path):
                out.append(f"Interface '{iface.name}': {problem}")
            if iface.color and not _HEX_COLOR.match(iface.color.strip()):
                out.append(f"Interface '{iface.name}': slot colour "
                           f"'{iface.color}' is not #rgb or #rrggbb.")

        colour = self._color.text().strip()
        if colour and not _HEX_COLOR.match(colour):
            out.append(f"Colour '{colour}' is not #rgb or #rrggbb.")

        fields = [self._prop_table.item(r, 0).text().strip()
                  for r in range(self._prop_table.rowCount())
                  if self._prop_table.item(r, 0)]
        named = [f for f in fields if f]
        field_dupes = {f for f in named if named.count(f) > 1}
        if field_dupes:
            out.append("Property fields must be unique — repeated: "
                       + ", ".join(sorted(field_dupes)))
        return out

    def _on_save(self):
        self._commit_iface_fields()
        problems = self._problems()
        if problems:
            QMessageBox.warning(self, "Asset Type",
                                "This asset type cannot be saved yet:\n\n• "
                                + "\n• ".join(problems))
            return
        self.accept()

    def asset_type(self) -> AssetType:
        self._commit_iface_fields()
        props = self._collect_properties()
        props.setdefault("type", {"default": self._type_id.text().strip(), "readonly": True})
        return AssetType(
            name=self._name.text().strip(),
            type_id=self._type_id.text().strip(),
            shape=self._shape.currentText(),
            color=self._color.text().strip() or "#f2994a",
            properties=props,
            interfaces=copy.deepcopy(self._interfaces),
        )


class AssetManagerDialog(QDialog):
    """List asset types with New / Edit / Duplicate / Delete.

    The dialog asks the questions; the caller performs them. ``on_save`` is
    given the edited type, the id it had before (empty for a new one) and
    whether the user agreed to rewrite the instances that use it — because a
    type id is not just a name, it is the key every existing node stores.
    """

    def __init__(self, entries: List[Tuple[AssetType, bool]],
                 on_save: Callable[[AssetType, str, bool], None],
                 on_delete: Callable[[str], None], parent=None,
                 usage: Optional[Callable[[str], int]] = None,
                 exists: Optional[Callable[[str], bool]] = None):
        super().__init__(parent)
        self.setWindowTitle("Asset Types")
        self.resize(460, 380)
        self._entries = list(entries)         # [(AssetType, is_descriptor)]
        self._on_save = on_save
        self._on_delete = on_delete
        self._usage = usage or (lambda _type_id: 0)
        self._exists = exists or (lambda _type_id: False)

        layout = QVBoxLayout(self)
        self._list = QListWidget()
        layout.addWidget(self._list, 1)
        self._reload_list()

        btns = QHBoxLayout()
        for text, fn in (("New", self._new), ("Edit", self._edit),
                         ("Duplicate", self._duplicate), ("Delete", self._delete)):
            b = QPushButton(text); b.clicked.connect(fn); btns.addWidget(b)
        btns.addStretch()
        layout.addLayout(btns)

        bb = QDialogButtonBox(QDialogButtonBox.Close)
        bb.rejected.connect(self.reject); bb.accepted.connect(self.accept)
        layout.addWidget(bb)

    def _reload_list(self):
        row = self._list.currentRow()
        self._list.clear()
        for at, is_desc in self._entries:
            src = "descriptor" if is_desc else "built-in"
            used = self._usage(at.type_id)
            if used:
                src += f" · {used} in use"
            self._list.addItem(f"{at.name}    [{at.type_id}]    ({src})")
        if 0 <= row < self._list.count():
            self._list.setCurrentRow(row)

    def _cur(self) -> Optional[Tuple[AssetType, bool]]:
        r = self._list.currentRow()
        return self._entries[r] if 0 <= r < len(self._entries) else None

    def _persist(self, at: AssetType, original_id: str = "") -> None:
        """Save one type, after settling what its id change means."""
        rewrite = False
        renamed = bool(original_id) and original_id != at.type_id
        if renamed:
            used = self._usage(original_id)
            box = QMessageBox(self)
            box.setWindowTitle("Rename asset type")
            box.setIcon(QMessageBox.Question)
            box.setText(f"The type id changed from '{original_id}' to "
                        f"'{at.type_id}'.")
            box.setInformativeText(
                (f"{used} node(s) in this project store the old id. "
                 "Renaming updates them; keeping both leaves them on the old "
                 "type.\n\n" if used else
                 "No node in this project uses the old id.\n\n")
                + "Rename replaces the old type. Keep both saves this as a new "
                  "type and leaves the original alone.")
            rename_btn = box.addButton("Rename", QMessageBox.AcceptRole)
            keep_btn = box.addButton("Keep both", QMessageBox.ActionRole)
            box.addButton(QMessageBox.Cancel)
            box.exec()
            if box.clickedButton() is None or box.clickedButton() not in (rename_btn, keep_btn):
                return
            rewrite = box.clickedButton() is rename_btn
            if not rewrite:
                original_id = ""            # a copy: the original stays put

        # Saving onto a *different* existing type is a silent data loss.
        target_taken = self._exists(at.type_id) and at.type_id != original_id
        if target_taken:
            if QMessageBox.question(
                self, "Replace asset type",
                f"An asset type descriptor for '{at.type_id}' already exists.\n\n"
                "Saving replaces it. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
            ) != QMessageBox.Yes:
                return

        self._on_save(at, original_id, rewrite)

        # update local list (drop the renamed-away entry, replace or append)
        if rewrite and original_id:
            self._entries = [(e, d) for (e, d) in self._entries
                             if e.type_id != original_id]
        for i, (e, _d) in enumerate(self._entries):
            if e.type_id == at.type_id:
                self._entries[i] = (at, True); break
        else:
            self._entries.append((at, True))
        self._reload_list()

    def _new(self):
        dlg = AssetTypeEditorDialog(parent=self)
        if dlg.exec() == QDialog.Accepted:
            self._persist(dlg.asset_type())

    def _edit(self):
        cur = self._cur()
        if not cur:
            return
        dlg = AssetTypeEditorDialog(cur[0], parent=self)
        if dlg.exec() == QDialog.Accepted:
            self._persist(dlg.asset_type(), original_id=cur[0].type_id)

    def _duplicate(self):
        cur = self._cur()
        if not cur:
            return
        at = copy.deepcopy(cur[0])
        at.name += " Copy"; at.type_id += " copy"
        dlg = AssetTypeEditorDialog(at, parent=self)
        if dlg.exec() == QDialog.Accepted:
            self._persist(dlg.asset_type())

    def _delete(self):
        cur = self._cur()
        if not cur:
            return
        at, is_desc = cur
        if not is_desc:
            QMessageBox.information(self, "Delete", "Built-in types can't be deleted (edit to override)."); return
        used = self._usage(at.type_id)
        warning = (f"\n\n{used} node(s) in this project use it. They keep their "
                   "stored values but fall back to the generic asset schema, and "
                   "their interface slots stop being described."
                   if used else "")
        if QMessageBox.question(
            self, "Delete", f"Delete asset type '{at.name}'?{warning}",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No,
        ) != QMessageBox.Yes:
            return
        self._on_delete(at.type_id)
        self._entries = [(e, d) for (e, d) in self._entries if e.type_id != at.type_id]
        self._reload_list()
