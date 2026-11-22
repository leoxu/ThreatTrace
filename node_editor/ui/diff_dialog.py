"""Dialog that displays a ModelDiff as a grouped, colour-coded tree."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QLabel, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from ..modeldiff import ModelDiff

_CHANGE_COLOR = {
    "added":   QColor("#2e7d32"),   # green
    "removed": QColor("#c62828"),   # red
    "changed": QColor("#e67e22"),   # amber
}
_CHANGE_SIGN = {"added": "＋", "removed": "－", "changed": "～"}
_KIND_ORDER = {"diagram": 0, "node": 1, "edge": 2, "threat": 3}
_CHANGE_ORDER = {"added": 0, "changed": 1, "removed": 2}


class DiffDialog(QDialog):
    """Show the result of comparing two project revisions."""

    def __init__(self, diff: ModelDiff, title_a: str, title_b: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Model Diff")
        self.resize(720, 560)

        layout = QVBoxLayout(self)

        header = QLabel(f"Comparing  <b>{title_a}</b>  →  <b>{title_b}</b>")
        header.setTextFormat(Qt.RichText)
        layout.addWidget(header)

        s = diff.summary()
        summary = QLabel(
            f"<span style='color:#2e7d32'>+{s.get('added',0)} added</span>   "
            f"<span style='color:#e67e22'>~{s.get('changed',0)} changed</span>   "
            f"<span style='color:#c62828'>-{s.get('removed',0)} removed</span>"
        )
        summary.setTextFormat(Qt.RichText)
        layout.addWidget(summary)

        tree = QTreeWidget()
        tree.setHeaderLabels(["Change", "Detail"])
        tree.setColumnWidth(0, 320)
        tree.setAlternatingRowColors(True)
        layout.addWidget(tree, 1)

        if diff.is_empty():
            empty = QTreeWidgetItem(["No differences", ""])
            tree.addTopLevelItem(empty)
        else:
            self._populate(tree, diff)
            tree.expandToDepth(0)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _populate(self, tree: QTreeWidget, diff: ModelDiff) -> None:
        # Group: kind → change → entries
        groups: dict = {}
        for e in diff.entries:
            groups.setdefault(e.kind, {}).setdefault(e.change, []).append(e)

        for kind in sorted(groups, key=lambda k: _KIND_ORDER.get(k, 9)):
            kind_item = QTreeWidgetItem([f"{kind.capitalize()}s", ""])
            f = kind_item.font(0)
            f.setBold(True)
            kind_item.setFont(0, f)
            tree.addTopLevelItem(kind_item)

            for change in sorted(groups[kind], key=lambda c: _CHANGE_ORDER.get(c, 9)):
                color = _CHANGE_COLOR.get(change, QColor("#333"))
                for e in groups[kind][change]:
                    sign = _CHANGE_SIGN.get(change, "?")
                    ctx = f"  @{e.diagram_name}" if e.diagram_name else ""
                    node = QTreeWidgetItem([f"{sign} {e.label}", ctx.strip()])
                    node.setForeground(0, QBrush(color))
                    kind_item.addChild(node)
                    for fc in e.fields:
                        child = QTreeWidgetItem(
                            [f"    {fc.field}", f"{fc.old!r}  →  {fc.new!r}"]
                        )
                        child.setForeground(1, QBrush(QColor("#666")))
                        node.addChild(child)
