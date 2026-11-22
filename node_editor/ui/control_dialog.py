"""
Editor for one security control inside a control container node.
"""
from __future__ import annotations

from typing import List, Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QVBoxLayout,
)

from ..controls import ControlDef, control_types, default_description, default_name, new_control


class ControlDialog(QDialog):
    """Create or edit a control definition (type, name, configuration, requirement)."""

    def __init__(self, control: Optional[ControlDef] = None, parent=None,
                 types: Optional[List[str]] = None):
        super().__init__(parent)
        self._editing = control
        self.setWindowTitle("Edit Security Control" if control else "Add Security Control")
        self.setMinimumWidth(520)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        layout.addWidget(QLabel("Control type"))
        self._type = QComboBox()
        self._type.addItems(types if types is not None else control_types())
        if control and control.control_type:
            idx = self._type.findText(control.control_type)
            if idx >= 0:
                self._type.setCurrentIndex(idx)
            else:
                self._type.insertItem(0, control.control_type)
                self._type.setCurrentIndex(0)
        self._type.currentTextChanged.connect(self._on_type_changed)
        layout.addWidget(self._type)

        layout.addWidget(QLabel("Name"))
        self._name = QLineEdit(control.name if control else
                               default_name(self._type.currentText()))
        self._name.setPlaceholderText("Name shown on the diagram")
        layout.addWidget(self._name)

        layout.addWidget(QLabel("Requirement ID"))
        self._req = QLineEdit(control.requirement_id if control else "")
        self._req.setPlaceholderText("e.g. SEC-101")
        layout.addWidget(self._req)

        layout.addWidget(QLabel("Description / configuration"))
        self._desc = QPlainTextEdit(control.description if control else
                                    default_description(self._type.currentText()))
        self._desc.setPlaceholderText(
            "How this control is configured — this is what the AI coverage check "
            "judges the threats against."
        )
        self._desc.setMinimumHeight(150)
        layout.addWidget(self._desc)

        hint = QLabel(
            "The control's coverage comes from the container circle it lives in; "
            "every control inside protects the same asset interfaces."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#666; font-size:11px;")
        layout.addWidget(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_type_changed(self, control_type: str) -> None:
        """Offer the type's preset name/description while they are untouched."""
        if self._editing is not None:
            return
        if not self._name.isModified():
            self._name.setText(default_name(control_type))
        current = self._desc.toPlainText().strip()
        if not current or current in _preset_descriptions():
            self._desc.setPlainText(default_description(control_type))

    def result_control(self) -> ControlDef:
        base = self._editing or new_control(self._type.currentText())
        return ControlDef(
            id=base.id,
            name=self._name.text().strip() or self._type.currentText() or "Control",
            control_type=self._type.currentText(),
            description=self._desc.toPlainText().strip(),
            requirement_id=self._req.text().strip(),
        )


def _preset_descriptions() -> set:
    """Descriptions that came from a template, so switching type may replace them."""
    return {default_description(t) for t in control_types() if default_description(t)}
