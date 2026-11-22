"""Global settings panel — shown as a tab in the right dock area."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
    QComboBox,
)


_CONFIG_PATH = Path.home() / ".config" / "node-editor" / "settings.json"

_DEFAULTS: Dict[str, Any] = {
    "threat_rules_file": "",
    # Sonnet, not Opus: less than half the wall clock for the same structured
    # extraction — see threat_gen.DEFAULT_CLAUDE_MODEL.
    "claude_model": "claude-sonnet-5",
    # Claude is the default generator — see threat_gen.DEFAULT_BACKENDS.
    "default_backend": "claude",
}

_BACKEND_LABELS = [
    ("claude", "Claude (default)"),
    ("all",    "All Backends"),
    ("codex",  "Codex"),
    ("rules",  "Local Template Rules"),
]

# Fastest first: the list is a speed/quality dial, and the default is the top
# entry. The field is editable, so any other model id can be typed in.
_CLAUDE_MODELS = [
    "claude-sonnet-5",
    "claude-haiku-4-5-20251001",
    "claude-opus-5",
    "claude-opus-4-6",
]

# Values that were only ever the shipped default, never a deliberate pick.
_RETIRED_MODEL_DEFAULTS = {"claude-opus-4-6"}


def load_settings() -> Dict[str, Any]:
    """Return the persisted settings dict, falling back to defaults for missing keys."""
    try:
        with _CONFIG_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}
    result = dict(_DEFAULTS)
    result.update({k: v for k, v in data.items() if k in _DEFAULTS})
    # A settings file written before the default changed carries the old default
    # rather than a choice, and would silently keep the slow model. Anyone who
    # does want Opus can still pick it from the list.
    if result.get("claude_model") in _RETIRED_MODEL_DEFAULTS:
        result["claude_model"] = _DEFAULTS["claude_model"]
    return result


def save_settings(settings: Dict[str, Any]) -> None:
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


class SettingsPanel(QWidget):
    """Widget for editing and persisting global application settings."""

    settingsChanged = Signal(dict)   # emitted whenever settings are saved

    def __init__(self, parent=None):
        super().__init__(parent)
        self._settings = load_settings()
        self._build_ui()

    # ── public ────────────────────────────────────────────────────────────────

    def get(self, key: str, default=None):
        return self._settings.get(key, default)

    def reload(self) -> None:
        self._settings = load_settings()
        self._refresh_ui()

    # ── UI build ──────────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        outer.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)
        vl = QVBoxLayout(container)
        vl.setContentsMargins(8, 8, 8, 8)
        vl.setSpacing(12)

        # ── Threat Generation ────────────────────────────────────────────────
        gen_box = QGroupBox("Threat Generation")
        gen_form = QFormLayout(gen_box)
        gen_form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        # Default backend
        self._combo_backend = QComboBox()
        for val, lbl in _BACKEND_LABELS:
            self._combo_backend.addItem(lbl, userData=val)
        cur_backend = self._settings.get("default_backend", "all")
        idx = next((i for i, (v, _) in enumerate(_BACKEND_LABELS) if v == cur_backend), 0)
        self._combo_backend.setCurrentIndex(idx)
        gen_form.addRow("Default backend:", self._combo_backend)

        # Local rules file
        rules_row = QWidget()
        rules_hl = QHBoxLayout(rules_row)
        rules_hl.setContentsMargins(0, 0, 0, 0)
        rules_hl.setSpacing(4)
        self._edit_rules = QLineEdit()
        self._edit_rules.setPlaceholderText("(built-in rules)")
        self._edit_rules.setText(self._settings.get("threat_rules_file", ""))
        self._edit_rules.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        btn_rules = QPushButton("Browse…")
        btn_rules.setFixedWidth(72)
        btn_rules.clicked.connect(self._browse_rules)
        rules_hl.addWidget(self._edit_rules)
        rules_hl.addWidget(btn_rules)
        gen_form.addRow("Local rules file:", rules_row)

        hint = QLabel(
            "JSON file with custom threat rules used by "
            "\"From Local Template Rules\" and the rules fallback."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: gray; font-size: 10px;")
        gen_form.addRow("", hint)

        vl.addWidget(gen_box)

        # ── AI Models ───────────────────────────────────────────────────────
        ai_box = QGroupBox("AI Models")
        ai_form = QFormLayout(ai_box)
        ai_form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)

        self._combo_claude = QComboBox()
        self._combo_claude.setEditable(True)
        for m in _CLAUDE_MODELS:
            self._combo_claude.addItem(m)
        cur_model = self._settings.get("claude_model", _DEFAULTS["claude_model"])
        if cur_model not in _CLAUDE_MODELS:
            self._combo_claude.insertItem(0, cur_model)
        self._combo_claude.setCurrentText(cur_model)
        ai_form.addRow("Claude model:", self._combo_claude)

        vl.addWidget(ai_box)

        # ── Save button ──────────────────────────────────────────────────────
        btn_save = QPushButton("Save Settings")
        btn_save.clicked.connect(self._on_save)
        vl.addWidget(btn_save)

        vl.addStretch(1)

    def _refresh_ui(self) -> None:
        self._edit_rules.setText(self._settings.get("threat_rules_file", ""))
        cur_model = self._settings.get("claude_model", _DEFAULTS["claude_model"])
        self._combo_claude.setCurrentText(cur_model)
        cur_backend = self._settings.get("default_backend", "all")
        idx = next((i for i, (v, _) in enumerate(_BACKEND_LABELS) if v == cur_backend), 0)
        self._combo_backend.setCurrentIndex(idx)

    # ── slots ─────────────────────────────────────────────────────────────────

    def _browse_rules(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Threat Rules File", "", "JSON files (*.json)"
        )
        if path:
            self._edit_rules.setText(path)

    def _on_save(self) -> None:
        self._settings["threat_rules_file"] = self._edit_rules.text().strip()
        self._settings["claude_model"] = self._combo_claude.currentText().strip()
        backend_idx = self._combo_backend.currentIndex()
        self._settings["default_backend"] = _BACKEND_LABELS[backend_idx][0]
        save_settings(self._settings)
        self.settingsChanged.emit(dict(self._settings))
