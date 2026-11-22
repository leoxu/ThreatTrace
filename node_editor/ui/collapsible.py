"""
CollapsibleSection — a titled group of widgets that folds away.

Shared by the properties panel and the sequence panel so both fold the same way.
"""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QPushButton, QSizePolicy, QVBoxLayout, QWidget


def invalidate_layout_chain(widget: QWidget) -> None:
    """Tell every ancestor layout that *widget*'s height just changed.

    Qt caches height-for-width per item, and a widget nested two layouts deep
    (a card inside a group inside a section) keeps its old height when it folds:
    ``updateGeometry()`` alone does not reach the outer caches, so a folded card
    stays as tall as it was open. Walking up and invalidating is what actually
    re-runs the calculation.
    """
    while widget is not None:
        layout = widget.layout()
        if layout is not None:
            layout.invalidate()
        widget.updateGeometry()
        widget = widget.parentWidget()


class CollapsibleSection(QWidget):
    """A titled group of rows with a header that toggles the body's visibility."""

    toggled = Signal(bool)  # emits the new expanded state

    def __init__(self, title: str, expanded: bool = True, parent=None):
        super().__init__(parent)
        self._title = title
        self._expanded = expanded

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 4, 0, 0)
        outer.setSpacing(2)

        self._header_btn = QPushButton()
        self._header_btn.setFlat(True)
        self._header_btn.setCursor(Qt.PointingHandCursor)
        self._header_btn.setStyleSheet(
            "QPushButton { text-align: left; font-weight: bold; border: none; padding: 2px 0; }"
        )
        self._header_btn.clicked.connect(self._toggle)
        outer.addWidget(self._header_btn)

        self._body = QWidget()
        self._body_layout = QVBoxLayout(self._body)
        self._body_layout.setContentsMargins(0, 0, 0, 0)
        self._body_layout.setSpacing(2)
        outer.addWidget(self._body, 1)

        # True once a child asks for stretch: the section then grows with the
        # panel while open, and shrinks to its header once folded.
        self._has_stretch = False

        self._update_header()
        self._body.setVisible(self._expanded)
        self._apply_size_policy()

    def add_widget(self, w: QWidget, stretch: int = 0) -> None:
        self._body_layout.addWidget(w, stretch)
        if stretch:
            self._has_stretch = True
            self._apply_size_policy()

    def add_stretch(self) -> None:
        """Park the body's spare height at the end.

        Without it a QVBoxLayout hands leftover space to whichever children can
        grow — so a group holding two folded cards stretches them into tall grey
        slabs instead of leaving a gap below.
        """
        self._body_layout.addStretch(1)

    def _apply_size_policy(self) -> None:
        """Three cases, and each one matters somewhere:

        * folded — `Fixed`: a header-only section must not soak up the panel's
          spare height (that is what left gaps between the folded sections of
          the sequence panel);
        * open with a child that asked for stretch — `Expanding`: the section
          shares the panel's spare height (the sequence panel's Steps/Threats);
        * open otherwise — `Minimum` **with heightForWidth**: never shrink below
          the content, and let the layout size it from its wrapped height. A
          `Fixed` section is sized from its width-independent sizeHint, which
          clipped wrapped rows and left the difference as slack that the layout
          centred as a gap above and below the section.
        """
        if not self._expanded:
            self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)
            return
        vertical = QSizePolicy.Expanding if self._has_stretch else QSizePolicy.Minimum
        policy = QSizePolicy(QSizePolicy.Preferred, vertical)
        policy.setHeightForWidth(True)
        self.setSizePolicy(policy)

    def is_expanded(self) -> bool:
        return self._expanded

    def set_expanded(self, expanded: bool) -> None:
        if expanded == self._expanded:
            return
        self._toggle()

    def set_header_color(self, color: str) -> None:
        """Tint the header text — used where the section itself has a meaning
        (open vs mitigated threats), so the colour is part of the label."""
        self._header_btn.setStyleSheet(
            "QPushButton { text-align: left; font-weight: bold; border: none;"
            f" padding: 2px 0; color: {color}; }}"
        )

    def set_title(self, title: str) -> None:
        """Update the header text — e.g. when a count in the title changes."""
        self._title = title
        self._update_header()

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._body.setVisible(self._expanded)
        self._apply_size_policy()
        self._update_header()
        invalidate_layout_chain(self)
        self.toggled.emit(self._expanded)

    def _update_header(self) -> None:
        arrow = "▼" if self._expanded else "▶"
        self._header_btn.setText(f"{arrow} {self._title}")
