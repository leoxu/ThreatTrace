"""
Run a long task (an LLM agent call) off the UI thread.

The AI backends shell out to the Claude / Codex CLIs, which routinely take a
minute or more. Running that on the GUI thread freezes the window — the OS marks
it "not responding" and nothing repaints. Instead the work runs in a QThread
while a modal :class:`BusyDialog` keeps the event loop turning: the window stays
alive and repaints, progress and elapsed time update, and the user can see what
the agent is doing.

Usage::

    result = run_task_with_progress(
        self, "Generate Threats", "Preparing…",
        lambda progress: generate_threats_combined_detailed(ctx, progress_callback=progress),
    )

``task`` receives one argument: a ``progress(step, total, text)`` callback that
is safe to call from the worker thread (it is delivered to the dialog through a
queued signal).
"""
from __future__ import annotations

import logging
from typing import Callable, Optional

from PySide6.QtCore import QElapsedTimer, QEventLoop, QObject, Qt, QThread, QTimer, Signal, Slot
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from ..cancel import CancelledError, CancelToken, set_current

_LOG = logging.getLogger("node_editor")


class BusyDialog(QDialog):
    """Friendly 'the agent is working' dialog: status, progress, elapsed time
    and a Cancel button that really stops the work."""

    cancelRequested = Signal()
    # "Stop waiting for the worker and give me the window back." Offered only
    # when a cancelled task has not unwound within _FORCE_CLOSE_AFTER_MS: this
    # dialog is modal and has no close button, so without it a task that refuses
    # to stop takes the whole application with it.
    forceCloseRequested = Signal()

    _FORCE_CLOSE_AFTER_MS = 5000

    def __init__(self, title: str, label: str, total_steps: int = 0, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        # No close button: the task owns the dialog's lifetime.
        self.setWindowFlags(
            (self.windowFlags() | Qt.CustomizeWindowHint)
            & ~Qt.WindowCloseButtonHint
            & ~Qt.WindowContextHelpButtonHint
        )
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(8)

        self._status = QLabel(label)
        self._status.setWordWrap(True)
        self._status.setStyleSheet("font-size: 13px; font-weight: bold;")
        layout.addWidget(self._status)

        self._bar = QProgressBar()
        # 0..0 renders as an indeterminate "busy" bar until a step count arrives.
        self._bar.setRange(0, max(0, total_steps))
        self._bar.setValue(0)
        self._bar.setTextVisible(False)
        self._bar.setFixedHeight(14)
        layout.addWidget(self._bar)

        self._elapsed_lbl = QLabel("")
        self._elapsed_lbl.setStyleSheet("color: #666; font-size: 11px;")
        layout.addWidget(self._elapsed_lbl)

        hint = QLabel(
            "The AI agent runs in the background — this can take a minute or "
            "two per backend."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #666; font-size: 11px;")
        layout.addWidget(hint)

        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self._cancel_btn: QPushButton = buttons.button(QDialogButtonBox.Cancel)
        self._cancel_btn.setToolTip(
            "Stop the agent: the running CLI call is killed and nothing further "
            "is started. Anything already accepted is kept."
        )
        buttons.rejected.connect(self._on_cancel)
        layout.addWidget(buttons)

        self._force_mode = False
        self._closing = False           # set only by force_close(), see reject()

        self._timer_source = QElapsedTimer()
        self._timer_source.start()
        self._tick()
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def _on_cancel(self) -> None:
        """Ask the task to stop; the dialog stays up until the worker returns."""
        if self._force_mode:
            self.forceCloseRequested.emit()
            return
        self._cancel_btn.setEnabled(False)
        self._cancel_btn.setText("Cancelling…")
        self._status.setText("Cancelling — stopping the agent…")
        self._bar.setRange(0, 0)          # back to indeterminate while it unwinds
        self.cancelRequested.emit()
        QTimer.singleShot(self._FORCE_CLOSE_AFTER_MS, self._offer_force_close)

    def _offer_force_close(self) -> None:
        """A cancel that is taking too long stops being the user's problem."""
        if not self.isVisible() or self._force_mode:
            return
        self._force_mode = True
        self._cancel_btn.setEnabled(True)
        self._cancel_btn.setText("Close anyway")
        self._cancel_btn.setToolTip(
            "Stop waiting and return to the editor. The backend call is left to "
            "finish in the background; nothing further will be applied."
        )
        self._status.setText(
            "Still stopping the agent — this is taking longer than it should.\n"
            "Close anyway to get back to the editor."
        )

    def force_close(self) -> None:
        """Close for real. The only way this dialog goes away.

        ``close()`` cannot be used: Qt implements it by delivering a close event,
        whose default handler calls ``reject()`` — and reject() here means
        "request cancel and stay up". Overriding reject() therefore turns
        close() into a no-op, which once left the dialog on screen forever with
        no button that could dismiss it.
        """
        self._closing = True
        self.done(QDialog.Rejected)

    def reject(self) -> None:  # type: ignore[override]
        # Esc and the window close button mean "cancel the work", not "close the
        # window" — the task owns this dialog's lifetime. force_close() is the
        # one exception, and says so explicitly.
        if self._closing:
            super().reject()
            return
        if self._cancel_btn.isEnabled():
            self._on_cancel()

    def _tick(self) -> None:
        secs = self._timer_source.elapsed() // 1000
        self._elapsed_lbl.setText(f"Elapsed {secs // 60}:{secs % 60:02d}")

    @Slot(int, int, str)
    def set_progress(self, step: int, total: int, text: str) -> None:
        if total > 0:
            self._bar.setRange(0, total)
            self._bar.setValue(max(0, min(step, total)))
        if text:
            self._status.setText(text)

    def stop(self) -> None:
        self._timer.stop()


# How long the GUI thread waits for a worker to unwind before detaching it.
_WAIT_FOR_WORKER_MS = 5000

# Detached workers, kept alive until they really finish: a QThread deleted (or
# whose parent is deleted) while still running takes the process down.
_ORPHANS: list = []


def _detach(thread: QThread, worker: "_TaskWorker", dlg: "BusyDialog") -> None:
    """Let a worker that will not stop finish on its own, out of the way.

    Its signals are disconnected first, so nothing it emits later reaches a
    dialog or an event loop that has gone — a detached task's results are
    deliberately dropped, since the user asked to stop.
    """
    for signal in (worker.progress, worker.done, worker.failed, worker.cancelled):
        try:
            signal.disconnect()
        except (RuntimeError, TypeError):
            pass
    thread.setParent(None)
    _ORPHANS.append((thread, worker))

    def _reap() -> None:
        for entry in [e for e in _ORPHANS if e[0].isFinished()]:
            _ORPHANS.remove(entry)
            entry[1].deleteLater()
            entry[0].deleteLater()

    thread.finished.connect(_reap)
    _LOG.warning("agent task did not stop within %ss; detached (%d running)",
                 _WAIT_FOR_WORKER_MS // 1000, len(_ORPHANS))


class _TaskWorker(QObject):
    """Runs ``task(progress)`` in whatever thread this object is moved to."""

    progress = Signal(int, int, str)
    done = Signal(object)
    failed = Signal(str)
    cancelled = Signal()

    def __init__(self, task: Callable, token: CancelToken):
        super().__init__()
        self._task = task
        self._token = token

    @Slot()
    def run(self) -> None:
        # Publish the token for this thread so the CLI runners can kill their
        # subprocess and the loops can stop between items.
        set_current(self._token)
        try:
            result = self._task(
                lambda step, total, text: self.progress.emit(int(step), int(total), str(text))
            )
        except CancelledError:
            self.cancelled.emit()
            return
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
            return
        finally:
            set_current(None)
        self.done.emit(result)


def run_task_with_progress(
    parent,
    title: str,
    label: str,
    task: Callable,
    total_steps: int = 0,
    dialog: Optional[BusyDialog] = None,
):
    """Run *task* in a worker thread, showing a busy dialog until it finishes.

    Returns the task's return value, or None when the user cancelled. If the
    task raised, the exception is re-raised here as a RuntimeError carrying the
    original message, so callers can keep their existing try/except structure.
    """
    dlg = dialog or BusyDialog(title, label, total_steps, parent)
    token = CancelToken()
    dlg.cancelRequested.connect(token.cancel)
    thread = QThread(parent)
    worker = _TaskWorker(task, token)
    worker.moveToThread(thread)
    thread.started.connect(worker.run)

    loop = QEventLoop()
    outcome: dict = {}

    def _done(result) -> None:
        outcome["result"] = result
        loop.quit()

    def _failed(message: str) -> None:
        outcome["error"] = message
        loop.quit()

    def _cancelled() -> None:
        outcome["cancelled"] = True
        loop.quit()

    def _force_close() -> None:
        outcome["cancelled"] = True
        outcome["detach"] = True
        loop.quit()

    worker.progress.connect(dlg.set_progress)
    worker.done.connect(_done)
    worker.failed.connect(_failed)
    worker.cancelled.connect(_cancelled)
    dlg.forceCloseRequested.connect(_force_close)

    dlg.show()
    thread.start()
    try:
        # The worker lives in another thread, so its signals are queued and can
        # only arrive once this loop runs — but guard anyway.
        if not outcome:
            loop.exec()
    finally:
        thread.quit()
        # Bounded, always. This runs on the GUI thread, so waiting here with no
        # limit hands the whole application to whatever the worker is stuck on —
        # exactly the freeze this dialog exists to prevent. A worker that will
        # not stop is detached instead: it keeps running (its CLI call is
        # already killed and its results are dropped), the window comes back.
        if outcome.get("detach") or not thread.wait(_WAIT_FOR_WORKER_MS):
            _detach(thread, worker, dlg)
        else:
            worker.deleteLater()
            thread.deleteLater()
        dlg.stop()
        dlg.force_close()

    if outcome.get("cancelled"):
        return None
    if "error" in outcome:
        raise RuntimeError(outcome["error"])
    return outcome.get("result")
