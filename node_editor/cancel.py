"""
Cooperative cancellation for long agent tasks.

A task runs in a worker thread (see ui/async_task.py) and spends nearly all of
its time inside a CLI subprocess. Cancelling therefore has to do two things:
kill the subprocess that is running right now, and stop the loop from starting
the next one.

The token is published per-thread rather than threaded through every function
signature, so `threat_gen` / `mitigation` only have to call `check()` at their
loop boundaries and the runners only have to poll `cancelled()`.

Qt-free.
"""
from __future__ import annotations

import threading
from typing import Optional


class CancelledError(Exception):
    """Raised inside a worker when the user cancelled the task."""


class CancelToken:
    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            raise CancelledError("cancelled by the user")


_local = threading.local()


def set_current(token: Optional[CancelToken]) -> None:
    """Publish *token* as this thread's cancellation token."""
    _local.token = token


def current() -> Optional[CancelToken]:
    return getattr(_local, "token", None)


def cancelled() -> bool:
    """True when this thread's task has been cancelled (never raises)."""
    token = current()
    return bool(token is not None and token.is_cancelled())


def check() -> None:
    """Raise CancelledError if this thread's task has been cancelled."""
    token = current()
    if token is not None:
        token.raise_if_cancelled()
