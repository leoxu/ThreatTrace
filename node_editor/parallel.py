"""
Running several agent calls at once.

Every backend call is a CLI subprocess that spends almost all of its wall clock
waiting, so a pass that makes N of them — one per connection, one per control,
one per batch of threats — takes N × the call time for no reason. Running a
handful concurrently turns that into roughly N/workers.

Concurrency here is deliberately plain: the tasks are independent, produce their
own results, and touch nothing shared. Anything that touches Qt stays on the GUI
thread, as before — these run inside the worker thread that ``ui/async_task``
already puts agent work on.

Qt-free.
"""
from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from typing import Callable, List, Optional, Sequence, TypeVar

from . import cancel

_LOG = logging.getLogger("node_editor")

T = TypeVar("T")


# How many backend CLI calls may be in flight at once, across the whole
# application. Each spends nearly all of its time waiting on a subprocess, so
# running a handful together turns an N-call pass into roughly N/4 calls of wall
# clock. Kept modest: the CLIs are rate limited, and a burst is worse than a
# queue.
MAX_PARALLEL_CALLS = 4

# The limit is a global semaphore rather than a per-site worker count because
# the passes nest — a coverage run has controls in parallel and, inside each,
# batches of threats in parallel. Bounding the calls themselves keeps the total
# in flight at the limit however deeply the callers nest.
_call_slots = threading.BoundedSemaphore(MAX_PARALLEL_CALLS)

# How long a failed or cancelled run waits for its still-running tasks before
# returning without them. Long enough for a killed CLI call to unwind, short
# enough that the caller is never held by one wedged task.
_UNWIND_TIMEOUT = 10.0

# How long a call waits for a slot before giving up on the cap and running
# anyway. Long enough that it never fires under honest contention (a CLI
# call is 20-40s), short enough that a leak costs one slow run, not the
# feature.
_SLOT_WAIT_LIMIT = 90.0


@contextmanager
def call_slot():
    """Hold one of the concurrent-backend-call slots for the duration.

    The wait is polled rather than blocking outright: a thread parked in an
    uninterruptible ``acquire()`` cannot notice that its task was cancelled, so
    it keeps a pool — and the pass waiting on that pool — alive indefinitely.
    Here a cancelled task gives up its place in the queue instead.
    """
    deadline = time.monotonic() + _SLOT_WAIT_LIMIT
    held = False
    while not held:
        held = _call_slots.acquire(timeout=0.25)
        if held:
            break
        cancel.check()          # raises CancelledError; we hold nothing yet
        if time.monotonic() >= deadline:
            # Fail open. A slot is leaked when a wedged task is abandoned while
            # holding one (see ui/async_task detachment), and four leaks would
            # otherwise disable every future agent run for the lifetime of the
            # process — a permanent hang with no subprocess ever started, which
            # is far worse than briefly exceeding the concurrency cap.
            _LOG.warning("no agent call slot after %.0fs — proceeding without one; "
                         "%d slot(s) appear leaked",
                         _SLOT_WAIT_LIMIT, MAX_PARALLEL_CALLS)
            break
    try:
        yield
    finally:
        if held:
            _call_slots.release()


def run_parallel(funcs: Sequence[Callable[[], T]],
                 max_workers: int = 4,
                 on_done: Optional[Callable[[], None]] = None) -> List[T]:
    """Run zero-argument callables concurrently; return results in input order.

    Each worker inherits the caller's cancellation token — it is thread-local,
    so without this a cancelled run would not reach the subprocesses started
    here — and checks it before taking work, so cancelling stops the queue as
    well as killing what is already running.

    ``on_done`` is called once per finished task, serialised, for progress
    reporting. An exception from any task propagates to the caller (the earliest
    one, in input order) and unstarted tasks are dropped; tasks already running
    are left to finish, which is bounded by their own CLI timeout.

    Deliberately **not** ``ThreadPoolExecutor``: its workers are non-daemon and
    joined at interpreter shutdown, so a single task wedged in a library call
    stops the application from exiting at all. These workers are daemon threads,
    and this function's own wait is polled, so a cancelled or failed run always
    returns and a hung task can be abandoned rather than inherited.
    """
    funcs = list(funcs)
    if not funcs:
        return []

    workers = max(1, min(int(max_workers), len(funcs)))
    if workers == 1:
        out: List[T] = []
        for fn in funcs:
            cancel.check()
            out.append(fn())
            if on_done is not None:
                on_done()
        return out

    token = cancel.current()
    results: List = [None] * len(funcs)
    errors: List = []               # (index, exception), earliest index wins
    lock = threading.Lock()
    cond = threading.Condition(lock)
    done_lock = threading.Lock()
    started = 0                     # how many tasks have been handed out
    finished = 0                    # how many of those have returned

    def _claim() -> Optional[int]:
        """The next task to run, or None when no more should start."""
        nonlocal started
        with lock:
            if started >= len(funcs) or errors or cancel.cancelled():
                return None
            index = started
            started += 1
            return index

    def _worker() -> None:
        nonlocal finished
        cancel.set_current(token)
        while True:
            index = _claim()
            if index is None:
                return
            try:
                value = funcs[index]()
                with lock:
                    results[index] = value
            except BaseException as exc:            # noqa: BLE001 - reported below
                with lock:
                    errors.append((index, exc))
            finally:
                with lock:
                    finished += 1
                    cond.notify_all()
                if on_done is not None:
                    with done_lock:                 # serialised, off the main lock
                        on_done()

    threads = [threading.Thread(target=_worker, daemon=True,
                                name=f"agent-worker-{n}") for n in range(workers)]
    for thread in threads:
        thread.start()

    with cond:
        while True:
            if errors:
                break
            if started >= len(funcs) and finished == started:
                break
            if cancel.cancelled():
                # The user asked to stop. Give the running tasks a moment to
                # unwind — a killed CLI call takes well under a second — then
                # leave them to it: this answer must not depend on a task
                # cooperating, or a wedged one takes the window with it.
                cond.wait(_UNWIND_TIMEOUT if finished < started else 0.0)
                raise cancel.CancelledError("cancelled by the user")
            cond.wait(0.25)

    if errors:
        raise min(errors, key=lambda item: item[0])[1]
    return results
