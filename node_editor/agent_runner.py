"""
One thread owns every agent process.

The backends are CLI subprocesses. Concurrency therefore belongs to the
**processes**, not to threads: one supervisor thread starts up to
``MAX_PARALLEL`` of them, records their pids, drains their pipes, reaps them, and
goes back to sleep when none are left. Callers never spawn, poll or kill
anything — they hand over a job and wait for it.

Why this shape:

* **Cancelling is exact.** The runner knows every live pid, so stopping is
  "kill these process groups", not "hope each thread notices a flag". A caller
  that walks away cannot leave an orphan process or a leaked slot behind,
  because it never owned either.
* **The cap is structural.** At most ``MAX_PARALLEL`` processes exist because
  the supervisor starts no more than that; there is no counter to leak. The
  previous design used a global semaphore held by worker threads, and an
  abandoned thread took its permit with it — four of those and every later run
  blocked forever with no subprocess ever started.
* **It is inspectable.** ``state()`` reports what is queued and what is running,
  which is what a stuck instance needs to explain itself (see diagnostics.py).

Qt-free. The supervisor is a daemon thread: a wedged CLI call can never keep the
application from exiting.
"""
from __future__ import annotations

import logging
import os
import selectors
import signal
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from . import cancel

_LOG = logging.getLogger("node_editor")

# How many agent processes may run at once. Kept modest: the CLIs are rate
# limited, and a burst of them is worse than a queue.
MAX_PARALLEL = 4

# How often the supervisor wakes to poll pipes and deadlines while work is live.
_TICK = 0.1

# How long a cancelled task list is given to actually stop before the caller
# gives up on it. A killed process dies in milliseconds; this is the bound that
# keeps a pathological one from holding the window.
_CANCEL_GRACE = 10.0


@dataclass
class Job:
    """One agent invocation: what to run, and what came back."""
    argv: List[str]
    stdin: Optional[str] = None
    timeout: float = 180.0
    label: str = ""
    # Where to run it. Static verification runs the agent inside the source tree
    # so its file tools resolve repository-relative paths.
    cwd: Optional[str] = None

    stdout: str = ""
    stderr: str = ""
    returncode: Optional[int] = None
    error: str = ""                     # "" when the call completed normally
    pid: Optional[int] = None
    started_at: float = 0.0

    _done: threading.Event = field(default_factory=threading.Event, repr=False)
    _cancel: bool = field(default=False, repr=False)
    _batch: Optional["Batch"] = field(default=None, repr=False)
    _released: bool = field(default=False, repr=False)   # counters dropped once

    @property
    def ok(self) -> bool:
        return not self.error and self.returncode == 0

    def cancel(self) -> None:
        self._cancel = True

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._done.wait(timeout)


@dataclass
class Batch:
    """A task list and how many of its tasks are still outstanding.

    The count — not a notification — is what completion means. A signal can be
    missed, delivered early, or sent by a thread that then dies; a counter that
    only the runner decrements, under the same mutex everyone waits on, cannot
    be any of those things. Waiters block on the condition variable and re-check
    ``remaining`` every time they wake.
    """
    jobs: List[Job] = field(default_factory=list)
    remaining: int = 0                  # guarded by AgentRunner._cond


class AgentRunner:
    """The single owner of agent processes.

    Synchronisation is one mutex and one condition variable (``_cond``, a
    ``threading.Condition`` — the mutex and the condvar together) plus counters:
    ``_outstanding`` for the whole runner and ``Batch.remaining`` per task list.
    Every mutation of the queue, the live-process table and those counters
    happens under that mutex, and every change that a waiter could care about is
    followed by ``notify_all()``.
    """

    def __init__(self, max_parallel: int = MAX_PARALLEL) -> None:
        self.max_parallel = max_parallel
        self._cond = threading.Condition()
        self._queue: deque = deque()
        self._live: Dict[int, Job] = {}          # pid → job
        self._procs: Dict[int, subprocess.Popen] = {}
        self._buffers: Dict[int, Dict[str, list]] = {}
        self._selector = selectors.DefaultSelector()
        self._thread: Optional[threading.Thread] = None
        self._outstanding = 0            # tasks submitted but not yet finished

    # ── public API ────────────────────────────────────────────────────────────

    def submit(self, job: Job) -> Job:
        """Queue a job. Returns immediately; wait on the job for its result."""
        self._ensure_thread()
        with self._cond:
            self._queue.append(job)
            self._outstanding += 1
            if job._batch is not None:
                job._batch.remaining += 1
            self._cond.notify_all()
        return job

    def run_one(self, job: Job) -> Job:
        """Submit and wait, honouring this thread's cancellation token.

        The caller blocks on the job, not on a process: if the user cancels, the
        job is marked and the supervisor kills its process group. The caller
        still waits for the job to *finish* — briefly — so that nothing is left
        running behind its back.
        """
        self.submit(job)
        while not job.wait(0.1):
            if cancel.cancelled() and not job._cancel:
                job.cancel()
                with self._cond:
                    self._cond.notify_all()
            if not self.healthy():
                self._fail_all("agent runner thread is not running")
        if job.error == "cancelled":
            cancel.check()                       # ours: raise CancelledError
            raise cancel.CancelledError("agent call was cancelled")
        return job

    def run_many(self, jobs: List[Job],
                 on_done: Optional[Callable[[Job], None]] = None) -> List[Job]:
        """Run a task list to completion; results stay in input order.

        The supervisor keeps ``max_parallel`` processes busy: as one exits the
        next task starts, until the list is empty. This returns when every task
        has finished — and it *verifies* that rather than trusting a signal:
        completion means "no task in this list is still outstanding", which is a
        fact about the list, not a notification that could be missed or sent
        early. ``on_done`` fires once per finished task, for progress.
        """
        batch = Batch(jobs=list(jobs))
        for job in jobs:
            job._batch = batch
            self.submit(job)

        reported: set = set()
        while True:
            # Wake on any change, then decide from the counter under the mutex.
            with self._cond:
                while batch.remaining > 0 and self.healthy() and not cancel.cancelled():
                    self._cond.wait(0.1)
                remaining = batch.remaining
                dead = not self.healthy()
                stopping = cancel.cancelled()

            for job in jobs:                    # progress, outside the mutex
                if job._done.is_set() and id(job) not in reported:
                    reported.add(id(job))
                    if on_done is not None:
                        on_done(job)

            if remaining == 0:
                break                           # every task accounted for
            if stopping:
                with self._cond:
                    for job in jobs:
                        if not job._done.is_set():
                            job.cancel()
                    self._cond.notify_all()
                # Round again: the supervisor kills the processes and releases
                # the tasks, so the counter still has to reach zero before this
                # returns — a cancelled run leaves nothing running behind it.
                with self._cond:
                    deadline = time.monotonic() + _CANCEL_GRACE
                    while batch.remaining > 0 and time.monotonic() < deadline:
                        self._cond.wait(0.1)
                    if batch.remaining > 0:
                        # Refuses to die: stop waiting rather than hold the UI.
                        _LOG.warning("%d agent task(s) did not stop within %.0fs",
                                     batch.remaining, _CANCEL_GRACE)
                        break
            if dead:
                # The owner is gone; its tasks can never complete, and waiting
                # for them would hang the window forever.
                self._fail_all("agent runner thread is not running")

        if any(j.error == "cancelled" for j in jobs):
            cancel.check()
        return jobs

    def healthy(self) -> bool:
        """Is the supervisor alive? Callers must never wait on a dead owner."""
        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def remaining(self) -> int:
        """Tasks submitted and not yet finished, across the whole runner."""
        with self._cond:
            return self._outstanding

    def cancel_all(self) -> int:
        """Stop everything queued and running. Returns how many were affected."""
        with self._cond:
            affected = len(self._queue) + len(self._live)
            for job in list(self._queue) + list(self._live.values()):
                job.cancel()
            self._cond.notify_all()
        return affected

    def state(self) -> dict:
        """What the runner is doing — for the diagnostics dump."""
        with self._cond:
            return {
                "alive": bool(self._thread and self._thread.is_alive()),
                "queued": len(self._queue),
                "running": [
                    {"pid": pid, "label": job.label,
                     "elapsed": round(time.monotonic() - job.started_at, 1),
                     "cancelled": job._cancel}
                    for pid, job in self._live.items()
                ],
            }

    # ── the supervisor ────────────────────────────────────────────────────────

    def _ensure_thread(self) -> None:
        with self._cond:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._loop, daemon=True,
                                                name="agent-runner")
                self._thread.start()

    def _loop(self) -> None:
        while True:
            try:
                with self._cond:
                    # Nothing to do: sleep until someone submits work.
                    while not self._queue and not self._live:
                        self._cond.wait()
                    # Start as many as the cap allows; as each one exits, the
                    # next tick starts the next task in the list.
                    while self._queue and len(self._live) < self.max_parallel:
                        self._start(self._queue.popleft())
                self._service()
            except BaseException as exc:          # noqa: BLE001
                # A supervisor that dies takes every waiting caller with it:
                # they would block on a completion that can never be signalled.
                # Fail the outstanding work loudly instead, and keep running.
                _LOG.exception("agent runner tick failed: %s", exc)
                self._fail_all(f"agent runner error: {type(exc).__name__}: {exc}")

    def _fail_all(self, error: str) -> None:
        """Release every queued and running job with an error. Nothing hangs."""
        with self._cond:
            for pid in list(self._live):
                job = self._live.pop(pid)
                proc = self._procs.pop(pid, None)
                self._buffers.pop(pid, None)
                if proc is not None:
                    self._kill(proc)
                if not job.error:
                    job.error = error
                self._release(job)
            while self._queue:
                job = self._queue.popleft()
                if not job.error:
                    job.error = error
                self._release(job)
            self._cond.notify_all()

    def _start(self, job: Job) -> None:
        """Spawn one process. Called with the lock held."""
        if job._cancel:
            self._finish_unstarted(job, "cancelled")
            return
        try:
            proc = subprocess.Popen(
                job.argv,
                cwd=job.cwd or None,
                stdin=subprocess.PIPE if job.stdin is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                # Its own process group: cancelling kills the CLI *and* anything
                # it spawned, so no grandchild survives holding the pipes open.
                start_new_session=True,
            )
        except (OSError, ValueError) as exc:
            self._finish_unstarted(job, f"could not start {job.argv[0]}: {exc}")
            return

        job.pid = proc.pid
        job.started_at = time.monotonic()
        self._live[proc.pid] = job
        self._procs[proc.pid] = proc
        self._buffers[proc.pid] = {"out": [], "err": []}

        if job.stdin is not None and proc.stdin is not None:
            try:
                proc.stdin.write(job.stdin.encode("utf-8"))
                proc.stdin.close()
            except (BrokenPipeError, ValueError, OSError):
                pass
        for pipe, which in ((proc.stdout, "out"), (proc.stderr, "err")):
            if pipe is not None:
                os.set_blocking(pipe.fileno(), False)
                self._selector.register(pipe, selectors.EVENT_READ, (proc.pid, which))

    def _release(self, job: Job) -> None:
        """Mark one task finished. Call with the mutex held.

        The single place a task's life ends: it drops the runner's counter and
        its batch's counter together, wakes every waiter, and only then sets the
        event. Anyone woken re-reads the counter and decides for itself.
        """
        if job._released:
            return
        job._released = True
        self._outstanding = max(0, self._outstanding - 1)
        if job._batch is not None:
            job._batch.remaining = max(0, job._batch.remaining - 1)
        job._done.set()
        self._cond.notify_all()

    def _finish_unstarted(self, job: Job, error: str) -> None:
        job.error = error
        self._release(job)

    def _service(self) -> None:
        """Drain pipes, enforce deadlines and cancellation, reap finished work."""
        if not self._live:
            return
        for key, _ in self._selector.select(timeout=_TICK):
            pid, which = key.data
            try:
                chunk = key.fileobj.read()
            except (OSError, ValueError):
                chunk = b""
            if chunk:
                buf = self._buffers.get(pid)
                if buf is not None:
                    buf[which].append(chunk)
            else:
                # EOF: the writer closed. Stop watching this pipe.
                try:
                    self._selector.unregister(key.fileobj)
                except (KeyError, ValueError):
                    pass

        with self._cond:
            for pid in list(self._live):
                job, proc = self._live[pid], self._procs[pid]
                overdue = time.monotonic() - job.started_at > job.timeout
                if job._cancel or overdue:
                    self._kill(proc)
                    if not job.error:
                        job.error = "cancelled" if job._cancel else "timeout"
                if proc.poll() is None:
                    continue
                self._reap(pid)
            self._cond.notify_all()

    def _reap(self, pid: int) -> None:
        """Collect a finished process's output and release it to its caller."""
        job = self._live.pop(pid)
        proc = self._procs.pop(pid)
        buffered = self._buffers.pop(pid, {"out": [], "err": []})

        for pipe in (proc.stdout, proc.stderr):
            if pipe is None:
                continue
            try:
                self._selector.unregister(pipe)
            except (KeyError, ValueError):
                pass

        out, err = b"", b""
        try:
            # Whatever is left in the pipe buffers after exit. The pipes are
            # non-blocking, so read() returns None rather than blocking.
            if proc.stdout is not None:
                out = proc.stdout.read() or b""
            if proc.stderr is not None:
                err = proc.stderr.read() or b""
        except (OSError, ValueError):
            pass
        job.stdout = (b"".join(buffered["out"]) + out).decode("utf-8", "replace")
        job.stderr = (b"".join(buffered["err"]) + err).decode("utf-8", "replace")
        job.returncode = proc.returncode
        for pipe in (proc.stdout, proc.stderr, proc.stdin):
            try:
                if pipe is not None:
                    pipe.close()
            except OSError:
                pass
        self._release(job)

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        """Kill the process group; never block waiting for it."""
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except OSError:
                pass


# The application's runner. One per process, started on first use.
_runner: Optional[AgentRunner] = None
_runner_lock = threading.Lock()


def runner() -> AgentRunner:
    global _runner
    with _runner_lock:
        if _runner is None:
            _runner = AgentRunner()
        return _runner


def run_cli(argv: List[str], stdin: Optional[str] = None, timeout: float = 180.0,
            label: str = "", cwd: Optional[str] = None) -> Job:
    """Run one agent CLI call on the runner thread and return the finished job."""
    return runner().run_one(Job(argv=argv, stdin=stdin, timeout=timeout,
                                label=label, cwd=cwd))


def run_batch(jobs: List[Job],
              on_done: Optional[Callable[[Job], None]] = None) -> List[Job]:
    """Run independent agent calls concurrently, capped by the runner."""
    return runner().run_many(jobs, on_done=on_done)


def state() -> dict:
    return runner().state()
