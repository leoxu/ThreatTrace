"""
Getting the truth out of a wedged instance.

When the window stops responding — a dialog that will not close, an agent run
that never finishes — the only useful evidence is where every thread actually
is. Attaching a profiler needs ptrace privileges that a normal desktop session
does not have (``kernel.yama.ptrace_scope=1``), and by the time anyone asks for
sudo the instance has usually been killed.

So the application dumps its own stacks on demand:

    kill -USR1 <pid>        # every thread's Python stack → the dump file

The path is printed at startup and returned by ``dump_path()``. The dump also
records what the agent machinery believes about itself — free call slots, live
worker threads — because a hang is nearly always one of those two waiting on
the other.

Qt-free, signal-safe, and does nothing at all until asked.
"""
from __future__ import annotations

import faulthandler
import os
import signal
import sys
import threading
import traceback
from pathlib import Path
from typing import Optional, TextIO

_dump_file: Optional[TextIO] = None
_dump_path: Optional[Path] = None


def dump_path() -> Optional[Path]:
    return _dump_path


def _state_summary() -> str:
    """What the agent plumbing thinks is going on, in a few lines."""
    lines = []
    try:
        from . import agent_runner
        state = agent_runner.state()
        lines.append(f"agent runner: alive={state['alive']} "
                     f"queued={state['queued']} outstanding="
                     f"{agent_runner.runner().remaining()}")
        for proc in state["running"]:
            lines.append(f"  pid {proc['pid']} {proc['label']} "
                         f"{proc['elapsed']}s cancelled={proc['cancelled']}")
        if not state["running"]:
            lines.append("  (no agent process running)")
    except Exception as exc:                                # pragma: no cover
        lines.append(f"agent runner: unavailable ({exc})")

    try:
        from .ui import async_task
        lines.append(f"detached worker threads: {len(async_task._ORPHANS)}")
    except Exception:                                       # pragma: no cover
        pass

    alive = [t for t in threading.enumerate() if t.is_alive()]
    lines.append(f"python threads ({len(alive)}): "
                 + ", ".join(sorted(t.name for t in alive)))
    return "\n".join(lines)


def dump_now(reason: str = "manual") -> Optional[Path]:
    """Write every thread's stack, plus the agent state, to the dump file."""
    if _dump_file is None:
        return None
    _dump_file.write(f"\n{'=' * 72}\n=== stack dump ({reason}) pid {os.getpid()}\n")
    _dump_file.write(_state_summary() + "\n\n")
    _dump_file.flush()
    # faulthandler writes at fd level: it works even when the interpreter is
    # wedged holding the GIL, which is the case that matters here.
    faulthandler.dump_traceback(file=_dump_file, all_threads=True)
    _dump_file.write("\n--- python-level frames (with thread names) ---\n")
    names = {t.ident: t.name for t in threading.enumerate()}
    for ident, frame in sys._current_frames().items():
        _dump_file.write(f"\nthread {ident} ({names.get(ident, '?')}):\n")
        _dump_file.write("".join(traceback.format_stack(frame)))
    _dump_file.flush()
    return _dump_path


def install(directory: str = "/tmp") -> Optional[Path]:
    """Enable the crash handler and the SIGUSR1 stack dump. Returns the path."""
    global _dump_file, _dump_path

    if _dump_file is not None:
        return _dump_path
    try:
        _dump_path = Path(directory) / f"threattrace-stacks-{os.getpid()}.txt"
        _dump_file = _dump_path.open("w", encoding="utf-8", buffering=1)
    except OSError:
        _dump_file, _dump_path = None, None
        return None

    # A hard crash should leave the same evidence as a hang.
    faulthandler.enable(file=_dump_file, all_threads=True)

    if hasattr(signal, "SIGUSR1"):
        # Two handlers, deliberately. A Python-level handler only runs when the
        # interpreter next executes bytecode, and the main thread of a Qt app
        # sits inside the C++ event loop — so on a *hung* GUI, the case this
        # exists for, it may never run at all. faulthandler's handler is C-level
        # and writes the stacks of every thread immediately, whatever the
        # interpreter is doing; the Python one then adds the agent state when it
        # gets a chance (chain=True keeps it in the queue).
        signal.signal(signal.SIGUSR1, lambda *_: dump_now("SIGUSR1 (python)"))
        faulthandler.register(signal.SIGUSR1, file=_dump_file,
                              all_threads=True, chain=True)
    return _dump_path
