"""
Review comment notes.

A review note is a plain box the reviewer drops next to whatever they are
questioning. It carries a thread: the reviewer's question and the author's
replies, each stamped with who wrote it and when. Notes stay open until someone
marks the thread resolved, so an unresolved question is visible both on the
canvas and in the design verification report.

The thread lives in the node's own properties (``comments``/``review-status``),
so it is saved, copied and diffed with the rest of the model.

Qt-free: everything here works on the plain properties dict.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Tuple

REVIEW_CLASS = "review comment"

SUBJECT_KEY = "subject"
COMMENTS_KEY = "comments"
STATUS_KEY = "review-status"
# Where the speech-bubble tail points, in node-local coordinates. Dragged by the
# handle on the canvas so a note can point at whatever it is about.
TAIL_KEY = "tail-anchor"

STATUS_OPEN = "open"
STATUS_RESOLVED = "resolved"

ROLE_REVIEWER = "reviewer"
ROLE_AUTHOR = "author"

# Keys the review UI owns; the generic property rows must not render or
# round-trip them as plain strings.
MANAGED_KEYS = {COMMENTS_KEY, STATUS_KEY, TAIL_KEY}


def default_tail_anchor(width: float, height: float) -> Tuple[float, float]:
    """Where a fresh note's tail points: just below the balloon, left of centre."""
    return (width * 0.20, height + 22.0)


def tail_anchor(props: dict, width: float, height: float) -> Tuple[float, float]:
    """The stored tail anchor, or the default when unset/malformed."""
    raw = props.get(TAIL_KEY)
    if isinstance(raw, (list, tuple)) and len(raw) == 2:
        try:
            return (float(raw[0]), float(raw[1]))
        except (TypeError, ValueError):
            pass
    return default_tail_anchor(width, height)


def with_tail_anchor(props: dict, x: float, y: float) -> dict:
    out = dict(props)
    out[TAIL_KEY] = [round(float(x), 1), round(float(y), 1)]
    return out


@dataclass
class Comment:
    """One entry in a review thread."""
    text: str
    author: str = ""
    role: str = ROLE_REVIEWER          # who is speaking: reviewer / author
    at: str = ""                       # "YYYY-MM-DD HH:MM"

    def to_dict(self) -> dict:
        return {"text": self.text, "author": self.author,
                "role": self.role, "at": self.at}

    @staticmethod
    def from_dict(d: dict) -> "Comment":
        return Comment(
            text=str(d.get("text", "")),
            author=str(d.get("author", "")),
            role=str(d.get("role", ROLE_REVIEWER)),
            at=str(d.get("at", "")),
        )

    def header(self) -> str:
        who = self.author or "(unknown)"
        tag = "Author" if self.role == ROLE_AUTHOR else "Reviewer"
        return f"{who} ({tag})" + (f" · {self.at}" if self.at else "")


def is_review_node(props: dict) -> bool:
    return str(props.get("class", "")).startswith(REVIEW_CLASS)


def default_author() -> str:
    """Best guess at who is using the editor, used to stamp new comments."""
    return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def now_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def read_thread(props: dict) -> List[Comment]:
    raw = props.get(COMMENTS_KEY)
    if not isinstance(raw, list):
        return []
    return [Comment.from_dict(c) for c in raw if isinstance(c, dict)]


def subject(props: dict) -> str:
    return str(props.get(SUBJECT_KEY, "") or props.get("name", "") or "Review")


def status(props: dict) -> str:
    value = str(props.get(STATUS_KEY, STATUS_OPEN)).strip().lower()
    return STATUS_RESOLVED if value == STATUS_RESOLVED else STATUS_OPEN


def is_open(props: dict) -> bool:
    return status(props) == STATUS_OPEN


def with_thread(props: dict, comments: List[Comment]) -> dict:
    out = dict(props)
    out[COMMENTS_KEY] = [c.to_dict() for c in comments]
    return out


def add_comment(props: dict, text: str, author: str = "",
                role: str = "", at: Optional[str] = None) -> dict:
    """Return a copy of *props* with one comment appended.

    The role defaults to reviewer for the first entry (the question) and author
    for replies — the common case, and either can be overridden.
    """
    text = str(text).strip()
    if not text:
        return dict(props)
    thread = read_thread(props)
    if not role:
        role = ROLE_REVIEWER if not thread else ROLE_AUTHOR
    thread.append(Comment(text=text, author=author or default_author(),
                          role=role, at=at if at is not None else now_stamp()))
    return with_thread(props, thread)


def set_status(props: dict, new_status: str) -> dict:
    out = dict(props)
    out[STATUS_KEY] = (STATUS_RESOLVED
                       if str(new_status).lower() == STATUS_RESOLVED else STATUS_OPEN)
    return out


def toggle_status(props: dict) -> dict:
    return set_status(props, STATUS_OPEN if not is_open(props) else STATUS_RESOLVED)


def summary(props: dict) -> str:
    """One-line summary used in reports and panels."""
    thread = read_thread(props)
    head = thread[0].text.splitlines()[0] if thread else "(empty)"
    return f"{subject(props)}: {head}"


def canvas_text(props: dict, max_chars: int = 220) -> str:
    """The text drawn inside the note on the canvas: subject + latest entry."""
    thread = read_thread(props)
    if not thread:
        return "(no comment yet)"
    last = thread[-1]
    who = "Author" if last.role == ROLE_AUTHOR else "Reviewer"
    body = " ".join(last.text.split())
    if len(body) > max_chars:
        body = body[: max_chars - 1].rstrip() + "…"
    return f"{who}: {body}"
