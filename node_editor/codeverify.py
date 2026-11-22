"""
Static verification — is this security control actually in the code?

The design phase says a control *should* be there; this asks whether it **is**,
and makes the agent show its work. The chain is:

    security control → the asset interfaces its circle covers
                     → the source that implements those interfaces
                     → an agent reading that source
                     → a verdict with file:line citations

Two rules keep it honest:

* **Locate deterministically, judge with the agent.** A cheap local search finds
  the candidate files from facts the model already has — the interface's device
  path, the syscall names in its operation steps, the control's own keywords —
  so the agent starts from evidence rather than from a guess, and the scan is
  bounded to one subtree.
* **Cite or fail.** A verdict with no ``file:line`` is not a pass; it is
  ``insufficient-evidence``. This is the rule that stops the feature becoming a
  machine that says "looks good" about code it never read.

Qt-free: the scene is used through the same duck-typed accessors as
``mitigation.py``, so this runs headless and under test.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from . import agent_runner, cancel
from .threat_gen import DEFAULT_CLAUDE_MODEL

# Verdicts. Deliberately four: "I could not tell" is a real answer and must not
# be collapsed into either a pass or a failure.
VERDICT_IMPLEMENTED = "implemented"
VERDICT_NOT_IMPLEMENTED = "not-implemented"
VERDICT_INSUFFICIENT = "insufficient-evidence"
VERDICT_ERROR = "error"

VERDICT_ORDER = {VERDICT_NOT_IMPLEMENTED: 0, VERDICT_INSUFFICIENT: 1,
                 VERDICT_ERROR: 2, VERDICT_IMPLEMENTED: 3}

# Extensions worth reading. A source tree is mostly not source.
_CODE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".S", ".s",
                  ".py", ".rs", ".go", ".java", ".kt", ".dts", ".dtsi",
                  ".mk", ".kconfig", ".rc", ".te", ".conf", ".json", ".xml"}
_SKIP_DIRS = {".git", ".svn", "node_modules", "__pycache__", "build", "out",
              "dist", ".venv", "venv", ".mypy_cache", ".pytest_cache"}

# Search terms a control type suggests when the model gives us nothing sharper.
_CONTROL_TERMS: Dict[str, List[str]] = {
    "File Permission (ACL)": ["chmod", "umask", "S_IRUSR", "inode_permission",
                              "device_create", "class_create", "0600", "0660"],
    "Linux Capability": ["capable(", "CAP_SYS_ADMIN", "ns_capable", "CAP_"],
    "QNX Ability": ["procmgr_ability", "PROCMGR_AID", "ability"],
    "Firewall Rule": ["iptables", "nftables", "bpf", "filter", "allowlist"],
    "Encryption": ["AES", "EVP_", "crypto_", "encrypt", "decrypt", "TLS"],
    "Integrity Check": ["hmac", "sha256", "signature", "verify", "checksum", "crc"],
    "Audit Logging": ["audit", "syslog", "log_", "dev_info", "pr_notice"],
    "Secure Boot": ["verified_boot", "signature", "rollback", "fuse", "bootloader"],
    "TrustZone / TEE": ["smc", "tee_", "optee", "secure_world"],
    "Hardware Security Module (HSM)": ["hsm", "key_store", "pkcs11", "se050"],
    "CPU Address Space Isolation": ["mmu", "page_table", "pgprot", "iommu",
                                    "vm_flags"],
}


@dataclass
class SourceRef:
    """One citation: where in the tree the evidence is."""
    file: str
    line_start: int = 0
    line_end: int = 0
    excerpt: str = ""

    def label(self) -> str:
        if self.line_start and self.line_end and self.line_end != self.line_start:
            return f"{self.file}:{self.line_start}-{self.line_end}"
        if self.line_start:
            return f"{self.file}:{self.line_start}"
        return self.file

    def to_dict(self) -> dict:
        return {"file": self.file, "line_start": self.line_start,
                "line_end": self.line_end, "excerpt": self.excerpt}

    @staticmethod
    def from_dict(d: dict) -> "SourceRef":
        def _int(v) -> int:
            try:
                return int(v)
            except (TypeError, ValueError):
                return 0
        lines = d.get("lines")
        start, end = _int(d.get("line_start")), _int(d.get("line_end"))
        if isinstance(lines, str) and "-" in lines and not start:
            head, _, tail = lines.partition("-")
            start, end = _int(head), _int(tail)
        elif lines is not None and not start:
            start = _int(lines)
        return SourceRef(file=str(d.get("file", "")).strip(), line_start=start,
                         line_end=end or start,
                         excerpt=str(d.get("excerpt", ""))[:400])


@dataclass
class VerifyTask:
    """One question: is *this* control implemented for *this* asset?"""
    control_id: str
    control_name: str
    control_type: str
    control_description: str
    requirement_id: str = ""
    container_name: str = ""
    asset_name: str = ""
    asset_type: str = ""
    interfaces: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    operations: List[str] = field(default_factory=list)
    syscalls: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    # From the model: files that implement this asset (paths relative to the
    # source root) and the symbols worth reading. A file is somewhere to *look*,
    # a symbol is something to *search for* — mixing them made the search look
    # for a path inside file contents, which never matches.
    source_files: List[str] = field(default_factory=list)
    source_symbols: List[str] = field(default_factory=list)

    def label(self) -> str:
        return f"{self.control_name} → {self.asset_name}" if self.asset_name \
            else self.control_name

    def search_terms(self) -> List[str]:
        """What to look for, most specific first.

        Model facts beat guesses: a device path or an ioctl name appears in the
        code verbatim, whereas a control type only suggests vocabulary.
        """
        terms: List[str] = []
        for group in (self.paths, self.syscalls, self.source_symbols,
                      self.operations):
            for t in group:
                t = str(t).strip()
                if t and t not in terms:
                    terms.append(t)
        for t in _CONTROL_TERMS.get(self.control_type, []):
            if t not in terms:
                terms.append(t)
        return terms


@dataclass
class StaticFinding:
    """The answer, with its evidence and where it came from."""
    task: VerifyTask
    verdict: str = VERDICT_INSUFFICIENT
    confidence: float = 0.0
    rationale: str = ""
    citations: List[SourceRef] = field(default_factory=list)
    searched: List[str] = field(default_factory=list)   # candidate files scanned
    backend: str = ""
    source_root: str = ""
    revision: str = ""
    error: str = ""
    accepted: bool = True                 # set by the review dialog

    @property
    def implemented(self) -> bool:
        return self.verdict == VERDICT_IMPLEMENTED

    def to_dict(self) -> dict:
        return {"control_id": self.task.control_id,
                "control": self.task.control_name,
                "asset": self.task.asset_name,
                "verdict": self.verdict, "confidence": self.confidence,
                "rationale": self.rationale,
                "citations": [c.to_dict() for c in self.citations],
                "backend": self.backend, "source_root": self.source_root,
                "revision": self.revision, "error": self.error}


# ── building the questions from the model ────────────────────────────────────

def build_tasks(scene, threats=None, sequences=None,
                source_hints: Optional[Dict[str, List[str]]] = None) -> List[VerifyTask]:
    """One task per (control definition × asset it covers).

    A control that covers two assets is two questions: the code that implements
    it for one is rarely the code that implements it for the other.
    """
    from .graphics.items import NodeItem
    from .mitigation import control_scopes, is_security_control

    tasks: List[VerifyTask] = []
    for item in scene.items():
        if not isinstance(item, NodeItem) or not is_security_control(item):
            continue
        for scope in control_scopes(item, scene, threats or {}, sequences):
            by_asset: Dict[str, List] = {}
            for slot in scope.slots:
                by_asset.setdefault(slot.asset_name, []).append(slot)
            for asset_name, slots in by_asset.items():
                syscalls: List[str] = []
                for slot in slots:
                    syscalls.extend(_slot_syscalls(scene, slot))
                model_hints = _asset_source_hints(scene, asset_name)
                tasks.append(VerifyTask(
                    control_id=scope.control.node_id,
                    control_name=scope.control.name,
                    control_type=scope.control.control_type,
                    control_description=scope.control.description,
                    requirement_id=scope.control.requirement_id,
                    container_name=scope.control.container_name,
                    asset_name=asset_name,
                    asset_type=slots[0].asset_type,
                    interfaces=[s.interface or s.slot_name for s in slots],
                    paths=[s.path for s in slots if s.path],
                    operations=sorted({o for s in slots for o in s.operations}),
                    syscalls=sorted(set(syscalls)),
                    categories=sorted({c for s in slots
                                       for c in [_slot_category(scene, s)] if c}),
                    source_files=model_hints[0],
                    source_symbols=(model_hints[1]
                                    + list((source_hints or {}).get(asset_name, []))),
                ))
    return tasks


def _asset_source_hints(scene, asset_name: str):
    """(files, symbols) the model records for this asset.

    ``source-files`` and ``source-symbols`` on the asset's security properties:
    paths relative to the source root, and the functions worth reading. Both
    beat anything a search could guess, so the files go straight into the
    candidate list and the symbols lead the search terms.
    """
    from .graphics.items import NodeItem

    for item in scene.items():
        if not isinstance(item, NodeItem):
            continue
        props = item.properties()
        if str(props.get("name", "")) != asset_name:
            continue
        sec = props.get("security-properties")
        if not isinstance(sec, dict):
            continue
        def _split(key: str) -> List[str]:
            raw = str(sec.get(key, "") or "")
            return [part.strip() for part in re.split(r"[,\n;]", raw) if part.strip()]
        return _split("source-files"), _split("source-symbols")
    return [], []


def _slot_props(scene, covered) -> dict:
    """The live slot properties behind a CoveredSlot, if we can find them."""
    from .graphics.items import NodeItem, SlotItem

    for item in scene.items():
        if not isinstance(item, SlotItem):
            continue
        owner = item.parentItem()
        if not isinstance(owner, NodeItem):
            continue
        if str(owner.properties().get("name", "")) != covered.asset_name:
            continue
        if item.name == covered.slot_name:
            return item.properties() if hasattr(item, "properties") else {}
    return {}


def _slot_syscalls(scene, covered) -> List[str]:
    """Concrete calls an interface's operations are made of (ioctl names etc.)."""
    props = _slot_props(scene, covered)
    out: List[str] = []
    steps = props.get("op_steps") or {}
    if isinstance(steps, dict):
        for calls in steps.values():
            for call in calls or []:
                out.extend(_identifiers(str(call)))
    return out


def _slot_category(scene, covered) -> str:
    from .interface_categories import describe, resolve_slot

    props = _slot_props(scene, covered)
    summary = str(props.get("category-summary", "") or "").strip()
    if summary:
        return summary
    category = resolve_slot(props, covered.asset_type,
                            covered.interface or covered.slot_name)
    return describe(category, {}, covered.path) if category else ""


_IDENT = re.compile(r"[A-Z][A-Z0-9_]{4,}|[a-z_][a-z0-9_]{4,}\(")


def _identifiers(call: str) -> List[str]:
    """Pull the greppable names out of a syscall line.

    ``ioctl(fd, MYDEV_IOCTL_SUBMIT, &args)`` gives the ioctl macro,
    which is the thing that appears verbatim in the driver.
    """
    out = []
    for m in _IDENT.finditer(call):
        token = m.group(0).rstrip("(")
        if token.lower() in ("ioctl", "open", "close", "mmap", "munmap", "write",
                             "read", "fcntl", "args"):
            continue
        out.append(token)
    return out


# ── deterministic pre-scan ───────────────────────────────────────────────────

@dataclass
class ScanHit:
    file: str
    term: str
    line: int
    text: str


def prescan(root: str, terms: List[str], max_hits: int = 60,
            max_files: int = 25) -> List[ScanHit]:
    """Find candidate files locally before spending an agent call.

    Uses ripgrep when present and falls back to a plain walk, so this works on a
    machine without extra tooling. The result bounds the agent's search and is
    also shown in the report as *what was looked at*.
    """
    root_path = Path(root)
    if not terms or not root_path.is_dir():
        return []
    hits: List[ScanHit] = []
    seen_files: set = set()

    if shutil.which("rg"):
        for term in terms:
            if len(seen_files) >= max_files or len(hits) >= max_hits:
                break
            cancel.check()
            cmd = ["rg", "--no-heading", "--line-number", "--fixed-strings",
                   "--max-count", "3", "--max-filesize", "2M", "-i", term, "."]
            try:
                done = subprocess.run(cmd, cwd=str(root_path), text=True,
                                      capture_output=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                continue
            for line in done.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                path, lineno, text = parts[0].lstrip("./"), parts[1], parts[2]
                if Path(path).suffix and Path(path).suffix not in _CODE_SUFFIXES:
                    continue
                try:
                    hits.append(ScanHit(path, term, int(lineno), text.strip()[:200]))
                except ValueError:
                    continue
                seen_files.add(path)
                if len(hits) >= max_hits:
                    break
        return hits

    lowered = [t.lower() for t in terms]
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if Path(name).suffix not in _CODE_SUFFIXES:
                continue
            if len(seen_files) >= max_files or len(hits) >= max_hits:
                return hits
            cancel.check()
            full = Path(dirpath) / name
            try:
                if full.stat().st_size > 2_000_000:
                    continue
                text = full.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(full.relative_to(root_path))
            for lineno, line in enumerate(text.splitlines(), start=1):
                low = line.lower()
                for term, term_low in zip(terms, lowered):
                    if term_low in low:
                        hits.append(ScanHit(rel, term, lineno, line.strip()[:200]))
                        seen_files.add(rel)
                        break
                if len(hits) >= max_hits:
                    return hits
    return hits


def candidate_files(hits: List[ScanHit], named: Optional[List[str]] = None,
                    root: str = "", limit: int = 12) -> List[str]:
    """The files worth reading: the model's own first, then the best search hits.

    A file the modeller named is a statement about the system; a search hit is a
    guess. When both exist the statement leads.
    """
    out: List[str] = []
    for path in (named or []):
        if root and not (Path(root) / path).exists():
            continue                    # stale entry: say nothing, do not mislead
        if path not in out:
            out.append(path)
    counts: Dict[str, int] = {}
    for h in hits:
        counts[h.file] = counts.get(h.file, 0) + 1
    for path, _ in sorted(counts.items(), key=lambda kv: -kv[1]):
        if path not in out:
            out.append(path)
    return out[:limit]


def git_revision(root: str) -> str:
    """The revision the evidence belongs to — evidence without one goes stale
    silently."""
    try:
        done = subprocess.run(["git", "-C", str(root), "rev-parse", "--short", "HEAD"],
                              text=True, capture_output=True, timeout=10)
        if done.returncode == 0:
            return done.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


# ── asking the agent ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a security engineer verifying whether a security \
control is actually implemented in a source tree.

You have read-only tools (Read, Grep, Glob). Use them: open the candidate files, \
follow the call chain, and read enough to be sure. Do not guess from file names.

Rules you must follow:
1. Every claim needs a citation: a real file path and line number you read.
2. If you cannot find the mechanism, answer "not-implemented". If the code is \
absent, unreadable or too ambiguous to judge, answer "insufficient-evidence". \
Never answer "implemented" without at least one citation.
3. Judge only the control described. A different control being present is not \
evidence for this one.
4. Report what the code does, not what it should do.

Reply with ONE JSON object and nothing else:
{"verdict": "implemented" | "not-implemented" | "insufficient-evidence",
 "confidence": 0.0-1.0,
 "rationale": "2-4 sentences: what the code does and why that does or does not \
implement the control",
 "citations": [{"file": "relative/path.c", "line_start": 120, "line_end": 134,
                "excerpt": "the decisive line(s)"}]}"""


def _format_prompt(task: VerifyTask, hits: List[ScanHit], files: List[str]) -> str:
    lines: List[str] = []
    lines.append("SECURITY CONTROL TO VERIFY")
    lines.append(f"  Name: {task.control_name}")
    lines.append(f"  Type: {task.control_type}")
    if task.requirement_id:
        lines.append(f"  Requirement: {task.requirement_id}")
    lines.append(f"  Specified configuration: {task.control_description or '(none given)'}")

    lines.append("")
    lines.append("WHAT IT IS SUPPOSED TO PROTECT")
    lines.append(f"  Asset: {task.asset_name} ({task.asset_type})")
    for iface in task.interfaces:
        lines.append(f"  Interface: {iface}")
    for cat in task.categories:
        lines.append(f"    Channel type: {cat}")
    for path in task.paths:
        lines.append(f"    Path: {path}")
    if task.operations:
        lines.append(f"    Operations: {', '.join(task.operations)}")
    if task.syscalls:
        lines.append(f"    Calls involved: {', '.join(task.syscalls[:12])}")

    if task.source_files:
        lines.append("")
        lines.append("FILES THE MODEL SAYS IMPLEMENT THIS ASSET (read these first)")
        for f in task.source_files:
            lines.append(f"  {f}")
    if task.source_symbols:
        lines.append(f"  Relevant symbols: {', '.join(task.source_symbols[:12])}")
    others = [f for f in files if f not in task.source_files]
    if others:
        lines.append("")
        lines.append("OTHER CANDIDATES (from a local search; follow the code "
                     "wherever it goes)")
        for f in others:
            lines.append(f"  {f}")
    if hits:
        lines.append("")
        lines.append("SEARCH HITS")
        for h in hits[:20]:
            lines.append(f"  {h.file}:{h.line}  [{h.term}]  {h.text}")
    if not files and not hits:
        lines.append("")
        lines.append("A local search for the interface path, its syscalls and the "
                     "control's usual vocabulary found nothing. Search the tree "
                     "yourself before concluding.")

    lines.append("")
    lines.append(f"Question: in this source tree, is the control "
                 f"'{task.control_name}' implemented for {task.asset_name}"
                 + (f" ({', '.join(task.interfaces)})" if task.interfaces else "")
                 + "? Read the code and answer with the JSON object.")
    return "\n".join(lines)


def _parse_response(raw: str) -> dict:
    """Pull the JSON object out of the reply, however it was wrapped."""
    text = (raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?|```$", "", text).strip()
    try:
        return json.loads(text)
    except ValueError:
        pass
    start, depth = None, 0
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    return json.loads(text[start:i + 1])
                except ValueError:
                    start = None
    return {}


def verify_task(task: VerifyTask, source_root: str,
                model: str = DEFAULT_CLAUDE_MODEL, timeout: float = 600.0,
                revision: str = "") -> StaticFinding:
    """Run one verification. Never raises for a backend problem — it reports it."""
    root = str(Path(source_root).expanduser())
    finding = StaticFinding(task=task, source_root=root,
                            revision=revision or git_revision(root))
    if not Path(root).is_dir():
        finding.verdict = VERDICT_ERROR
        finding.error = f"Source root '{root}' is not a directory."
        return finding

    hits = prescan(root, task.search_terms())
    files = candidate_files(hits, named=task.source_files, root=root)
    finding.searched = files

    cmd = [
        "claude",
        "-p", _format_prompt(task, hits, files),
        "--output-format", "json",
        "--model", model,
        "--system-prompt", _SYSTEM_PROMPT,
        # Read-only tools, scoped to the tree being verified. The agent has to
        # read the code — that is the entire point — but it must not change it.
        "--allowedTools", "Read", "Grep", "Glob",
        "--add-dir", root,
        "--strict-mcp-config",
        "--no-session-persistence",
    ]
    job = agent_runner.run_cli(cmd, timeout=timeout, cwd=root,
                               label=f"verify {task.control_name[:24]}")
    finding.backend = "Claude CLI"
    if job.error or job.returncode != 0:
        finding.verdict = VERDICT_ERROR
        finding.error = job.error or (job.stderr.strip()[:300] or "backend failed")
        return finding

    try:
        answer = _parse_response(json.loads(job.stdout).get("result", ""))
    except (ValueError, KeyError):
        answer = _parse_response(job.stdout)
    if not answer:
        finding.verdict = VERDICT_ERROR
        finding.error = "Could not parse the backend's reply."
        return finding

    verdict = str(answer.get("verdict", "")).strip().lower()
    if verdict not in (VERDICT_IMPLEMENTED, VERDICT_NOT_IMPLEMENTED,
                       VERDICT_INSUFFICIENT):
        verdict = VERDICT_INSUFFICIENT
    finding.rationale = str(answer.get("rationale", "")).strip()
    finding.citations = [SourceRef.from_dict(c) for c in answer.get("citations", [])
                         if isinstance(c, dict) and str(c.get("file", "")).strip()]
    try:
        finding.confidence = max(0.0, min(1.0, float(answer.get("confidence", 0))))
    except (TypeError, ValueError):
        finding.confidence = 0.0

    # Cite or fail. An "implemented" with nothing to point at is the failure
    # mode this whole feature exists to prevent, so it is demoted, not trusted.
    if verdict == VERDICT_IMPLEMENTED and not finding.citations:
        finding.verdict = VERDICT_INSUFFICIENT
        finding.rationale = ("Reported as implemented but cited no source "
                             "location, so it cannot be checked. "
                             + finding.rationale).strip()
        finding.confidence = min(finding.confidence, 0.3)
    else:
        finding.verdict = verdict
    return finding


def verify_all(tasks: List[VerifyTask], source_root: str,
               model: str = DEFAULT_CLAUDE_MODEL, timeout: float = 600.0,
               progress_callback: Optional[Callable[[int, int, str], None]] = None
               ) -> List[StaticFinding]:
    """Verify every task, one agent call each, reporting progress."""
    revision = git_revision(str(Path(source_root).expanduser()))
    total = max(1, len(tasks))
    out: List[StaticFinding] = []
    for index, task in enumerate(tasks):
        cancel.check()
        if progress_callback is not None:
            progress_callback(index, total, f"Verifying {task.label()}…")
        out.append(verify_task(task, source_root, model=model, timeout=timeout,
                               revision=revision))
    if progress_callback is not None:
        progress_callback(total, total, "Finished")
    return out


def apply_findings(findings: List[StaticFinding], threats,
                   asset_of_threat: Optional[Callable[[object], str]] = None) -> int:
    """Record each verdict against the threats that rely on that control.

    A threat is linked to a *control definition*; a finding is about that
    definition in one asset's code. When a control covers two assets there are
    two findings, so prefer the one whose asset matches the threat's — a control
    implemented for one asset says nothing about the other.

    Returns how many (threat, control) links were updated. Only accepted
    findings are applied: a verdict the reviewer dropped is not evidence.
    """
    from . import verification as V

    by_control: Dict[str, List[StaticFinding]] = {}
    for f in findings:
        if f.accepted and f.verdict != VERDICT_ERROR:
            by_control.setdefault(f.task.control_id, []).append(f)

    result_for = {VERDICT_IMPLEMENTED: V.RESULT_VERIFIED,
                  VERDICT_NOT_IMPLEMENTED: V.RESULT_FAILED,
                  VERDICT_INSUFFICIENT: V.RESULT_INSUFFICIENT}

    updated = 0
    for threat in threats:
        asset = asset_of_threat(threat) if asset_of_threat else ""
        for control_id in list(getattr(threat, "mitigation_sc_ids", []) or []):
            candidates = by_control.get(control_id)
            if not candidates:
                continue
            match = next((c for c in candidates if asset and c.task.asset_name == asset),
                         candidates[0])
            V.record(threat, control_id, V.PHASE_STATIC,
                     result_for.get(match.verdict, V.RESULT_INSUFFICIENT),
                     rationale=match.rationale, confidence=match.confidence,
                     citations=[c.to_dict() for c in match.citations],
                     revision=match.revision, source=match.backend)
            updated += 1
    return updated


def summarise(findings: List[StaticFinding]) -> Dict[str, int]:
    counts = {VERDICT_IMPLEMENTED: 0, VERDICT_NOT_IMPLEMENTED: 0,
              VERDICT_INSUFFICIENT: 0, VERDICT_ERROR: 0}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    return counts


# ── the report ───────────────────────────────────────────────────────────────

_VERDICT_LABEL = {
    VERDICT_IMPLEMENTED: "IMPLEMENTED",
    VERDICT_NOT_IMPLEMENTED: "NOT IMPLEMENTED",
    VERDICT_INSUFFICIENT: "INSUFFICIENT EVIDENCE",
    VERDICT_ERROR: "ERROR",
}


def _esc(text: str) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def build_markdown(findings: List[StaticFinding], model_name: str = "",
                   source_root: str = "", revision: str = "",
                   generated: str = "") -> str:
    """The static verification report.

    Verdict first, then a row per control, then the evidence in full. A reader
    should be able to check any claim without opening the tool: every citation
    is a path and a line number in a named revision.
    """
    from datetime import datetime

    accepted = [f for f in findings if f.accepted]
    counts = summarise(accepted)
    gaps = [f for f in accepted if f.verdict in (VERDICT_NOT_IMPLEMENTED,
                                                 VERDICT_INSUFFICIENT,
                                                 VERDICT_ERROR)]
    stamp = generated or datetime.now().strftime("%Y-%m-%d %H:%M")

    L: List[str] = []
    L.append("# Static Verification Report")
    L.append("")
    L.append(f"Generated: {stamp}")
    if model_name:
        L.append(f"Model: {model_name}")
    if source_root:
        L.append(f"Source root: `{source_root}`"
                 + (f" at revision `{revision}`" if revision else ""))
    L.append("")
    L.append("Scope: every security control in the model, checked against the "
             "source that implements the asset interfaces it covers. A verdict "
             "of *implemented* requires a citation; an agent that cannot point "
             "at the code reports *insufficient evidence* instead.")
    L.append("")

    # ── 1. verdict ──
    L.append("## 1. Verdict")
    L.append("")
    if not accepted:
        L.append("**NOTHING VERIFIED** — no control was checked.")
    elif not gaps:
        L.append(f"**PASS** — all {len(accepted)} control(s) are implemented in "
                 "the source, with citations.")
    else:
        L.append(f"**NEEDS ATTENTION** — {len(gaps)} of {len(accepted)} control(s) "
                 "could not be confirmed.")
    L.append("")
    L.append("| Result | Controls |")
    L.append("|---|---|")
    for verdict in (VERDICT_IMPLEMENTED, VERDICT_NOT_IMPLEMENTED,
                    VERDICT_INSUFFICIENT, VERDICT_ERROR):
        if counts.get(verdict):
            L.append(f"| {_VERDICT_LABEL[verdict]} | {counts[verdict]} |")
    L.append("")
    if gaps:
        L.append("**Follow-up items**")
        L.append("")
        for f in gaps:
            L.append(f"- {_VERDICT_LABEL[f.verdict]}: **{_esc(f.task.control_name)}** "
                     f"on {_esc(f.task.asset_name)}"
                     + (f" — {_esc(f.error)}" if f.error else ""))
        L.append("")

    # ── 2. the table ──
    L.append("## 2. Controls")
    L.append("")
    L.append("| Control | Type | Asset / interface | Requirement | Verdict | Evidence |")
    L.append("|---|---|---|---|---|---|")
    for f in accepted:
        where = _esc(f.task.asset_name)
        if f.task.interfaces:
            where += " · " + _esc(", ".join(f.task.interfaces))
        cites = ", ".join(f"`{c.label()}`" for c in f.citations[:3]) or "—"
        L.append(f"| {_esc(f.task.control_name)} | {_esc(f.task.control_type)} | "
                 f"{where} | {_esc(f.task.requirement_id) or '—'} | "
                 f"{_VERDICT_LABEL[f.verdict]} | {cites} |")
    L.append("")

    # ── 3. the evidence ──
    L.append("## 3. Evidence")
    L.append("")
    for index, f in enumerate(accepted, 1):
        L.append(f"### V{index:02d} — {f.task.control_name} · {f.task.asset_name}")
        L.append("")
        L.append(f"**Verdict:** {_VERDICT_LABEL[f.verdict]}"
                 + (f" (confidence {f.confidence:.2f})" if f.confidence else ""))
        L.append("")
        if f.task.requirement_id:
            L.append(f"**Requirement:** {f.task.requirement_id}")
            L.append("")
        L.append(f"**Specified:** {f.task.control_description or '(no configuration given)'}")
        L.append("")
        if f.task.interfaces:
            L.append(f"**Covers:** {', '.join(f.task.interfaces)}"
                     + (f" — {', '.join(f.task.paths)}" if f.task.paths else ""))
            L.append("")
        if f.rationale:
            L.append(f"**Finding:** {f.rationale}")
            L.append("")
        if f.citations:
            L.append("**Citations**")
            L.append("")
            for c in f.citations:
                L.append(f"- `{c.label()}`")
                if c.excerpt:
                    L.append("")
                    L.append("  ```")
                    for line in c.excerpt.splitlines()[:6]:
                        L.append(f"  {line}")
                    L.append("  ```")
            L.append("")
        if f.searched:
            L.append(f"**Files searched:** {', '.join(f'`{s}`' for s in f.searched[:8])}")
            L.append("")
        if f.error:
            L.append(f"**Error:** {f.error}")
            L.append("")
        L.append(f"*Backend: {f.backend or 'n/a'}"
                 + (f" · source `{f.source_root}`" if f.source_root else "")
                 + (f" @ `{f.revision}`" if f.revision else "") + "*")
        L.append("")
    return "\n".join(L)


def export_markdown(findings: List[StaticFinding], out_path, **kwargs) -> Path:
    out_path = Path(out_path)
    out_path.write_text(build_markdown(findings, **kwargs), encoding="utf-8")
    return out_path


def export_pdf(findings: List[StaticFinding], out_path, **kwargs) -> Path:
    """PDF by way of Markdown, like the other reports."""
    from PySide6.QtGui import QTextDocument
    from PySide6.QtPrintSupport import QPrinter

    from .report import fit_document_images_to_page

    out_path = Path(out_path)
    md_path = export_markdown(findings, out_path.with_suffix(".md"), **kwargs)
    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(out_path))
    doc = QTextDocument()
    doc.setMarkdown(md_path.read_text(encoding="utf-8"))
    fit_document_images_to_page(doc, printer)
    doc.print_(printer)
    return out_path
