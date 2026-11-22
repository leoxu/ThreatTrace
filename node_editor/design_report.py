"""
Design phase verification report.

The artifact that closes the design phase of the threat model: the diagram as
designed, the threats identified on it, and the security controls applied to
mitigate them — plus a verdict on whether the design is ready to hand to
implementation.

Entry points:
    build_markdown(scene, threats, diag_name, ...) -> str
    export_markdown(scene, threats, diag_name, out_path, ...) -> Path
    export_pdf(scene, threats, diag_name, out_path, ...) -> Path

The implementation-phase counterpart (does the code match this design?) lives in
conformance.py — see doc/impl-verification-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, TYPE_CHECKING

from .report import _capture_scene_png, fit_document_images_to_page

if TYPE_CHECKING:
    from .threat import Threat, ThreatRegistry
    from .validation import ValidationIssue


_PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}


# ── gathering ─────────────────────────────────────────────────────────────────

@dataclass
class ControlSummary:
    """One security control as designed, with what it covers and mitigates."""
    node_id: str          # the control definition's id (what threats link to)
    name: str
    container_name: str = ""
    control_type: str = ""
    requirement_id: str = ""
    description: str = ""
    covered: List[str] = field(default_factory=list)     # "asset.interface"
    edge_count: int = 0
    in_scope: int = 0                                    # threats within its scope
    mitigated: List["Threat"] = field(default_factory=list)


@dataclass
class ReviewNote:
    """An open or resolved review thread from the comment layer."""
    subject: str
    status: str
    entries: List[str] = field(default_factory=list)   # "Who (Role) · when: text"


@dataclass
class ReportData:
    diag_name: str
    generated: str
    source_file: str
    threats: List["Threat"]
    controls: List[ControlSummary]
    issues: List["ValidationIssue"]
    orphan_controls: List[ControlSummary]     # placed but covering nothing
    reviews: List[ReviewNote] = field(default_factory=list)

    @property
    def open_reviews(self) -> List[ReviewNote]:
        return [r for r in self.reviews if r.status == "open"]

    @property
    def mitigated(self) -> List["Threat"]:
        return [t for t in self.threats if t.mitigation_sc_ids]

    @property
    def open(self) -> List["Threat"]:
        return [t for t in self.threats if not t.mitigation_sc_ids]

    def open_by_priority(self, priority: str) -> List["Threat"]:
        return [t for t in self.open if t.priority == priority]

    @property
    def errors(self) -> List["ValidationIssue"]:
        return [i for i in self.issues if i.severity == "Error"]

    @property
    def passed(self) -> bool:
        """Ready to hand on: no validation errors, no open High-priority threats,
        and no unanswered review question."""
        return (not self.errors
                and not self.open_by_priority("High")
                and not self.open_reviews)


def collect(scene, threats: "ThreatRegistry", diag_name: str,
            issues: Optional[List["ValidationIssue"]] = None,
            source_file: str = "", sequences: Optional[dict] = None) -> ReportData:
    """Gather everything the report needs from the live scene."""
    from .mitigation import control_scopes, is_security_control
    from .graphics.items import NodeItem
    from .review import is_review_node, read_thread, status as review_status, subject as review_subject

    by_guid = dict(threats)
    controls: List[ControlSummary] = []
    orphans: List[ControlSummary] = []
    reviews: List[ReviewNote] = []

    for item in scene.items() if scene is not None else []:
        if isinstance(item, NodeItem) and is_review_node(item.properties()):
            p = item.properties()
            reviews.append(ReviewNote(
                subject=review_subject(p),
                status=review_status(p),
                entries=[f"{c.header()}: {c.text}" for c in read_thread(p)],
            ))
        if not isinstance(item, NodeItem) or not is_security_control(item):
            continue
        # One entry per control definition inside the container.
        scopes = control_scopes(item, scene, by_guid, sequences)
        if not scopes:
            orphans.append(ControlSummary(
                node_id=item.node_id,
                name=str(item.properties().get("name", item.title)),
                container_name=str(item.properties().get("name", item.title)),
                control_type="(container holds no control)",
            ))
            continue
        for scope in scopes:
            summary = ControlSummary(
                node_id=scope.control.node_id,
                name=scope.control.name,
                container_name=scope.control.container_name,
                control_type=scope.control.control_type,
                requirement_id=scope.control.requirement_id,
                description=scope.control.description,
                covered=[f"{s.asset_name}.{s.slot_name}" for s in scope.slots],
                edge_count=scope.edge_count,
                in_scope=len(scope.items),
                mitigated=[t for t in by_guid.values()
                           if scope.control.node_id in (t.mitigation_sc_ids or [])],
            )
            (controls if summary.covered else orphans).append(summary)

    controls.sort(key=lambda c: c.name)
    orphans.sort(key=lambda c: c.name)

    threat_list = sorted(
        by_guid.values(),
        key=lambda t: (_PRIORITY_ORDER.get(t.priority, 3), t.title),
    )
    return ReportData(
        diag_name=diag_name,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        source_file=source_file,
        threats=threat_list,
        controls=controls,
        issues=list(issues or []),
        orphan_controls=orphans,
        reviews=sorted(reviews, key=lambda r: (r.status != "open", r.subject)),
    )


# ── markdown rendering ────────────────────────────────────────────────────────

def _esc(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip() or "—"


def _cvss(t: "Threat") -> str:
    metrics = [t.cvss_av, t.cvss_ac, t.cvss_pr, t.cvss_ui,
               t.cvss_s, t.cvss_c, t.cvss_i, t.cvss_a]
    if not all(metrics):
        return "—"
    from .cvss import cvss_base_score
    return f"{cvss_base_score(*metrics):.1f}"


def _cvss_detail(t: "Threat") -> str:
    """'7.8 (High) — CVSS:3.1/AV:L/...' or '—' when the metrics are not set."""
    score = _cvss(t)
    if score == "—":
        return "—"
    from .cvss import cvss_severity
    severity = cvss_severity(float(score))
    return f"{score} ({severity})" + (f" — {t.cvss_vector}" if t.cvss_vector else "")


def _verification_evidence(threat, control_id: str) -> List[str]:
    """Where the verification evidence came from, so a reader can check it."""
    from . import verification as _V

    out: List[str] = []
    entries = (getattr(threat, "verification", {}) or {}).get(control_id) or {}
    for phase in (_V.PHASE_STATIC, _V.PHASE_DYNAMIC):
        entry = entries.get(phase)
        if not entry:
            continue
        where = ", ".join(
            f"`{c.get('file', '?')}"
            + (f":{c.get('line_start')}" if c.get("line_start") else "") + "`"
            for c in (entry.get("citations") or [])[:4])
        bits = [f"{phase}: {entry.get('result', '?')}"]
        if entry.get("revision"):
            bits.append(f"revision `{entry['revision']}`")
        if entry.get("at"):
            bits.append(str(entry["at"]))
        line = " · ".join(bits)
        if where:
            line += f" — {where}"
        out.append(line)
    return out


def _control_names(data: ReportData) -> Dict[str, str]:
    return {c.node_id: c.name for c in data.controls + data.orphan_controls}


def _sequence_labels(sequences: Optional[dict]) -> Dict[str, str]:
    """{seq_id: 'Sequence: name (n steps)'} — used for threats with no edge."""
    return {
        sid: f"Sequence: {seq.name} ({len(seq.steps)} steps)"
        for sid, seq in (sequences or {}).items()
    }


def _threat_location(t: "Threat", edges: Dict[str, str], seqs: Dict[str, str]) -> str:
    """Where a threat sits: its connection, or the sequence that owns it."""
    if t.edge_guid:
        label = edges.get(t.edge_guid, "")
        if t.sequence_guid and t.sequence_guid in seqs:
            label = f"{label} — step of {seqs[t.sequence_guid].removeprefix('Sequence: ')}"
        return label
    return seqs.get(t.sequence_guid, "Sequence" if t.sequence_guid else "")


def _edge_labels(scene) -> Dict[str, str]:
    """{edge_id: 'Src → Dst (sub-type)'} for every edge in the scene."""
    from .graphics.items import EdgeItem, NodeItem

    labels: Dict[str, str] = {}
    for item in scene.items() if scene is not None else []:
        if not isinstance(item, EdgeItem):
            continue

        def _name(slot):
            node = slot.parentItem() if slot is not None else None
            return str(node.properties().get("name", node.title)) if isinstance(node, NodeItem) else "?"

        sub = str(item.properties().get("sub-type", "")).strip()
        label = f"{_name(item.src)} → {_name(item.dst)}"
        labels[item.edge_id] = f"{label} ({sub})" if sub else label
    return labels


def _threat_table(threats: List["Threat"], control_names: Dict[str, str],
                  edge_labels: Dict[str, str], with_controls: bool,
                  ids: Optional[Dict[str, str]] = None,
                  seq_labels: Optional[Dict[str, str]] = None) -> List[str]:
    seq_labels = seq_labels or {}
    header = "| ID | Threat | Category | Priority | CVSS | Connection / Sequence |"
    divider = "|----|--------|----------|----------|------|------------|"
    if with_controls:
        header += " Mitigating control(s) |"
        divider += "-----------------------|"
    out = [header, divider]
    for i, t in enumerate(threats, 1):
        tid = (ids or {}).get(t.guid, str(i))
        row = (f"| {tid} | {_esc(t.title)} | {_esc(t.category)} | {t.priority or '—'} "
               f"| {_cvss(t)} | {_esc(_threat_location(t, edge_labels, seq_labels))} |")
        if with_controls:
            names = ", ".join(control_names.get(c, c) for c in t.mitigation_sc_ids) or "—"
            row += f" {_esc(names)} |"
        out.append(row)
    out.append("")
    return out


def _threat_detail(t: "Threat", tid: str, control_names: Dict[str, str],
                   edge_labels: Dict[str, str],
                   seq_labels: Optional[Dict[str, str]] = None) -> List[str]:
    """Full record for one threat: every field the author filled in."""
    L: List[str] = [f"### {tid} — {t.title or '(untitled)'}", ""]

    facts = [
        ("Category", t.category),
        ("Priority", t.priority),
        ("Status", t.status),
        ("CVSS", _cvss_detail(t)),
        ("Connection", _threat_location(t, edge_labels, seq_labels or {})),
        ("Scope", "Whole sequence" if (t.sequence_guid and not t.edge_guid)
                  else ("Sequence step" if t.sequence_guid else "Connection")),
        ("Interaction", t.interaction),
        ("Asset", " ".join(x for x in (t.asset, f"({t.asset_property})"
                                       if t.asset_property else "") if x)),
        ("Attack path", t.attack_path),
        ("Authorizer", t.authorizer),
        ("Identified by", ", ".join(t.ai_backends)),
    ]
    compliance = ", ".join(t.cwe_ids + t.nist_controls + t.owasp_categories)
    if compliance:
        facts.append(("Compliance", compliance))
    trace = "; ".join(x for x in (
        f"Bug/Jira: {t.bug_jira_link}" if t.bug_jira_link else "",
        f"JAMA: {t.jama_link}" if t.jama_link else "",
        f"Failure mode: {t.failure_mode_id}" if t.failure_mode_id else "",
        f"Duplicate of: {t.duplicate_threat}" if t.duplicate_threat else "",
    ) if x)
    if trace:
        facts.append(("Traceability", trace))

    L += ["| Field | Value |", "|-------|-------|"]
    for label, value in facts:
        if str(value).strip() and str(value).strip() != "—":
            L.append(f"| {label} | {_esc(value)} |")
    L.append("")

    for heading, text in (
        ("Description", t.description),
        ("Short description", t.short_description),
        ("Damage scenario", t.damage_scenario),
        ("Justification", t.justification),
        ("Failure mode", t.failure_mode_description),
        ("Recommended mitigations", t.mitigations),
    ):
        if str(text).strip():
            L += [f"**{heading}**", "", str(text).strip(), ""]

    L += ["**Applied security controls**", ""]
    if t.mitigation_sc_ids:
        from . import verification as _V
        for sc_id in t.mitigation_sc_ids:
            L.append(f"- {control_names.get(sc_id, sc_id)}"
                     f" — *{_V.label(t, sc_id)}*")
            for line in _verification_evidence(t, sc_id):
                L.append(f"  - {line}")
            note = (t.mitigation_notes or {}).get(sc_id, "").strip()
            for line in note.splitlines():
                if line.strip():
                    L.append(f"  - {line.strip()}")
    else:
        L.append("- None — this threat is open.")
    L.append("")
    return L


def build_markdown(scene, threats: "ThreatRegistry", diag_name: str,
                   issues: Optional[List["ValidationIssue"]] = None,
                   source_file: str = "", image_name: str = "",
                   sequences: Optional[dict] = None) -> str:
    """Render the design phase verification report as Markdown."""
    from .ui.attack_surface_panel import scan_attack_surface

    data = collect(scene, threats, diag_name, issues, source_file, sequences)
    names = _control_names(data)
    edges = _edge_labels(scene)
    seqs = _sequence_labels(sequences)
    total = len(data.threats)
    n_mit = len(data.mitigated)
    coverage = f"{(n_mit / total * 100):.0f}%" if total else "—"

    L: List[str] = [
        f"# Design Phase Verification Report — {data.diag_name}",
        "",
        f"Generated: {data.generated}  ",
        f"Model: {data.source_file or '(unsaved)'}  ",
        "Scope: the threat model as designed — diagram, identified threats, and "
        "the security controls applied to mitigate them.",
        "",
        "---",
        "",
        "## 1. Verdict",
        "",
    ]

    verdict = "**PASS** — design ready for implementation" if data.passed else \
              "**NEEDS ATTENTION** — see the blocking items below"
    L += [
        verdict,
        "",
        "| Check | Result |",
        "|-------|--------|",
        f"| Model validation errors | {len(data.errors)} |",
        f"| Model validation warnings | {len(data.issues) - len(data.errors)} |",
        f"| Threats identified | {total} |",
        f"| Threats mitigated by a control | {n_mit} ({coverage}) |",
        f"| Threats open | {len(data.open)} |",
        f"| Open — High priority | {len(data.open_by_priority('High'))} |",
        f"| Open — Medium priority | {len(data.open_by_priority('Medium'))} |",
        f"| Open — Low priority | {len(data.open_by_priority('Low'))} |",
        f"| Security controls applied | {len(data.controls)} |",
        f"| Review threads open | {len(data.open_reviews)} of {len(data.reviews)} |",
        "",
    ]

    blocking: List[str] = []
    if data.errors:
        blocking.append(f"{len(data.errors)} model validation error(s) — see section 6.")
    if data.open_by_priority("High"):
        blocking.append(
            f"{len(data.open_by_priority('High'))} High-priority threat(s) with no "
            "mitigating control — see section 5."
        )
    if not data.controls and total:
        blocking.append("No security control covers any asset interface.")
    if data.orphan_controls:
        blocking.append(
            f"{len(data.orphan_controls)} control(s) placed but covering no asset "
            "interface: " + ", ".join(c.name for c in data.orphan_controls) + "."
        )
    if data.open_reviews:
        blocking.append(
            f"{len(data.open_reviews)} unresolved review thread(s) — see section 9."
        )
    if blocking:
        L += ["**Blocking / follow-up items**", ""]
        L += [f"- {b}" for b in blocking] + [""]

    # ── 2. diagram ───────────────────────────────────────────────────────────
    L += ["---", "", "## 2. Design", ""]
    if image_name:
        L += [f"![{data.diag_name}]({image_name})", ""]
    else:
        L += ["_(diagram image not exported)_", ""]

    # ── 3. controls ──────────────────────────────────────────────────────────
    L += ["---", "", "## 3. Security Controls Applied", ""]
    if not data.controls:
        L += ["_No security control covers an asset interface in this design._", ""]
    else:
        L += [
            "| Control | Container | Type | Requirement | Covers | Connections | Threats in scope | Mitigated |",
            "|---------|-----------|------|-------------|--------|-------------|------------------|-----------|",
        ]
        for c in data.controls:
            L.append(
                f"| {_esc(c.name)} | {_esc(c.container_name)} | {_esc(c.control_type)} "
                f"| {_esc(c.requirement_id)} | {_esc(', '.join(c.covered))} "
                f"| {c.edge_count} | {c.in_scope} | {len(c.mitigated)} |"
            )
        L.append("")
        for c in data.controls:
            L += [f"### {c.name} ({c.control_type or 'no type'})", ""]
            if c.requirement_id:
                L += [f"Requirement: {c.requirement_id}", ""]
            if c.description:
                L += [c.description, ""]
            L += [f"Applied to: {', '.join(c.covered)}", ""]
            if c.mitigated:
                L += ["Mitigates:", ""]
                for t in c.mitigated:
                    L.append(f"- **{t.title}** ({t.category or '—'}, {t.priority or '—'})")
                    note = (t.mitigation_notes or {}).get(c.node_id, "").strip()
                    for line in note.splitlines():
                        if line.strip():
                            L.append(f"  - {line.strip()}")
                L.append("")
            else:
                L += ["_No threat in this control's scope is currently linked to it._", ""]

    if data.orphan_controls:
        L += ["### Controls covering nothing", "",
              "Placed in the diagram but mitigating nothing — either the "
              "container covers no asset interface, or it holds no control:", ""]
        L += [f"- {c.name} ({c.control_type or 'no type'})" for c in data.orphan_controls]
        L.append("")

    # ── 4/5. threats ─────────────────────────────────────────────────────────
    # Stable per-threat ids so the summary tables and the detail records below
    # cross-reference each other.
    ids = {t.guid: f"T{i}" for i, t in enumerate(data.threats, 1)}

    L += ["---", "", "## 4. Threats Mitigated", ""]
    if data.mitigated:
        L += _threat_table(data.mitigated, names, edges, with_controls=True, ids=ids,
                           seq_labels=seqs)
    else:
        L += ["_No threat has a mitigating control linked._", ""]

    L += ["---", "", "## 5. Open Threats", ""]
    if data.open:
        L += ["These threats have no mitigating security control in the design:", ""]
        L += _threat_table(data.open, names, edges, with_controls=False, ids=ids,
                           seq_labels=seqs)
    else:
        L += ["_Every identified threat has at least one mitigating control._", ""]

    # ── 6. threat details ────────────────────────────────────────────────────
    L += ["---", "", "## 6. Threat Details", ""]
    if data.threats:
        L += ["Full record of every identified threat, highest priority first.", ""]
        for t in data.threats:
            L += _threat_detail(t, ids[t.guid], names, edges, seqs)
    else:
        L += ["_No threats identified in this design._", ""]

    # ── 7. validation ────────────────────────────────────────────────────────
    L += ["---", "", "## 7. Model Validation", ""]
    if data.issues:
        L += ["| Severity | Rule | Detail |", "|----------|------|--------|"]
        for i in sorted(data.issues, key=lambda x: x.severity != "Error"):
            L.append(f"| {i.severity} | {_esc(i.rule)} | {_esc(i.message)} |")
        L.append("")
    else:
        L += ["_No validation issues._", ""]

    # ── 8. attack surface ────────────────────────────────────────────────────
    entry_points = scan_attack_surface(scene, threats) if scene is not None else []
    if entry_points:
        L += ["---", "", "## 8. Attack Surface Entry Points", "",
              "| Connection | Source | Destination | Boundary | Threats | Open |",
              "|------------|--------|-------------|----------|---------|------|"]
        for ep in entry_points:
            L.append(
                f"| {_esc(ep.edge_label)} | {_esc(ep.src_name)} | {_esc(ep.dst_name)} "
                f"| {_esc(ep.boundary_name)} | {ep.threat_count} | {ep.unmitigated} |"
            )
        L.append("")

    # ── 9. review threads ────────────────────────────────────────────────────
    if data.reviews:
        L += ["---", "", "## 9. Review Threads", "",
              f"{len(data.open_reviews)} of {len(data.reviews)} thread(s) unresolved.", ""]
        for r in data.reviews:
            L += [f"### {r.subject} — {r.status}", ""]
            L += ([f"- {e}" for e in r.entries] if r.entries else ["_(no comment)_"]) + [""]

    return "\n".join(L) + "\n"


# ── export ────────────────────────────────────────────────────────────────────

def export_markdown(scene, threats: "ThreatRegistry", diag_name: str, out_path: Path,
                    issues: Optional[List["ValidationIssue"]] = None,
                    source_file: str = "", sequences: Optional[dict] = None) -> Path:
    """Write the report (and its diagram PNG) next to *out_path*."""
    out_path = Path(out_path)
    png_path = out_path.with_suffix(".png")
    png_path.write_bytes(_capture_scene_png(scene))
    text = build_markdown(scene, threats, diag_name, issues, source_file,
                          png_path.name, sequences)
    out_path.write_text(text, encoding="utf-8")
    return out_path


def export_pdf(scene, threats: "ThreatRegistry", diag_name: str, out_path: Path,
               issues: Optional[List["ValidationIssue"]] = None,
               source_file: str = "", sequences: Optional[dict] = None) -> Path:
    from PySide6.QtGui import QTextDocument
    from PySide6.QtPrintSupport import QPrinter

    out_path = Path(out_path)
    md_path = export_markdown(scene, threats, diag_name, out_path.with_suffix(".md"),
                              issues, source_file, sequences)

    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(out_path))
    doc = QTextDocument()
    # Resolve the ![](diagram.png) link relative to the markdown file.
    doc.setBaseUrl(_file_url(md_path.parent))
    doc.setMarkdown(md_path.read_text(encoding="utf-8"))
    # Without this the diagram is laid out at its pixel size scaled to the
    # printer's dpi and runs off the page.
    fit_document_images_to_page(doc, printer)
    doc.print_(printer)
    return out_path


def _file_url(directory: Path):
    from PySide6.QtCore import QUrl
    return QUrl.fromLocalFile(str(directory) + "/")
