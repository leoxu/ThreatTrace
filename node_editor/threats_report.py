"""
Threats report — the project's threat register, ranked by risk.

Distinct from the other two reports: `report.py` shows one diagram with its
threats, `design_report.py` answers "is this design ready to hand on". This one
answers "what is our risk, and what is still open" across the whole project, in
risk order, and is the thing you take to a review or attach to a release.

Entry points:
    collect(project, nodes, options)      -> ThreatsReportData
    build_markdown(data)                  -> str
    export_markdown / export_pdf / export_csv(data, out_path)

Qt-free apart from the PDF step: `collect` reads the saved project structure
(diagrams, their edges and threats, the shared node registry), not live scene
items, so the report covers every diagram and can be unit-tested headless.

See doc/threats-report-design.md. Phase 1: summary, ranking, register and
traceability. CVSS scoring, distribution/asset breakdowns, revision comparison
and charts are later phases.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .threat import Threat

# Risk score without CVSS: the priority is all we have, and a mitigated threat
# is demoted rather than hidden — a mitigation is a claim, and its residual risk
# stays on the register. The report prints this rule so two copies can never be
# compared under different assumptions.
PRIORITY_SCORE = {"High": 8.0, "Medium": 5.0, "Low": 2.0}
UNSET_SCORE = 1.0
MITIGATED_FACTOR = 0.4

RISK_RULE = (
    "Risk score = priority (High 8, Medium 5, Low 2, unset 1); a threat with at "
    "least one security control linked is multiplied by 0.4 — demoted, not "
    "hidden, because its residual risk still counts."
)

_PRIORITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

SCOPE_PROJECT = "project"
SCOPE_DIAGRAM = "diagram"

FILTER_ALL = "all"
FILTER_OPEN = "open"
FILTER_MITIGATED = "mitigated"


@dataclass
class ReportOptions:
    scope: str = SCOPE_PROJECT
    threat_filter: str = FILTER_ALL
    min_priority: str = ""          # "", "Medium" or "High"
    diagram_name: str = ""          # when scope is a single diagram
    source_file: str = ""

    def describe_scope(self) -> str:
        return (f"diagram “{self.diagram_name}”" if self.scope == SCOPE_DIAGRAM
                else "whole project")

    def describe_filters(self) -> str:
        parts = {
            FILTER_OPEN: "open threats only",
            FILTER_MITIGATED: "mitigated threats only",
        }.get(self.threat_filter, "all threats")
        if self.min_priority:
            parts += f", {self.min_priority} priority and above"
        return parts


@dataclass
class RiskEntry:
    """One threat, scored and located."""
    threat: Threat
    score: float
    diagram: str
    location: str            # "A → B (submit cmdbuf)" or "Sequence: … (n steps)"
    asset: str = ""
    interface: str = ""
    controls: List[str] = field(default_factory=list)

    @property
    def mitigated(self) -> bool:
        return bool(self.threat.mitigation_sc_ids)


@dataclass
class ThreatsReportData:
    entries: List[RiskEntry]
    generated: str
    options: ReportOptions
    total_before_filters: int = 0
    orphaned: List[RiskEntry] = field(default_factory=list)

    @property
    def mitigated(self) -> List[RiskEntry]:
        return [e for e in self.entries if e.mitigated]

    @property
    def open(self) -> List[RiskEntry]:
        return [e for e in self.entries if not e.mitigated]

    def open_by_priority(self, priority: str) -> List[RiskEntry]:
        return [e for e in self.open if e.threat.priority == priority]

    def by_category(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for e in self.entries:
            out[e.threat.category or "—"] = out.get(e.threat.category or "—", 0) + 1
        return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


# ── scoring ───────────────────────────────────────────────────────────────────

def risk_score(threat: Threat) -> float:
    base = PRIORITY_SCORE.get(threat.priority, UNSET_SCORE)
    return base * (MITIGATED_FACTOR if threat.mitigation_sc_ids else 1.0)


# ── gathering ─────────────────────────────────────────────────────────────────

def _node_name(nodes: dict, node_id: str) -> str:
    entry = nodes.get(node_id) or {}
    props = entry.get("properties", {}) if isinstance(entry, dict) else {}
    return str(props.get("name", "")) or "?"


def _node_class(nodes: dict, node_id: str) -> str:
    entry = nodes.get(node_id) or {}
    props = entry.get("properties", {}) if isinstance(entry, dict) else {}
    return str(props.get("class", ""))


def _control_names(nodes: dict) -> Dict[str, str]:
    """{control definition id: 'Container ▸ Control'} across the project."""
    from .controls import read_controls

    out: Dict[str, str] = {}
    for nid, entry in (nodes or {}).items():
        props = entry.get("properties", {}) if isinstance(entry, dict) else {}
        if not str(props.get("class", "")).startswith("security control"):
            continue
        container = str(props.get("name", ""))
        for c in read_controls(props, nid):
            out[c.id] = c.name if c.name == container else f"{container} ▸ {c.name}"
    return out


def _edge_index(diagram: dict, nodes: dict) -> Dict[str, dict]:
    """{edge id: {label, asset, interface}} for one diagram's stored edges."""
    index: Dict[str, dict] = {}
    for edge in diagram.get("edges", []):
        src = (edge.get("from") or {})
        dst = (edge.get("to") or {})
        src_name = _node_name(nodes, src.get("node", ""))
        dst_name = _node_name(nodes, dst.get("node", ""))
        sub = str((edge.get("properties") or {}).get("sub-type", "")).strip()
        label = f"{src_name} → {dst_name}" + (f" ({sub})" if sub else "")

        # The asset end of the edge, when there is one.
        asset, interface = "", ""
        for end in (dst, src):
            if _node_class(nodes, end.get("node", "")).startswith("security asset"):
                asset = _node_name(nodes, end.get("node", ""))
                interface = str(end.get("slot", ""))
                break
        index[str(edge.get("id", ""))] = {
            "label": label, "asset": asset, "interface": interface,
        }
    return index


def collect(project: List[dict], nodes: dict,
            options: Optional[ReportOptions] = None) -> ThreatsReportData:
    """Build the register from the saved project structure."""
    options = options or ReportOptions()
    control_names = _control_names(nodes)

    entries: List[RiskEntry] = []
    orphaned: List[RiskEntry] = []
    total = 0

    for diagram in project:
        diag_name = str(diagram.get("name", "Diagram"))
        if (options.scope == SCOPE_DIAGRAM
                and options.diagram_name
                and diag_name != options.diagram_name):
            continue

        edges = _edge_index(diagram, nodes)
        sequences = diagram.get("sequences", {}) or {}

        for raw in (diagram.get("threats", {}) or {}).values():
            threat = raw if isinstance(raw, Threat) else Threat.from_dict(raw)
            total += 1

            location, asset, interface = "", "", ""
            orphan = False
            if threat.edge_guid:
                info = edges.get(threat.edge_guid)
                if info is None:
                    location, orphan = "(connection no longer in the model)", True
                else:
                    location = info["label"]
                    asset, interface = info["asset"], info["interface"]
            elif threat.sequence_guid:
                seq = sequences.get(threat.sequence_guid)
                if seq is None:
                    location, orphan = "(sequence no longer in the model)", True
                else:
                    steps = len(seq.get("steps", []) if isinstance(seq, dict) else [])
                    location = f"Sequence: {seq.get('name', 'Sequence')} ({steps} steps)"
            else:
                location, orphan = "(not attached to a connection)", True

            entry = RiskEntry(
                threat=threat,
                score=risk_score(threat),
                diagram=diag_name,
                location=location,
                asset=asset,
                interface=interface,
                controls=[control_names.get(c, c) for c in threat.mitigation_sc_ids],
            )
            (orphaned if orphan else entries).append(entry)

    keep = entries + orphaned
    if options.threat_filter == FILTER_OPEN:
        keep = [e for e in keep if not e.mitigated]
    elif options.threat_filter == FILTER_MITIGATED:
        keep = [e for e in keep if e.mitigated]
    if options.min_priority:
        limit = _PRIORITY_ORDER.get(options.min_priority, 3)
        keep = [e for e in keep
                if _PRIORITY_ORDER.get(e.threat.priority, 3) <= limit]

    kept = set(id(e) for e in keep)
    entries = [e for e in entries if id(e) in kept]
    orphaned = [e for e in orphaned if id(e) in kept]

    # Highest risk first; ties broken so the order never wobbles between runs.
    entries.sort(key=lambda e: (-e.score,
                                _PRIORITY_ORDER.get(e.threat.priority, 3),
                                e.threat.title, e.threat.guid))
    orphaned.sort(key=lambda e: (-e.score, e.threat.title))

    return ThreatsReportData(
        entries=entries,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M"),
        options=options,
        total_before_filters=total,
        orphaned=orphaned,
    )


# ── markdown ──────────────────────────────────────────────────────────────────

def _esc(text) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ").strip() or "—"


def _register_id(index: int) -> str:
    return f"R{index}"


def _verified_links(data: "ThreatsReportData") -> str:
    """Mitigations backed by evidence, not just by a design decision."""
    from . import verification as _V

    c = _V.counts([e.threat for e in data.entries])
    if not c["links"]:
        return "0"
    parts = [f"{c['verified']} of {c['links']} control link(s)"]
    if c["source"]:
        parts.append(f"{c['source']} in source")
    if c["runtime"]:
        parts.append(f"{c['runtime']} at runtime")
    if c["contradicted"]:
        parts.append(f"{c['contradicted']} contradicted")
    return " · ".join(parts)


def build_markdown(data: ThreatsReportData) -> str:
    """Render the register: summary, ranking, full records, traceability."""
    opt = data.options
    total = len(data.entries) + len(data.orphaned)
    mitigated = len(data.mitigated)
    coverage = f"{(mitigated / total * 100):.0f}%" if total else "—"

    L: List[str] = [
        "# Threats Report",
        "",
        f"Generated: {data.generated}  ",
        f"Model: {opt.source_file or '(unsaved)'}  ",
        f"Scope: {opt.describe_scope()}  ",
        f"Filter: {opt.describe_filters()}  ",
        f"Ranking: {RISK_RULE}",
        "",
        "---",
        "",
        "## 1. Summary",
        "",
        "| Measure | Value |",
        "|---------|-------|",
        f"| Threats in this report | {total} |",
    ]
    if total != data.total_before_filters:
        L.append(f"| Threats in scope before filtering | {data.total_before_filters} |")
    L += [
        f"| Mitigated by a control | {mitigated} ({coverage}) |",
        f"| …of those, verified | {_verified_links(data)} |",
        f"| Open | {len(data.open)} |",
        f"| Open — High | {len(data.open_by_priority('High'))} |",
        f"| Open — Medium | {len(data.open_by_priority('Medium'))} |",
        f"| Open — Low | {len(data.open_by_priority('Low'))} |",
        f"| Not attached to a live connection | {len(data.orphaned)} |",
        "",
    ]

    categories = data.by_category()
    if categories:
        L += ["Threats by STRIDE category:", ""]
        L += ["| Category | Count |", "|----------|-------|"]
        L += [f"| {_esc(k)} | {v} |" for k, v in categories.items()]
        L.append("")

    # ── 2. ranking ───────────────────────────────────────────────────────────
    L += ["---", "", "## 2. Risk Ranking", "",
          "Highest risk first. Full records in section 3.", "",
          "| ID | Risk | Threat | Priority | Category | Status | Where | Mitigated by |",
          "|----|------|--------|----------|----------|--------|-------|--------------|"]
    for i, e in enumerate(data.entries, 1):
        t = e.threat
        L.append(
            f"| {_register_id(i)} | {e.score:.1f} | {_esc(t.title)} "
            f"| {t.priority or '—'} | {_esc(t.category)} | {_esc(t.status)} "
            f"| {_esc(e.location)} | {_esc(', '.join(e.controls))} |"
        )
    if not data.entries:
        L.append("| — | — | _no threats match this scope and filter_ | | | | | |")
    L.append("")

    # ── 3. register ──────────────────────────────────────────────────────────
    L += ["---", "", "## 3. Threat Register", ""]
    if not data.entries:
        L += ["_No threats match this scope and filter._", ""]
    for i, e in enumerate(data.entries, 1):
        L += _register_record(e, _register_id(i))

    # ── 4. traceability ──────────────────────────────────────────────────────
    untagged = [e for e in data.entries
                if not (e.threat.cwe_ids or e.threat.nist_controls
                        or e.threat.owasp_categories)]
    unowned = [e for e in data.entries if not e.threat.authorizer.strip()]
    untracked = [e for e in data.entries
                 if not (e.threat.bug_jira_link.strip() or e.threat.jama_link.strip())]

    L += ["---", "", "## 4. Traceability Gaps", "",
          "| Gap | Count |", "|-----|-------|",
          f"| No CWE / NIST / OWASP tag | {len(untagged)} |",
          f"| No authorizer | {len(unowned)} |",
          f"| No Bug/Jira or JAMA link | {len(untracked)} |", ""]
    for heading, group in (("No compliance tag", untagged),
                           ("No authorizer", unowned),
                           ("No tracker link", untracked)):
        if group:
            L += [f"**{heading}**", ""]
            L += [f"- {_esc(e.threat.title)} ({e.diagram})" for e in group[:20]]
            if len(group) > 20:
                L.append(f"- …and {len(group) - 20} more")
            L.append("")

    # ── orphans ──────────────────────────────────────────────────────────────
    if data.orphaned:
        L += ["---", "", "## 5. Detached Threats", "",
              "These threats no longer point at a connection or sequence in the "
              "model — re-attach or delete them:", ""]
        for e in data.orphaned:
            L.append(f"- **{_esc(e.threat.title)}** ({e.diagram}) — {_esc(e.location)}")
        L.append("")

    return "\n".join(L) + "\n"


def _register_record(entry: RiskEntry, rid: str) -> List[str]:
    t = entry.threat
    L = [f"### {rid} — {t.title or '(untitled)'}", ""]

    facts = [
        ("Risk score", f"{entry.score:.1f}"),
        ("Priority", t.priority),
        ("Category", t.category),
        ("Status", t.status),
        ("Diagram", entry.diagram),
        ("Where", entry.location),
        ("Asset", " ".join(x for x in (entry.asset,
                                       f"({entry.interface})" if entry.interface else "") if x)),
        ("Asset property", t.asset_property),
        ("Attack path", t.attack_path),
        ("Interaction", t.interaction),
        ("Authorizer", t.authorizer),
        ("Identified by", ", ".join(t.ai_backends)),
        ("Compliance", ", ".join(t.cwe_ids + t.nist_controls + t.owasp_categories)),
    ]
    trace = "; ".join(x for x in (
        f"Bug/Jira: {t.bug_jira_link}" if t.bug_jira_link else "",
        f"JAMA: {t.jama_link}" if t.jama_link else "",
        f"Failure mode: {t.failure_mode_id}" if t.failure_mode_id else "",
    ) if x)
    if trace:
        facts.append(("Traceability", trace))

    L += ["| Field | Value |", "|-------|-------|"]
    for label, value in facts:
        if str(value).strip():
            L.append(f"| {label} | {_esc(value)} |")
    L.append("")

    for heading, text in (
        ("Description", t.description),
        ("Damage scenario", t.damage_scenario),
        ("Justification", t.justification),
        ("Failure mode", t.failure_mode_description),
        ("Recommended mitigations", t.mitigations),
    ):
        if str(text).strip():
            L += [f"**{heading}**", "", str(text).strip(), ""]

    L += ["**Applied security controls**", ""]
    if entry.controls:
        from . import verification as _V
        for name, sc_id in zip(entry.controls, t.mitigation_sc_ids):
            L.append(f"- {name} — *{_V.label(t, sc_id)}*")
            note = (t.mitigation_notes or {}).get(sc_id, "").strip()
            for line in note.splitlines():
                if line.strip():
                    L.append(f"  - {line.strip()}")
    else:
        L.append("- None — this threat is open.")
    L.append("")
    return L


# ── export ────────────────────────────────────────────────────────────────────

CSV_COLUMNS = [
    "id", "risk_score", "title", "priority", "category", "status", "diagram",
    "where", "asset", "interface", "mitigated", "controls", "description",
    "mitigations", "damage_scenario", "attack_path", "asset_property",
    "authorizer", "cwe", "nist", "owasp", "bug_jira", "jama",
    "failure_mode_id", "ai_backends", "guid",
]


def export_markdown(data: ThreatsReportData, out_path: Path) -> Path:
    out_path = Path(out_path)
    out_path.write_text(build_markdown(data), encoding="utf-8")
    return out_path


def export_csv(data: ThreatsReportData, out_path: Path) -> Path:
    """The register as one row per threat, for spreadsheets and trackers."""
    out_path = Path(out_path)
    with out_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for i, e in enumerate(data.entries + data.orphaned, 1):
            t = e.threat
            writer.writerow([
                _register_id(i), f"{e.score:.1f}", t.title, t.priority, t.category,
                t.status, e.diagram, e.location, e.asset, e.interface,
                "yes" if e.mitigated else "no", "; ".join(e.controls),
                t.description, t.mitigations, t.damage_scenario, t.attack_path,
                t.asset_property, t.authorizer, "; ".join(t.cwe_ids),
                "; ".join(t.nist_controls), "; ".join(t.owasp_categories),
                t.bug_jira_link, t.jama_link, t.failure_mode_id,
                "; ".join(t.ai_backends), t.guid,
            ])
    return out_path


def export_pdf(data: ThreatsReportData, out_path: Path) -> Path:
    from PySide6.QtGui import QTextDocument
    from PySide6.QtPrintSupport import QPrinter

    from .report import fit_document_images_to_page

    out_path = Path(out_path)
    md_path = export_markdown(data, out_path.with_suffix(".md"))

    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(out_path))
    doc = QTextDocument()
    doc.setMarkdown(md_path.read_text(encoding="utf-8"))
    fit_document_images_to_page(doc, printer)
    doc.print_(printer)
    return out_path
