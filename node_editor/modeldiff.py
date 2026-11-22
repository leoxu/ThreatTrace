"""
Model versioning / diff (Qt-free).

Compare two saved ThreatTrace project dicts and report what was added, removed,
or changed across nodes, edges, threats and diagrams. Matching is by stable ID
(node_id / diagram id / edge id / threat guid), so reordering or re-layout does
not register as a change. See doc/model-diff-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

# Curated per-kind comparison fields (layout noise deliberately excluded).
_EDGE_FIELDS = ("type", "sub-type", "description", "function")
_THREAT_FIELDS = (
    "title", "category", "priority", "status", "cvss_vector", "mitigations",
    "mitigation_sc_ids", "owasp_categories", "cwe_ids", "nist_controls",
    "description",
)


@dataclass
class FieldChange:
    field: str
    old: Any
    new: Any


@dataclass
class DiffEntry:
    kind: str             # "node" | "edge" | "threat" | "diagram"
    change: str           # "added" | "removed" | "changed"
    id: str
    label: str
    diagram_id: str = ""
    diagram_name: str = ""
    fields: List[FieldChange] = field(default_factory=list)


@dataclass
class ModelDiff:
    entries: List[DiffEntry] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.entries

    def summary(self) -> Dict[str, int]:
        """Counts keyed by '<kind>.<change>', plus per-change totals."""
        out: Dict[str, int] = {}
        for e in self.entries:
            out[f"{e.kind}.{e.change}"] = out.get(f"{e.kind}.{e.change}", 0) + 1
            out[e.change] = out.get(e.change, 0) + 1
        return out


# ── normalization ──────────────────────────────────────────────────────────────
def _nodes_registry(project: dict) -> Dict[str, dict]:
    """Return {node_id: node_dict}, converting a v1 nodes-list to a registry."""
    raw = project.get("nodes", {})
    if isinstance(raw, dict):
        return raw
    reg: Dict[str, dict] = {}
    for nd in raw or []:
        nid = nd.get("id")
        if nid:
            reg[nid] = nd
    return reg


def _diagrams(project: dict) -> List[dict]:
    if "diagrams" in project:
        return list(project["diagrams"])
    # v1 single-diagram fallback
    return [{
        "id": "main", "name": "Main",
        "edges": project.get("edges", []),
        "threats": project.get("threats", {}),
    }]


# ── label helpers ────────────────────────────────────────────────────────────────
def _node_label(node: dict) -> str:
    props = node.get("properties", {}) if isinstance(node, dict) else {}
    name = str(props.get("name", "")) or "(unnamed)"
    cls = str(props.get("class", ""))
    return f"{name} ({cls})" if cls else name


def _node_name(nodes: Dict[str, dict], nid: str) -> str:
    nd = nodes.get(nid)
    if isinstance(nd, dict):
        return str(nd.get("properties", {}).get("name", "")) or nid
    return nid or "?"


def _edge_props(edge: dict) -> dict:
    p = edge.get("properties", {})
    return p if isinstance(p, dict) else {}


def _edge_label(edge: dict, nodes: Dict[str, dict]) -> str:
    src = _node_name(nodes, str(edge.get("from", {}).get("node", "")))
    dst = _node_name(nodes, str(edge.get("to", {}).get("node", "")))
    p = _edge_props(edge)
    kind = p.get("sub-type") or p.get("type") or ""
    base = f"{src} → {dst}"
    return f"{base} [{kind}]" if kind else base


# ── field comparison ─────────────────────────────────────────────────────────────
def _slot_names(node: dict) -> Tuple[list, list]:
    def names(entries):
        out = []
        for e in entries or []:
            out.append(e.get("name") if isinstance(e, dict) else e)
        return out
    return names(node.get("inputs")), names(node.get("outputs"))


def _node_field_changes(old: dict, new: dict) -> List[FieldChange]:
    changes: List[FieldChange] = []
    op = old.get("properties", {}) if isinstance(old, dict) else {}
    np = new.get("properties", {}) if isinstance(new, dict) else {}
    for key in ("name", "class"):
        if op.get(key) != np.get(key):
            changes.append(FieldChange(key, op.get(key), np.get(key)))
    # security-properties, per sub-key
    osec = op.get("security-properties", {}) or {}
    nsec = np.get("security-properties", {}) or {}
    if isinstance(osec, dict) and isinstance(nsec, dict):
        for k in sorted(set(osec) | set(nsec)):
            if osec.get(k) != nsec.get(k):
                changes.append(FieldChange(f"security.{k}", osec.get(k), nsec.get(k)))
    # interface (slot names)
    oin, oout = _slot_names(old)
    nin, nout = _slot_names(new)
    if oin != nin:
        changes.append(FieldChange("inputs", oin, nin))
    if oout != nout:
        changes.append(FieldChange("outputs", oout, nout))
    return changes


def _edge_field_changes(old: dict, new: dict) -> List[FieldChange]:
    changes: List[FieldChange] = []
    op, np = _edge_props(old), _edge_props(new)
    for f in _EDGE_FIELDS:
        if op.get(f) != np.get(f):
            changes.append(FieldChange(f, op.get(f), np.get(f)))
    for end in ("from", "to"):
        oe, ne = old.get(end, {}) or {}, new.get(end, {}) or {}
        if (oe.get("node"), oe.get("slot")) != (ne.get("node"), ne.get("slot")):
            changes.append(FieldChange(
                end, f"{oe.get('node')}:{oe.get('slot')}", f"{ne.get('node')}:{ne.get('slot')}"))
    ol = (old.get("label") or {}).get("text", "")
    nl = (new.get("label") or {}).get("text", "")
    if ol != nl:
        changes.append(FieldChange("label", ol, nl))
    return changes


def _threat_field_changes(old: dict, new: dict) -> List[FieldChange]:
    changes: List[FieldChange] = []
    for f in _THREAT_FIELDS:
        if old.get(f) != new.get(f):
            changes.append(FieldChange(f, old.get(f), new.get(f)))
    return changes


# ── main entry point ─────────────────────────────────────────────────────────────
def diff_projects(old: dict, new: dict) -> ModelDiff:
    entries: List[DiffEntry] = []

    old_nodes = _nodes_registry(old)
    new_nodes = _nodes_registry(new)

    # ── nodes ──
    for nid in sorted(set(old_nodes) | set(new_nodes)):
        o, n = old_nodes.get(nid), new_nodes.get(nid)
        if o is None:
            entries.append(DiffEntry("node", "added", nid, _node_label(n)))
        elif n is None:
            entries.append(DiffEntry("node", "removed", nid, _node_label(o)))
        else:
            fc = _node_field_changes(o, n)
            if fc:
                entries.append(DiffEntry("node", "changed", nid, _node_label(n), fields=fc))

    # ── diagrams (and their edges + threats) ──
    old_diags = {d.get("id"): d for d in _diagrams(old)}
    new_diags = {d.get("id"): d for d in _diagrams(new)}
    for did in list(dict.fromkeys(list(old_diags) + list(new_diags))):
        od, nd = old_diags.get(did), new_diags.get(did)
        dname = (nd or od or {}).get("name", "") or str(did)
        if od is None:
            entries.append(DiffEntry("diagram", "added", str(did), dname))
        elif nd is None:
            entries.append(DiffEntry("diagram", "removed", str(did), dname))
        elif od.get("name") != nd.get("name"):
            entries.append(DiffEntry("diagram", "changed", str(did), dname,
                                     fields=[FieldChange("name", od.get("name"), nd.get("name"))]))

        _diff_edges(od or {}, nd or {}, str(did), dname, old_nodes, new_nodes, entries)
        _diff_threats(od or {}, nd or {}, str(did), dname, entries)

    return ModelDiff(entries)


def _diff_edges(od, nd, did, dname, old_nodes, new_nodes, entries) -> None:
    oe = {e.get("id"): e for e in (od.get("edges") or []) if e.get("id")}
    ne = {e.get("id"): e for e in (nd.get("edges") or []) if e.get("id")}
    for eid in list(dict.fromkeys(list(oe) + list(ne))):
        o, n = oe.get(eid), ne.get(eid)
        if o is None:
            entries.append(DiffEntry("edge", "added", eid, _edge_label(n, new_nodes), did, dname))
        elif n is None:
            entries.append(DiffEntry("edge", "removed", eid, _edge_label(o, old_nodes), did, dname))
        else:
            fc = _edge_field_changes(o, n)
            if fc:
                entries.append(DiffEntry("edge", "changed", eid, _edge_label(n, new_nodes),
                                         did, dname, fields=fc))


def _diff_threats(od, nd, did, dname, entries) -> None:
    ot = od.get("threats", {}) or {}
    nt = nd.get("threats", {}) or {}
    if not isinstance(ot, dict) or not isinstance(nt, dict):
        return
    for guid in sorted(set(ot) | set(nt)):
        o, n = ot.get(guid), nt.get(guid)
        if o is None:
            entries.append(DiffEntry("threat", "added", guid, str(n.get("title", "")) or guid, did, dname))
        elif n is None:
            entries.append(DiffEntry("threat", "removed", guid, str(o.get("title", "")) or guid, did, dname))
        else:
            fc = _threat_field_changes(o, n)
            if fc:
                entries.append(DiffEntry("threat", "changed", guid, str(n.get("title", "")) or guid,
                                         did, dname, fields=fc))


def format_text(diff: ModelDiff) -> str:
    """Plain-text rendering for the CLI."""
    if diff.is_empty():
        return "No differences."
    s = diff.summary()
    lines: List[str] = []
    order = {"added": 0, "changed": 1, "removed": 2}
    header = ", ".join(
        f"{c}: {s.get(c, 0)}" for c in ("added", "changed", "removed") if s.get(c)
    )
    lines.append(f"Model diff — {header}")
    for e in sorted(diff.entries, key=lambda x: (order.get(x.change, 9), x.kind, x.label)):
        sign = {"added": "+", "removed": "-", "changed": "~"}.get(e.change, "?")
        ctx = f" @{e.diagram_name}" if e.diagram_name else ""
        lines.append(f"  {sign} {e.kind}: {e.label}{ctx}")
        for fc in e.fields:
            lines.append(f"      {fc.field}: {fc.old!r} -> {fc.new!r}")
    return "\n".join(lines)
