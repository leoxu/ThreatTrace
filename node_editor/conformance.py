"""
Design <-> Implementation conformance verification (Qt-free).

Compares a *design* project (drawn in the tool) against an *implementation*
project (extracted from a runtime capture by implmodel.py) and reports where
they diverge:

  - conform     : an impl element/interaction matches an allowed design one
  - violation   : impl did something the design never modeled (drift / new
                  attack surface); the most important output
  - unrealized  : a design-allowed interaction with no runtime evidence
                  (coverage gap or over-broad allowance)

Matching is by normalized name (components) and path/name (assets), with an
optional user-supplied alias map ({impl_node_id or impl_name: design_node_id})
that overrides the automatic matching. See doc/impl-verification-design.md.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

_COMPONENT_CLASSES = {
    "security host-app", "security dynamic-library", "security process",
    "security linux-kmd", "security qnx-resmgr", "security proxy",
}
_ASSET_CLASS = "security asset"

SEV_HIGH, SEV_MEDIUM, SEV_LOW, SEV_INFO = "High", "Medium", "Low", "Info"
_SEV_ORDER = {SEV_HIGH: 0, SEV_MEDIUM: 1, SEV_LOW: 2, SEV_INFO: 3}


@dataclass
class ConformanceFinding:
    status: str        # "conform" | "violation" | "unrealized"
    kind: str          # "component" | "asset" | "interaction"
    severity: str
    title: str
    detail: str = ""
    impl_ref: str = ""
    design_ref: str = ""


@dataclass
class ConformanceReport:
    findings: List[ConformanceFinding] = field(default_factory=list)
    matches: Dict[str, str] = field(default_factory=dict)   # impl_id -> design_id

    def by_status(self, status: str) -> List[ConformanceFinding]:
        return [f for f in self.findings if f.status == status]

    def summary(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for f in self.findings:
            out[f.status] = out.get(f.status, 0) + 1
            out[f"sev.{f.severity}"] = out.get(f"sev.{f.severity}", 0) + 1
        return out


# ── helpers ──────────────────────────────────────────────────────────────────────
def _nodes(project: dict) -> Dict[str, dict]:
    raw = project.get("nodes", {})
    if isinstance(raw, dict):
        return raw
    return {nd.get("id"): nd for nd in (raw or []) if nd.get("id")}


def _class_of(node: dict) -> str:
    return str(node.get("properties", {}).get("class", ""))


def _name_of(node: dict) -> str:
    return str(node.get("properties", {}).get("name", ""))


def _path_of(node: dict) -> str:
    sec = node.get("properties", {}).get("security-properties", {})
    return str(sec.get("path", "")) if isinstance(sec, dict) else ""


def _norm_component(name: str) -> str:
    """Normalize a component name for fuzzy matching.

    'libfoo_bar.so' -> 'foobar';  'Foo Bar' -> 'foobar';
    'vksc_01tri' -> 'vksc01tri'.
    """
    s = name.lower()
    s = re.sub(r"\.so(\.\d+)*$", "", s)      # strip .so / .so.1
    s = re.sub(r"-\d+$", "", s)              # strip -24 version tag
    if s.startswith("lib"):
        s = s[3:]
    return re.sub(r"[^a-z0-9]", "", s)


def _norm_asset(node: dict) -> str:
    """Prefer the resource path; fall back to a normalized name."""
    p = _path_of(node)
    if p:
        return p.strip().lower()
    return re.sub(r"[^a-z0-9]", "", _name_of(node).lower())


def _diagram_edges(project: dict) -> List[dict]:
    edges: List[dict] = []
    for d in project.get("diagrams", []):
        edges.extend(d.get("edges", []) or [])
    if "edges" in project:  # v1 fallback
        edges.extend(project.get("edges", []) or [])
    return edges


# ── matching ─────────────────────────────────────────────────────────────────────
def _match_nodes(design: dict, impl: dict, alias: Dict[str, str]) -> Dict[str, str]:
    """Resolve impl_node_id -> design_node_id via alias, then path, then norm-name."""
    d_nodes = _nodes(design)
    i_nodes = _nodes(impl)

    # design lookup indexes
    d_comp_by_norm: Dict[str, str] = {}
    d_asset_by_key: Dict[str, str] = {}
    for did, dn in d_nodes.items():
        cls = _class_of(dn)
        if cls in _COMPONENT_CLASSES:
            d_comp_by_norm.setdefault(_norm_component(_name_of(dn)), did)
        elif cls == _ASSET_CLASS:
            d_asset_by_key.setdefault(_norm_asset(dn), did)

    matches: Dict[str, str] = {}
    for iid, inode in i_nodes.items():
        # explicit alias by impl id or impl name
        if iid in alias:
            matches[iid] = alias[iid]
            continue
        iname = _name_of(inode)
        if iname in alias:
            matches[iid] = alias[iname]
            continue
        cls = _class_of(inode)
        if cls in _COMPONENT_CLASSES:
            did = d_comp_by_norm.get(_norm_component(iname))
            if did:
                matches[iid] = did
        elif cls == _ASSET_CLASS:
            did = d_asset_by_key.get(_norm_asset(inode))
            if did:
                matches[iid] = did
    return matches


def _edge_endpoints(edge: dict) -> Tuple[str, str]:
    return (str(edge.get("from", {}).get("node", "")),
            str(edge.get("to", {}).get("node", "")))


def _is_asset_op(edge: dict) -> bool:
    return str(edge.get("properties", {}).get("type", "")) == "Asset Operation"


# ── main entry point ─────────────────────────────────────────────────────────────
def verify_conformance(design: dict, impl: dict,
                       alias: Optional[Dict[str, str]] = None) -> ConformanceReport:
    alias = alias or {}
    d_nodes = _nodes(design)
    i_nodes = _nodes(impl)
    matches = _match_nodes(design, impl, alias)
    report = ConformanceReport(matches=matches)

    # ── node-level findings ──
    for iid, inode in i_nodes.items():
        cls = _class_of(inode)
        is_asset = cls == _ASSET_CLASS
        is_comp = cls in _COMPONENT_CLASSES
        if not (is_asset or is_comp):
            continue
        kind = "asset" if is_asset else "component"
        if iid in matches:
            report.findings.append(ConformanceFinding(
                "conform", kind, SEV_INFO,
                f"{kind.capitalize()} present in design: {_name_of(inode)}",
                impl_ref=_name_of(inode),
                design_ref=_name_of(d_nodes.get(matches[iid], {})),
            ))
        else:
            sev = SEV_HIGH if is_asset else SEV_MEDIUM
            report.findings.append(ConformanceFinding(
                "violation", kind, sev,
                f"Undocumented {kind} accessed at runtime: {_name_of(inode)}",
                detail="This element was exercised by the running software but "
                       "does not appear in the design model.",
                impl_ref=_name_of(inode),
            ))

    # design nodes with no runtime evidence (matched from impl side)
    matched_design_ids = set(matches.values())
    for did, dn in d_nodes.items():
        cls = _class_of(dn)
        if cls in _COMPONENT_CLASSES or cls == _ASSET_CLASS:
            if did not in matched_design_ids:
                kind = "asset" if cls == _ASSET_CLASS else "component"
                report.findings.append(ConformanceFinding(
                    "unrealized", kind, SEV_LOW,
                    f"Design {kind} not observed at runtime: {_name_of(dn)}",
                    detail="Present in the design model but no runtime evidence "
                           "in this capture (coverage gap or unused).",
                    design_ref=_name_of(dn),
                ))

    # ── interaction-level findings ──
    # design adjacency: {(src_id, dst_id)}
    design_adj: Set[Tuple[str, str]] = set()
    for e in _diagram_edges(design):
        s, d = _edge_endpoints(e)
        if s and d:
            design_adj.add((s, d))

    impl_adj_mapped: Set[Tuple[str, str]] = set()
    for e in _diagram_edges(impl):
        si, di = _edge_endpoints(e)
        ds, dd = matches.get(si), matches.get(di)
        label = _impl_edge_label(e, i_nodes)
        if ds and dd:
            impl_adj_mapped.add((ds, dd))
            if (ds, dd) in design_adj:
                report.findings.append(ConformanceFinding(
                    "conform", "interaction", SEV_INFO,
                    f"Allowed interaction observed: {label}",
                    impl_ref=label,
                ))
            else:
                report.findings.append(ConformanceFinding(
                    "violation", "interaction", SEV_MEDIUM,
                    f"Undocumented interaction: {label}",
                    detail="Both endpoints exist in the design, but the design "
                           "does not model this interaction between them.",
                    impl_ref=label,
                ))
        else:
            # endpoint(s) unmapped — undocumented, and an asset op is worse
            sev = SEV_HIGH if _is_asset_op(e) else SEV_MEDIUM
            report.findings.append(ConformanceFinding(
                "violation", "interaction", sev,
                f"Undocumented interaction: {label}",
                detail="Involves a component/asset that is not in the design model.",
                impl_ref=label,
            ))

    # design interactions never exercised (both endpoints have runtime presence)
    impl_present_design_ids = set(matches.values())
    for (s, d) in design_adj:
        if s in impl_present_design_ids and d in impl_present_design_ids:
            if (s, d) not in impl_adj_mapped:
                label = f"{_name_of(d_nodes.get(s, {}))} -> {_name_of(d_nodes.get(d, {}))}"
                report.findings.append(ConformanceFinding(
                    "unrealized", "interaction", SEV_LOW,
                    f"Design interaction not observed: {label}",
                    detail="Allowed by the design but no runtime evidence — "
                           "consider tightening if this path should not exist.",
                    design_ref=label,
                ))

    report.findings.sort(key=lambda f: (_status_order(f.status), _SEV_ORDER.get(f.severity, 9)))
    return report


def _status_order(status: str) -> int:
    return {"violation": 0, "unrealized": 1, "conform": 2}.get(status, 3)


def _impl_edge_label(edge: dict, i_nodes: Dict[str, dict]) -> str:
    s, d = _edge_endpoints(edge)
    sn = _name_of(i_nodes.get(s, {})) or s
    dn = _name_of(i_nodes.get(d, {})) or d
    sub = edge.get("properties", {}).get("sub-type", "") or edge.get("properties", {}).get("type", "")
    return f"{sn} --{sub}--> {dn}" if sub else f"{sn} -> {dn}"


def format_text(report: ConformanceReport) -> str:
    s = report.summary()
    lines = [
        "Conformance: "
        f"{s.get('violation', 0)} violations, "
        f"{s.get('unrealized', 0)} unrealized, "
        f"{s.get('conform', 0)} conforming"
    ]
    for status, header in (("violation", "VIOLATIONS"), ("unrealized", "UNREALIZED"),
                           ("conform", "CONFORMING")):
        group = report.by_status(status)
        if not group:
            continue
        lines.append(f"\n{header}:")
        for f in group:
            lines.append(f"  [{f.severity}] ({f.kind}) {f.title}")
            if f.detail:
                lines.append(f"        {f.detail}")
    return "\n".join(lines)
