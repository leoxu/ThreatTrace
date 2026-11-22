"""
Mitigation coverage analysis for security control nodes.

A security control is drawn as a circle that is placed *on top of* the part of
the model it protects. When that circle covers one or more of an asset's
interface slots, every edge attached to those slots is in the control's scope,
and every threat on those edges is a candidate for mitigation by the control.

Entry points:
    build_coverage_scope(control_node, scene, threats) -> CoverageScope
    assess_combined_detailed(scope, progress_callback=...) -> AssessmentRun (LLM)
    assess_rules(scope)                                    -> List[ThreatAssessment]

Qt-free: scene/node/slot/edge objects are used through their public accessors
only (duck-typed), so this module can be unit-tested without a QApplication.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from typing import TYPE_CHECKING, Callable, Dict, List, Optional, Tuple

from . import cancel
from .parallel import MAX_PARALLEL_CALLS, run_parallel
from .threat_gen import (DEFAULT_CLAUDE_MODEL, _backend_names, _parse_raw_json,
                         _run_claude_cli, _run_codex_cli)

if TYPE_CHECKING:
    from .graphics.items import EdgeItem, NodeItem, SlotItem
    from .threat import Threat, ThreatRegistry


SEC_PROPS_KEY = "security-properties"

# How many threats are described in a single LLM request. Keeping batches small
# keeps each answer focused (and each retry cheap) on large models.
_BATCH_SIZE = 8


# ── context dataclasses ───────────────────────────────────────────────────────

@dataclass
class ControlContext:
    """One security control: what a threat links to.

    ``node_id`` is the *control definition's* id (unique across the model), not
    the container node's — a container holds several controls and each is judged
    and linked on its own. ``container_id`` / ``container_name`` identify the
    circle that provides the geometry.
    """
    node_id: str
    name: str
    control_type: str
    description: str
    requirement_id: str
    container_id: str = ""
    container_name: str = ""


@dataclass
class CoveredSlot:
    """One asset interface slot covered by the control."""
    asset_name: str
    asset_class: str
    asset_type: str
    slot_name: str
    slot_details: str
    interface: str = ""              # interface name declared by the slot, if any
    path: str = ""                   # interface path (e.g. /dev/mydev-ctrl)
    operations: List[str] = field(default_factory=list)


@dataclass
class ThreatItem:
    """A threat in the control's scope, with the edge it sits on."""
    threat_guid: str
    threat_title: str
    threat_category: str
    threat_priority: str
    threat_description: str
    threat_mitigations: str
    edge_id: str
    edge_label: str       # "src node -> dst node (sub-type)"
    edge_type: str
    covered_slot: str     # name of the covered asset slot this edge attaches to
    already_mitigated: bool


@dataclass
class CoverageScope:
    control: ControlContext
    slots: List[CoveredSlot] = field(default_factory=list)
    items: List[ThreatItem] = field(default_factory=list)
    edge_count: int = 0


@dataclass
class ScopeAssessment:
    """One control's scope together with the verdicts produced for it."""
    scope: "CoverageScope"
    assessments: List["ThreatAssessment"] = field(default_factory=list)
    backend_results: List["BackendRunResult"] = field(default_factory=list)
    used_rules: bool = False


@dataclass
class ThreatAssessment:
    threat_guid: str
    threat_title: str
    edge_label: str
    mitigated: bool
    rationale: str = ""
    residual_risk: str = ""
    backend: str = ""


@dataclass
class BackendRunResult:
    backend_name: str
    assessed_count: int = 0
    error: str = ""


@dataclass
class AssessmentRun:
    assessments: List[ThreatAssessment]
    backend_results: List[BackendRunResult]


# ── geometry: what does the control circle cover? ─────────────────────────────

def is_security_control(node) -> bool:
    return str(node.properties().get("class", "")).startswith("security control")


# Node classes whose slots are asset interfaces (mirrors the app's asset set).
_ASSET_CLASS_PREFIXES = ("security asset",)
_ASSET_CLASSES = {"process memory"}


def is_asset_node(node) -> bool:
    cls = str(node.properties().get("class", ""))
    return cls.startswith(_ASSET_CLASS_PREFIXES) or cls in _ASSET_CLASSES


def is_interface_slot(slot) -> bool:
    """True when a slot on an asset node is one of the asset's interfaces.

    Descriptor-driven assets tag each interface slot with its ``interface``
    name; legacy template assets (e.g. ``memory.json``) only have plain slot
    names. Both count. The one slot that is *not* an interface is the asset's
    dedicated ``owner`` slot, which carries the ownership link rather than an
    access channel.
    """
    props = slot.properties() if hasattr(slot, "properties") else {}
    if props.get("owner-slot") or slot.name == "owner":
        return False
    return True


@dataclass
class ControlRegion:
    """The area a control node occupies in scene coordinates.

    ``kind`` is "ellipse" for round controls (the default circle template) and
    "rect" for any other shape. ``hw``/``hh`` are half the node's width/height,
    so resizing the control directly changes what it covers.
    """
    kind: str
    cx: float
    cy: float
    hw: float
    hh: float

    def covers_rect(self, rect) -> bool:
        """True when any part of *rect* (scene coords) lies inside the region."""
        if self.hw <= 0 or self.hh <= 0:
            return False
        # Nearest point of the rect to the region's centre, per axis.
        dx = max(rect.left() - self.cx, 0.0, self.cx - rect.right())
        dy = max(rect.top() - self.cy, 0.0, self.cy - rect.bottom())
        if self.kind == "rect":
            return dx <= self.hw and dy <= self.hh
        # Ellipse: exact for an axis-aligned rect once normalised to a unit circle.
        nx, ny = dx / self.hw, dy / self.hh
        return nx * nx + ny * ny <= 1.0


def control_region(node) -> Optional[ControlRegion]:
    """The control node's covering region, taken from its size in scene coords."""
    rect = node.mapToScene(node._shape_rect()).boundingRect()
    if rect.width() <= 0 or rect.height() <= 0:
        return None
    centre = rect.center()
    kind = "ellipse" if getattr(node, "shape_kind", "") in ("Circle", "Ellipse") else "rect"
    return ControlRegion(kind, centre.x(), centre.y(),
                         rect.width() / 2.0, rect.height() / 2.0)


def covered_asset_slots(control_node, scene) -> List[Tuple["NodeItem", "SlotItem"]]:
    """Asset interface slots covered by the control node's area.

    A slot counts when the control's shape — sized from the node itself, so
    resizing it widens or narrows the scope — overlaps the slot, the slot's node
    is an asset, and the slot is one of that asset's interfaces (not its owner
    slot).
    """
    from .graphics.items import NodeItem, SlotItem

    region = control_region(control_node)
    if region is None or scene is None:
        return []

    covered: List[Tuple[NodeItem, SlotItem]] = []
    for item in scene.items():
        if not isinstance(item, SlotItem):
            continue
        owner = item.parentItem()
        if not isinstance(owner, NodeItem) or owner is control_node:
            continue
        if not is_asset_node(owner) or not is_interface_slot(item):
            continue
        if region.covers_rect(item.mapToScene(item.rect()).boundingRect()):
            covered.append((owner, item))
    return covered


def edges_for_slots(scene, slots) -> List["EdgeItem"]:
    """Every non-alias edge attached to one of *slots* (source or destination)."""
    from .graphics.items import EdgeItem

    if scene is None or not slots:
        return []
    wanted = {id(s) for s in slots}
    edges: List[EdgeItem] = []
    for item in scene.items():
        if not isinstance(item, EdgeItem) or getattr(item, "_virtual", False):
            continue
        if str(item.properties().get("type", "")) == "alias":
            continue
        if id(item.src) in wanted or id(item.dst) in wanted:
            edges.append(item)
    return edges


def _edge_label(edge) -> str:
    from .graphics.items import NodeItem

    def _name(slot) -> str:
        node = slot.parentItem() if slot is not None else None
        if isinstance(node, NodeItem):
            return str(node.properties().get("name", node.title))
        return "?"

    sub = str(edge.properties().get("sub-type", "")).strip()
    label = f"{_name(edge.src)} → {_name(edge.dst)}"
    return f"{label} ({sub})" if sub else label


def build_coverage_scope(control_node, scene, threats: "ThreatRegistry",
                         sequences: Optional[dict] = None) -> CoverageScope:
    """Collect the control's covered slots, in-scope edges and their threats.

    When ``sequences`` is given, sequence-wide threats (no single edge) are in
    scope too if any step of their sequence runs over a covered interface — a
    control on one step of a flow can still mitigate a multi-step threat.
    """
    from .controls import summary as control_summary

    props = control_node.properties()
    container_name = str(props.get("name", control_node.title))

    # Container-level context: the geometry is shared by every control inside.
    # control_scopes() below swaps in each contained control.
    control = ControlContext(
        node_id=control_node.node_id,
        name=container_name,
        control_type=control_summary(props, control_node.node_id),
        description="",
        requirement_id="",
        container_id=control_node.node_id,
        container_name=container_name,
    )

    pairs = covered_asset_slots(control_node, scene)
    covered_slots: List[CoveredSlot] = []
    slot_names: Dict[int, str] = {}
    for asset, slot in pairs:
        a_props = asset.properties()
        a_sec = a_props.get(SEC_PROPS_KEY, {})
        if not isinstance(a_sec, dict):
            a_sec = {}
        s_props = slot.properties()
        details = str(s_props.get("details", ""))
        ops = s_props.get("operations")
        covered_slots.append(CoveredSlot(
            asset_name=str(a_props.get("name", asset.title)),
            asset_class=str(a_props.get("class", "")),
            asset_type=str(a_sec.get("type", "")),
            slot_name=slot.name,
            slot_details="" if details in ("", "...") else details,
            interface=str(s_props.get("interface", "")),
            path=str(s_props.get("path", "")),
            operations=[str(o) for o in ops] if isinstance(ops, list) else [],
        ))
        slot_names[id(slot)] = slot.name

    edges = edges_for_slots(scene, [s for _, s in pairs])

    items: List[ThreatItem] = []
    for edge in edges:
        label = _edge_label(edge)
        slot_name = slot_names.get(id(edge.src)) or slot_names.get(id(edge.dst)) or ""
        for guid in sorted(edge.threat_guids):
            t = threats.get(guid)
            if t is None:
                continue
            items.append(ThreatItem(
                threat_guid=t.guid,
                threat_title=t.title,
                threat_category=t.category,
                threat_priority=t.priority,
                threat_description=t.description,
                threat_mitigations=t.mitigations,
                edge_id=edge.edge_id,
                edge_label=label,
                edge_type=str(edge.properties().get("sub-type", "")
                              or edge.properties().get("type", "")),
                covered_slot=slot_name,
                already_mitigated=control.node_id in (t.mitigation_sc_ids or []),
            ))

    # Sequence-wide threats whose flow touches one of the covered edges.
    covered_edge_ids = {e.edge_id for e in edges}
    seen = {i.threat_guid for i in items}
    for seq in (sequences or {}).values():
        if not covered_edge_ids.intersection(seq.steps):
            continue
        label = f"sequence '{seq.name}' ({len(seq.steps)} steps)"
        for guid in seq.threat_guids:
            t = threats.get(guid)
            if t is None or t.edge_guid or t.guid in seen:
                continue        # step-pinned ones already came in via their edge
            seen.add(t.guid)
            items.append(ThreatItem(
                threat_guid=t.guid,
                threat_title=t.title,
                threat_category=t.category,
                threat_priority=t.priority,
                threat_description=t.description,
                threat_mitigations=t.mitigations,
                edge_id="",
                edge_label=label,
                edge_type="multi-step sequence",
                covered_slot=", ".join(sorted({s.slot_name for s in covered_slots})),
                already_mitigated=control.node_id in (t.mitigation_sc_ids or []),
            ))

    return CoverageScope(control=control, slots=covered_slots,
                         items=items, edge_count=len(edges))


def control_scopes(control_node, scene, threats: "ThreatRegistry",
                   sequences: Optional[dict] = None) -> List[CoverageScope]:
    """One scope per control defined inside a container node.

    All of them share the container's geometry (covered slots, edges, threats);
    only the control being judged differs, so two controls in one circle are
    assessed, linked and reported separately.
    """
    from .controls import read_controls

    base = build_coverage_scope(control_node, scene, threats, sequences)
    out: List[CoverageScope] = []
    for definition in read_controls(control_node.properties(), control_node.node_id):
        out.append(CoverageScope(
            control=ControlContext(
                node_id=definition.id,
                name=definition.name,
                control_type=definition.control_type,
                description=definition.description,
                requirement_id=definition.requirement_id,
                container_id=base.control.container_id,
                container_name=base.control.container_name,
            ),
            slots=base.slots,
            items=base.items,
            edge_count=base.edge_count,
        ))
    return out


def scopes_for_all_controls(scene, threats: "ThreatRegistry",
                            only_guids: Optional[set] = None,
                            sequences: Optional[dict] = None) -> List[CoverageScope]:
    """Coverage scope of every security control in the scene, in name order.

    ``only_guids`` restricts each scope to those threats — used after threat
    generation so the pass judges the newly added threats instead of
    re-litigating verdicts the user already reviewed. Controls that end up with
    nothing to assess are dropped.
    """
    from .graphics.items import NodeItem

    if scene is None:
        return []

    scopes: List[CoverageScope] = []
    for item in scene.items():
        if not isinstance(item, NodeItem) or not is_security_control(item):
            continue
        for scope in control_scopes(item, scene, threats, sequences):
            if only_guids is not None:
                scope = CoverageScope(
                    control=scope.control, slots=scope.slots,
                    edge_count=scope.edge_count,
                    items=[i for i in scope.items if i.threat_guid in only_guids],
                )
            if scope.items:
                scopes.append(scope)
    return sorted(scopes, key=lambda s: (s.control.container_name, s.control.name))


@dataclass
class StaleLink:
    """A mitigation link that no longer holds, and why."""
    threat_guid: str
    threat_title: str
    control_id: str
    control_name: str
    reason: str


def prune_stale_links(scene, threats: "ThreatRegistry",
                      sequences: Optional[dict] = None,
                      only_guids: Optional[set] = None,
                      known_names: Optional[dict] = None) -> List[StaleLink]:
    """Drop mitigation links that the model no longer supports.

    A link is stale when the control node is gone from the diagram, or when the
    control has been moved/resized/rewired so the threat is no longer in its
    coverage scope. Returns what was removed so the caller can report it.

    This is the cheap, offline half of "update threats": it never calls an
    agent, it only removes claims the geometry no longer backs.

    ``known_names`` maps control node ids to names for controls that are no
    longer in the scene, so a deleted control can still be reported by name.
    """
    from .graphics.items import NodeItem

    if scene is None:
        return []

    # control id -> the threats it currently covers
    scope_guids: Dict[str, set] = {}
    control_names: Dict[str, str] = {}
    for item in scene.items():
        if not isinstance(item, NodeItem) or not is_security_control(item):
            continue
        for scope in control_scopes(item, scene, threats, sequences):
            scope_guids[scope.control.node_id] = {i.threat_guid for i in scope.items}
            control_names[scope.control.node_id] = scope.control.name

    fallback_names = dict(known_names or {})

    removed: List[StaleLink] = []
    for t in threats.values():
        if only_guids is not None and t.guid not in only_guids:
            continue
        if not t.mitigation_sc_ids:
            continue
        keep: List[str] = []
        for sc_id in t.mitigation_sc_ids:
            if sc_id not in scope_guids:
                reason = "control was removed from the diagram"
            elif t.guid not in scope_guids[sc_id]:
                reason = "control no longer covers this threat"
            else:
                keep.append(sc_id)
                continue
            removed.append(StaleLink(
                threat_guid=t.guid, threat_title=t.title, control_id=sc_id,
                control_name=control_names.get(sc_id)
                             or fallback_names.get(sc_id)
                             or f"(deleted control {sc_id[:8]})",
                reason=reason,
            ))
            if t.mitigation_notes:
                t.mitigation_notes.pop(sc_id, None)
        t.mitigation_sc_ids = keep
    return removed


# ── LLM assessment ────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security architect reviewing whether a deployed security control \
mitigates previously identified STRIDE threats in a software threat model.

For each numbered threat you are given, decide whether the described security \
control — as configured — actually mitigates that specific threat. Be strict: \
a control mitigates a threat only if it blocks or substantially reduces the \
concrete attack mechanism described. Do not mark a threat mitigated merely \
because the control is in the same security domain, and do not assume controls \
or configuration that are not stated.

Return ONLY a JSON array, one object per threat you were given, each with \
exactly these fields:
  "index"         - the threat number you were given (integer)
  "mitigated"     - true only if the control mitigates this threat (boolean)
  "rationale"     - 1-2 sentences explaining the decision (string)
  "residual_risk" - what remains unmitigated, "" if nothing (string)

Do not include any text outside the JSON array.\
"""


def _format_control(control: ControlContext, slots: List[CoveredSlot]) -> List[str]:
    lines = [
        f"Security control: {control.name!r}",
        f"  Control type: {control.control_type or '(unspecified)'}",
    ]
    if control.requirement_id:
        lines.append(f"  Requirement ID: {control.requirement_id}")
    if control.description:
        lines.append(f"  Description / configuration: {control.description}")

    lines.append("")
    lines.append("The control is applied to these asset interfaces:")
    for s in slots:
        atype = f", type={s.asset_type}" if s.asset_type else ""
        iface = s.interface or s.slot_name
        lines.append(f"  - {s.asset_name!r} ({s.asset_class}{atype}) interface {iface!r}")
        if s.path:
            lines.append(f"      path: {s.path}")
        if s.operations:
            lines.append(f"      operations: {', '.join(s.operations)}")
        if s.slot_details:
            lines.append(f"      details: {s.slot_details}")
    return lines


def _format_batch(control: ControlContext, slots: List[CoveredSlot],
                  batch: List[Tuple[int, ThreatItem]]) -> str:
    lines = _format_control(control, slots)
    lines.append("")
    lines.append("Threats to assess:")
    for idx, item in batch:
        lines.append("")
        lines.append(f"Threat {idx}: {item.threat_title}")
        lines.append(f"  Category: {item.threat_category}  Priority: {item.threat_priority}")
        lines.append(f"  On connection: {item.edge_label}")
        if item.edge_type:
            lines.append(f"  Connection type: {item.edge_type}")
        if item.covered_slot:
            lines.append(f"  Covered asset interface: {item.covered_slot}")
        if item.threat_description:
            lines.append(f"  Description: {item.threat_description}")
        if item.threat_mitigations:
            lines.append(f"  Recommended mitigations: {item.threat_mitigations}")

    lines.append("")
    lines.append(
        f"For each of the {len(batch)} threats above, decide whether the security "
        "control mitigates it. Answer with one JSON object per threat, using the "
        "threat numbers shown."
    )
    return "\n".join(lines)


def _parse_assessments(items: list, batch: List[Tuple[int, ThreatItem]],
                       backend: str) -> List[ThreatAssessment]:
    by_index = {idx: item for idx, item in batch}
    out: List[ThreatAssessment] = []
    seen: set = set()
    for entry in items:
        if not isinstance(entry, dict):
            continue
        try:
            idx = int(entry.get("index"))
        except (TypeError, ValueError):
            continue
        item = by_index.get(idx)
        if item is None or idx in seen:
            continue
        seen.add(idx)
        out.append(ThreatAssessment(
            threat_guid=item.threat_guid,
            threat_title=item.threat_title,
            edge_label=item.edge_label,
            mitigated=bool(entry.get("mitigated")),
            rationale=str(entry.get("rationale", "")).strip(),
            residual_risk=str(entry.get("residual_risk", "")).strip(),
            backend=backend,
        ))
    return out


def _batches(items: List[ThreatItem]) -> List[List[Tuple[int, ThreatItem]]]:
    numbered = list(enumerate(items, start=1))
    return [numbered[i:i + _BATCH_SIZE] for i in range(0, len(numbered), _BATCH_SIZE)]


def _assess(scope: CoverageScope, runner: Callable[[str, str], str],
            backend: str) -> List[ThreatAssessment]:
    """Assess one control's scope, a batch of threats per call.

    The batches are independent questions about the same control, so they run
    concurrently: a control covering 24 threats is 3 calls in the time of one
    rather than three times as long.
    """
    def _one(batch):
        raw = runner(_format_batch(scope.control, scope.slots, batch), _SYSTEM_PROMPT)
        return _parse_assessments(_parse_raw_json(raw), batch, backend)

    groups = run_parallel([partial(_one, b) for b in _batches(scope.items)],
                          MAX_PARALLEL_CALLS)
    return [a for group in groups for a in group]


def assess_claude(scope: CoverageScope, model: str = DEFAULT_CLAUDE_MODEL,
                  timeout: int = 180) -> List[ThreatAssessment]:
    """Assess every threat in scope with the claude CLI."""
    return _assess(
        scope,
        lambda msg, sys_p: _run_claude_cli(msg, sys_p, model, timeout),
        "Claude CLI",
    )


def assess_codex(scope: CoverageScope, model: Optional[str] = None,
                 timeout: int = 180) -> List[ThreatAssessment]:
    """Assess every threat in scope with the Codex CLI."""
    return _assess(
        scope,
        lambda msg, sys_p: _run_codex_cli(msg, sys_p, model, timeout),
        "Codex CLI",
    )


def _merge(groups: List[List[ThreatAssessment]]) -> List[ThreatAssessment]:
    """Merge per-backend verdicts, one entry per threat.

    A threat counts as mitigated when *every* backend that answered says so —
    the conservative reading, so a single sceptical reviewer keeps the threat
    open. Rationales from all backends are kept, tagged by backend.
    """
    order: List[str] = []
    by_guid: Dict[str, List[ThreatAssessment]] = {}
    for group in groups:
        for a in group:
            if a.threat_guid not in by_guid:
                by_guid[a.threat_guid] = []
                order.append(a.threat_guid)
            by_guid[a.threat_guid].append(a)

    merged: List[ThreatAssessment] = []
    for guid in order:
        votes = by_guid[guid]
        first = votes[0]
        rationale = "\n".join(
            f"[{v.backend}] {v.rationale}" if len(votes) > 1 and v.backend else v.rationale
            for v in votes if v.rationale
        )
        residual = "\n".join(v.residual_risk for v in votes if v.residual_risk)
        merged.append(ThreatAssessment(
            threat_guid=guid,
            threat_title=first.threat_title,
            edge_label=first.edge_label,
            mitigated=all(v.mitigated for v in votes),
            rationale=rationale,
            residual_risk=residual,
            backend=", ".join(dict.fromkeys(v.backend for v in votes if v.backend)),
        ))
    return merged


def assess_combined_detailed(
    scope: CoverageScope,
    claude_model: str = DEFAULT_CLAUDE_MODEL,
    codex_model: Optional[str] = None,
    timeout: int = 180,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    backends=None,
) -> AssessmentRun:
    """Run every available backend and merge their verdicts.

    Backend failures are reported in ``backend_results`` instead of raising, so
    a partial result (or an empty one, letting the caller fall back to
    ``assess_rules``) is always returned.
    """
    generators = []
    for name in _backend_names(backends):
        if name == "claude":
            generators.append(("Claude CLI",
                               lambda: assess_claude(scope, claude_model, timeout)))
        elif name == "codex":
            generators.append(("Codex CLI",
                               lambda: assess_codex(scope, codex_model, timeout)))

    groups: List[List[ThreatAssessment]] = []
    backend_results: List[BackendRunResult] = []
    total = len(generators)
    for index, (name, func) in enumerate(generators, start=1):
        cancel.check()
        if progress_callback is not None:
            progress_callback(index - 1, total, f"Checking coverage with {name}…")
        try:
            group = func()
            groups.append(group)
            backend_results.append(BackendRunResult(name, assessed_count=len(group)))
        except cancel.CancelledError:
            raise                       # the user stopped; not a backend failure
        except Exception as exc:
            backend_results.append(BackendRunResult(name, error=str(exc)))
        if progress_callback is not None:
            progress_callback(index, total, f"Finished {name}")

    return AssessmentRun(assessments=_merge(groups), backend_results=backend_results)


def assess_scopes(
    scopes: List[CoverageScope],
    claude_model: str = DEFAULT_CLAUDE_MODEL,
    codex_model: Optional[str] = None,
    timeout: int = 180,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    backends=None,
) -> List[ScopeAssessment]:
    """Assess every control's scope in turn (one step per control).

    Used by the "go through all security controls" pass that follows threat
    generation. A control whose backends all fail falls back to ``assess_rules``
    for that control only, so one dead backend does not blank the whole pass.
    """
    total = max(1, len(scopes))
    done = 0

    if progress_callback is not None:
        progress_callback(0, total, f"Checking {len(scopes)} security control(s)…")

    def _one(scope: CoverageScope) -> ScopeAssessment:
        run = assess_combined_detailed(scope, claude_model, codex_model, timeout,
                                       None, backends)
        assessments, used_rules = run.assessments, False
        if not assessments:
            assessments, used_rules = assess_rules(scope), True
        return ScopeAssessment(scope, assessments, run.backend_results, used_rules)

    def _tick() -> None:
        # Called once per finished control, already serialised by run_parallel.
        nonlocal done
        done += 1
        if progress_callback is not None:
            progress_callback(done, total, f"Checked {done} of {total} control(s)…")

    # Controls are independent questions, so they run together rather than one
    # after another. Progress counts completions instead of narrating a single
    # current control, which no longer means anything once several are running.
    out = run_parallel([partial(_one, s) for s in scopes],
                       MAX_PARALLEL_CALLS, on_done=_tick)

    if progress_callback is not None:
        progress_callback(total, total, "Finished")
    return out


# ── rule-based fallback ───────────────────────────────────────────────────────

# control type -> (STRIDE categories it can address, evidence keywords)
_CONTROL_RULES: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "File Permission (ACL)": (
        ("Elevation of Privilege", "Tampering", "Information Disclosure"),
        ("permission", "acl", "chmod", "ownership", "access control", "file mode"),
    ),
    "QNX Ability": (
        ("Elevation of Privilege", "Spoofing"),
        ("ability", "privilege", "procmgr", "drop privileges"),
    ),
    "Linux Capability": (
        ("Elevation of Privilege", "Spoofing"),
        ("capability", "cap_", "privilege", "drop privileges"),
    ),
    "Firewall Rule": (
        ("Denial of Service", "Spoofing", "Information Disclosure"),
        ("firewall", "network", "port", "iptables", "filter traffic"),
    ),
    "Encryption": (
        ("Information Disclosure", "Tampering"),
        ("encrypt", "cipher", "tls", "confidential", "aes", "key"),
    ),
    "Integrity Check": (
        # Validating attacker-supplied structures before a privileged consumer
        # acts on them also blocks the escalation they would otherwise buy.
        # Accountability (Repudiation) belongs to Audit Logging, not here.
        ("Tampering", "Elevation of Privilege"),
        ("integrity", "checksum", "hash", "signature", "hmac", "verify",
         "validate", "validation", "bounds", "relocation", "command buffer",
         "cmdbuf", "sanitiz"),
    ),
    "Audit Logging": (
        # An audit trail is the answer to Repudiation; it also detects (not
        # prevents) tampering after the fact.
        ("Repudiation", "Tampering"),
        ("audit", "log", "trace", "record", "accountability", "forensic",
         "non-repudiation", "deny having", "attribution"),
    ),
    "Secure Boot": (
        ("Tampering", "Spoofing"),
        ("boot", "signed image", "chain of trust", "firmware"),
    ),
    "TrustZone / TEE": (
        ("Information Disclosure", "Tampering", "Elevation of Privilege"),
        ("tee", "trustzone", "secure world", "isolation", "key"),
    ),
    "Hardware Security Module (HSM)": (
        ("Information Disclosure", "Tampering"),
        ("hsm", "key", "secure element", "crypto"),
    ),
    "CPU Address Space Isolation": (
        ("Information Disclosure", "Elevation of Privilege", "Tampering"),
        ("isolation", "address space", "mmu", "page table", "memory"),
    ),
}


def assess_rules(scope: CoverageScope) -> List[ThreatAssessment]:
    """Offline fallback: match the control type against the threat's category
    and the wording of its description / recommended mitigations.

    Deliberately conservative — a threat is only marked mitigated when its
    STRIDE category is one the control type addresses *and* the threat text
    mentions the control's mechanism.
    """
    categories, keywords = _CONTROL_RULES.get(
        scope.control.control_type, ((), ())
    )
    results: List[ThreatAssessment] = []
    for item in scope.items:
        text = f"{item.threat_description} {item.threat_mitigations}".lower()
        hits = [k for k in keywords if k in text]
        mitigated = bool(categories) and item.threat_category in categories and bool(hits)
        if mitigated:
            rationale = (
                f"{scope.control.control_type} addresses {item.threat_category} "
                f"threats and this threat references {', '.join(hits[:3])}."
            )
        elif not categories:
            rationale = f"No rule available for control type {scope.control.control_type!r}."
        elif item.threat_category not in categories:
            rationale = (
                f"{scope.control.control_type} does not address "
                f"{item.threat_category} threats."
            )
        else:
            rationale = (
                f"Threat text does not reference the {scope.control.control_type} "
                "mechanism."
            )
        results.append(ThreatAssessment(
            threat_guid=item.threat_guid,
            threat_title=item.threat_title,
            edge_label=item.edge_label,
            mitigated=mitigated,
            rationale=rationale,
            backend="Rule-based",
        ))
    return results


def apply_assessments(
    control_id: str,
    assessments: List[ThreatAssessment],
    threats: "ThreatRegistry",
) -> int:
    """Link accepted assessments to their threats. Returns the number changed.

    Linking is idempotent, and un-accepting a previously linked control removes
    the link again so a re-run can correct an earlier verdict.
    """
    changed = 0
    for a in assessments:
        t = threats.get(a.threat_guid)
        if t is None:
            continue
        linked = list(t.mitigation_sc_ids or [])
        notes = dict(t.mitigation_notes or {})
        before = (list(linked), dict(notes))

        if a.mitigated:
            if control_id not in linked:
                linked.append(control_id)
            note = a.rationale
            if a.residual_risk:
                note = f"{note}\nResidual risk: {a.residual_risk}".strip()
            if a.backend:
                note = f"{note}\n— {a.backend}".strip()
            if note:
                notes[control_id] = note
        else:
            if control_id in linked:
                linked.remove(control_id)
            notes.pop(control_id, None)

        if (linked, notes) != before:
            changed += 1
        t.mitigation_sc_ids = linked
        t.mitigation_notes = notes
    return changed
