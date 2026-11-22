"""
Threat generation for security model edges.

Entry points:
    build_edge_context(edge, scene, threats) -> EdgeContext | None
    generate_threats(ctx, api_key)           -> List[Threat]   (LLM)
    generate_threats_rules(ctx)              -> List[Threat]   (rule fallback)
"""
from __future__ import annotations

import json
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, List, Optional, Sequence

from . import cancel
from . import agent_runner
from .parallel import MAX_PARALLEL_CALLS, run_parallel
from .threat import Threat

if TYPE_CHECKING:
    from .graphics.items import EdgeItem, NodeItem
    from .threat import ThreatRegistry


# ── backends ──────────────────────────────────────────────────────────────────

# Claude is the default generator: it is the backend everyone here has
# installed, so a run does not spend half its time failing over to a CLI that
# is not present. Codex (or both) can be selected in Settings, or per run from
# Tools → Generate Threats.
DEFAULT_BACKENDS = ("claude",)

# Sonnet by default, not Opus. Threat generation and mitigation assessment are
# structured extraction against a short, fully-specified prompt, which Sonnet
# does as well here while taking well under half the time (measured on a
# representative connection: ~20s vs ~47s per call). A slow generate is a
# generate people skip, and every flow makes one call per connection — per
# control per batch for the coverage pass. Opus stays selectable in Settings
# for a model worth waiting for.
DEFAULT_CLAUDE_MODEL = "claude-sonnet-5"


def _backend_names(backends: Optional[Sequence[str]]) -> List[str]:
    """Normalise a backend selection to a list of CLI names."""
    if backends is None:
        return list(DEFAULT_BACKENDS)
    names = [str(b).strip().lower() for b in backends]
    if "all" in names:
        return ["claude", "codex"]
    return [n for n in names if n in ("claude", "codex")]


# ── node classes ──────────────────────────────────────────────────────────────

_KERNEL_CLASSES = {"security linux-kmd", "security qnx-resmgr"}

_ASSET_CLASSES = {
    "security asset",
    "security asset file",
    "security asset shared-memory",
    "security asset register",
}


# ── context dataclasses ───────────────────────────────────────────────────────

@dataclass
class NodeContext:
    node_id: str
    node_class: str      # e.g. "security process", "security linux-kmd"
    name: str
    parent_name: str     # name of the containing process/host-app, "" if none
    boundary_name: str   # name of the containing trust boundary, "" if none
    security_props: dict # path/abilities/uid/gids (process); type (asset)
    is_kernel: bool      # True for linux-kmd, qnx-resmgr
    is_asset: bool


@dataclass
class SequenceContext:
    seq_id: str
    seq_name: str
    steps: List["EdgeContext"]          # ordered, may be a subset if some edges were skipped
    existing_threat_titles: List[str]   # across all edges in the sequence
    # Per-step properties authored in the sequence panel, aligned with ``steps``
    # (skipped steps are dropped from both lists together).
    step_props: List[dict] = field(default_factory=list)
    # Threats already recorded on the sequence itself (multi-step ones).
    existing_sequence_threat_titles: List[str] = field(default_factory=list)


@dataclass
class EdgeContext:
    edge_id: str
    source_node_id: str
    dest_node_id: str
    edge_type: str           # func call / ioctl call / mem read / mem read/write / open / close
    edge_description: str
    src_slot_name: str
    src_slot_details: str
    dst_slot_name: str
    dst_slot_details: str
    source: NodeContext
    destination: NodeContext
    crosses_trust_boundary: bool
    trust_boundary_names: List[str]
    existing_threat_titles: List[str]  # already on this edge — avoid duplicates
    # The asset interface behind each slot, when the slot declares one.
    src_slot_category: str = ""
    dst_slot_category: str = ""
    src_slot_interface: str = ""
    src_slot_path: str = ""
    src_slot_operations: List[str] = field(default_factory=list)
    dst_slot_interface: str = ""
    dst_slot_path: str = ""
    dst_slot_operations: List[str] = field(default_factory=list)


@dataclass
class BackendRunResult:
    backend_name: str
    threat_count: int = 0
    error: str = ""


@dataclass
class CombinedGenerationResult:
    threats: List[Threat]
    backend_results: List[BackendRunResult]


# ── context builder ───────────────────────────────────────────────────────────

def _node_context(node: "NodeItem") -> NodeContext:
    from .graphics.items import NodeItem

    props = node.properties()
    node_class = str(props.get("class", ""))

    sec_props = props.get("security-properties", {})
    if not isinstance(sec_props, dict):
        sec_props = {}

    parent_name = ""
    if isinstance(getattr(node, "parent_node", None), NodeItem):
        p = node.parent_node.properties()
        parent_name = str(p.get("name", ""))

    boundary_name = ""
    if isinstance(getattr(node, "boundary", None), NodeItem):
        b = node.boundary.properties()
        boundary_name = str(b.get("name", "Trust Boundary"))

    return NodeContext(
        node_id=node.node_id,
        node_class=node_class,
        name=str(props.get("name", node.title)),
        parent_name=parent_name,
        boundary_name=boundary_name,
        security_props=dict(sec_props),
        is_kernel=node_class in _KERNEL_CLASSES,
        is_asset="security asset" in node_class or node_class in _ASSET_CLASSES,
    )


def validate_edge_for_generation(
    edge: "EdgeItem",
    type_by_subtype: Optional[dict] = None,
) -> Optional[str]:
    """Check whether an edge is eligible for threat generation.

    Returns None if the edge is valid, or a human-readable error string
    explaining why it is not eligible.
    """
    from .graphics.items import NodeItem

    if edge.src is None or edge.dst is None:
        return "Edge is not fully connected (missing source or destination slot)."

    src_node = edge.src.parentItem()
    dst_node = edge.dst.parentItem()
    if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
        return "Edge endpoints are not attached to nodes."

    # Internal edges never cross boundaries — skip them entirely
    props = edge.properties()
    etype = str(props.get("type", "")).strip()
    if not etype and type_by_subtype:
        etype = type_by_subtype.get(str(props.get("sub-type", "")).strip(), "")

    if etype in ("internal func call", "alias"):
        edge_subtype = str(props.get("sub-type", "")).strip()
        if etype == "alias":
            return (
                f"Edge type '{edge_subtype}' is an alias (structural) link. "
                "Threat generation does not apply to alias edges."
            )
        return (
            f"Edge type '{edge_subtype}' is an internal func call. "
            "Threat generation only applies to edges that cross a trust boundary."
        )

    # For flow and resource edges, require that the edge actually crosses a boundary.
    # Resource edges to an asset in another boundary are valid threat targets.
    src_boundary = getattr(src_node, "boundary", None)
    dst_boundary = getattr(dst_node, "boundary", None)
    if src_boundary is dst_boundary:
        src_name = src_node.properties().get("name", "source")
        dst_name = dst_node.properties().get("name", "destination")
        if src_boundary is None:
            return (
                f"'{src_name}' and '{dst_name}' are both outside any trust boundary. "
                "Threat generation requires the edge to cross a trust boundary."
            )
        boundary_name = src_boundary.properties().get("name", "the same trust boundary")
        return (
            f"'{src_name}' and '{dst_name}' are both inside '{boundary_name}'. "
            "Threat generation requires the edge to cross a trust boundary."
        )

    return None


def build_edge_context(
    edge: "EdgeItem",
    scene,
    threats: "ThreatRegistry",
) -> Optional[EdgeContext]:
    """Build an EdgeContext from a live EdgeItem in the scene.

    Returns None if the edge is incomplete (missing src or dst slot).
    """
    from .graphics.items import NodeItem

    if edge.src is None or edge.dst is None:
        return None

    src_node = edge.src.parentItem()
    dst_node = edge.dst.parentItem()
    if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
        return None

    edge_props = edge.properties()
    src_slot_props = edge.src.properties()
    dst_slot_props = edge.dst.properties()

    # Trust boundary crossing: nodes are on different sides when their
    # containing boundary objects differ (including one being None).
    src_boundary = getattr(src_node, "boundary", None)
    dst_boundary = getattr(dst_node, "boundary", None)
    crosses = src_boundary is not dst_boundary

    boundary_names: List[str] = []
    if crosses:
        for b in {src_boundary, dst_boundary}:
            if isinstance(b, NodeItem):
                name = str(b.properties().get("name", "Trust Boundary"))
                boundary_names.append(name)
        boundary_names.sort()

    existing_titles = [
        threats[g].title
        for g in edge.threat_guids
        if g in threats and threats[g].title
    ]

    # Edge type: prefer edge sub-type property, fall back to source slot type
    edge_type = str(
        edge_props.get("sub-type")
        or src_slot_props.get("type")
        or ""
    )
    src_details = str(src_slot_props.get("details", ""))
    dst_details = str(dst_slot_props.get("details", ""))

    def _ops(props) -> List[str]:
        raw = props.get("operations")
        return [str(o) for o in raw] if isinstance(raw, list) else []

    return EdgeContext(
        edge_id=edge.edge_id,
        source_node_id=src_node.node_id,
        dest_node_id=dst_node.node_id,
        edge_type=edge_type,
        edge_description=str(edge_props.get("description", "")),
        src_slot_name=edge.src.name,
        src_slot_details=src_details if src_details not in ("", "...") else "",
        dst_slot_name=edge.dst.name,
        dst_slot_details=dst_details if dst_details not in ("", "...") else "",
        source=_node_context(src_node),
        destination=_node_context(dst_node),
        src_slot_category=_slot_category(src_slot_props, _node_context(src_node)),
        dst_slot_category=_slot_category(dst_slot_props, _node_context(dst_node)),
        src_slot_interface=str(src_slot_props.get("interface", "")),
        src_slot_path=str(src_slot_props.get("path", "")),
        src_slot_operations=_ops(src_slot_props),
        dst_slot_interface=str(dst_slot_props.get("interface", "")),
        dst_slot_path=str(dst_slot_props.get("path", "")),
        dst_slot_operations=_ops(dst_slot_props),
        crosses_trust_boundary=crosses,
        trust_boundary_names=boundary_names,
        existing_threat_titles=existing_titles,
    )


def build_sequence_context(
    seq_id: str,
    seq_name: str,
    edge_ids: List[str],
    scene,
    threats: "ThreatRegistry",
    step_props: Optional[List[dict]] = None,
    sequence_threat_guids: Optional[List[str]] = None,
) -> "SequenceContext":
    """Build a SequenceContext from an ordered list of edge IDs.

    Edges that are not found, incomplete, or ineligible for generation are
    silently skipped — the caller should warn the user separately.
    """
    from .graphics.items import EdgeItem

    edge_map = {
        item.edge_id: item
        for item in scene.items()
        if isinstance(item, EdgeItem)
    }

    steps: List[EdgeContext] = []
    kept_props: List[dict] = []
    existing_titles: List[str] = []
    props_in = list(step_props or [])

    for index, eid in enumerate(edge_ids):
        edge = edge_map.get(eid)
        if edge is None:
            continue
        if validate_edge_for_generation(edge) is not None:
            continue
        ctx = build_edge_context(edge, scene, threats)
        if ctx is None:
            continue
        steps.append(ctx)
        # Keep the authored step properties aligned with the steps that survived.
        kept_props.append(dict(props_in[index]) if index < len(props_in)
                          and isinstance(props_in[index], dict) else {})
        existing_titles.extend(ctx.existing_threat_titles)

    seq_titles = [
        threats[g].title for g in (sequence_threat_guids or [])
        if g in threats and threats[g].title
    ]

    return SequenceContext(
        seq_id=seq_id,
        seq_name=seq_name,
        steps=steps,
        existing_threat_titles=list(dict.fromkeys(existing_titles)),  # deduplicated
        step_props=kept_props,
        existing_sequence_threat_titles=list(dict.fromkeys(seq_titles)),
    )


# ── prompt helpers ────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security threat analyst specializing in embedded software, operating \
system drivers, and inter-process communication security. Your role is to \
identify specific, actionable STRIDE threats for a data-flow connection between \
two software components.

Return ONLY a JSON array of threat objects. Each object must have exactly these \
fields:
  "title"       - concise threat title (string)
  "category"    - one of: Spoofing, Tampering, Repudiation, \
Information Disclosure, Denial of Service, Elevation of Privilege
  "priority"    - one of: High, Medium, Low
  "description" - 2-4 sentence description of the threat mechanism (string)
  "attack_path" - the concrete steps an attacker takes, as a JSON array of \
2-5 short strings, ordered from the attacker's starting position to the impact. \
Start from what the attacker already has (e.g. "unprivileged local process"), \
name the real interface, operation and identifier from the connection above \
rather than a generic one, and end with the effect on the asset. Each step \
must be something an attacker does or obtains, not a property of the system.
  "mitigations" - 1-3 concrete mitigation steps (string)

Do not include any text outside the JSON array.\
"""


def _slot_category(slot_props: dict, node_ctx: "NodeContext") -> str:
    """The channel type behind a slot, described in one line.

    Models saved before categories existed have no ``category`` on their slots,
    so fall back to the asset type's descriptor: the interface name on the slot
    is the key. Re-authoring a model must not be the price of a better prompt.
    """
    summary = str(slot_props.get("category-summary", "") or "").strip()
    if summary:
        return summary
    category = str(slot_props.get("category", "") or "").strip()
    interface_name = str(slot_props.get("interface", "") or "").strip()
    type_id = str((node_ctx.security_props or {}).get("type", "") or "").strip()
    if not category and type_id and interface_name:
        try:
            from .asset_registry import descriptor_asset_types
            at = descriptor_asset_types().get(type_id)
        except Exception:                       # a prompt is not worth a crash
            at = None
        if at is not None:
            iface = next((i for i in at.interfaces if i.name == interface_name), None)
            if iface is not None:
                return iface.category_summary() or iface.category
    if category:
        from .interface_categories import describe
        return describe(category, {}, str(slot_props.get("path", "")))
    return ""


def _category_hints(summary: str) -> List[str]:
    """Failure modes the catalogue records for this channel type.

    Given to the agent as *prompts to consider*, not as findings: they steer it
    toward the mechanism's real weaknesses instead of generic STRIDE, and the
    review dialog still decides what is kept.
    """
    if not summary:
        return []
    from .interface_categories import all_categories
    for cat in all_categories():
        if summary.startswith(cat.label):
            return list(cat.threat_hints)
    return []


def _format_user_message(ctx: EdgeContext) -> str:
    lines: List[str] = []

    def _fmt_node(label: str, n: NodeContext) -> None:
        lines.append(f"{label}: {n.name!r} ({n.node_class})")
        if n.parent_name:
            lines.append(f"  Contained in: {n.parent_name}")
        if n.boundary_name:
            lines.append(f"  Trust boundary: {n.boundary_name}")
        if n.is_kernel:
            lines.append("  Privilege: kernel mode")
        sp = n.security_props
        if sp.get("path"):
            lines.append(f"  Path: {sp['path']}")
        if sp.get("uid") is not None:
            lines.append(f"  UID: {sp['uid']}")
        if sp.get("gids"):
            lines.append(f"  GIDs: {sp['gids']}")
        if sp.get("abilities"):
            lines.append(f"  Abilities: {sp['abilities']}")
        if sp.get("type"):
            lines.append(f"  Asset type: {sp['type']}")

    _fmt_node("Source", ctx.source)
    lines.append("")
    _fmt_node("Destination", ctx.destination)
    lines.append("")

    lines.append(f"Connection type: {ctx.edge_type or '(unspecified)'}")
    if ctx.edge_description:
        lines.append(f"Description: {ctx.edge_description}")
    if ctx.src_slot_details:
        lines.append(f"Source slot details: {ctx.src_slot_details}")
    if ctx.dst_slot_details:
        lines.append(f"Destination slot details: {ctx.dst_slot_details}")

    # How the channel works — an ioctl, a mapped region, a hypercall and a CAN
    # bus fail in entirely different ways, and the category is the only field
    # that says which of those this is.
    for side, category, iface, path, ops in (
            ("Source", ctx.src_slot_category, ctx.src_slot_interface,
             ctx.src_slot_path, ctx.src_slot_operations),
            ("Destination", ctx.dst_slot_category, ctx.dst_slot_interface,
             ctx.dst_slot_path, ctx.dst_slot_operations)):
        if not (category or iface):
            continue
        lines.append(f"{side} interface: {iface or '(unnamed)'}")
        if category:
            lines.append(f"  Channel type: {category}")
        if path:
            lines.append(f"  Path: {path}")
        if ops:
            lines.append(f"  Operations: {', '.join(ops)}")
        hints = _category_hints(category)
        if hints:
            lines.append("  Known failure modes for this channel type:")
            for hint in hints:
                lines.append(f"    - {hint}")
    if ctx.crosses_trust_boundary:
        names = ", ".join(ctx.trust_boundary_names) or "unnamed"
        lines.append(f"Trust boundary crossed: {names}")
    if ctx.existing_threat_titles:
        lines.append("\nAlready identified threats (do not repeat):")
        for t in ctx.existing_threat_titles:
            lines.append(f"  - {t}")

    lines.append(
        "\nGenerate STRIDE threats for this connection. Focus on threats "
        "specific to the component types, privilege levels, and connection "
        "method shown above."
    )
    return "\n".join(lines)


_SEQUENCE_SYSTEM_PROMPT = """\
You are a security threat analyst specializing in embedded software, operating \
system drivers, and inter-process communication security. Your role is to \
identify STRIDE threats that arise from an ordered multi-step data flow \
sequence — including threats that span multiple steps or exploit the \
combination of operations in the sequence.

Return ONLY a JSON array of threat objects. Each object must have exactly \
these fields:
  "title"       - concise threat title (string)
  "category"    - one of: Spoofing, Tampering, Repudiation, \
Information Disclosure, Denial of Service, Elevation of Privilege
  "priority"    - one of: High, Medium, Low
  "step"        - 0-based index of the most relevant step, or -1 if the \
threat spans the whole sequence (integer)
  "description" - 2-4 sentence description of the threat mechanism, \
referencing specific steps where relevant (string)
  "attack_path" - the concrete steps an attacker takes, as a JSON array of \
2-5 short strings, ordered from the attacker's starting position to the \
impact. Name the sequence steps the attacker rides on (by their real \
operation, not the index alone) and end with the effect on the asset. Each \
step must be something an attacker does or obtains, not a property of the \
system.
  "mitigations" - 1-3 concrete mitigation steps (string)

Do not include any text outside the JSON array.\
"""


def _fmt_node_inline(n: "NodeContext") -> str:
    parts = [f"{n.name!r} ({n.node_class})"]
    if n.parent_name:
        parts.append(f"in {n.parent_name!r}")
    if n.boundary_name:
        parts.append(f"[boundary: {n.boundary_name}]")
    if n.is_kernel:
        parts.append("[kernel mode]")
    sp = n.security_props
    attrs = []
    if sp.get("path"):
        attrs.append(f"path={sp['path']}")
    if sp.get("uid") is not None:
        attrs.append(f"uid={sp['uid']}")
    if sp.get("abilities"):
        attrs.append(f"abilities={sp['abilities']}")
    if sp.get("type"):
        attrs.append(f"type={sp['type']}")
    if attrs:
        parts.append(f"({', '.join(attrs)})")
    return " ".join(parts)


def _fmt_node_block(n: "NodeContext", indent: str = "  ") -> List[str]:
    """Full context for one participant: role, placement and every security property."""
    lines = [f"{indent}{n.name!r} — {n.node_class}"]
    detail = indent + "  "
    if n.is_kernel:
        lines.append(f"{detail}Privilege: kernel mode")
    if n.is_asset:
        lines.append(f"{detail}Role: security asset (the thing being protected)")
    lines.append(f"{detail}Trust boundary: {n.boundary_name or '(outside any boundary)'}")
    if n.parent_name:
        lines.append(f"{detail}Contained in: {n.parent_name}")
    # Every authored security property, not a hand-picked subset — uid, gids,
    # abilities, capabilities, owner, asset type, and anything a template adds.
    for key, value in n.security_props.items():
        if value in ("", None, [], {}):
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(v) for v in value)
        lines.append(f"{detail}{key}: {value}")
    return lines


def _format_sequence_message(seq_ctx: "SequenceContext") -> str:
    lines: List[str] = [
        f"Sequence: {seq_ctx.seq_name!r}",
        f"Total steps: {len(seq_ctx.steps)}",
        "",
    ]

    # ── participants: every distinct node in the flow, described once, in full ──
    participants: dict = {}
    for step in seq_ctx.steps:
        for node in (step.source, step.destination):
            participants.setdefault(node.node_id, node)

    lines.append(f"PARTICIPANTS ({len(participants)}):")
    for node in participants.values():
        lines.extend(_fmt_node_block(node))
    lines.append("")

    boundaries = []
    for step in seq_ctx.steps:
        for name in step.trust_boundary_names:
            if name not in boundaries:
                boundaries.append(name)
    if boundaries:
        lines.append(f"TRUST BOUNDARIES INVOLVED: {', '.join(boundaries)}")
        lines.append("")

    # ── the flow, in order ─────────────────────────────────────────────────────
    lines.append("FLOW (ordered — each step happens after the one before it):")
    for i, step in enumerate(seq_ctx.steps):
        lines.append("")
        lines.append(f"  Step {i}: {step.edge_type or '(unspecified operation)'}")
        lines.append(f"    From: {step.source.name!r} (slot {step.src_slot_name!r})")
        lines.append(f"    To:   {step.destination.name!r} (slot {step.dst_slot_name!r})")
        if step.edge_description:
            lines.append(f"    Description: {step.edge_description}")
        if step.crosses_trust_boundary:
            names = ", ".join(step.trust_boundary_names) or "unnamed"
            lines.append(f"    Crosses trust boundary: {names}")
        else:
            lines.append("    Stays within one trust boundary")

        for side, iface, path, ops, details in (
            ("Source", step.src_slot_interface, step.src_slot_path,
             step.src_slot_operations, step.src_slot_details),
            ("Destination", step.dst_slot_interface, step.dst_slot_path,
             step.dst_slot_operations, step.dst_slot_details),
        ):
            if iface:
                lines.append(f"    {side} interface: {iface}"
                             + (f" (path {path})" if path else ""))
            if ops:
                lines.append(f"    {side} interface operations: {', '.join(ops)}")
            if details:
                lines.append(f"    {side} details: {details}")

        props = seq_ctx.step_props[i] if i < len(seq_ctx.step_props) else {}
        for key, value in (props or {}).items():
            if str(value).strip():
                lines.append(f"    {key}: {value}")

    if seq_ctx.existing_threat_titles or seq_ctx.existing_sequence_threat_titles:
        lines.append("")
        lines.append("ALREADY IDENTIFIED (do not repeat these):")
        for t in seq_ctx.existing_sequence_threat_titles:
            lines.append(f"  - [sequence] {t}")
        for t in seq_ctx.existing_threat_titles:
            lines.append(f"  - [step] {t}")

    lines.append(
        "\nAnalyse this sequence as a whole. Identify STRIDE threats that arise "
        "from the combination and ordering of steps — including multi-step attack "
        "chains, privilege escalation paths across boundaries, state left behind "
        "by an earlier step, time-of-check/time-of-use windows between steps, and "
        "threats that only become possible because of earlier steps in the flow. "
        "Use \"step\": -1 for a threat that spans the sequence rather than living "
        "on one step."
    )
    return "\n".join(lines)


def _run_claude_cli(
    user_message: str,
    system_prompt: str,
    model: str = DEFAULT_CLAUDE_MODEL,
    timeout: int = 120,
) -> str:
    """Invoke the claude CLI non-interactively and return the raw text response.

    Raises RuntimeError on any failure so callers can fall back to rule-based generation.
    """
    cmd = [
        "claude",
        "-p", user_message,
        "--output-format", "json",
        "--model", model,
        # One self-contained question, no tools, no follow-up: skip the MCP
        # servers this project may configure and the session transcript, both
        # pure startup cost here.
        "--strict-mcp-config",
        "--no-session-persistence",
    ]
    if system_prompt:
        cmd += ["--system-prompt", system_prompt]

    # The agent runner owns every process: it spawns, records the pid, drains
    # the pipes, enforces the deadline and kills the group on cancel. This
    # function only builds the command and reads the answer.
    job = agent_runner.run_cli(cmd, timeout=timeout, label=f"claude {model}")
    if job.error == "timeout":
        raise RuntimeError(f"Claude CLI timed out after {timeout}s.")
    if job.error:
        if "could not start" in job.error:
            raise RuntimeError(
                "'claude' CLI not found. Install Claude Code: https://claude.ai/code")
        raise RuntimeError(job.error)
    if job.returncode != 0:
        raise RuntimeError(job.stderr.strip() or "Claude CLI failed.")

    return json.loads(job.stdout)["result"]


def _run_codex_cli(
    user_message: str,
    system_prompt: str,
    model: Optional[str] = None,
    timeout: int = 120,
) -> str:
    """Invoke the Codex CLI non-interactively and return the final text response."""
    prompt = (
        f"{system_prompt.strip()}\n\n"
        f"{user_message.strip()}\n"
    ).strip()

    with tempfile.NamedTemporaryFile("r+", encoding="utf-8", suffix=".txt") as output_file:
        cmd = [
            "codex",
            "exec",
            "--skip-git-repo-check",
            "--sandbox", "read-only",
            "--color", "never",
            "--ephemeral",
            "-o", output_file.name,
        ]
        if model:
            cmd += ["--model", model]
        cmd.append("-")

        job = agent_runner.run_cli(cmd, stdin=prompt, timeout=timeout, label="codex")
        if job.error == "timeout":
            raise RuntimeError(f"Codex CLI timed out after {timeout}s.")
        if job.error:
            if "could not start" in job.error:
                raise RuntimeError("'codex' CLI not found. Install Codex CLI to "
                                   "enable dual threat generation.")
            raise RuntimeError(job.error)

        if job.returncode != 0:
            err = job.stderr.strip() or job.stdout.strip() or "Codex CLI failed."
            raise RuntimeError(err)

        output_file.seek(0)
        result = output_file.read().strip()

    if not result:
        raise RuntimeError("Codex CLI returned an empty response.")

    return result


# An attack path is stored as one line: the steps joined by an arrow. A list
# would read better in the panel, but the field is a plain string everywhere
# else already — the dialog, both reports, and every model written before this
# existed — and one line is what a reviewer scans.
ATTACK_PATH_SEP = " → "


def _attack_path(item: dict) -> str:
    """Normalise the model's attack path to a single arrow-joined line.

    Accepts the array the prompt asks for, or a string if the backend answered
    in prose anyway: a path phrased the wrong way is still worth keeping.
    """
    raw = item.get("attack_path", "")
    if isinstance(raw, str):
        return raw.strip()
    if not isinstance(raw, (list, tuple)):
        return ""
    steps = [str(step).strip() for step in raw if isinstance(step, (str, int, float))]
    return ATTACK_PATH_SEP.join(step for step in steps if step)


def _parse_raw_json(raw: str) -> list:
    """Strip optional markdown fences and parse the JSON array."""
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[-1]
        if raw.endswith("```"):
            raw = raw.rsplit("```", 1)[0]
    raw = raw.strip()

    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"CLI returned non-JSON:\n{raw[:400]}") from exc

    if not isinstance(items, list):
        raise RuntimeError(f"Expected a JSON array, got: {type(items).__name__}")

    return items


def _normalize_threat_key(threat: Threat) -> tuple[str, str, str]:
    return (
        (threat.edge_guid or "").strip(),
        (threat.category or "").strip().lower(),
        (threat.title or "").strip().lower(),
    )


def _merge_backend_names(*backend_groups: List[str]) -> List[str]:
    merged: List[str] = []
    for group in backend_groups:
        for name in group:
            clean = str(name).strip()
            if clean and clean not in merged:
                merged.append(clean)
    return merged


def _dedupe_threats(threats: List[Threat]) -> List[Threat]:
    deduped: List[Threat] = []
    seen: dict[tuple[str, str, str], Threat] = {}

    for threat in threats:
        key = _normalize_threat_key(threat)
        existing = seen.get(key)
        if existing is None:
            seen[key] = threat
            deduped.append(threat)
            continue

        if not existing.description and threat.description:
            existing.description = threat.description
        if not existing.mitigations and threat.mitigations:
            existing.mitigations = threat.mitigations
        if not existing.attack_path and threat.attack_path:
            existing.attack_path = threat.attack_path
        existing.ai_backends = _merge_backend_names(existing.ai_backends, threat.ai_backends)

    return deduped


def _combine_generation_results_detailed(
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    *generators,
) -> CombinedGenerationResult:
    combined: List[Threat] = []
    backend_results: List[BackendRunResult] = []
    total = len(generators)

    for index, (name, func) in enumerate(generators, start=1):
        cancel.check()
        if progress_callback is not None:
            progress_callback(index - 1, total, f"Running {name}...")
        try:
            generated = func()
            combined.extend(generated)
            backend_results.append(
                BackendRunResult(backend_name=name, threat_count=len(generated))
            )
        except cancel.CancelledError:
            raise                       # not a backend failure — the user stopped
        except Exception as exc:
            backend_results.append(
                BackendRunResult(backend_name=name, error=str(exc))
            )
        if progress_callback is not None:
            progress_callback(index, total, f"Finished {name}")

    return CombinedGenerationResult(
        threats=_dedupe_threats(combined),
        backend_results=backend_results,
    )


def _combine_generation_results(
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    *generators,
) -> List[Threat]:
    result = _combine_generation_results_detailed(progress_callback, *generators)
    if result.threats:
        return result.threats

    errors = [
        f"{item.backend_name}: {item.error}"
        for item in result.backend_results
        if item.error
    ]
    raise RuntimeError(" | ".join(errors) if errors else "Threat generation failed.")


def generate_threats_for_sequence(
    seq_ctx: "SequenceContext",
    model: str = DEFAULT_CLAUDE_MODEL,
    timeout: int = 180,
) -> List[Threat]:
    """Generate threats for a full sequence via the claude CLI.

    Each returned Threat has edge_guid set to the edge at the indicated step
    (or the first step's edge for sequence-wide threats).
    Raises RuntimeError on CLI or parse failure.
    """
    if not seq_ctx.steps:
        return []

    raw = _run_claude_cli(
        _format_sequence_message(seq_ctx), _SEQUENCE_SYSTEM_PROMPT, model, timeout
    )
    return _parse_sequence_threats(_parse_raw_json(raw), seq_ctx)


def generate_threats_for_sequence_codex(
    seq_ctx: "SequenceContext",
    model: Optional[str] = None,
    timeout: int = 180,
) -> List[Threat]:
    """Generate threats for a full sequence via the Codex CLI."""
    if not seq_ctx.steps:
        return []

    raw = _run_codex_cli(
        _format_sequence_message(seq_ctx), _SEQUENCE_SYSTEM_PROMPT, model, timeout
    )
    return _parse_sequence_threats(_parse_raw_json(raw), seq_ctx)


def generate_threats_for_sequence_combined(
    seq_ctx: "SequenceContext",
    claude_model: str = DEFAULT_CLAUDE_MODEL,
    codex_model: Optional[str] = None,
    timeout: int = 180,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> List[Threat]:
    """Generate sequence threats from Claude and Codex, then merge unique results."""
    return _combine_generation_results(
        progress_callback,
        ("Claude CLI", lambda: _tag_threat_backends(
            generate_threats_for_sequence(seq_ctx, claude_model, timeout), "Claude CLI"
        )),
        ("Codex CLI", lambda: _tag_threat_backends(
            generate_threats_for_sequence_codex(seq_ctx, codex_model, timeout), "Codex CLI"
        )),
    )


def generate_threats_for_sequence_combined_detailed(
    seq_ctx: "SequenceContext",
    claude_model: str = DEFAULT_CLAUDE_MODEL,
    codex_model: Optional[str] = None,
    timeout: int = 180,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    backends: Optional[Sequence[str]] = None,
) -> CombinedGenerationResult:
    """Generate sequence threats with the requested backends (default: Claude)."""
    generators = []
    for name in _backend_names(backends):
        if name == "claude":
            generators.append(("Claude CLI", lambda: _tag_threat_backends(
                generate_threats_for_sequence(seq_ctx, claude_model, timeout), "Claude CLI")))
        elif name == "codex":
            generators.append(("Codex CLI", lambda: _tag_threat_backends(
                generate_threats_for_sequence_codex(seq_ctx, codex_model, timeout), "Codex CLI")))
    return _combine_generation_results_detailed(progress_callback, *generators)


def _parse_sequence_threats(items: list, seq_ctx: "SequenceContext") -> List[Threat]:
    _VALID_CATEGORIES = {
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege",
    }
    _VALID_PRIORITIES = {"High", "Medium", "Low"}

    threats: List[Threat] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        category = str(item.get("category", "")).strip()
        if not title or category not in _VALID_CATEGORIES:
            continue
        priority = str(item.get("priority", "Medium")).strip()
        if priority not in _VALID_PRIORITIES:
            priority = "Medium"

        # Map step index to the corresponding EdgeContext
        step_idx = item.get("step", -1)
        try:
            step_idx = int(step_idx)
        except (TypeError, ValueError):
            step_idx = -1

        if 0 <= step_idx < len(seq_ctx.steps):
            # Pinned to one step: the threat belongs to that edge, and the
            # sequence lists it too.
            ctx = seq_ctx.steps[step_idx]
            source_id, dest_id, edge_id = ctx.source_node_id, ctx.dest_node_id, ctx.edge_id
        else:
            # Sequence-wide: no single edge owns it. Span the whole flow, from
            # the first step's source to the last step's destination.
            source_id = seq_ctx.steps[0].source_node_id
            dest_id = seq_ctx.steps[-1].dest_node_id
            edge_id = ""

        threats.append(Threat(
            source_guid=source_id,
            dest_guid=dest_id,
            edge_guid=edge_id,
            sequence_guid=seq_ctx.seq_id,
            guid=str(uuid.uuid4()),
            title=title,
            category=category,
            priority=priority,
            status="Open",
            description=str(item.get("description", "")).strip(),
            attack_path=_attack_path(item),
            mitigations=str(item.get("mitigations", "")).strip(),
            ai_backends=[],
        ))
    return threats


# ── CLI generation ────────────────────────────────────────────────────────────

def generate_threats(
    ctx: EdgeContext,
    model: str = DEFAULT_CLAUDE_MODEL,
    timeout: int = 120,
) -> List[Threat]:
    """Generate threats via the claude CLI.

    Raises RuntimeError on failure — caller should catch and fall back to
    generate_threats_rules().
    """
    raw = _run_claude_cli(_format_user_message(ctx), _SYSTEM_PROMPT, model, timeout)
    return _parse_threats(_parse_raw_json(raw), ctx)


def generate_threats_codex(
    ctx: EdgeContext,
    model: Optional[str] = None,
    timeout: int = 120,
) -> List[Threat]:
    """Generate threats via the Codex CLI."""
    raw = _run_codex_cli(_format_user_message(ctx), _SYSTEM_PROMPT, model, timeout)
    return _parse_threats(_parse_raw_json(raw), ctx)


def generate_threats_combined(
    ctx: EdgeContext,
    claude_model: str = DEFAULT_CLAUDE_MODEL,
    codex_model: Optional[str] = None,
    timeout: int = 120,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
) -> List[Threat]:
    """Generate threats from Claude and Codex, then merge unique results."""
    return _combine_generation_results(
        progress_callback,
        ("Claude CLI", lambda: _tag_threat_backends(
            generate_threats(ctx, claude_model, timeout), "Claude CLI"
        )),
        ("Codex CLI", lambda: _tag_threat_backends(
            generate_threats_codex(ctx, codex_model, timeout), "Codex CLI"
        )),
    )


def generate_threats_combined_detailed(
    ctx: EdgeContext,
    claude_model: str = DEFAULT_CLAUDE_MODEL,
    codex_model: Optional[str] = None,
    timeout: int = 120,
    progress_callback: Optional[Callable[[int, int, str], None]] = None,
    backends: Optional[Sequence[str]] = None,
) -> CombinedGenerationResult:
    """Generate with the requested backends (default: Claude only)."""
    generators = []
    for name in _backend_names(backends):
        if name == "claude":
            generators.append(("Claude CLI", lambda: _tag_threat_backends(
                generate_threats(ctx, claude_model, timeout), "Claude CLI")))
        elif name == "codex":
            generators.append(("Codex CLI", lambda: _tag_threat_backends(
                generate_threats_codex(ctx, codex_model, timeout), "Codex CLI")))
    return _combine_generation_results_detailed(progress_callback, *generators)


def _parse_threats(items: list, ctx: EdgeContext) -> List[Threat]:
    _VALID_CATEGORIES = {
        "Spoofing", "Tampering", "Repudiation",
        "Information Disclosure", "Denial of Service", "Elevation of Privilege",
    }
    _VALID_PRIORITIES = {"High", "Medium", "Low"}

    threats: List[Threat] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title", "")).strip()
        category = str(item.get("category", "")).strip()
        if not title or category not in _VALID_CATEGORIES:
            continue
        priority = str(item.get("priority", "Medium")).strip()
        if priority not in _VALID_PRIORITIES:
            priority = "Medium"
        threats.append(Threat(
            source_guid=ctx.source_node_id,
            dest_guid=ctx.dest_node_id,
            edge_guid=ctx.edge_id,
            guid=str(uuid.uuid4()),
            title=title,
            category=category,
            priority=priority,
            status="Open",
            description=str(item.get("description", "")).strip(),
            attack_path=_attack_path(item),
            mitigations=str(item.get("mitigations", "")).strip(),
            ai_backends=[],
        ))
    return threats


def _tag_threat_backends(threats: List[Threat], backend_name: str) -> List[Threat]:
    for threat in threats:
        threat.ai_backends = _merge_backend_names(threat.ai_backends, [backend_name])
    return threats


# ── rule-based fallback ───────────────────────────────────────────────────────

@dataclass
class _Rule:
    edge_types: List[str]          # [] = any
    src_classes: List[str]         # [] = any
    dst_classes: List[str]         # [] = any
    require_boundary: bool
    category: str
    priority: str
    title_tpl: str                 # {src}, {dst}, {edge} substituted
    description_tpl: str
    mitigations_tpl: str
    # Optional: rule files written before attack paths existed have none, and
    # a rule with no path is better than an invented one.
    attack_path_tpl: str = ""


def _load_rules() -> List[_Rule]:
    path = Path(__file__).parent / "threat_rules.json"
    with path.open(encoding="utf-8") as f:
        items = json.load(f)
    return [_Rule(**item) for item in items]


_RULES: List[_Rule] = _load_rules()


def generate_threats_rules(
    ctx: EdgeContext,
    rules_path: Optional[str] = None,
) -> List[Threat]:
    """Rule-based threat generation.

    If *rules_path* is given (and points to a valid JSON file), rules are
    loaded from that file instead of the built-in threat_rules.json.
    """
    if rules_path:
        try:
            custom_rules = [_Rule(**item) for item in json.loads(Path(rules_path).read_text(encoding="utf-8"))]
        except Exception:
            custom_rules = None
    else:
        custom_rules = None
    rules = custom_rules if custom_rules is not None else _RULES

    src_name = ctx.source.name
    dst_name = ctx.destination.name
    edge_type = ctx.edge_type.lower()

    def _subst(tpl: str) -> str:
        return (tpl
                .replace("{src}", src_name)
                .replace("{dst}", dst_name)
                .replace("{edge}", ctx.edge_type))

    def _matches(rule: _Rule) -> bool:
        if rule.require_boundary and not ctx.crosses_trust_boundary:
            return False
        if rule.edge_types and edge_type not in [e.lower() for e in rule.edge_types]:
            return False
        if rule.src_classes and ctx.source.node_class not in rule.src_classes:
            return False
        if rule.dst_classes and ctx.destination.node_class not in rule.dst_classes:
            return False
        return True

    existing = {t.lower() for t in ctx.existing_threat_titles}
    threats: List[Threat] = []

    for rule in rules:
        if not _matches(rule):
            continue
        title = _subst(rule.title_tpl)
        if title.lower() in existing:
            continue
        threats.append(Threat(
            source_guid=ctx.source_node_id,
            dest_guid=ctx.dest_node_id,
            edge_guid=ctx.edge_id,
            guid=str(uuid.uuid4()),
            title=title,
            category=rule.category,
            priority=rule.priority,
            status="Open",
            description=_subst(rule.description_tpl),
            attack_path=_subst(rule.attack_path_tpl),
            mitigations=_subst(rule.mitigations_tpl),
            ai_backends=["Rule-based"],
        ))

    return threats
