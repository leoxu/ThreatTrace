"""
Deciding what "update threats" should actually do.

Threats are produced from two inputs: the **connection context** (who talks to
whom, over which interface, across which boundary) and the **security controls**
covering that connection's asset interface. Each input goes stale on its own, and
the right repair differs:

* the connection changed — different source, destination, operation, interface
  or boundary — then the existing threats were derived from a system that no
  longer exists: **re-generate**;
* the connection is unchanged but the controls changed — one added, removed,
  edited or moved — then the threats are still valid, only their mitigation
  status is in question: **re-assess** (and drop links the geometry no longer
  supports);
* neither changed: **nothing to do**, and no agent call is made.

To tell those apart a threat records what it was produced under:

* ``Threat.context_hash``  — hash of the connection context at generation time;
* ``Threat.controls_hash`` — hash of the covering controls at assessment time.

The context hash covers the connection's *facts* — endpoints, their classes,
containing components, trust boundaries and security properties, the operation,
and the interface behind each slot — not the rendered prompt. Re-wording a
prompt must not invalidate every model's threats, and a cosmetic edit (a colour,
a position) must not either. An empty hash means "produced before this was recorded" and is treated as
up-to-date, so old models do not all demand a re-generation on first open.

Qt-free.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Iterable, List, Optional

if TYPE_CHECKING:
    from .mitigation import CoverageScope
    from .threat import Threat
    from .threat_gen import EdgeContext


# What an update should do next.
ACTION_GENERATE = "generate"        # the connection changed
ACTION_ASSESS = "assess"            # only the controls changed
ACTION_UP_TO_DATE = "up-to-date"    # nothing changed
ACTION_NO_THREATS = "no-threats"    # nothing to update yet


@dataclass
class Decision:
    action: str
    reason: str
    changed: List[str] = field(default_factory=list)
    context_hash: str = ""
    controls_hash: str = ""

    @property
    def needs_agent(self) -> bool:
        return self.action in (ACTION_GENERATE, ACTION_ASSESS)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def _node_fingerprint(n) -> str:
    props = ";".join(f"{k}={v}" for k, v in sorted(n.security_props.items()))
    return "|".join([n.name, n.node_class, n.parent_name, n.boundary_name, props])


def context_hash(ctx: "EdgeContext") -> str:
    """Hash of the connection as the agent sees it.

    Covers exactly what the agent is told about the *system*: both endpoints
    (name, class, containing component, trust boundary and every security
    property), the operation, the description, and the interface behind each
    slot. Deliberately not the prompt text — the wording of the prompt changes
    with the tool, and that must not invalidate a model's threats. Equally, a
    cosmetic edit (colour, position) changes nothing here.
    """
    parts = [
        _node_fingerprint(ctx.source),
        _node_fingerprint(ctx.destination),
        ctx.edge_type,
        ctx.edge_description,
        f"{ctx.src_slot_name}/{ctx.src_slot_interface}/{ctx.src_slot_path}/"
        f"{','.join(ctx.src_slot_operations)}/{ctx.src_slot_details}",
        f"{ctx.dst_slot_name}/{ctx.dst_slot_interface}/{ctx.dst_slot_path}/"
        f"{','.join(ctx.dst_slot_operations)}/{ctx.dst_slot_details}",
        f"crosses={ctx.crosses_trust_boundary}",
        ",".join(sorted(ctx.trust_boundary_names)),
    ]
    return _digest("\n".join(parts))


def controls_hash(scopes: Iterable["CoverageScope"]) -> str:
    """Hash of the controls covering a connection, and of what they cover.

    Covers the cases the user actually hits: a control added or removed, its
    configuration edited, or the circle moved so it covers a different set of
    interfaces.
    """
    parts: List[str] = []
    for scope in sorted(scopes, key=lambda s: s.control.node_id):
        c = scope.control
        covered = ",".join(sorted(f"{s.asset_name}.{s.slot_name}" for s in scope.slots))
        parts.append("|".join([c.node_id, c.name, c.control_type,
                               c.requirement_id, c.description, covered]))
    return _digest("\n".join(parts)) if parts else ""


def stamp_context(threats: Iterable["Threat"], value: str) -> None:
    for t in threats:
        t.context_hash = value


def stamp_controls(threats: Iterable["Threat"], value: str) -> None:
    for t in threats:
        t.controls_hash = value


def classify(threats: List["Threat"], ctx: Optional["EdgeContext"],
             scopes: Iterable["CoverageScope"]) -> Decision:
    """Work out what an update of these threats should do.

    ``ctx`` is the connection's current context (None when it cannot be built —
    the edge is incomplete — in which case only the controls are considered).
    """
    scopes = list(scopes)
    current_ctx = context_hash(ctx) if ctx is not None else ""
    current_controls = controls_hash(scopes)

    if not threats:
        return Decision(ACTION_NO_THREATS,
                        "This connection has no threats yet — generate them first.",
                        context_hash=current_ctx, controls_hash=current_controls)

    # A recorded hash that differs is a real change. An empty one means the
    # threat predates this bookkeeping: adopt the current value rather than
    # forcing a re-generation of every old model.
    stale_ctx = [t for t in threats if t.context_hash and t.context_hash != current_ctx]
    if stale_ctx and current_ctx:
        return Decision(
            ACTION_GENERATE,
            f"The connection changed since {len(stale_ctx)} of {len(threats)} "
            "threat(s) were generated, so they describe a system that no longer "
            "matches the model.",
            changed=["connection context (endpoints, operation, interface or "
                     "trust boundary)"],
            context_hash=current_ctx, controls_hash=current_controls,
        )

    stale_controls = [t for t in threats
                      if (t.controls_hash or "") != current_controls]
    if stale_controls:
        if current_controls:
            reason = ("The security controls covering this connection changed, "
                      "so the mitigation status needs re-checking.")
        else:
            reason = ("No security control covers this connection any more, so "
                      "any mitigation links have to be dropped.")
        return Decision(ACTION_ASSESS, reason, changed=["security controls"],
                        context_hash=current_ctx, controls_hash=current_controls)

    return Decision(ACTION_UP_TO_DATE,
                    "Neither the connection nor its security controls have "
                    "changed since the last update — nothing to do.",
                    context_hash=current_ctx, controls_hash=current_controls)
