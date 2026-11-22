"""
Subgraph placeholder support (Phase 1: interface contract + slot generation).

A Subgraph node is a placeholder for a component that someone else models
later.  It is defined by an *interface contract*: an ordered list of named
ports.  Each port becomes a slot on the placeholder node, so external edges
connect to the ports.  Later phases bind/import a component JSON and rebind the
external edges to the component's matching interface points (by port name).

This module is pure logic (no Qt) so it can be unit-tested independently.

Interface storage (inside a node's ``security-properties``):

    "interface": [
        {"name": "ctrl", "dir": "in",  "expects": "security process"},
        {"name": "irq",  "dir": "out", "expects": ""}
    ]

Slots generated from the interface:
    inputs  = [port.name for port in interface if port.dir == "in"]
    outputs = [port.name for port in interface if port.dir == "out"]
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

PORT_IN = "in"
PORT_OUT = "out"
_VALID_DIRS = (PORT_IN, PORT_OUT)

SUBGRAPH_CLASS = "security subgraph"
SUBGRAPH_SHAPE = "Subgraph"

# Subgraph lifecycle states (see doc/subgraph-design.md §4.2)
STATE_UNBOUND = "unbound"
STATE_BOUND = "bound"
STATE_STALE = "stale"
STATE_MISSING = "missing"


@dataclass
class Port:
    """One named connection point on a subgraph placeholder."""
    name: str
    dir: str = PORT_IN            # "in" | "out"
    expects: str = ""             # optional expected node class/type hint

    def __post_init__(self) -> None:
        self.name = str(self.name).strip()
        self.dir = self.dir if self.dir in _VALID_DIRS else PORT_IN
        self.expects = str(self.expects or "")

    def to_dict(self) -> Dict[str, str]:
        return {"name": self.name, "dir": self.dir, "expects": self.expects}

    @staticmethod
    def from_dict(d: dict) -> "Port":
        return Port(
            name=str(d.get("name", "")),
            dir=str(d.get("dir", PORT_IN)),
            expects=str(d.get("expects", "")),
        )


@dataclass
class Interface:
    """Ordered list of ports defining a subgraph's contract.

    Port names are unique (case-sensitive); duplicates are dropped on
    construction, keeping the first occurrence.
    """
    ports: List[Port] = field(default_factory=list)

    def __post_init__(self) -> None:
        seen: set = set()
        unique: List[Port] = []
        for p in self.ports:
            if p.name and p.name not in seen:
                seen.add(p.name)
                unique.append(p)
        self.ports = unique

    # ── serialization ────────────────────────────────────────────────────────
    def to_list(self) -> List[dict]:
        return [p.to_dict() for p in self.ports]

    @staticmethod
    def from_list(raw) -> "Interface":
        if not isinstance(raw, list):
            return Interface()
        return Interface([Port.from_dict(d) for d in raw if isinstance(d, dict)])

    # ── slot generation ──────────────────────────────────────────────────────
    def input_names(self) -> List[str]:
        return [p.name for p in self.ports if p.dir == PORT_IN]

    def output_names(self) -> List[str]:
        return [p.name for p in self.ports if p.dir == PORT_OUT]

    # ── queries / mutation helpers (used by the interface editor) ─────────────
    def names(self) -> List[str]:
        return [p.name for p in self.ports]

    def get(self, name: str) -> Port | None:
        for p in self.ports:
            if p.name == name:
                return p
        return None


def read_interface(props: dict) -> Interface:
    """Extract the Interface from a node's full property dict."""
    sec = props.get("security-properties", {})
    if not isinstance(sec, dict):
        return Interface()
    return Interface.from_list(sec.get("interface", []))


def write_interface(props: dict, interface: Interface) -> dict:
    """Return a copy of ``props`` with the interface stored and slots regenerated.

    The returned dict carries the interface under security-properties and a
    top-level ``_slots`` hint (input/output name lists) that the caller uses to
    rebuild the node's actual SlotItems.
    """
    result = dict(props)
    sec = dict(result.get("security-properties", {}))
    sec["interface"] = interface.to_list()
    result["security-properties"] = sec
    result["_slots"] = {
        "inputs": interface.input_names(),
        "outputs": interface.output_names(),
    }
    return result


def is_subgraph(props: dict) -> bool:
    return str(props.get("class", "")) == SUBGRAPH_CLASS
