"""
Asset type model with interfaces (Qt-free).

An asset is one logical resource exposed through one or more *interfaces*; each
interface is a distinct access channel (device node, device VA, …) with its own
ordered operations (syscalls / compounds). See
doc/asset-interface-model-design.md and doc/asset-interface-impl-plan.md.

This module is the pure model + descriptor loader (Phase 1). Rendering, the
property panel, the asset editor and conformance build on it in later phases.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

ROLE_ACQUIRE = "acquire"
ROLE_OPERATE = "operate"

DIR_IN = "in"
DIR_OUT = "out"
DIR_BIDIR = "bidir"

ASSET_CLASS = "security asset"


@dataclass
class OpStep:
    """One syscall within an operation, tagged with its security role."""
    call: str
    role: str = ROLE_OPERATE

    def to_dict(self) -> dict:
        return {"call": self.call, "role": self.role}

    @staticmethod
    def from_json(v) -> "OpStep":
        if isinstance(v, str):
            return OpStep(call=v, role=_default_role(v))
        if isinstance(v, dict):
            call = str(v.get("call", ""))
            return OpStep(call=call, role=str(v.get("role", "") or _default_role(call)))
        return OpStep(call=str(v))


@dataclass
class Operation:
    """A named operation on an interface: one syscall (leaf) or an ordered compound."""
    name: str
    steps: List[OpStep] = field(default_factory=list)

    @property
    def is_compound(self) -> bool:
        return len(self.steps) > 1

    def calls(self) -> List[str]:
        return [s.call for s in self.steps]

    def to_dict(self):
        if not self.is_compound and self.steps and self.steps[0].call == self.name:
            return self.name          # round-trips a leaf back to a bare string
        return {"op": self.name, "steps": [s.to_dict() for s in self.steps]}

    @staticmethod
    def from_json(v) -> "Operation":
        # Leaf: "shm_open"  or  "ioctl:MYDEV_IOC_FREE"
        if isinstance(v, str):
            return Operation(name=v, steps=[OpStep(call=v, role=_default_role(v))])
        # Compound: {"op": "...", "steps": ["open", {"call":"ioctl:X","role":"operate"}]}
        if isinstance(v, dict):
            name = str(v.get("op", v.get("name", "")))
            raw = v.get("steps", [])
            steps = [OpStep.from_json(s) for s in raw] if isinstance(raw, list) else []
            if not steps and name:
                steps = [OpStep(call=name, role=_default_role(name))]
            return Operation(name=name or (steps[0].call if steps else ""), steps=steps)
        return Operation(name=str(v))


# Distinct colours cycled per interface slot when a descriptor gives none.
_INTERFACE_PALETTE = [
    "#e53935", "#1e88e5", "#43a047", "#8e24aa", "#fb8c00", "#00acc1", "#6d4c41",
]


@dataclass
class Interface:
    """One access channel to an asset."""
    name: str
    path: str = ""
    actor: str = ""
    direction: str = DIR_IN
    access_class: str = ""      # glob filter over allowed component access-classes
    color: str = ""             # slot colour (auto-assigned per interface if empty)
    operations: List[Operation] = field(default_factory=list)
    # How the channel works — an id from template/security/interface_categories.json
    # (ioctl, mmap, hypercall, bus-can, …). Orthogonal to access_class, which says
    # *who* may use it. Free-form: an unknown id loads and simply has no schema.
    category: str = ""
    # Values for the fields that category declares. A field with maps-to: path is
    # kept in ``path`` above rather than duplicated here.
    category_fields: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self):
        if self.direction not in (DIR_IN, DIR_OUT, DIR_BIDIR):
            self.direction = DIR_IN

    def category_summary(self) -> str:
        """'ioctl (device node) — /dev/x, driver: y' — for prompts and reports."""
        from .interface_categories import describe
        return describe(self.category, self.category_fields, self.path) if self.category else ""

    def operation_names(self) -> List[str]:
        return [o.name for o in self.operations]

    def allows(self, access_class: str) -> bool:
        """True if a component with ``access_class`` may connect to this interface.

        The filter is one or more comma-separated globs; empty filter = allow all.
        """
        import fnmatch
        patterns = [p.strip() for p in self.access_class.split(",") if p.strip()]
        if not patterns:
            return True
        ac = (access_class or "").strip()
        return any(fnmatch.fnmatch(ac, pat) for pat in patterns)

    def to_dict(self) -> dict:
        d = {
            "name": self.name, "path": self.path, "actor": self.actor,
            "direction": self.direction,
            "operations": [o.to_dict() for o in self.operations],
        }
        if self.access_class:
            d["access-class"] = self.access_class
        if self.color:
            d["color"] = self.color
        if self.category:
            d["category"] = self.category
        if self.category_fields:
            d["fields"] = dict(self.category_fields)
        return d

    @staticmethod
    def from_json(v: dict) -> "Interface":
        ops = v.get("operations", [])
        return Interface(
            name=str(v.get("name", "")),
            path=str(v.get("path", "")),
            actor=str(v.get("actor", "")),
            direction=str(v.get("direction", DIR_IN)),
            access_class=str(v.get("access-class", v.get("access_class", ""))),
            color=str(v.get("color", "")),
            operations=[Operation.from_json(o) for o in ops] if isinstance(ops, list) else [],
            category=str(v.get("category", "")),
            category_fields={str(k): str(val) for k, val in
                             (v.get("fields") or {}).items()},
        )


def interface_color(interface: "Interface", index: int) -> str:
    """Resolve an interface's slot colour (explicit, else from the palette)."""
    return interface.color or _INTERFACE_PALETTE[index % len(_INTERFACE_PALETTE)]


@dataclass
class AssetType:
    """A reusable asset type: identity + property schema + interfaces."""
    name: str
    type_id: str                         # the security-properties.type value (stable key)
    node_class: str = ASSET_CLASS
    shape: str = "Box"
    color: str = "#62a0ea"
    properties: dict = field(default_factory=dict)   # security-properties schema (raw)
    interfaces: List[Interface] = field(default_factory=list)

    # ── slot derivation (slots ARE interfaces) ──
    def input_slot_names(self) -> List[str]:
        return [i.name for i in self.interfaces if i.direction in (DIR_IN, DIR_BIDIR)]

    def output_slot_names(self) -> List[str]:
        return [i.name for i in self.interfaces if i.direction in (DIR_OUT, DIR_BIDIR)]

    def interface_for_slot(self, slot_name: str) -> Optional[Interface]:
        for i in self.interfaces:
            if i.name == slot_name:
                return i
        return None

    def operation_names_for_slot(self, slot_name: str) -> List[str]:
        iface = self.interface_for_slot(slot_name)
        return iface.operation_names() if iface else []

    def all_operation_names(self) -> List[str]:
        names: List[str] = []
        for i in self.interfaces:
            for n in i.operation_names():
                if n not in names:
                    names.append(n)
        return names

    def to_descriptor(self) -> dict:
        return {
            "kind": "asset-type", "name": self.name, "type": self.type_id,
            "class": self.node_class, "shape": self.shape, "color": self.color,
            "properties": self.properties,
            "interfaces": [i.to_dict() for i in self.interfaces],
        }


def _default_role(call: str) -> str:
    """Handle-acquiring syscalls are 'acquire'; everything else is 'operate'."""
    c = call.lower()
    if c in ("open", "open64", "openat", "shm_open", "socket", "connectattach") \
            or c.endswith("open") or "connectattach" in c:
        return ROLE_ACQUIRE
    return ROLE_OPERATE


# ── loading ──────────────────────────────────────────────────────────────────────
def asset_type_from_descriptor(data: dict) -> AssetType:
    ifaces = data.get("interfaces", [])
    return AssetType(
        name=str(data.get("name", "")),
        type_id=str(data.get("type", data.get("name", ""))),
        node_class=str(data.get("class", ASSET_CLASS)),
        shape=str(data.get("shape", "Box")),
        color=str(data.get("color", "#62a0ea")),
        properties=dict(data.get("properties", {})),
        interfaces=[Interface.from_json(i) for i in ifaces] if isinstance(ifaces, list) else [],
    )


def load_asset_descriptor(path) -> Optional[AssetType]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if str(data.get("kind", "")) != "asset-type":
            return None
        return asset_type_from_descriptor(data)
    except Exception:
        return None


def discover_asset_types(directory) -> Dict[str, AssetType]:
    """Load every *.asset.json descriptor in a directory, keyed by type_id."""
    out: Dict[str, AssetType] = {}
    d = Path(directory)
    if not d.is_dir():
        return out
    for p in sorted(d.glob("*.asset.json")):
        at = load_asset_descriptor(p)
        if at and at.type_id:
            out[at.type_id] = at
    return out


def asset_type_from_legacy(name: str, type_id: str, properties: dict,
                           operations: Optional[list] = None,
                           inputs: Optional[list] = None,
                           color: str = "#62a0ea", shape: str = "Box") -> AssetType:
    """Wrap a pre-interface asset as a single default interface.

    ``operations`` is the flat op list from asset_operations.json; ``inputs`` is
    the asset template's input slot names (unused for slot derivation — the
    single interface owns the one slot — but accepted for signature symmetry).
    """
    ops = [Operation.from_json(o) for o in (operations or [])]
    iface = Interface(name=name, path=str(properties.get("path", "")),
                      direction=DIR_IN, operations=ops)
    return AssetType(name=name, type_id=type_id, properties=dict(properties or {}),
                     color=color, shape=shape, interfaces=[iface])
