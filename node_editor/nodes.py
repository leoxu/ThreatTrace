from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .graphics.items import NodeItem, SlotSpec

_TEMPLATE_DIR = Path(__file__).parent.parent / "template"
_PROJECT_ROOT = Path(__file__).parent.parent


@dataclass
class PropDef:
    """Definition of a single template property: its default value and optional combo choices."""
    default: str = ""
    options: List[str] = field(default_factory=list)

    @property
    def has_options(self) -> bool:
        return bool(self.options)


def _parse_prop_def(value) -> PropDef:
    """Parse a property definition from JSON.

    Accepts two formats:
      - Plain string:  "some default"
      - Object:        {"default": "val", "options": ["a", "b"]}
    """
    if isinstance(value, str):
        return PropDef(default=value)
    if isinstance(value, dict):
        return PropDef(
            default=str(value.get("default", "")),
            options=[str(o) for o in value.get("options", [])],
        )
    return PropDef()


@dataclass
class NodeSpec:
    name: str
    default_properties: Dict[str, object] = field(default_factory=dict)
    inputs: List[SlotSpec] = field(default_factory=list)
    outputs: List[SlotSpec] = field(default_factory=list)
    shape_kind: str = ""  # base shape type; defaults to name
    inputs_sealed: bool = False   # user cannot add new input slots
    outputs_sealed: bool = False  # user cannot add new output slots

    def __post_init__(self):
        if not self.shape_kind:
            self.shape_kind = self.name


@dataclass
class EdgeSpec:
    name: str = ""
    prop_defs: Dict[str, PropDef] = field(default_factory=dict)

    def default_properties(self) -> Dict[str, str]:
        return {k: v.default for k, v in self.prop_defs.items()}


_ABSENT = object()  # sentinel: key was not present in the merged template


def _make_slots(raw: list, kind: str) -> List[SlotSpec]:
    result = []
    for entry in raw:
        if isinstance(entry, str):
            result.append(SlotSpec(entry, kind))
        elif isinstance(entry, dict):
            result.append(SlotSpec(entry["name"], kind, entry.get("properties", {})))
    return result


def _default_slots(kind: str, shape_kind: str) -> List[SlotSpec]:
    """Return shape-based default slots when the template doesn't specify any."""
    prefix = "in" if kind == "input" else "out"
    if shape_kind in ("Circle", "Ellipse"):
        count = 4
    elif shape_kind in ("Box", "Composite", "Subgraph", "Diamond", "Hexagon", "Triangle"):
        count = 2
    else:
        return []
    names = [prefix] + [f"{prefix}-{i}" for i in range(2, count + 1)]
    return [SlotSpec(n, kind) for n in names]


def create_node(spec: NodeSpec, node_id: str | None = None) -> NodeItem:
    from copy import deepcopy

    from .graphics.items import ensure_owner_slot
    # Deep copy: nested values (security-properties, a review thread's comment
    # list) must not be shared between every node created from one template.
    props = deepcopy(spec.default_properties)
    props.setdefault("name", spec.name)
    node = NodeItem(spec.name, props, spec.inputs, spec.outputs, shape_kind=spec.shape_kind, node_id=node_id,
                    inputs_sealed=spec.inputs_sealed, outputs_sealed=spec.outputs_sealed)
    ensure_owner_slot(node)
    return node


def _merge_node_data(path: Path) -> dict | None:
    """Recursively resolve 'extends' and return a fully merged raw node dict."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        node_data = dict(data["nodes"][0])
        if "extends" not in node_data:
            return node_data
        base_path = _PROJECT_ROOT / node_data.pop("extends")
        base = _merge_node_data(base_path)
        if base is None:
            return None
        # Deep-merge properties; all other keys: derived wins
        merged_props = {**base.get("properties", {}), **node_data.get("properties", {})}
        merged = {**base, **node_data, "properties": merged_props}
        return merged
    except Exception:
        return None


def load_template(path: Path) -> NodeSpec | None:
    """Load a NodeSpec from a template file, resolving extends chains."""
    node_data = _merge_node_data(path)
    if node_data is None or "type" not in node_data:
        return None

    shape_kind = node_data["type"]
    props = dict(node_data.get("properties", {}))
    props.setdefault("name", shape_kind)

    name = props["name"]
    inputs_raw = node_data.get("inputs", _ABSENT)
    outputs_raw = node_data.get("outputs", _ABSENT)
    inputs  = _make_slots(inputs_raw,  "input")  if inputs_raw  is not _ABSENT else _default_slots("input",  shape_kind)
    outputs = _make_slots(outputs_raw, "output") if outputs_raw is not _ABSENT else _default_slots("output", shape_kind)
    inputs_sealed = bool(node_data.get("sealed_inputs", False))
    outputs_sealed = bool(node_data.get("sealed_outputs", False))
    return NodeSpec(name=name, default_properties=props, inputs=inputs, outputs=outputs,
                    shape_kind=shape_kind, inputs_sealed=inputs_sealed, outputs_sealed=outputs_sealed)


def load_edge_template(path: Path) -> Optional[EdgeSpec]:
    """Load an EdgeSpec from a template file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        name = str(data.get("name", path.stem))
        edges = data.get("edges", [])
        if not edges:
            return None
        prop_defs = {k: _parse_prop_def(v) for k, v in edges[0].get("properties", {}).items()}
        return EdgeSpec(name=name, prop_defs=prop_defs)
    except Exception:
        return None


def load_sec_prop_defs(path: Path) -> Optional[Dict[str, PropDef]]:
    """Load security-property PropDefs from a *_props.json file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        sec = data.get("security-properties", {})
        if not sec:
            return None
        return {k: _parse_prop_def(v) for k, v in sec.items()}
    except Exception:
        return None


def load_slot_template(path: Path) -> Optional[Dict[str, PropDef]]:
    """Load slot PropDefs from a template file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        slots = data.get("slots", [])
        if not slots:
            return None
        return {k: _parse_prop_def(v) for k, v in slots[0].get("properties", {}).items()}
    except Exception:
        return None


def load_toolbox() -> List[tuple]:
    """Load toolbox categories from template/toolbox.json.

    Returns a list of (category_name, [NodeSpec, ...]) tuples in file order.
    Missing or unresolvable template entries are silently skipped.
    """
    toolbox_path = _TEMPLATE_DIR / "toolbox.json"
    try:
        data = json.loads(toolbox_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    result: List[tuple] = []
    for cat in data.get("categories", []):
        name = str(cat.get("name", ""))
        specs = []
        for node_path in cat.get("nodes", []):
            spec = load_template(_PROJECT_ROOT / node_path)
            if spec is not None:
                specs.append(spec)
        for edge_path in cat.get("edges", []):
            spec = load_edge_template(_PROJECT_ROOT / edge_path)
            if spec is not None:
                specs.append(spec)
        if specs:
            result.append((name, specs))
    return result


def builtin_nodes() -> Dict[str, NodeSpec]:
    nodes: Dict[str, NodeSpec] = {}
    for path in sorted(_TEMPLATE_DIR.glob("*.json")):
        spec = load_template(path)
        if spec is not None:
            nodes[spec.name] = spec
    return nodes


def security_nodes() -> Dict[str, NodeSpec]:
    nodes: Dict[str, NodeSpec] = {}
    for path in sorted((_TEMPLATE_DIR / "security").glob("*.json")):
        spec = load_template(path)
        if spec is not None:
            nodes[spec.name] = spec
    return nodes
