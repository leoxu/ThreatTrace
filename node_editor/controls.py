"""
Security controls held inside a security-control container node.

Placing one circle per control made overlapping controls on the same asset
unreadable, so a control node is now a **container**: one visible circle whose
geometry defines what is protected, holding any number of control definitions:

    "security-properties": {
      "controls": [
        {"id": "…", "name": "AS Isolation",
         "control_type": "CPU Address Space Isolation",
         "description": "…", "requirement_id": "SEC-101"},
        …
      ]
    }

Each definition has its own stable id and is what a threat links to
(``Threat.mitigation_sc_ids``), so two controls in one container are judged —
and reported — separately while sharing the container's coverage.

Legacy compatibility: a node saved before this change carries `control_type` /
`description` / `requirement_id` directly. ``read_controls`` presents it as a
single control **whose id is the node id**, which is exactly what the old
threat links point at, so old models keep their mitigation links with no
rewriting.

Qt-free.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

SEC_PROPS_KEY = "security-properties"
CONTROLS_KEY = "controls"

CONTAINER_CLASS = "security control"

# Legacy per-node keys, folded into a single control definition on read.
_LEGACY_KEYS = ("control_type", "description", "requirement_id")

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "template"
_ELEMENT_DIR = _TEMPLATE_DIR / "security" / "element"


@dataclass
class ControlDef:
    """One security control inside a container."""
    id: str
    name: str
    control_type: str
    description: str = ""
    requirement_id: str = ""

    def to_dict(self) -> dict:
        return {"id": self.id, "name": self.name, "control_type": self.control_type,
                "description": self.description, "requirement_id": self.requirement_id}

    @staticmethod
    def from_dict(d: dict) -> "ControlDef":
        control_type = str(d.get("control_type", ""))
        return ControlDef(
            id=str(d.get("id") or uuid.uuid4()),
            name=str(d.get("name") or control_type or "Control"),
            control_type=control_type,
            description=str(d.get("description", "")),
            requirement_id=str(d.get("requirement_id", "")),
        )

    def label(self) -> str:
        return f"{self.name} ({self.control_type})" if self.control_type else self.name


def is_control_container(props: dict) -> bool:
    return str(props.get("class", "")).startswith(CONTAINER_CLASS)


def _sec(props: dict) -> dict:
    sec = props.get(SEC_PROPS_KEY)
    return dict(sec) if isinstance(sec, dict) else {}


def read_controls(props: dict, node_id: str = "") -> List[ControlDef]:
    """Control definitions in this container, oldest first.

    A legacy single-control node yields one definition carrying the node's id,
    so threats linked to that node stay linked.
    """
    sec = _sec(props)
    raw = sec.get(CONTROLS_KEY)
    if isinstance(raw, list) and raw:
        return [ControlDef.from_dict(c) for c in raw if isinstance(c, dict)]

    if any(str(sec.get(k, "")).strip() for k in _LEGACY_KEYS):
        return [ControlDef(
            id=node_id or str(uuid.uuid4()),
            name=str(props.get("name", "")) or str(sec.get("control_type", "Control")),
            control_type=str(sec.get("control_type", "")),
            description=str(sec.get("description", "")),
            requirement_id=str(sec.get("requirement_id", "")),
        )]
    return []


def write_controls(props: dict, controls: List[ControlDef]) -> dict:
    """Return a copy of *props* holding exactly *controls*.

    Writing the list also clears the legacy scalar keys, so a migrated node has
    one source of truth.
    """
    out = dict(props)
    sec = _sec(props)
    for key in _LEGACY_KEYS:
        sec.pop(key, None)
    sec[CONTROLS_KEY] = [c.to_dict() for c in controls]
    out[SEC_PROPS_KEY] = sec
    return out


def add_control(props: dict, control: ControlDef, node_id: str = "") -> dict:
    controls = read_controls(props, node_id)
    controls.append(control)
    return write_controls(props, controls)


def update_control(props: dict, control: ControlDef, node_id: str = "") -> dict:
    controls = read_controls(props, node_id)
    for i, existing in enumerate(controls):
        if existing.id == control.id:
            controls[i] = control
            break
    else:
        controls.append(control)
    return write_controls(props, controls)


def remove_control(props: dict, control_id: str, node_id: str = "") -> dict:
    controls = [c for c in read_controls(props, node_id) if c.id != control_id]
    return write_controls(props, controls)


def new_control(control_type: str, name: str = "") -> ControlDef:
    """A fresh control of *control_type*, pre-filled from its template."""
    return ControlDef(
        id=str(uuid.uuid4()),
        name=name or default_name(control_type) or control_type or "Control",
        control_type=control_type,
        description=default_description(control_type),
    )


def summary(props: dict, node_id: str = "") -> str:
    """Short canvas/report label: '3 controls' or the single control's name."""
    controls = read_controls(props, node_id)
    if not controls:
        return "no controls"
    if len(controls) == 1:
        return controls[0].name
    return f"{len(controls)} controls"


# ── control types, loaded from the templates ──────────────────────────────────

def _load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def control_types() -> List[str]:
    """The available control types (option list from the control props schema)."""
    data = _load_json(_ELEMENT_DIR / "security-control_props.json")
    defn = data.get(SEC_PROPS_KEY, {}).get("control_type", {})
    options = defn.get("options") if isinstance(defn, dict) else None
    return [str(o) for o in options] if isinstance(options, list) else []


def _type_defaults() -> Dict[str, Dict[str, str]]:
    """{control type: {"name":…, "description":…}} from the per-type templates.

    The per-type templates are no longer dropped on the canvas as nodes; they
    now serve as the presets behind "add a control".
    """
    out: Dict[str, Dict[str, str]] = {}
    for path in sorted(_ELEMENT_DIR.glob("security-control-*.json")):
        node = (_load_json(path).get("nodes") or [{}])[0]
        props = node.get("properties", {}) if isinstance(node, dict) else {}
        sec = props.get(SEC_PROPS_KEY, {})
        if not isinstance(sec, dict):
            continue
        ctype = str(sec.get("control_type", "")).strip()
        if ctype:
            out[ctype] = {"name": str(props.get("name", ctype)),
                          "description": str(sec.get("description", ""))}
    return out


_TYPE_DEFAULTS: Optional[Dict[str, Dict[str, str]]] = None


def _defaults_for(control_type: str) -> Dict[str, str]:
    global _TYPE_DEFAULTS
    if _TYPE_DEFAULTS is None:
        _TYPE_DEFAULTS = _type_defaults()
    return _TYPE_DEFAULTS.get(control_type, {})


def default_description(control_type: str) -> str:
    return _defaults_for(control_type).get("description", "")


def default_name(control_type: str) -> str:
    return _defaults_for(control_type).get("name", control_type)
