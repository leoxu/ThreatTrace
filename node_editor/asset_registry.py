"""
Asset registry — merges asset-type descriptors into the running app.

Loads `*.asset.json` descriptors (see asset_types.py) and exposes them to the
rest of the app as: property-schema-by-class, operations-by-type, and toolbox
NodeSpecs. Legacy split templates (`<type>.json` + `<type>_props.json` +
`asset_operations.json`) keep working unchanged; descriptors are additive and
override a legacy type with the same `type` id.

Phase 2 of doc/asset-interface-impl-plan.md.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from .asset_types import AssetType, discover_asset_types
from .graphics.items import SlotSpec
from .nodes import NodeSpec, PropDef, _parse_prop_def

_ASSET_DIR = Path(__file__).parent.parent / "template" / "security" / "asset"


def _descriptor_path(type_id: str) -> Path:
    slug = re.sub(r"[^a-z0-9]+", "-", type_id.lower()).strip("-") or "asset"
    return _ASSET_DIR / f"{slug}.asset.json"


def _descriptor_for_type(type_id: str) -> Optional[Path]:
    """The file that actually defines this type, whatever it is called.

    A descriptor's filename is only a slug of its type id *by convention*, and
    several shipped ones break it (``foo-channel.asset.json`` defines type
    ``foo channel``). Resolving by filename alone meant editing such a type
    wrote a second descriptor for the same id, and deleting it deleted nothing.
    """
    if not type_id:
        return None
    for path in sorted(_ASSET_DIR.glob("*.asset.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if str(data.get("type", "")).strip() == type_id:
            return path
    return None


def descriptor_path(type_id: str) -> Path:
    """Where this type's descriptor lives, or would live if written."""
    return _descriptor_for_type(type_id) or _descriptor_path(type_id)


def descriptor_exists(type_id: str) -> bool:
    return _descriptor_for_type(type_id) is not None


def save_descriptor(at: AssetType, overwrite: bool = True) -> Path:
    """Write an asset type as a *.asset.json descriptor; return the path.

    An existing descriptor for the same type id is updated **in place**, so a
    type never ends up defined twice. ``overwrite=False`` raises
    ``FileExistsError`` rather than replacing another type's file — losing a
    colleague's asset type to a name collision is not recoverable in the app.
    """
    existing = _descriptor_for_type(at.type_id)
    if existing is not None and not overwrite:
        raise FileExistsError(str(existing))
    path = existing or _descriptor_path(at.type_id)
    path.write_text(json.dumps(at.to_descriptor(), indent=2) + "\n", encoding="utf-8")
    return path


def delete_descriptor(type_id: str) -> bool:
    """Delete the descriptor defining *type_id*. True if a file was removed."""
    path = _descriptor_for_type(type_id)
    if path is not None and path.exists():
        path.unlink()
        return True
    return False


def descriptor_asset_types() -> Dict[str, AssetType]:
    """All descriptor-defined asset types, keyed by type_id."""
    return discover_asset_types(_ASSET_DIR)


def _prop_defs_for(at: AssetType) -> Dict[str, PropDef]:
    return {k: _parse_prop_def(v) for k, v in (at.properties or {}).items()}


def descriptor_prop_defs_by_class() -> Dict[str, Dict[str, PropDef]]:
    """{"security asset <type>": {field: PropDef}} for every descriptor type.

    Merges into the app's sec-prop-defs map so a descriptor asset's property
    schema is rendered automatically — no hardcoded entry needed.
    """
    out: Dict[str, Dict[str, PropDef]] = {}
    for at in descriptor_asset_types().values():
        key = f"{at.node_class} {at.type_id}".strip()
        out[key] = _prop_defs_for(at)
    return out


def descriptor_operations_by_type() -> Dict[str, List[str]]:
    """{type_id: [operation names across all interfaces]} for descriptor types."""
    return {at.type_id: at.all_operation_names()
            for at in descriptor_asset_types().values()}


def _asset_type_to_spec(at: AssetType) -> NodeSpec:
    """Build a toolbox NodeSpec from an asset descriptor.

    Slots are generated per interface and each carries its interface's
    operations + path in its properties, so per-interface edge binding works.
    """
    sec: Dict[str, object] = {}
    for field_name, defn in (at.properties or {}).items():
        sec[field_name] = defn.get("default", "") if isinstance(defn, dict) else str(defn)
    sec.setdefault("type", at.type_id)

    props: Dict[str, object] = {
        "name": at.name, "class": at.node_class, "color": at.color,
        "text-color": "#000000", "z-order": 11, "security-properties": sec,
    }

    from .asset_types import interface_color
    inputs: List[SlotSpec] = []
    outputs: List[SlotSpec] = []
    for idx, iface in enumerate(at.interfaces):
        sp = {"interface": iface.name, "path": iface.path,
              "operations": iface.operation_names(),
              "op_steps": {op.name: op.calls() for op in iface.operations},
              "access-class": iface.access_class,
              # How the channel works, and the category's own fields, so threat
              # generation and conformance can see the mechanism without a
              # registry lookup from the scene.
              "category": iface.category,
              "category-summary": iface.category_summary(),
              "color": interface_color(iface, idx)}
        if iface.direction in ("in", "bidir"):
            inputs.append(SlotSpec(iface.name, "input", dict(sp)))
        if iface.direction in ("out", "bidir"):
            outputs.append(SlotSpec(iface.name, "output", dict(sp)))
    if not inputs and not outputs:
        inputs.append(SlotSpec("in", "input", {}))

    return NodeSpec(
        name=at.name, default_properties=props,
        inputs=inputs, outputs=outputs, shape_kind=at.shape,
        inputs_sealed=True, outputs_sealed=True,
    )


def descriptor_asset_specs() -> List[NodeSpec]:
    """Toolbox NodeSpecs for every descriptor asset type."""
    return [_asset_type_to_spec(at) for at in descriptor_asset_types().values()]
