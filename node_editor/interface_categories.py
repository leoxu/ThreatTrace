"""
Predefined interface categories — *how* an asset's access channel works.

An interface already says **where** it is (`path`), **who** may use it
(`access-class`) and **what** it exposes (operations). The category says how the
channel works — ioctl, mmap, hypercall, CAN — and that is what decides which
threats are worth asking about, which controls could plausibly apply, and how a
line in a runtime log maps back to the model.

Categories live in ``template/security/interface_categories.json`` so the set can
grow without code changes. Each declares its own **fields**: an ioctl channel
needs a device node, a CAN channel needs an interface and message ids. A field
with ``maps-to: path`` is stored in the interface's existing ``path`` rather than
duplicated beside it.

An unknown category id is tolerated — a model authored against a newer catalogue
still loads, it just has no schema to check.

Qt-free.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_CATALOGUE = (Path(__file__).parent.parent / "template" / "security"
              / "interface_categories.json")


@dataclass
class CategoryField:
    """One field a category asks for."""
    name: str
    label: str = ""
    required: bool = False
    maps_to: str = ""          # "path" → stored in Interface.path, not in fields
    placeholder: str = ""
    pattern: str = ""
    help: str = ""

    @staticmethod
    def from_dict(d: dict) -> "CategoryField":
        return CategoryField(
            name=str(d.get("name", "")),
            label=str(d.get("label", "")) or str(d.get("name", "")),
            required=bool(d.get("required", False)),
            maps_to=str(d.get("maps-to", "")),
            placeholder=str(d.get("placeholder", "")),
            pattern=str(d.get("pattern", "")),
            help=str(d.get("help", "")),
        )


@dataclass
class Category:
    id: str
    label: str = ""
    group: str = ""
    description: str = ""
    access_class: str = ""
    fields: List[CategoryField] = field(default_factory=list)
    default_operations: List[str] = field(default_factory=list)
    threat_hints: List[str] = field(default_factory=list)
    relevant_controls: List[str] = field(default_factory=list)

    @staticmethod
    def from_dict(d: dict) -> "Category":
        return Category(
            id=str(d.get("id", "")),
            label=str(d.get("label", "")) or str(d.get("id", "")),
            group=str(d.get("group", "")),
            description=str(d.get("description", "")),
            access_class=str(d.get("access-class", "")),
            fields=[CategoryField.from_dict(f) for f in d.get("fields", [])],
            default_operations=[str(o) for o in d.get("default-operations", [])],
            threat_hints=[str(t) for t in d.get("threat-hints", [])],
            relevant_controls=[str(c) for c in d.get("relevant-controls", [])],
        )

    def field(self, name: str) -> Optional[CategoryField]:
        return next((f for f in self.fields if f.name == name), None)

    @property
    def path_field(self) -> Optional[CategoryField]:
        """The field stored in the interface's ``path``, if the category has one."""
        return next((f for f in self.fields if f.maps_to == "path"), None)


_cache: Optional[Dict[str, Category]] = None


def load(force: bool = False) -> Dict[str, Category]:
    """The catalogue, keyed by id. Missing or broken file → empty catalogue."""
    global _cache
    if _cache is not None and not force:
        return _cache
    try:
        data = json.loads(_CATALOGUE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _cache = {}
        return _cache
    cats = [Category.from_dict(c) for c in data.get("categories", [])]
    _cache = {c.id: c for c in cats if c.id}
    return _cache


def all_categories() -> List[Category]:
    """Catalogue order, which groups related mechanisms together."""
    return list(load().values())


def get(category_id: str) -> Optional[Category]:
    return load().get(str(category_id or "").strip())


def label_for(category_id: str) -> str:
    cat = get(category_id)
    return cat.label if cat else str(category_id or "")


def describe(category_id: str, values: Dict[str, str], path: str = "") -> str:
    """One line for a prompt or a report: 'ioctl (device node) — /dev/x, driver=y'."""
    cat = get(category_id)
    if cat is None:
        return str(category_id or "")
    parts = []
    for f in cat.fields:
        value = path if f.maps_to == "path" else str(values.get(f.name, "")).strip()
        if value:
            parts.append(value if f.maps_to == "path" else f"{f.label}: {value}")
    return cat.label + (" — " + ", ".join(parts) if parts else "")


def problems(category_id: str, values: Dict[str, str], path: str = "") -> List[str]:
    """What is missing or malformed for this category. Empty when it is fine.

    An unknown category is not an error: the catalogue can be ahead of, or behind,
    the model being edited.
    """
    cat = get(category_id)
    if cat is None:
        return []
    out: List[str] = []
    for f in cat.fields:
        value = (path if f.maps_to == "path" else str(values.get(f.name, ""))).strip()
        if f.required and not value:
            out.append(f"{cat.label}: '{f.label}' is required.")
            continue
        if value and f.pattern and not re.match(f.pattern, value):
            out.append(f"{cat.label}: '{f.label}' should match {f.pattern} (got '{value}').")
    return out


def resolve_slot(slot_props: Dict, asset_type: str = "",
                 interface_name: str = "") -> str:
    """The category id behind a slot, falling back to the asset's descriptor.

    Models saved before categories existed carry no ``category`` on their slots.
    Re-authoring a model must not be the price of a feature, so when the slot is
    silent the asset type's descriptor is asked instead — the interface name on
    the slot is the key.
    """
    category = str((slot_props or {}).get("category", "") or "").strip()
    if category:
        return category
    interface_name = str(interface_name
                         or (slot_props or {}).get("interface", "") or "").strip()
    asset_type = str(asset_type or "").strip()
    if not (asset_type and interface_name):
        return ""
    try:
        from .asset_registry import descriptor_asset_types
        at = descriptor_asset_types().get(asset_type)
    except Exception:                       # a category is not worth a crash
        return ""
    if at is None:
        return ""
    iface = next((i for i in at.interfaces if i.name == interface_name), None)
    return str(getattr(iface, "category", "") or "") if iface else ""


def prune(category_id: str, values: Dict[str, str]) -> Dict[str, str]:
    """Drop values that this category does not declare, and empty ones.

    Keeps a descriptor from accumulating leftovers when the category is changed.
    """
    cat = get(category_id)
    if cat is None:
        return {k: v for k, v in (values or {}).items() if str(v).strip()}
    keep = {f.name for f in cat.fields if f.maps_to != "path"}
    return {k: str(v) for k, v in (values or {}).items()
            if k in keep and str(v).strip()}
