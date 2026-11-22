#!/usr/bin/env python3
"""Convert threat-model JSON files to node-editor format.

Usage:
    python convert_threat_model.py <components.json> <connections.json> <threats.json> [output.json]

If output path is omitted, writes to stdout.
"""

import json
import sys
from collections import defaultdict
from pathlib import Path


# ---------------------------------------------------------------------------
# Shape / colour mappings
# ---------------------------------------------------------------------------

# (node-editor type, fill-color, display-category)
_ELLIPSE_TYPE_MAP = {
    "f2379495-6f3d-40c9-aa82-d42c4745effd": ("Ellipse", "#6fcf97", "Dynamic Library"),
    "GE.P":                                  ("Circle",  "#e67e22", "Process"),
    "7503a832-9d14-4064-8682-89f8f09168f5": ("Circle",  "#9b59b6", "Hardware"),
    "33adca3e-53a0-4e63-a240-439c4ab0faa5": ("Box",     "#3498db", "Data Store"),
    "GE.DS":                                 ("Box",     "#3498db", "Data Store"),
}
_ELLIPSE_DEFAULT = ("Ellipse", "#95a5a6", "Component")


def _shape_info(comp: dict) -> tuple:
    t = comp["type"]
    gid = comp.get("generic_type_id", "")
    if t == "StencilEllipse":
        return _ELLIPSE_TYPE_MAP.get(gid, _ELLIPSE_DEFAULT)
    if t == "BorderBoundary":
        return ("Boundary", "#f2994a", "Trust Boundary")
    if t == "StencilParallelLines":
        return ("Box", "#3498db", "Data Store")
    return ("Box", "#95a5a6", "Unknown")


# ---------------------------------------------------------------------------
# Main converter
# ---------------------------------------------------------------------------

def convert(components_path: str, connections_path: str, threats_path: str) -> dict:
    with open(components_path, encoding="utf-8") as f:
        comp_data = json.load(f)
    with open(connections_path, encoding="utf-8") as f:
        conn_data = json.load(f)
    with open(threats_path, encoding="utf-8") as f:
        threat_data = json.load(f)

    components: list = comp_data.get("components", comp_data) if isinstance(comp_data, dict) else comp_data
    connections: list = conn_data if isinstance(conn_data, list) else conn_data.get("connections", [])
    threats_raw: list = threat_data.get("threats", []) if isinstance(threat_data, dict) else threat_data

    # Index components by guid
    comp_by_guid = {c["guid"]: c for c in components}

    # -----------------------------------------------------------------------
    # Build slot name sets per node
    # output slots  = unique connection Names where this guid is SourceGuid
    # input slots   = unique connection Names where this guid is TargetGuid
    # -----------------------------------------------------------------------
    out_slots: dict[str, set] = defaultdict(set)
    in_slots:  dict[str, set] = defaultdict(set)
    for conn in connections:
        src = conn.get("SourceGuid", "")
        dst = conn.get("TargetGuid", "")
        name = conn.get("Name", "connection").strip()
        if src:
            out_slots[src].add(name)
        if dst:
            in_slots[dst].add(name)

    # -----------------------------------------------------------------------
    # Group threats by FlowGuid
    # -----------------------------------------------------------------------
    threats_by_flow: dict[str, list] = defaultdict(list)
    for t in threats_raw:
        val = t.get("Value", t)
        fguid = val.get("FlowGuid", "")
        if fguid:
            p = val.get("Properties", {})
            threats_by_flow[fguid].append({
                "id": val.get("Id", ""),
                "title": p.get("Title", ""),
                "category": p.get("UserThreatCategory", ""),
                "priority": p.get("Priority", ""),
                "status": p.get("Status", ""),
                "description": p.get("UserThreatDescription", ""),
                "mitigations": p.get("Mitigations", ""),
            })

    # -----------------------------------------------------------------------
    # Build nodes
    # -----------------------------------------------------------------------
    nodes_out = []
    for comp in components:
        guid = comp["guid"]
        pos_raw = comp.get("position", {})
        x = float(pos_raw.get("left", 0))
        y = float(pos_raw.get("top", 0))
        w = float(pos_raw.get("width", 180))
        h = float(pos_raw.get("height", 180))

        shape, color, category = _shape_info(comp)

        # Boundary nodes need extra padding so inner nodes fit
        is_boundary = shape == "Boundary"
        z = -10 if is_boundary else 10

        node = {
            "id": guid,
            "type": shape,
            "pos": [x, y],
            "properties": {
                "label": comp["name"],
                "name": comp["name"],
                "color": color,
                "fill": not is_boundary,
                "z-order": z,
                "parent-id": comp.get("parent_id"),
                "children": [],
                "width": w,
                "height": h,
                "category": category,
                "source-type": comp["type"],
                "generic-type-id": comp.get("generic_type_id", ""),
            },
            "inputs":  sorted(in_slots.get(guid, [])),
            "outputs": sorted(out_slots.get(guid, [])),
        }
        nodes_out.append(node)

    # -----------------------------------------------------------------------
    # Build edges and threats registry
    # -----------------------------------------------------------------------
    edges_out = []
    threats_out = {}

    for conn in connections:
        src_guid = conn.get("SourceGuid", "")
        dst_guid = conn.get("TargetGuid", "")
        name = conn.get("Name", "connection").strip()
        edge_guid = conn.get("guid", "") or str(__import__("uuid").uuid4())

        if src_guid not in comp_by_guid or dst_guid not in comp_by_guid:
            continue  # skip dangling connections

        # Create Threat objects for each threat on this connection
        threat_guids = []
        for raw in threats_by_flow.get(edge_guid, []):
            t_guid = str(__import__("uuid").uuid4())
            threats_out[t_guid] = {
                "guid": t_guid,
                "source_guid": src_guid,
                "dest_guid": dst_guid,
                "edge_guid": edge_guid,
                "title": raw.get("title", ""),
                "category": raw.get("category", ""),
                "priority": raw.get("priority", ""),
                "status": raw.get("status", ""),
                "description": raw.get("description", ""),
                "mitigations": raw.get("mitigations", ""),
            }
            threat_guids.append(t_guid)

        edges_out.append({
            "id": edge_guid,
            "from": {"node": src_guid, "slot": name},
            "to":   {"node": dst_guid, "slot": name},
            "label": {"text": name, "pos": None},
            "threat_guids": threat_guids,
        })

    return {"version": 1, "nodes": nodes_out, "edges": edges_out, "threats": threats_out}


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    if len(args) < 3:
        print(__doc__, file=sys.stderr)
        sys.exit(1)

    result = convert(args[0], args[1], args[2])

    if len(args) >= 4:
        out_path = args[3]
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)
        print(f"Written to {out_path}  ({len(result['nodes'])} nodes, {len(result['edges'])} edges)")
    else:
        json.dump(result, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
