#!/usr/bin/env python3
"""
Merge proxy nodes in a diagram JSON file.

Proxy nodes (class "security proxy") are placeholders that reference a
sub-diagram via their security-properties.source field.  This script
replaces each proxy node with the nodes and edges from the referenced
sub-diagram.

Edge reconnection rule:
  An edge in the source diagram that connects TO proxy input slot <S> is
  redirected to the first node in the replacement diagram that also has
  an input slot named <S>.  Edges with no matching slot in the replacement
  are dropped.

Usage:
  python merge_proxy.py source.json [-o output.json] [proxy_id=replacement.json ...]

  proxy_id=replacement.json  Override the source file for a specific proxy
                             node (identified by its id).  If omitted, the
                             source is read from the proxy's
                             security-properties.source property.

Examples:
  # Use source paths stored in each proxy node's properties
  python merge_proxy.py diagram.json -o merged.json

  # Override the source for one specific proxy
  python merge_proxy.py diagram.json -o merged.json abc-123=subgraph.json
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
import uuid
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_proxy(node: dict) -> bool:
    return node.get("properties", {}).get("class") == "security proxy"


def _proxy_source(node: dict) -> str:
    return (
        node.get("properties", {})
        .get("security-properties", {})
        .get("source", "")
    )


def _remap_nodes(nodes: List[dict], edges: List[dict]) -> Tuple[List[dict], List[dict], Dict[str, str]]:
    """Assign fresh UUIDs to all nodes and update edge references accordingly.

    Returns (new_nodes, new_edges, old_id -> new_id mapping).
    """
    id_map: Dict[str, str] = {}
    new_nodes = []
    for node in nodes:
        old_id = node.get("id", "")
        new_id = str(uuid.uuid4())
        id_map[old_id] = new_id
        n = copy.deepcopy(node)
        n["id"] = new_id
        new_nodes.append(n)

    new_edges = []
    for edge in edges:
        e = copy.deepcopy(edge)
        e["id"] = str(uuid.uuid4())
        if "from" in e:
            e["from"]["node"] = id_map.get(e["from"]["node"], e["from"]["node"])
        if "to" in e:
            e["to"]["node"] = id_map.get(e["to"]["node"], e["to"]["node"])
        # preserve any properties stored on the edge
        new_edges.append(e)

    return new_nodes, new_edges, id_map


def _offset_positions(nodes: List[dict], dx: float, dy: float) -> None:
    """Shift all node positions by (dx, dy) in-place."""
    for node in nodes:
        pos = node.get("pos", [0.0, 0.0])
        node["pos"] = [pos[0] + dx, pos[1] + dy]


def _slot_names(entries: list) -> List[str]:
    """Extract slot names from a list that may contain strings or {"name": ...} dicts."""
    return [e["name"] if isinstance(e, dict) else e for e in entries]


def _find_slot_owner(nodes: List[dict], slot_name: str, slot_kind: str) -> Optional[str]:
    """Return the id of the first node that has a slot with the given name and kind."""
    key = "inputs" if slot_kind == "input" else "outputs"
    for node in nodes:
        if slot_name in _slot_names(node.get(key, [])):
            return node["id"]
    return None


# ---------------------------------------------------------------------------
# Core merge
# ---------------------------------------------------------------------------

def merge(source: dict, overrides: Dict[str, str], base_dir: Path) -> dict:
    """Return a new diagram with all proxy nodes replaced.

    overrides: mapping of proxy node id -> replacement file path (str).
    base_dir:  directory used to resolve relative source paths.
    """
    result = copy.deepcopy(source)
    nodes: List[dict] = result.setdefault("nodes", [])
    edges: List[dict] = result.setdefault("edges", [])

    # Collect proxy nodes (iterate over a snapshot; we modify nodes in-place)
    proxies = [n for n in nodes if _is_proxy(n)]

    for proxy in proxies:
        proxy_id: str = proxy["id"]
        proxy_pos: List[float] = proxy.get("pos", [0.0, 0.0])

        # Determine the replacement file
        src_str = overrides.get(proxy_id) or _proxy_source(proxy)
        if not src_str:
            print(
                f"[warn] proxy {proxy_id!r} has no source — skipping",
                file=sys.stderr,
            )
            continue

        src_path = Path(src_str)
        if not src_path.is_absolute():
            src_path = base_dir / src_path

        if not src_path.exists():
            print(
                f"[warn] replacement file {src_path} not found for proxy {proxy_id!r} — skipping",
                file=sys.stderr,
            )
            continue

        replacement = _load(src_path)
        rep_nodes: List[dict] = copy.deepcopy(replacement.get("nodes", []))
        rep_edges: List[dict] = copy.deepcopy(replacement.get("edges", []))

        # Fresh UUIDs so replacement ids never clash with source ids
        rep_nodes, rep_edges, _id_map = _remap_nodes(rep_nodes, rep_edges)

        # Position replacement nodes around the proxy's location
        _offset_positions(rep_nodes, proxy_pos[0], proxy_pos[1])

        # Redirect edges that point TO this proxy
        edges_to_proxy = [e for e in edges if e.get("to", {}).get("node") == proxy_id]
        redirected_edges: List[dict] = []
        for edge in edges_to_proxy:
            slot_name: str = edge["to"]["slot"]
            target_node_id = _find_slot_owner(rep_nodes, slot_name, "input")
            if target_node_id is None:
                print(
                    f"[warn] no node in {src_path.name} has input slot {slot_name!r} "
                    f"— dropping edge {edge.get('id', '?')}",
                    file=sys.stderr,
                )
                continue
            new_edge = copy.deepcopy(edge)
            new_edge["id"] = str(uuid.uuid4())
            new_edge["to"]["node"] = target_node_id
            redirected_edges.append(new_edge)

        # Remove proxy node and its incoming edges from the diagram
        nodes[:] = [n for n in nodes if n["id"] != proxy_id]
        edges[:] = [e for e in edges if e.get("to", {}).get("node") != proxy_id]

        # Insert replacement content
        nodes.extend(rep_nodes)
        edges.extend(rep_edges)
        edges.extend(redirected_edges)

        print(
            f"[info] replaced proxy {proxy_id!r} with {len(rep_nodes)} node(s) "
            f"from {src_path.name}",
            file=sys.stderr,
        )

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("source", help="Source diagram JSON file")
    parser.add_argument(
        "-o", "--output", default="-",
        help="Output file (default: stdout)",
    )
    parser.add_argument(
        "overrides", nargs="*", metavar="proxy_id=replacement.json",
        help="Override replacement file for a specific proxy node id",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    source_path = Path(args.source)
    if not source_path.exists():
        print(f"error: source file {source_path} not found", file=sys.stderr)
        sys.exit(1)

    source = _load(source_path)

    # Parse proxy_id=file overrides
    overrides: Dict[str, str] = {}
    for token in args.overrides:
        if "=" not in token:
            print(f"error: override must be in the form proxy_id=file.json, got {token!r}", file=sys.stderr)
            sys.exit(1)
        proxy_id, _, file_path = token.partition("=")
        overrides[proxy_id.strip()] = file_path.strip()

    result = merge(source, overrides, base_dir=source_path.parent)

    output_text = json.dumps(result, indent=2)
    if args.output == "-":
        print(output_text)
    else:
        Path(args.output).write_text(output_text, encoding="utf-8")
        print(f"[info] wrote {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
