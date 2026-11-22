from __future__ import annotations

import random
from typing import List, Tuple, Dict

from PySide6.QtCore import QPointF


def force_directed_layout(
    nodes: List[Tuple[str, float, float]],   # (node_id, width, height)
    edges: List[Tuple[str, str]],            # (src_id, dst_id)
    iterations: int = 250,
    spring_k: float = 0.008,
    repulsion_k: float = 6000.0,
    rest_len: float = 280.0,
    damping: float = 0.82,
    seed: int = 42,
) -> Dict[str, QPointF]:
    """Return a {node_id: QPointF} layout computed by force-directed simulation."""
    if not nodes:
        return {}

    rng = random.Random(seed)
    ids = [nid for nid, _, _ in nodes]
    sizes = {nid: (w, h) for nid, w, h in nodes}

    # Random initial positions spread over a grid
    span = max(300.0, rest_len * (len(nodes) ** 0.5))
    pos: Dict[str, QPointF] = {
        nid: QPointF(rng.uniform(-span, span), rng.uniform(-span, span))
        for nid in ids
    }
    vel: Dict[str, QPointF] = {nid: QPointF(0.0, 0.0) for nid in ids}

    edge_set = [(s, d) for s, d in edges if s in pos and d in pos]

    for _ in range(iterations):
        forces: Dict[str, QPointF] = {nid: QPointF(0.0, 0.0) for nid in ids}

        # Repulsion between every pair
        for i, a in enumerate(ids):
            for b in ids[i + 1:]:
                dx = pos[b].x() - pos[a].x()
                dy = pos[b].y() - pos[a].y()
                # Use effective distance accounting for node sizes so large nodes
                # don't overlap
                min_gap = (sizes[a][0] + sizes[b][0]) * 0.5 + 40
                dist = max((dx * dx + dy * dy) ** 0.5, min_gap * 0.5)
                f = repulsion_k / (dist * dist)
                ux, uy = dx / dist, dy / dist
                forces[a] = QPointF(forces[a].x() - ux * f, forces[a].y() - uy * f)
                forces[b] = QPointF(forces[b].x() + ux * f, forces[b].y() + uy * f)

        # Spring attraction along edges
        for src, dst in edge_set:
            dx = pos[dst].x() - pos[src].x()
            dy = pos[dst].y() - pos[src].y()
            dist = max((dx * dx + dy * dy) ** 0.5, 1.0)
            f = spring_k * (dist - rest_len)
            ux, uy = dx / dist, dy / dist
            forces[src] = QPointF(forces[src].x() + ux * f, forces[src].y() + uy * f)
            forces[dst] = QPointF(forces[dst].x() - ux * f, forces[dst].y() - uy * f)

        # Integrate with damping
        for nid in ids:
            vx = (vel[nid].x() + forces[nid].x()) * damping
            vy = (vel[nid].y() + forces[nid].y()) * damping
            vel[nid] = QPointF(vx, vy)
            pos[nid] = QPointF(pos[nid].x() + vx, pos[nid].y() + vy)

    # Snap to nearest 20-unit grid and shift so top-left is at (40, 40)
    min_x = min(p.x() for p in pos.values())
    min_y = min(p.y() for p in pos.values())
    result: Dict[str, QPointF] = {}
    for nid in ids:
        x = round((pos[nid].x() - min_x + 40) / 20) * 20
        y = round((pos[nid].y() - min_y + 40) / 20) * 20
        result[nid] = QPointF(x, y)
    return result
