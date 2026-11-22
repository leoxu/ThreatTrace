from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


DEFAULT_SEQUENCE_COLOR = "#ff0000"


@dataclass
class Sequence:
    seq_id: str
    name: str
    color: str = DEFAULT_SEQUENCE_COLOR
    steps: List[str] = field(default_factory=list)       # ordered list of edge_ids
    step_props: List[dict] = field(default_factory=list) # per-step sequence properties (parallel to steps)
    # Threats this sequence owns: multi-step threats (Threat.edge_guid == "")
    # plus the step-pinned ones found while analysing it, so the sequence lists
    # everything its analysis produced.
    threat_guids: List[str] = field(default_factory=list)

    def _sync_step_props(self) -> None:
        """Ensure step_props has the same length as steps."""
        while len(self.step_props) < len(self.steps):
            self.step_props.append({})
        if len(self.step_props) > len(self.steps):
            self.step_props = self.step_props[:len(self.steps)]

    def to_dict(self) -> dict:
        self._sync_step_props()
        return {
            "name": self.name,
            "color": self.color,
            "steps": list(self.steps),
            "step_props": [dict(p) for p in self.step_props],
            "threat_guids": list(self.threat_guids),
        }

    @staticmethod
    def from_dict(seq_id: str, d: dict) -> "Sequence":
        steps = [str(s) for s in d.get("steps", [])]
        raw_props = d.get("step_props", [])
        step_props = [dict(p) if isinstance(p, dict) else {} for p in raw_props]
        obj = Sequence(
            seq_id=seq_id,
            name=str(d.get("name", "Sequence")),
            color=str(d.get("color", DEFAULT_SEQUENCE_COLOR)),
            steps=steps,
            step_props=step_props,
            threat_guids=[str(g) for g in d.get("threat_guids", [])],
        )
        obj._sync_step_props()
        return obj


SequenceRegistry = Dict[str, Sequence]


def edge_sequence_steps(
    registry: SequenceRegistry, edge_id: str
) -> List[Tuple[str, int]]:
    """Return [(seq_id, step_index), ...] for every occurrence of edge_id across all sequences."""
    result = []
    for seq_id, seq in registry.items():
        for i, eid in enumerate(seq.steps):
            if eid == edge_id:
                result.append((seq_id, i))
    return result


def new_sequence(registry: SequenceRegistry, name: str = "New Sequence") -> Sequence:
    seq_id = str(uuid.uuid4())
    seq = Sequence(seq_id=seq_id, name=name)
    registry[seq_id] = seq
    return seq
