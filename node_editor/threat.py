from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class Threat:
    """A single security threat linking a source node, destination node, and edge."""
    source_guid: str
    dest_guid: str
    edge_guid: str                 # "" for a threat that belongs to a sequence
    # Set when the threat came from (or belongs to) a sequence. A threat with
    # both guids was found during sequence analysis but pinned to one step: it
    # belongs to that edge and is also listed under the sequence.
    sequence_guid: str = ""
    guid: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    category: str = ""
    priority: str = ""
    status: str = ""
    description: str = ""
    short_description: str = ""
    justification: str = ""
    interaction: str = ""
    authorizer: str = ""
    bug_jira_link: str = ""
    jama_link: str = ""
    damage_scenario: str = ""
    attack_path: str = ""
    asset: str = ""
    asset_property: str = ""
    mitigations: str = ""
    failure_mode_id: str = ""
    failure_mode_description: str = ""
    duplicate_threat: str = ""
    ai_backends: List[str] = field(default_factory=list)
    mitigation_sc_ids: List[str] = field(default_factory=list)
    # security-control node id -> why that control mitigates this threat
    # (written by the mitigation coverage analysis, see mitigation.py)
    mitigation_notes: Dict[str, str] = field(default_factory=dict)
    # control id -> {"static": {...}, "dynamic": {...}} — whether each linked
    # control was found in the source and seen at runtime. Design-phase
    # mitigation is a claim; this is the evidence for it. See verification.py.
    verification: Dict[str, dict] = field(default_factory=dict)
    # What this threat was produced under, so an update can tell whether the
    # connection changed (re-generate) or only the controls did (re-assess).
    # See threat_sync.py; empty means "recorded before this existed".
    context_hash: str = ""
    controls_hash: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    nist_controls: List[str] = field(default_factory=list)
    owasp_categories: List[str] = field(default_factory=list)
    # CVSS v3.1 fields (single-letter codes; empty = not set)
    cvss_av: str = ""
    cvss_ac: str = ""
    cvss_pr: str = ""
    cvss_ui: str = ""
    cvss_s:  str = ""
    cvss_c:  str = ""
    cvss_i:  str = ""
    cvss_a:  str = ""
    cvss_vector: str = ""

    def to_dict(self) -> dict:
        return {
            "guid": self.guid,
            "source_guid": self.source_guid,
            "dest_guid": self.dest_guid,
            "edge_guid": self.edge_guid,
            "sequence_guid": self.sequence_guid,
            "title": self.title,
            "category": self.category,
            "priority": self.priority,
            "status": self.status,
            "description": self.description,
            "short_description": self.short_description,
            "justification": self.justification,
            "interaction": self.interaction,
            "authorizer": self.authorizer,
            "bug_jira_link": self.bug_jira_link,
            "jama_link": self.jama_link,
            "damage_scenario": self.damage_scenario,
            "attack_path": self.attack_path,
            "asset": self.asset,
            "asset_property": self.asset_property,
            "mitigations": self.mitigations,
            "failure_mode_id": self.failure_mode_id,
            "failure_mode_description": self.failure_mode_description,
            "duplicate_threat": self.duplicate_threat,
            "ai_backends": list(self.ai_backends),
            "mitigation_sc_ids": list(self.mitigation_sc_ids),
            "mitigation_notes": dict(self.mitigation_notes),
            "verification": {k: dict(v) for k, v in self.verification.items()},
            "context_hash": self.context_hash,
            "controls_hash": self.controls_hash,
            "cwe_ids": list(self.cwe_ids),
            "nist_controls": list(self.nist_controls),
            "owasp_categories": list(self.owasp_categories),
            "cvss_av": self.cvss_av,
            "cvss_ac": self.cvss_ac,
            "cvss_pr": self.cvss_pr,
            "cvss_ui": self.cvss_ui,
            "cvss_s":  self.cvss_s,
            "cvss_c":  self.cvss_c,
            "cvss_i":  self.cvss_i,
            "cvss_a":  self.cvss_a,
            "cvss_vector": self.cvss_vector,
        }

    @staticmethod
    def from_dict(d: dict) -> "Threat":
        return Threat(
            guid=d.get("guid", str(uuid.uuid4())),
            source_guid=d.get("source_guid", ""),
            dest_guid=d.get("dest_guid", ""),
            edge_guid=d.get("edge_guid", ""),
            sequence_guid=d.get("sequence_guid", ""),
            title=d.get("title", ""),
            category=d.get("category", ""),
            priority=d.get("priority", ""),
            status=d.get("status", ""),
            description=d.get("description", ""),
            short_description=d.get("short_description", ""),
            justification=d.get("justification", ""),
            interaction=d.get("interaction", ""),
            authorizer=d.get("authorizer", ""),
            bug_jira_link=d.get("bug_jira_link", ""),
            jama_link=d.get("jama_link", ""),
            damage_scenario=d.get("damage_scenario", ""),
            attack_path=d.get("attack_path", ""),
            asset=d.get("asset", ""),
            asset_property=d.get("asset_property", ""),
            mitigations=d.get("mitigations", ""),
            failure_mode_id=d.get("failure_mode_id", ""),
            failure_mode_description=d.get("failure_mode_description", ""),
            duplicate_threat=d.get("duplicate_threat", ""),
            ai_backends=[
                str(item).strip()
                for item in d.get("ai_backends", [])
                if str(item).strip()
            ],
            mitigation_sc_ids=list(d.get("mitigation_sc_ids", [])),
            mitigation_notes={
                str(k): str(v) for k, v in (d.get("mitigation_notes") or {}).items()
            },
            verification={str(k): dict(v) for k, v in
                          (d.get("verification") or {}).items()
                          if isinstance(v, dict)},
            context_hash=d.get("context_hash", ""),
            controls_hash=d.get("controls_hash", ""),
            cwe_ids=list(d.get("cwe_ids", [])),
            nist_controls=list(d.get("nist_controls", [])),
            owasp_categories=list(d.get("owasp_categories", [])),
            cvss_av=d.get("cvss_av", ""),
            cvss_ac=d.get("cvss_ac", ""),
            cvss_pr=d.get("cvss_pr", ""),
            cvss_ui=d.get("cvss_ui", ""),
            cvss_s=d.get("cvss_s",  ""),
            cvss_c=d.get("cvss_c",  ""),
            cvss_i=d.get("cvss_i",  ""),
            cvss_a=d.get("cvss_a",  ""),
            cvss_vector=d.get("cvss_vector", ""),
        )


# guid → Threat
ThreatRegistry = Dict[str, "Threat"]
