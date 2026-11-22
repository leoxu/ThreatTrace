"""
Verification status of a threat's mitigation.

A threat is *mitigated by* a security control once someone accepted that verdict
(see mitigation.py). That is a design-phase claim: the control is in the model
and the reviewer believes it addresses the threat. Whether the control actually
exists in the built system is a separate question, asked twice:

* **static** — an agent read the source and found the control implemented,
  citing file and line (codeverify.py);
* **dynamic** — a test written for that control ran on target and the runtime
  log shows the behaviour the control promises (not implemented yet).

So every (threat, control) link carries its own status, and the two phases are
recorded independently: passing one does not imply the other. The default is
**Not verified** — absence of evidence is never a pass.

Stored on ``Threat.verification`` as ``{control id: {"static": {...},
"dynamic": {...}}}``, so it saves, diffs and survives a round trip like the rest
of the model.

Qt-free.
"""
from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

# Per-phase outcomes.
RESULT_VERIFIED = "verified"           # the evidence supports it
RESULT_FAILED = "failed"               # the evidence contradicts it
RESULT_INSUFFICIENT = "insufficient"   # looked, could not tell
RESULT_ERROR = "error"                 # could not look

PHASE_STATIC = "static"
PHASE_DYNAMIC = "dynamic"

# What the user sees for a link, derived from the phases — never stored, so it
# cannot drift from the evidence underneath it.
LABEL_NOT_VERIFIED = "Not verified"
LABEL_SOURCE = "Verified in source code"
LABEL_RUNTIME = "Verified in runtime"
LABEL_BOTH = "Verified in source code + runtime"
LABEL_NOT_IN_SOURCE = "Not found in source code"
LABEL_FAILED_RUNTIME = "Failed in runtime"
LABEL_INCONCLUSIVE = "Evidence inconclusive"

# An agent that is unsure is not evidence. Below this, a positive verdict is
# recorded but does not count as verification.
MIN_CONFIDENCE = 0.6


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def record(threat, control_id: str, phase: str, result: str,
           rationale: str = "", confidence: float = 0.0,
           citations: Optional[List[dict]] = None, revision: str = "",
           source: str = "", at: str = "") -> dict:
    """Write one phase's outcome for one (threat, control) link.

    Returns the stored entry. Overwrites the previous outcome for that phase:
    the latest look at the code (or the latest test run) is the one that counts,
    and the provenance below says which revision it looked at.
    """
    if not control_id:
        return {}
    entry = {
        "result": result,
        "rationale": rationale,
        "confidence": round(float(confidence or 0.0), 2),
        "citations": list(citations or []),
        "revision": revision,
        "source": source,
        "at": at or _now(),
    }
    per_control = threat.verification.setdefault(str(control_id), {})
    per_control[phase] = entry
    return entry


def phase_result(threat, control_id: str, phase: str) -> str:
    """The recorded outcome for one phase, or "" when never run."""
    entry = (threat.verification.get(str(control_id)) or {}).get(phase) or {}
    return str(entry.get("result", ""))


def _counts_as_verified(threat, control_id: str, phase: str) -> bool:
    entry = (threat.verification.get(str(control_id)) or {}).get(phase) or {}
    if str(entry.get("result", "")) != RESULT_VERIFIED:
        return False
    try:
        confident = float(entry.get("confidence", 0)) >= MIN_CONFIDENCE
    except (TypeError, ValueError):
        confident = False
    # Source evidence must point at code; a claim with nothing to check is not
    # verification, whatever the agent said.
    if phase == PHASE_STATIC and not entry.get("citations"):
        return False
    return confident


def label(threat, control_id: str) -> str:
    """What to show for this link. Derived, never stored."""
    static_ok = _counts_as_verified(threat, control_id, PHASE_STATIC)
    dynamic_ok = _counts_as_verified(threat, control_id, PHASE_DYNAMIC)
    if static_ok and dynamic_ok:
        return LABEL_BOTH
    if dynamic_ok:
        return LABEL_RUNTIME
    if static_ok:
        return LABEL_SOURCE

    static = phase_result(threat, control_id, PHASE_STATIC)
    dynamic = phase_result(threat, control_id, PHASE_DYNAMIC)
    if dynamic == RESULT_FAILED:
        return LABEL_FAILED_RUNTIME
    if static == RESULT_FAILED:
        return LABEL_NOT_IN_SOURCE
    if RESULT_INSUFFICIENT in (static, dynamic) or RESULT_VERIFIED in (static, dynamic):
        # "verified" that did not clear the bar lands here too: looked, unsure.
        return LABEL_INCONCLUSIVE
    return LABEL_NOT_VERIFIED


def is_verified(threat, control_id: str) -> bool:
    return (_counts_as_verified(threat, control_id, PHASE_STATIC)
            or _counts_as_verified(threat, control_id, PHASE_DYNAMIC))


def threat_summary(threat) -> str:
    """One line for a threat with several controls linked."""
    controls = list(getattr(threat, "mitigation_sc_ids", []) or [])
    if not controls:
        return ""
    verified = [c for c in controls if is_verified(threat, c)]
    if not verified:
        return LABEL_NOT_VERIFIED
    if len(verified) == len(controls):
        labels = {label(threat, c) for c in verified}
        return LABEL_BOTH if labels == {LABEL_BOTH} else sorted(labels)[0]
    return f"{len(verified)} of {len(controls)} controls verified"


def counts(threats) -> Dict[str, int]:
    """How the mitigated links stand overall — for reports and the matrix."""
    out = {"links": 0, "verified": 0, "source": 0, "runtime": 0,
           "not_verified": 0, "contradicted": 0}
    for threat in threats:
        for control_id in (getattr(threat, "mitigation_sc_ids", []) or []):
            out["links"] += 1
            if _counts_as_verified(threat, control_id, PHASE_STATIC):
                out["source"] += 1
            if _counts_as_verified(threat, control_id, PHASE_DYNAMIC):
                out["runtime"] += 1
            if is_verified(threat, control_id):
                out["verified"] += 1
            elif phase_result(threat, control_id, PHASE_STATIC) == RESULT_FAILED \
                    or phase_result(threat, control_id, PHASE_DYNAMIC) == RESULT_FAILED:
                out["contradicted"] += 1
            else:
                out["not_verified"] += 1
    return out
