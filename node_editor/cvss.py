"""CVSS v3.1 base score calculator (FIRST.org specification)."""
from __future__ import annotations

import math


# ── metric option tables ──────────────────────────────────────────────────────

AV_OPTIONS  = [("N", "Network"),   ("A", "Adjacent"), ("L", "Local"),  ("P", "Physical")]
AC_OPTIONS  = [("L", "Low"),       ("H", "High")]
PR_OPTIONS  = [("N", "None"),      ("L", "Low"),       ("H", "High")]
UI_OPTIONS  = [("N", "None"),      ("R", "Required")]
SC_OPTIONS  = [("U", "Unchanged"), ("C", "Changed")]
CIA_OPTIONS = [("N", "None"),      ("L", "Low"),       ("H", "High")]

ALL_METRICS = {
    "av": AV_OPTIONS,
    "ac": AC_OPTIONS,
    "pr": PR_OPTIONS,
    "ui": UI_OPTIONS,
    "s":  SC_OPTIONS,
    "c":  CIA_OPTIONS,
    "i":  CIA_OPTIONS,
    "a":  CIA_OPTIONS,
}

METRIC_LABELS = {
    "av": "Attack Vector",
    "ac": "Attack Complexity",
    "pr": "Privileges Required",
    "ui": "User Interaction",
    "s":  "Scope",
    "c":  "Confidentiality",
    "i":  "Integrity",
    "a":  "Availability",
}

# ── score weights ─────────────────────────────────────────────────────────────

_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC  = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.50, "H": 0.50}   # Scope Changed
_UI  = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0,  "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    """CVSS round-up: smallest value at 1 decimal place >= input."""
    return math.ceil(value * 10) / 10


def cvss_base_score(av: str, ac: str, pr: str, ui: str,
                    s: str, c: str, i: str, a: str) -> float:
    """Return the CVSS v3.1 base score (0.0 – 10.0).

    All parameters are single-letter codes as defined in ALL_METRICS.
    Returns 0.0 if any parameter is empty or unrecognised.
    """
    try:
        AV = _AV[av]
        AC = _AC[ac]
        PR = (_PR_C if s == "C" else _PR_U)[pr]
        UI = _UI[ui]
        C_w = _CIA[c]
        I_w = _CIA[i]
        A_w = _CIA[a]
    except KeyError:
        return 0.0

    ISS = 1.0 - (1.0 - C_w) * (1.0 - I_w) * (1.0 - A_w)

    if s == "C":
        impact = 7.52 * (ISS - 0.029) - 3.25 * (ISS - 0.02) ** 15
    else:
        impact = 6.42 * ISS

    if impact <= 0:
        return 0.0

    exploitability = 8.22 * AV * AC * PR * UI

    if s == "C":
        base = min(1.08 * (impact + exploitability), 10.0)
    else:
        base = min(impact + exploitability, 10.0)

    return _roundup(base)


def cvss_severity(score: float) -> str:
    """Map a CVSS base score to a severity label."""
    if score == 0.0:  return "None"
    if score < 4.0:   return "Low"
    if score < 7.0:   return "Medium"
    if score < 9.0:   return "High"
    return "Critical"


_SEVERITY_COLORS = {
    "Critical": ("#6a1b9a", "#fff"),
    "High":     ("#c0392b", "#fff"),
    "Medium":   ("#e67e22", "#fff"),
    "Low":      ("#27ae60", "#fff"),
    "None":     ("#555555", "#fff"),
}


def cvss_severity_color(severity: str) -> tuple[str, str]:
    """Return (bg, fg) hex colors for a severity label."""
    return _SEVERITY_COLORS.get(severity, ("#555555", "#fff"))


def cvss_vector_string(av: str, ac: str, pr: str, ui: str,
                       s: str, c: str, i: str, a: str) -> str:
    """Build the CVSS v3.1 vector string."""
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


def cvss_from_vector(vector: str) -> dict:
    """Parse a CVSS v3.1 vector string into a metric dict."""
    result = {}
    for part in vector.split("/"):
        if ":" in part and not part.startswith("CVSS"):
            k, v = part.split(":", 1)
            result[k.lower()] = v
    return result
