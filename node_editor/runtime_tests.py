"""
Runtime (dynamic) verification: does the control behave that way on target?

Static verification asks whether a control exists in the source. This asks
whether the built system actually refuses what the control promises to refuse.

    control type  →  test template     (template/security/control_tests.json)
    control × covered interface  →  test spec   (placeholders filled from the model)
    spec  →  skeleton + manifest entry          (SQA runs it, captures a log)
    log + manifest  →  pass / fail / not-exercised  →  evidence on each threat link

Two decisions carry the design:

* **The template belongs to the control type.** A File Permission control is
  verified the same way everywhere — an unauthorised actor must be refused — so
  that test is written once, as data, and every instance in every model inherits
  it. Same shape as ``interface_categories.json``.
* **Expectations speak the log's vocabulary.** ``implmodel.parse_log`` yields
  records with ``op``, ``resource`` (a path or an fd's link), ``cmd`` and raw
  fields including ``ret``. An expectation is a filter over those, so matching is
  deterministic — no agent is asked to interpret a log.

Qt-free.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

_CATALOGUE = (Path(__file__).parent.parent / "template" / "security"
              / "control_tests.json")

# Outcomes. "not exercised" is not a failure: it means the test did not run, and
# a report that conflates the two teaches people to ignore it.
RESULT_PASS = "pass"
RESULT_FAIL = "fail"
RESULT_NOT_EXERCISED = "not-exercised"

KIND_NEGATIVE = "negative"      # the attempt must be refused
KIND_POSITIVE = "positive"      # the legitimate path must still work

# errno names the expectations use, resolved to the numbers a log carries.
_ERRNO = {"EPERM": 1, "ENOENT": 2, "EIO": 5, "EBADF": 9, "EACCES": 13,
          "EFAULT": 14, "EBUSY": 16, "EEXIST": 17, "ENODEV": 19, "EINVAL": 22,
          "ENOTTY": 25, "ENOSPC": 28, "ERANGE": 34, "ENOSYS": 38,
          "ECONNREFUSED": 111, "ETIMEDOUT": 110}


@dataclass
class TestTemplate:
    """How a control of one type is verified at runtime."""
    id: str
    kind: str = KIND_NEGATIVE
    title: str = ""
    intent: str = ""
    applies_to: List[str] = field(default_factory=list)   # interface categories
    requires: List[str] = field(default_factory=list)     # environment needs
    steps: List[str] = field(default_factory=list)
    expect: Dict[str, str] = field(default_factory=dict)
    evidence: str = ""

    @staticmethod
    def from_dict(d: dict) -> "TestTemplate":
        return TestTemplate(
            id=str(d.get("id", "")), kind=str(d.get("kind", KIND_NEGATIVE)),
            title=str(d.get("title", "")), intent=str(d.get("intent", "")),
            applies_to=[str(x) for x in d.get("applies_to", [])],
            requires=[str(x) for x in d.get("requires", [])],
            steps=[str(x) for x in d.get("steps", [])],
            expect={str(k): str(v) for k, v in (d.get("expect") or {}).items()},
            evidence=str(d.get("evidence", "")),
        )


_cache: Optional[Dict[str, List[TestTemplate]]] = None


def load(force: bool = False) -> Dict[str, List[TestTemplate]]:
    """Templates keyed by control type."""
    global _cache
    if _cache is not None and not force:
        return _cache
    try:
        data = json.loads(_CATALOGUE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _cache = {}
        return _cache
    out: Dict[str, List[TestTemplate]] = {}
    for entry in data.get("controls", []):
        control_type = str(entry.get("control_type", ""))
        if control_type:
            out[control_type] = [TestTemplate.from_dict(t)
                                 for t in entry.get("tests", [])]
    _cache = out
    return out


def templates_for(control_type: str) -> List[TestTemplate]:
    return list(load().get(str(control_type or ""), []))


def control_types_without_tests(types: List[str]) -> List[str]:
    known = load()
    return [t for t in types if t not in known]


@dataclass
class TestSpec:
    """One concrete test: what to run, and what the log must show."""
    test_id: str
    template_id: str
    kind: str
    title: str
    intent: str
    steps: List[str] = field(default_factory=list)
    expect: Dict[str, str] = field(default_factory=dict)
    requires: List[str] = field(default_factory=list)
    evidence: str = ""
    # what it is a test *of*
    control_id: str = ""
    control_name: str = ""
    control_type: str = ""
    requirement_id: str = ""
    asset_name: str = ""
    interface: str = ""
    path: str = ""
    category: str = ""
    operations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "test_id": self.test_id, "template": self.template_id,
            "kind": self.kind, "title": self.title, "intent": self.intent,
            "steps": list(self.steps), "expect": dict(self.expect),
            "requires": list(self.requires), "evidence": self.evidence,
            "control_id": self.control_id, "control": self.control_name,
            "control_type": self.control_type, "requirement": self.requirement_id,
            "asset": self.asset_name, "interface": self.interface,
            "path": self.path, "category": self.category,
        }

    @staticmethod
    def from_dict(d: dict) -> "TestSpec":
        return TestSpec(
            test_id=str(d.get("test_id", "")), template_id=str(d.get("template", "")),
            kind=str(d.get("kind", KIND_NEGATIVE)), title=str(d.get("title", "")),
            intent=str(d.get("intent", "")), steps=[str(s) for s in d.get("steps", [])],
            expect={str(k): str(v) for k, v in (d.get("expect") or {}).items()},
            requires=[str(r) for r in d.get("requires", [])],
            evidence=str(d.get("evidence", "")),
            control_id=str(d.get("control_id", "")), control_name=str(d.get("control", "")),
            control_type=str(d.get("control_type", "")),
            requirement_id=str(d.get("requirement", "")),
            asset_name=str(d.get("asset", "")), interface=str(d.get("interface", "")),
            path=str(d.get("path", "")), category=str(d.get("category", "")),
        )


# ── instantiation ────────────────────────────────────────────────────────────

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "x"


def _fill(text: str, values: Dict[str, str]) -> str:
    out = str(text)
    for key, value in values.items():
        out = out.replace("{" + key + "}", value)
    return out


def build_specs(scene, threats=None, sequences=None) -> List[TestSpec]:
    """A concrete test per (control definition × covered interface × template).

    Walks the same coverage as mitigation and static verification, so a test
    always targets the interface the control was placed over.
    """
    from .graphics.items import NodeItem
    from .mitigation import control_scopes, is_security_control

    specs: List[TestSpec] = []
    for item in scene.items():
        if not isinstance(item, NodeItem) or not is_security_control(item):
            continue
        for scope in control_scopes(item, scene, threats or {}, sequences):
            control = scope.control
            for slot in scope.slots:
                category = _slot_category(scene, slot)
                ioctls = _slot_ioctls(scene, slot)
                values = {
                    "path": slot.path or slot.slot_name,
                    "device": slot.path or slot.slot_name,
                    "asset": slot.asset_name,
                    "interface": slot.interface or slot.slot_name,
                    "control": control.name,
                    "config": control.description or "as specified in the model",
                    "operation": (slot.operations or ["the guarded operation"])[0],
                    "ioctl": (ioctls or ["the guarded ioctl"])[0],
                    "marker": "THREATTRACE-MARKER",
                }
                for template in templates_for(control.control_type):
                    # A file-permission test on a DMA interface is nonsense —
                    # nothing opens anything. Skip rather than emit a test that
                    # cannot be run.
                    if template.applies_to and category not in template.applies_to:
                        continue
                    specs.append(TestSpec(
                        test_id=f"{_slug(control.name)}-{_slug(slot.asset_name)}-{template.id}",
                        template_id=template.id, kind=template.kind,
                        title=_fill(template.title, values),
                        intent=_fill(template.intent, values),
                        steps=[_fill(s, values) for s in template.steps],
                        expect={k: _fill(v, values) for k, v in template.expect.items()},
                        requires=list(template.requires), evidence=template.evidence,
                        control_id=control.node_id, control_name=control.name,
                        control_type=control.control_type,
                        requirement_id=control.requirement_id,
                        asset_name=slot.asset_name,
                        interface=slot.interface or slot.slot_name,
                        path=slot.path, category=category,
                        operations=list(slot.operations),
                    ))
    return specs


def _slot_props(scene, covered) -> dict:
    from .graphics.items import NodeItem, SlotItem

    for item in scene.items():
        if not isinstance(item, SlotItem):
            continue
        owner = item.parentItem()
        if not isinstance(owner, NodeItem):
            continue
        if str(owner.properties().get("name", "")) == covered.asset_name \
                and item.name == covered.slot_name:
            return item.properties() if hasattr(item, "properties") else {}
    return {}


def _slot_category(scene, covered) -> str:
    """The channel type behind a covered interface, descriptor fallback included."""
    from .interface_categories import resolve_slot

    return resolve_slot(_slot_props(scene, covered), covered.asset_type,
                        covered.interface or covered.slot_name)


def _slot_ioctls(scene, covered) -> List[str]:
    """The concrete ioctl names behind this interface's operations."""
    out: List[str] = []
    steps = _slot_props(scene, covered).get("op_steps") or {}
    if isinstance(steps, dict):
        for calls in steps.values():
            for call in calls or []:
                for token in re.findall(r"[A-Z][A-Z0-9_]{6,}", str(call)):
                    if token not in out:
                        out.append(token)
    return out


# ── artifacts: manifest and harness skeletons ────────────────────────────────

def build_manifest(specs: List[TestSpec], model_name: str = "",
                   revision: str = "") -> dict:
    """The contract between the model and whoever runs the tests.

    Everything the matcher needs later, and nothing it does not: which test, for
    which control, and what the log must show.
    """
    from datetime import datetime

    return {
        "version": 1,
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "model": model_name,
        "revision": revision,
        "tests": [s.to_dict() for s in specs],
    }


def export_manifest(specs: List[TestSpec], out_path, **kwargs) -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(build_manifest(specs, **kwargs), indent=2) + "\n",
                        encoding="utf-8")
    return out_path


def load_manifest(path) -> List[TestSpec]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [TestSpec.from_dict(t) for t in data.get("tests", [])]


_SHELL_HEADER = """#!/bin/sh
# {title}
#
# Generated by ThreatTrace from the security model — fill in the marked steps.
# Control      : {control} ({control_type}){requirement}
# Verifies     : {intent}
# Asset        : {asset} · {interface}{path}
# Kind         : {kind} — {kind_note}
# Needs        : {requires}
#
# The run must be captured by the syscall hook; the importer matches:
#   {expect}
set -u
"""

_KIND_NOTE = {
    KIND_NEGATIVE: "this attempt MUST be refused",
    KIND_POSITIVE: "this attempt MUST succeed",
}


def render_skeleton(spec: TestSpec, harness: str = "shell") -> str:
    """A stub in the harness SQA uses. The tool stops here: it does not run tests."""
    head = _SHELL_HEADER.format(
        title=spec.title, control=spec.control_name, control_type=spec.control_type,
        requirement=f" · {spec.requirement_id}" if spec.requirement_id else "",
        intent=spec.intent, asset=spec.asset_name, interface=spec.interface,
        path=f" · {spec.path}" if spec.path else "",
        kind=spec.kind, kind_note=_KIND_NOTE.get(spec.kind, ""),
        requires=", ".join(spec.requires) or "nothing special",
        expect=json.dumps(spec.expect),
    )
    body = ["", f'TEST_ID="{spec.test_id}"', "", 'echo "== $TEST_ID"']
    for i, step in enumerate(spec.steps, 1):
        body.append("")
        body.append(f"# Step {i}: {step}")
        body.append(f"# TODO: implement step {i}")
    body += ["", "# The verdict comes from the captured log, not from this script's",
             "# exit code — the importer matches the expectation above.", ""]
    if harness == "python":
        lines = [f'"""{spec.title}\n\n{spec.intent}\n"""', "",
                 f'TEST_ID = "{spec.test_id}"', "", "def test():"]
        for i, step in enumerate(spec.steps, 1):
            lines.append(f"    # Step {i}: {step}")
            lines.append("    raise NotImplementedError")
        lines += ["", 'if __name__ == "__main__":', "    test()", ""]
        return "\n".join(lines)
    return head + "\n".join(body)


def export_skeletons(specs: List[TestSpec], out_dir, harness: str = "shell") -> List[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = {"shell": ".sh", "python": ".py"}.get(harness, ".sh")
    written: List[Path] = []
    for spec in specs:
        path = out_dir / f"{spec.test_id}{suffix}"
        path.write_text(render_skeleton(spec, harness), encoding="utf-8")
        if suffix == ".sh":
            path.chmod(0o755)
        written.append(path)
    return written


# ── matching a run ───────────────────────────────────────────────────────────

@dataclass
class TestResult:
    spec: TestSpec
    result: str = RESULT_NOT_EXERCISED
    detail: str = ""
    evidence_line: str = ""
    accepted: bool = True

    def to_dict(self) -> dict:
        return {"test_id": self.spec.test_id, "control_id": self.spec.control_id,
                "result": self.result, "detail": self.detail,
                "evidence": self.evidence_line}


def _ret_value(raw: str) -> Optional[int]:
    raw = str(raw).strip()
    if not raw:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        pass
    name = raw.lstrip("-")
    if name in _ERRNO:
        return -_ERRNO[name]
    return None


def _ret_matches(expected: str, actual: str) -> bool:
    """Compare a log's ``ret`` with an expectation.

    ``0`` means it succeeded, ``!=0`` that it failed somehow, a name or number
    that it failed *that* way. Sign is ignored for named errnos: hooks report
    ``-13`` or ``13`` depending on where they sit.
    """
    actual_value = _ret_value(actual)
    if actual_value is None:
        return False
    expected = str(expected).strip()
    if expected in ("0", "==0"):
        return actual_value == 0
    if expected in ("!=0", "nonzero", "fail", "failed"):
        return actual_value != 0
    wanted = _ret_value(expected)
    if wanted is None:
        return False
    return abs(actual_value) == abs(wanted)


def _record_matches(spec: TestSpec, record) -> bool:
    expect = spec.expect
    op = str(expect.get("op", "")).strip().lower()
    if op:
        # open64/openat all count as "open"; the hook names vary by platform.
        if not str(record.op).lower().startswith(op):
            return False
    resource = str(expect.get("resource", "")).strip()
    if resource and resource not in str(record.resource):
        return False
    cmd = str(expect.get("cmd", "")).strip()
    if cmd and cmd not in str(record.cmd) and cmd not in " ".join(record.fields.values()):
        return False
    if "ret" in expect:
        if not _ret_matches(expect["ret"], record.fields.get("ret", "")):
            return False
    return True


def _touches_target(spec: TestSpec, record) -> bool:
    """Did the run actually attempt *this action*, whatever the outcome?

    Matching the resource alone is too loose: a log full of ``open`` calls on a
    device would make every ioctl test "fail" without that ioctl ever being
    tried. The action has to have happened — same op, same command — for a wrong
    outcome to mean anything. Otherwise the honest answer is "not exercised".
    """
    resource = str(spec.expect.get("resource", "") or spec.path).strip()
    if resource and resource not in str(record.resource):
        return False
    op = str(spec.expect.get("op", "")).strip().lower()
    if op and not str(record.op).lower().startswith(op):
        return False
    cmd = str(spec.expect.get("cmd", "")).strip()
    if cmd and cmd not in str(record.cmd) and cmd not in " ".join(record.fields.values()):
        return False
    return bool(resource) or bool(op)


def match_log(specs: List[TestSpec], log_text: str,
              extra_text: str = "") -> List[TestResult]:
    """Decide each test from the captured run.

    pass  — the expected observable is present (for a negative test, the refusal
            happened);
    fail  — the interface was exercised but the opposite happened;
    not-exercised — nothing in the log touched it, so the test did not run.
    """
    from .implmodel import parse_log

    records = parse_log(log_text or "")
    results: List[TestResult] = []
    for spec in specs:
        # Text-only expectations (a marker that must be absent, a log line that
        # must be present) are checked against the supplementary capture.
        if "absent" in spec.expect:
            marker = spec.expect["absent"]
            haystack = (extra_text or "") + (log_text or "")
            found = marker in haystack
            results.append(TestResult(
                spec, RESULT_FAIL if found else RESULT_PASS,
                detail=(f"Marker {marker!r} appeared in the capture."
                        if found else f"Marker {marker!r} did not appear.")))
            continue
        if "log_contains" in spec.expect:
            needle = spec.expect["log_contains"]
            haystack = (extra_text or "") + (log_text or "")
            found = needle in haystack
            results.append(TestResult(
                spec, RESULT_PASS if found else RESULT_FAIL,
                detail=(f"Found {needle!r} in the audit capture."
                        if found else f"No audit record mentioning {needle!r}.")))
            continue

        matched = next((r for r in records if _record_matches(spec, r)), None)
        if matched is not None:
            results.append(TestResult(
                spec, RESULT_PASS,
                detail=f"{matched.op} on {matched.resource or '?'} returned "
                       f"{matched.fields.get('ret', '?')} as required.",
                evidence_line=f"{matched.op} {matched.resource} "
                              f"{matched.cmd} ret={matched.fields.get('ret', '?')}"))
            continue
        touched = [r for r in records if _touches_target(spec, r)]
        if touched:
            r = touched[0]
            results.append(TestResult(
                spec, RESULT_FAIL,
                detail=f"The interface was exercised but the expectation "
                       f"{json.dumps(spec.expect)} did not hold; saw {r.op} "
                       f"ret={r.fields.get('ret', '?')}.",
                evidence_line=f"{r.op} {r.resource} {r.cmd} "
                              f"ret={r.fields.get('ret', '?')}"))
        else:
            results.append(TestResult(
                spec, RESULT_NOT_EXERCISED,
                detail="Nothing in the log touched this interface — the test "
                       "did not run."))
    return results


def apply_results(results: List[TestResult], threats,
                  asset_of_threat=None, build: str = "",
                  manifest_hash: str = "") -> int:
    """Record runtime evidence on every (threat, control) link the tests cover.

    A failure outranks a pass: if any test for a control failed, the control is
    recorded as failed at runtime. Code that exists but does not behave is not a
    mitigation.
    """
    from . import verification as V

    by_control: Dict[str, List[TestResult]] = {}
    for r in results:
        if r.accepted:
            by_control.setdefault(r.spec.control_id, []).append(r)

    updated = 0
    for threat in threats:
        asset = asset_of_threat(threat) if asset_of_threat else ""
        for control_id in list(getattr(threat, "mitigation_sc_ids", []) or []):
            group = by_control.get(control_id)
            if not group:
                continue
            if asset:
                scoped = [r for r in group if r.spec.asset_name == asset]
                group = scoped or group
            failed = [r for r in group if r.result == RESULT_FAIL]
            passed = [r for r in group if r.result == RESULT_PASS]
            if failed:
                result, confidence = V.RESULT_FAILED, 0.9
                rationale = failed[0].detail
            elif passed:
                result, confidence = V.RESULT_VERIFIED, 0.9
                rationale = "; ".join(r.detail for r in passed[:2])
            else:
                result, confidence = V.RESULT_INSUFFICIENT, 0.0
                rationale = ("The tests for this control did not run in this "
                             "capture.")
            V.record(threat, control_id, V.PHASE_DYNAMIC, result,
                     rationale=rationale, confidence=confidence,
                     citations=[{"file": r.spec.test_id,
                                 "excerpt": r.evidence_line} for r in group
                                if r.evidence_line],
                     revision=build, source=f"runtime tests ({manifest_hash[:8]})"
                     if manifest_hash else "runtime tests")
            updated += 1
    return updated


def summarise(results: List[TestResult]) -> Dict[str, int]:
    out = {RESULT_PASS: 0, RESULT_FAIL: 0, RESULT_NOT_EXERCISED: 0}
    for r in results:
        out[r.result] = out.get(r.result, 0) + 1
    return out


# ── the report ───────────────────────────────────────────────────────────────

_RESULT_LABEL = {RESULT_PASS: "PASS", RESULT_FAIL: "FAIL",
                 RESULT_NOT_EXERCISED: "NOT EXERCISED"}


def _esc(text: str) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def build_markdown(results: List[TestResult], model_name: str = "",
                   log_name: str = "", build: str = "", generated: str = "") -> str:
    """The dynamic verification report: what ran, what held, what did not."""
    from datetime import datetime

    accepted = [r for r in results if r.accepted]
    counts = summarise(accepted)
    failed = [r for r in accepted if r.result == RESULT_FAIL]
    missing = [r for r in accepted if r.result == RESULT_NOT_EXERCISED]
    stamp = generated or datetime.now().strftime("%Y-%m-%d %H:%M")

    L: List[str] = ["# Dynamic Verification Report", ""]
    L.append(f"Generated: {stamp}")
    if model_name:
        L.append(f"Model: {model_name}")
    if log_name:
        L.append(f"Runtime capture: `{log_name}`" + (f" · build `{build}`" if build else ""))
    L += ["", "Scope: the runtime tests generated for each security control in the "
              "model, decided from the captured syscall log. A *negative* test "
              "passes when the attempt it makes is refused.", ""]

    L += ["## 1. Verdict", ""]
    if not accepted:
        L.append("**NOTHING VERIFIED** — no test result was accepted.")
    elif failed:
        L.append(f"**FAILED** — {len(failed)} test(s) show a control not behaving "
                 "as specified on target.")
    elif missing:
        L.append(f"**INCOMPLETE** — nothing failed, but {len(missing)} test(s) "
                 "never ran in this capture.")
    else:
        L.append(f"**PASS** — all {len(accepted)} test(s) held on target.")
    L += ["", "| Result | Tests |", "|---|---|"]
    for key in (RESULT_PASS, RESULT_FAIL, RESULT_NOT_EXERCISED):
        if counts.get(key):
            L.append(f"| {_RESULT_LABEL[key]} | {counts[key]} |")
    L.append("")
    if failed:
        L += ["**Failures**", ""]
        for r in failed:
            L.append(f"- **{_esc(r.spec.control_name)}** on {_esc(r.spec.asset_name)} "
                     f"— {_esc(r.spec.title)}")
        L.append("")
    if missing:
        L += ["**Not exercised** (the test did not run; this is not a pass)", ""]
        for r in missing:
            L.append(f"- {_esc(r.spec.test_id)} — needs: "
                     f"{_esc(', '.join(r.spec.requires) or 'nothing special')}")
        L.append("")

    L += ["## 2. Tests", "",
          "| Test | Control | Requirement | Asset / interface | Kind | Result |",
          "|---|---|---|---|---|---|"]
    for r in accepted:
        where = _esc(r.spec.asset_name) + (f" · {_esc(r.spec.interface)}"
                                           if r.spec.interface else "")
        L.append(f"| `{_esc(r.spec.test_id)}` | {_esc(r.spec.control_name)} | "
                 f"{_esc(r.spec.requirement_id) or '—'} | {where} | {r.spec.kind} | "
                 f"{_RESULT_LABEL[r.result]} |")
    L.append("")

    L += ["## 3. Evidence", ""]
    for index, r in enumerate(accepted, 1):
        L.append(f"### D{index:02d} — {r.spec.title}")
        L += ["", f"**Result:** {_RESULT_LABEL[r.result]}", ""]
        L += [f"**Control:** {r.spec.control_name} ({r.spec.control_type})"
              + (f" · {r.spec.requirement_id}" if r.spec.requirement_id else ""), ""]
        if r.spec.intent:
            L += [f"**Verifies:** {r.spec.intent}", ""]
        L += [f"**Expectation:** `{json.dumps(r.spec.expect)}`", ""]
        if r.detail:
            L += [f"**Observed:** {r.detail}", ""]
        if r.evidence_line:
            L += ["```", r.evidence_line, "```", ""]
        if r.spec.steps:
            L += ["**Steps**", ""]
            for step in r.spec.steps:
                L.append(f"1. {step}")
            L.append("")
    return "\n".join(L)


def export_markdown(results: List[TestResult], out_path, **kwargs) -> Path:
    out_path = Path(out_path)
    out_path.write_text(build_markdown(results, **kwargs), encoding="utf-8")
    return out_path


def export_pdf(results: List[TestResult], out_path, **kwargs) -> Path:
    from PySide6.QtGui import QTextDocument
    from PySide6.QtPrintSupport import QPrinter

    from .report import fit_document_images_to_page

    out_path = Path(out_path)
    md_path = export_markdown(results, out_path.with_suffix(".md"), **kwargs)
    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(out_path))
    doc = QTextDocument()
    doc.setMarkdown(md_path.read_text(encoding="utf-8"))
    fit_document_images_to_page(doc, printer)
    doc.print_(printer)
    return out_path
