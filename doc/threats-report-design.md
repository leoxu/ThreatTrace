# Threats Report — design + TODO

**Status: Phase 1 implemented** (`node_editor/threats_report.py`,
`ui/threats_report_dialog.py`, File → *Export Threats Report…*). Phases 2–4 are
still TODO. CVSS is deliberately left out for now — scoring is priority-based
until the team settles on a formula.

## Why another report

Two reports already exist and neither is a threat register:

| Artifact | Question it answers | Audience |
|---|---|---|
| `report.py` — Threat Model | what does this diagram look like, with its threats | whoever opens the model |
| `design_report.py` — Design Verification | is this **design** ready to hand to implementation | reviewer / sign-off |
| **Threats Report** (this doc) | what is our **risk**, where is it concentrated, and what is still open | security lead, programme management, audit |

The design report is verdict-shaped and scoped to one diagram. The threats
report is **register-shaped**, ranked by risk, and covers the whole project —
what you take to a review meeting or attach to a release.

## Contents

1. **Summary** — totals: threats, mitigated, open; open threats by priority;
   CVSS severity buckets; mitigation coverage as a percentage; how many threats
   carry no compliance tag; how many carry no CVSS.
2. **Risk ranking** — the register sorted by a single risk score so the top of
   the report is the work that matters. **As built (no CVSS):** score =
   priority (High 8.0 / Medium 5.0 / Low 2.0, unset 1.0), with mitigated
   threats demoted (× 0.4) rather than hidden — a mitigated High still outranks
   an open Low. The rule is printed in the report header (`RISK_RULE`), not
   just in code. Adding CVSS later means changing `risk_score()` and that
   string; nothing else depends on the formula.
3. **Distribution** — STRIDE category × priority matrix, and open vs mitigated
   per category. Text tables first; charts are a later phase.
4. **Where the risk sits** — open risk aggregated per trust boundary, per asset
   and per asset interface, ranked. This is what makes the report actionable:
   "3 of the 5 top risks are on `Device Channel.submit`".
5. **Threat register** — one full record per threat, in risk order, with the
   same field set the design report's *Threat Details* section uses (category,
   priority, status, CVSS + vector, connection or sequence, asset, attack path,
   description, damage scenario, mitigations, applied controls with rationale
   and residual risk, CWE/NIST/OWASP, Bug/JAMA/failure-mode).
6. **Controls in force** — every security control with the threats it mitigates
   and its residual risks, so the reader sees what the mitigation claims rest on.
7. **Traceability** — threats with no compliance tag, no CVSS, no owner
   (authorizer), or no Bug/JAMA link: the housekeeping list.
8. **Change since a previous revision** (optional input) — added / removed /
   newly mitigated / re-opened threats, via `modeldiff.py`.

## Scope and filters

- **Project-wide by default**, per diagram optionally: a threat carries
  `edge_guid` / `sequence_guid`, and diagrams own edges, so a threat is
  attributed to the diagram holding its edge; sequence threats to the diagram
  holding the sequence's first step. Threats whose edge no longer exists go in
  an "orphaned" appendix rather than vanishing.
- Filters mirror the Threats panel: all / open only / mitigated only, and
  minimum priority.
- Scope, filters and the risk formula are printed in the report header, so two
  copies of the report can never be confused.

## Formats

- **PDF — the default.** This report is read, circulated and attached to
  releases, so the export dialog offers PDF first and a path with no suffix
  becomes a PDF. Rendered through the existing `QTextDocument` path, reusing
  `report.fit_document_images_to_page`. The Markdown source is written
  alongside the PDF (same stem), so the exact text stays diffable.
- **Markdown** — pick `.md` explicitly when you want only the source.
- **CSV** — the register as one row per threat (26 columns), for spreadsheets
  and trackers.

## Implementation

New `node_editor/threats_report.py`, Qt-free apart from the PNG/PDF steps, so
the gathering and ranking can be unit-tested:

```python
@dataclass
class RiskEntry:      # one threat, scored and located
    threat: Threat
    score: float
    diagram: str
    location: str           # "A → B (submit cmdbuf)" or "Sequence: … (n steps)"
    boundary: str
    asset: str
    interface: str
    controls: List[str]

@dataclass
class ThreatsReportData:
    entries: List[RiskEntry]
    generated: str
    scope: str
    filters: str
    by_priority / by_category / by_boundary / by_asset: Dict[str, int]
    untagged / uncvssed / unowned: List[RiskEntry]
    previous: Optional[DiffSummary]
```

- `collect(project, threats, sequences, scope, filters) -> ThreatsReportData`
- `build_markdown(data, image_name) -> str`
- `export_markdown/export_pdf/export_csv(...)`

## Phases

**Phase 1 — the register (the useful 80%)  ✅ done**
- [x] `threats_report.py`: `RiskEntry`, `risk_score()`, `collect()` over the
      whole project, `build_markdown()` — summary, risk ranking, full register,
      traceability gaps, plus a *Detached Threats* appendix.
- [x] File → **Export Threats Report…** (`.md` / `.pdf` / `.csv` by suffix),
      plus `MainWindow.export_threats_report_to(path, options)`.
- [x] Options dialog: scope (project / current diagram), filter (all / open /
      mitigated), minimum priority; the chosen scope, filter and risk rule are
      printed in the report header.
- [x] `collect()` reads the saved project structure (diagram `threats`, `edges`,
      `sequences` + the shared node registry), so it covers **every** diagram
      without needing each one open, and is testable headless.

**Phase 2 — where the risk sits**
- [ ] Sections 3, 4 and 6: distribution matrix, per-boundary/asset/interface
      ranking, controls in force with residual risk.
- [ ] Orphaned-threat appendix.

**Phase 3 — comparison and charts**
- [ ] Section 8 via `modeldiff.py` against a chosen previous project file.
- [ ] Charts rendered with QPainter (no new dependency): priority bars,
      category bars, coverage gauge — the same approach as
      `doc/make_intro_slide.py`.

**Phase 4 — optional AI summary**
- [ ] A short "state of the risk" paragraph written by the configured backend
      from the aggregate numbers only (never the raw threat text), behind the
      existing busy dialog with cancellation. Clearly labelled as generated.

## Risks / decisions to confirm

- **The risk formula is a policy choice.** The one above is a starting point;
  if the team already scores risk (e.g. CVSS × asset criticality), the report
  should use that instead. Whatever is chosen must be printed in the report.
- **Demoting rather than hiding mitigated threats** keeps the register honest —
  a mitigation is a claim, and the residual risk stays visible.
- **Asset attribution** for a threat on an edge between two components (no
  asset) needs a rule: attribute to the destination node and mark the asset
  column "—".
- Overlap with the design report's threat details is deliberate: they are read
  by different people at different times. The shared renderer should live in
  one place to avoid drift — extract the threat-detail block from
  `design_report.py` and use it in both.
