# Design phase verification report — design

The artifact that closes the design phase: the model as designed, the threats
identified on it, and the security controls applied to mitigate them, with a
verdict on whether the design can be handed to implementation. The
implementation-phase counterpart — does the code match this design? — is
`conformance.py` (see `impl-verification-design.md`); this report is what that
later stage verifies *against*.

## Sections

1. **Verdict** — a counts table (validation errors/warnings, threats identified /
   mitigated / open, open threats per priority, controls applied) plus
   **PASS** or **NEEDS ATTENTION** and an explicit blocking list. The design
   passes when there are no validation errors and no open High-priority threats.
   Blocking items also call out controls placed in the diagram that cover no
   asset interface — a control that mitigates nothing is nearly always a
   modelling mistake.
2. **Design** — the rendered diagram, exported as a PNG next to the report
   (reuses `report._capture_scene_png`).
3. **Security Controls Applied** — one summary table (control, type, requirement
   id, covered `asset.interface` list, connections and threats in scope, threats
   mitigated) followed by a section per control with its configuration
   description, what it is applied to, and each threat it mitigates *with the
   rationale recorded when the verdict was accepted* (`Threat.mitigation_notes`,
   including residual risk and which backend judged it).
4. **Threats Mitigated** — index table with the mitigating control named per
   threat.
5. **Open Threats** — the gap list: every threat with no control linked.
6. **Threat Details** — the full record of every threat, highest priority
   first: a field table (category, priority, status, CVSS score + severity +
   vector, connection, interaction, asset and asset property, attack path,
   authorizer, which backends identified it, CWE/NIST/OWASP tags, and
   Bug/JAMA/failure-mode traceability) followed by description, short
   description, damage scenario, justification, failure mode, recommended
   mitigations, and the applied controls with their rationale and residual
   risk. Threats carry stable ids (`T1`, `T2`, …) shown in the tables in
   sections 4 and 5 so the index and the details cross-reference.
7. **Model Validation** — the `validate_scene` issues, errors first.
8. **Attack Surface Entry Points** — boundary-crossing connections with their
   threat and open counts (`scan_attack_surface`).
9. **Review Threads** — every review note with its full history; open threads
   are also a blocking item in section 1.

## Data flow

`collect(scene, threats, diag_name, issues, source_file)` gathers a `ReportData`:
threats sorted by priority, and a `ControlSummary` per security control built
from `mitigation.build_coverage_scope` (so "covers" and "threats in scope" use
exactly the same geometry as the mitigation coverage check) plus the threats
that actually link back to that control via `mitigation_sc_ids`. Controls whose
shape covers no interface are separated into `orphan_controls`.

`build_markdown(...)` renders it; `export_markdown` writes the `.md` + `.png`
pair; `export_pdf` renders the markdown through `QTextDocument`/`QPrinter`.

Two things are needed for the diagram to come out right in the PDF, both handled
by `report.fit_document_images_to_page`:

- **Size.** `QTextDocument.print_()` lays out at 96 dpi and scales to the
  printer's resolution (1200 dpi), so an image is placed at its pixel size times
  that factor — a 2000 px diagram becomes ~25 000 device px wide and is clipped
  at the page edge. Every image fragment gets an explicit width/height in
  document units, fitted to the printable area with its aspect ratio kept, while
  the high-resolution source is still what gets printed.
- **Resolution of the file.** `QTextDocument` does not load a relative markdown
  image path by itself and prints a "broken image" placeholder, so the loaded
  `QImage` is registered with `addResource()` under the name the fragment uses.

## Entry point

File → **Export Design Verification Report…** — the format follows the chosen
suffix (`.md` or `.pdf`). Validation runs as part of the export, so the verdict
always reflects the model at export time. `MainWindow.export_design_report_to(path)`
is the scriptable form.
