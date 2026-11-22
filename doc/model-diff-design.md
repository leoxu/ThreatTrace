# Model Versioning / Diff — Design

## Goal
Compare two saved ThreatTrace project revisions (or the current in-memory
model against a saved file) and report what **added / removed / changed** across
**nodes, edges, threats**, and **diagrams**. Enables review cycles ("what did
this change do to the threat model?") and change-impact analysis.

No data-model change: the diff is a pure function over two project dicts.

## Matching strategy — by stable ID
Everything in the project format already has a stable identity, so we match by
ID (never by position/order):

- **Nodes**: `project["nodes"]` is `{node_id: {...}}`. Match by `node_id`.
- **Diagrams**: `project["diagrams"]` is a list of `{id, name, ...}`. Match by `id`.
- **Edges**: per diagram, `diagram["edges"]` each have `id`. Match by edge `id`
  within matched diagrams.
- **Threats**: per diagram, `diagram["threats"]` is `{guid: {...}}`. Match by `guid`.

An ID present only in the new project → **added**; only in the old →
**removed**; in both with differing content → **changed** (with a per-field
delta). Unchanged items are omitted.

## What counts as "changed" (curated, noise-free)
We compare only meaningful fields, ignoring pure layout noise (node position,
width/height, z-order, label offsets) unless the user opts into a
"layout changes" view.

- **Node**: `name`, `class`, every `security-properties` sub-key, and the set of
  input/output slot names (interface change).
- **Edge**: `type`, `sub-type`, `description`, `function`, endpoints
  (`from.node`/`from.slot`, `to.node`/`to.slot`), and label text.
- **Threat**: `title`, `category`, `priority`, `status`, `cvss_vector`,
  `mitigations`, `mitigation_sc_ids`, `owasp_categories`, `cwe_ids`,
  `nist_controls`, `description`.

Each changed field is reported as `(field, old, new)`.

## Human-readable labels
IDs are opaque, so each entry carries a label resolved from the *new* project
(falling back to old, then the raw id):
- node → `properties.name` + `(class)`
- edge → `"<src name> → <dst name>"` using node names + `type/sub-type`
- threat → `title`
- diagram → `name`

## Data structures (`node_editor/modeldiff.py`, Qt-free)
```python
@dataclass
class FieldChange: field: str; old: Any; new: Any

@dataclass
class DiffEntry:
    kind: str            # "node" | "edge" | "threat" | "diagram"
    change: str          # "added" | "removed" | "changed"
    id: str
    label: str
    diagram_id: str = "" # context for edges/threats
    diagram_name: str = ""
    fields: List[FieldChange] = []   # only for change == "changed"

@dataclass
class ModelDiff:
    entries: List[DiffEntry]
    def summary(self) -> Dict[str,int]     # counts per (kind, change)
    def is_empty(self) -> bool
```

Entry point: `diff_projects(old: dict, new: dict) -> ModelDiff`.
- Normalizes v1 (nodes-as-list) → v2 registry so old files still diff.
- Diagrams matched by id; edges/threats diffed inside each matched pair; a
  diagram present on one side only yields a diagram add/remove **plus** its
  edges/threats as adds/removes (so nothing is invisible).

## Surfaces
1. **GUI** — `node_editor/ui/diff_dialog.py`: a `DiffDialog` showing a grouped,
   color-coded tree (added=green, removed=red, changed=amber) with expandable
   per-field deltas and a summary header. Menu action **Compare With File…**
   (Tools/Edit menu): serializes the current project and diffs it against a
   chosen `.json`; a second action **Diff Two Files…** picks A and B.
2. **Headless CLI** — `diff <fileA> <fileB>` command in `run_command`, printing a
   plain-text summary (for pipelines / CI review gates). Exit-friendly:
   prints "no differences" when empty.

## Why this design
- **ID-based matching** is stable across reordering and re-layout, so the diff
  reflects real semantic change, not file churn.
- **Pure function over dicts** → unit-testable without Qt, reusable by both the
  dialog and the CLI, and trivially works on any two saved revisions.
- **Curated field set** keeps the diff signal-dense (a moved node is not a
  "change"); layout noise is opt-in.
