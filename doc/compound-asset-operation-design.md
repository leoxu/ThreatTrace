# Compound Asset Operations — Design

## Motivation
A single logical asset access is rarely one syscall. To use an asset M owned by
a KMD/ResMgr, a client typically does:

```
fd = open("/dev/M")        # acquire a handle (access grant)
ioctl(fd, CMD_A)           # operate on the handle
ioctl(fd, CMD_B)           # ...
```

So one *operation the analyst cares about* — e.g. **SubmitJob**, **MapBuffer** —
decomposes into an ordered set of syscalls. The model must let the analyst draw
the **logical operation** (one readable edge) while retaining the **syscall
composition** underneath, so it stays faithful to what the implementation
actually does.

This bridges the two phases the tool already targets:
- **Design**: analyst thinks in operations (`SubmitJob`), not syscalls.
- **Implementation** (runtime log → `implmodel.py`): produces exactly
  `{open, ioctl(SUBMIT), ioctl(WAIT)}` to `/dev/M`.
- **Conformance** (`conformance.py`): a design compound op maps to the *set* of
  observed syscall edges; an unexpected extra syscall is a violation.

## The security concept it captures
`open` and `ioctl` are different security primitives and must remain
distinguishable even inside a compound:

| Step role | Meaning | Where checks/threats attach |
|---|---|---|
| **acquire** (`open`, `shm_open`, `ConnectAttach`) | access grant → a **capability/handle (fd)** | access control, device-node perms, authN; STRIDE: Spoofing, Elevation |
| **operate** (`ioctl:CMD`, `read`, `write`, `mmap`) | action on the held handle | per-command authZ, input validation, TOCTOU; STRIDE: Tampering, EoP, DoS |

A compound records the ordered steps and tags each step's **role** so analysis
can reason about "grant then use" (e.g. TOCTOU between acquire and operate, or a
missing re-check on a later operate step).

## Data model

### 1. Operation catalog (`template/security/asset_operations.json`)
An operation entry is either a **leaf** syscall (string, unchanged) or a
**compound** object:

```jsonc
{
  "version": 2,
  "operations": {
    "shared memory": [
      "shm_open",                                  // leaf (unchanged)
      { "op": "MapBuffer",
        "steps": [
          { "call": "shm_open",              "role": "acquire" },
          { "call": "ioctl:MYDEV_IOC_CREATE","role": "operate" },
          { "call": "mmap",                  "role": "operate" }
        ] },
      { "op": "SubmitJob",
        "steps": [
          { "call": "open",         "role": "acquire" },
          { "call": "ioctl:SUBMIT", "role": "operate" },
          { "call": "ioctl:WAIT",   "role": "operate" }
        ] }
    ]
  }
}
```
Backward-compatible: existing string entries keep working; `version` bumps to 2
but a v1 file (all-strings) loads unchanged. A shorthand `"steps": ["open",
"ioctl:SUBMIT"]` (plain strings) is accepted, defaulting role by call name
(`open`/`*open*`/`ConnectAttach` → acquire, else operate).

### 2. Edge storage
A compound-op edge keeps the existing `type = "Asset Operation"` and sets
`sub-type` to the compound name (`SubmitJob`). The decomposition rides along in
edge properties so nothing is lost on save/load or when the catalog changes:

```jsonc
"properties": {
  "type": "Asset Operation",
  "sub-type": "SubmitJob",
  "op-steps": ["open", "ioctl:SUBMIT", "ioctl:WAIT"]   // resolved at bind time
}
```
`op-steps` is authoritative for verification; the catalog is the source used to
populate it. If the catalog later changes, a "re-sync steps" action refreshes
`op-steps` (mirrors the subgraph staleness pattern).

### 3. Core module (`node_editor/asset_ops.py`, Qt-free)
```python
@dataclass class OpStep: call: str; role: str            # "acquire" | "operate"
@dataclass class AssetOp: name: str; steps: List[OpStep]; is_compound: bool
def load_operations(path) -> Dict[str, List[AssetOp]]     # by asset type
def resolve_steps(asset_type, op_name) -> List[str]       # for op-steps
def acquire_steps(op) / operate_steps(op)                 # role queries
```
Pure logic → unit-testable; reused by the property editor, conformance, and any
CLI.

## UI

- **Sub-type dropdown** (`_SearchableSubTypeRow`): when the edge is bound to an
  asset, the curated list shows leaf ops **and** compound ops (compounds shown
  with a small "▸" and a tooltip listing their steps). Selecting a compound sets
  `sub-type` + `op-steps`.
- **Property panel (Classification section)**: under a compound sub-type, show a
  read-only, ordered **Steps** sub-list (`acquire`/`operate` tinted), plus a
  "Sync steps from catalog" button when `op-steps` drifts from the catalog.
- Leaf operations render exactly as today (no steps sub-list).

## Conformance integration (`conformance.py`)
Today an impl asset-op edge maps to a design asset-op edge by (matched
component, matched asset). Extend the interaction check for compound design
edges:

1. Collect the impl syscall edges from the same matched component → matched asset
   (the runtime already emits `open`, `ioctl` with cmd sets — see `implmodel`).
2. Expand the design edge's `op-steps` to expected calls.
3. Compare:
   - every expected step observed → **conform** ("SubmitJob fully realized").
   - expected step **not** observed → **unrealized** (Low) — dead sub-op.
   - observed syscall to M **not** in any design op's steps → **violation**
     (undocumented sub-operation; High if it's an `ioctl:cmd` never modeled).
This turns the "asset-op-x = {open, ioctl, …}" question into a precise
design-vs-runtime check at the syscall granularity.

## Relationship to Sequences (existing feature)
- **Compound op** = ordered syscalls of **one operation on one asset** (a
  transaction over a single handle). Lives on **one edge**.
- **Sequence** = ordered **edges across multiple assets/components** (a
  multi-step attack chain / end-to-end flow). Unchanged.

They compose: a Sequence step can be a compound-op edge. Use a compound when the
steps share one handle to one asset; use a Sequence when the flow spans assets.

## Modeling the handle (optional, when in scope)
When fd leak / inheritance across `fork` / retention after privilege-drop is in
scope, model the **handle as a derived capability asset** ("M handle"): the
`acquire` step *produces* it, `operate` steps *consume* it. The compound's
`acquire`/`operate` roles are exactly the hook for auto-generating this handle
node later. Out of scope for v1 (roles are recorded; handle materialization is a
follow-up).

## Phasing
1. **Catalog + core module** (`asset_ops.json` v2, `asset_ops.py`) + tests. ← first
2. **Edge storage + sub-type dropdown + property-panel Steps sub-list.**
3. **Conformance step-level check** (compound design op ⟷ runtime syscall set).
4. **Handle-as-capability** materialization (optional).

## Why this design
- **One edge = one logical operation** keeps diagrams readable while the syscall
  truth is preserved as metadata — the analyst's mental model and the
  implementation reality both fit, with no lossy abstraction.
- **Backward-compatible catalog** — leaf ops and v1 files are untouched.
- **Role-tagged steps** carry the real security distinction (grant vs use), which
  is what threat generation and TOCTOU analysis need.
- **Closes the loop to verification** — compound steps are precisely what the
  runtime log yields, so conformance gets syscall-level precision for free.
