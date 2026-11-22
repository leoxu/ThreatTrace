# Edge Groups — Source Edge → Auto-Derived Edges

Builds on `doc/asset-interface-model-design.md` and
`doc/compound-asset-operation-design.md`.

## Concept
When a user draws **one** edge from a component to a security asset (landing on
an interface slot), that single **source edge** represents the *intent* — e.g.
"the process **Allocates** device memory." The interface defines how that intent is
realized in syscalls, so the tool **auto-creates one or more derived edges** —
one per syscall/step — and binds them with the source edge into a **group**.

```
User draws:     Process ──"Allocate"──▶ Device Memory (MYDEV interface)

Tool expands to a group:
    source   Process ──Allocate──▶ Device Memory          (semantic)
    derived  Process ──open──────▶ Device Memory          (syscall, role=acquire)
    derived  Process ──ioctl:MYDEV_IOC_ALLOC──▶ Device Memory  (syscall, role=operate)
```
All three share one `group_id`; the derived edges "belong to" the source edge.

## What drives the expansion
The connected **interface's operations** (from the asset descriptor). Two cases:
- The chosen operation is a **compound** (`open`→`ioctl`…) → one derived edge per
  step, ordered, carrying each step's `acquire`/`operate` role.
- The interface exposes **several mandatory operations** for an access → derived
  edge per operation.
If the operation is a single leaf syscall, the group is just the source edge
(no expansion) — the mechanism is uniform.

## Data model
Each edge gains:
```jsonc
"group": {
  "id": "grp-<uuid>",
  "role": "source" | "derived",
  "op": "Allocate",          // on source: the semantic operation
  "step": 1,                 // on derived: order within the group
  "call": "ioctl:MYDEV_IOC_ALLOC",   // on derived: the syscall
  "syscall_role": "operate"  // acquire | operate
}
```
Serialized on the edge dict; on load, edges are re-grouped by `group.id`.

## Group behaves as a unit
- **Select** the source edge → the whole group highlights (like sequences do).
- **Delete** the source → the group is deleted; deleting a derived edge alone is
  disallowed (or detaches with a warning) since it's owned by the source.
- **Endpoint move / reconnect** on the source re-routes all derived edges (they
  share the same node pair and slot).
- **Re-sync**: if the interface's operations change, a "re-expand" refreshes the
  derived edges from the interface, preserving any per-derived threats keyed by
  `call` (staleness pattern from subgraph).

## Rendering
Derived edges share the source's endpoints, so draw them as a **bundle**: a
slight parallel offset per step (fanned), or collapsed under the source edge with
an expand/collapse toggle on the source (default collapsed → shows just
"Allocate"; expanded → shows the syscall edges). Group members share a subtle
tint so the grouping is visible. Orthogonal routing applies per edge.

## Property panel
- **Source edge**: shows the operation and its ordered syscall expansion
  **read-only** (consistent with the interface being locked at instance level),
  plus a group summary ("3 edges: open → ioctl:ALLOC").
- **Derived edge**: shows its single syscall + role, read-only, with a link back
  to the source.

## Threats & conformance
- Threat generation can target the **group** (the semantic operation) or a
  specific syscall edge; threats attach by `call` so they survive re-expansion.
- Conformance (`implmodel`/`conformance`): the runtime log's `open` + `ioctl` on
  `/dev/mydev` map to the group's derived edges by `call` + interface `path` —
  the group is "fully realized" when every derived edge has runtime evidence, and
  an extra observed syscall not in the group is a violation. Grouping is exactly
  what makes "one design intent ⟷ N observed syscalls" verify cleanly.

## Auto-creation flow (where it hooks in)
On `edgeCreated` (or on drop) when `src` is a component and `dst` is a
security-asset interface slot:
1. Resolve the interface + its operation (from the connected slot / chosen
   sub-type).
2. Build the ordered step list (compound steps, or the interface's operations).
3. Mark the drawn edge as the **source** (label = operation, `group.role=source`).
4. Create one **derived** edge per step (same src slot → same interface slot),
   assign the shared `group.id`, `step`, `call`, `syscall_role`.
5. Push as a single undo command so the whole group adds/removes atomically.

## Dependencies & phasing
Full behaviour needs the **interface model** (to know what to expand into). Order:
1. **Edge-group primitive** (independent, buildable now): `group` field on edges,
   group select/move/delete, serialization, bundle rendering, undo. Expansion
   count = 1 until interfaces exist (no visible change yet, but the machinery is
   in place).
2. **Auto-expansion** once interfaces/compound-ops land: resolve interface ops on
   `edgeCreated` and create the derived edges.
3. **Panel + conformance** wiring (read-only expansion view; per-`call` threats
   and runtime matching).

## Why this design
- **Draw intent once, get syscall fidelity** — the analyst draws "Allocate"; the
  model still contains the real `open`/`ioctl` edges for threats and verification.
- **Groups keep it coherent** — the syscalls stay owned by their semantic edge, so
  select/move/delete/threat operate on the right granularity.
- **Reuses proven mechanisms** — grouping like sequences, slot binding like
  subgraph interfaces, steps like compound operations, matching like conformance.
