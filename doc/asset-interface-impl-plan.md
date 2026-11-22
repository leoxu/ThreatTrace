# Asset Interface Model — Implementation Plan

Implements `doc/asset-interface-model-design.md` (+ `asset-editor-design.md`,
`compound-asset-operation-design.md`, `edge-group-design.md`). Incremental and
backward-compatible: each phase ships and the app keeps working throughout.

## Phase 1 — Core model + descriptor loader  (Qt-free)   ← this phase
`node_editor/asset_types.py`:
- `OpStep{call, role}`, `Operation{name, steps}` (leaf = 1 step),
  `Interface{name, path, actor, direction, operations}`,
  `AssetType{name, type_id, node_class, shape, color, properties, interfaces}`.
- `load_asset_descriptor(path) -> AssetType` — reads a `*.asset.json` descriptor.
- `discover_asset_types(dir) -> {type_id: AssetType}` — scans a folder.
- `asset_type_from_legacy(name, type_id, props, operations, inputs) -> AssetType`
  — wraps a pre-interface asset as **one default interface** (name = asset name,
  operations = its `asset_operations` list, slot = its current input), so
  existing templates load unchanged.
- Slot/operation helpers: `input_slot_names()`, `output_slot_names()`,
  `interface_for_slot(name)`, `operation_names_for_slot(name)`.
- Unit test + one example descriptor (`my-memory.asset.json`).

## Phase 2 — Registry + wire-through (remove hardcoded map)
`node_editor/asset_registry.py`: merge built-in descriptors + legacy split
templates + user overrides into one `{type_id: AssetType}`. Provide
`prop_defs_by_class()`, `operations_by_type()`, `slots_for_type()`. Rewire
`app.py::_load_sec_prop_defs_by_class`, the toolbox "Security Assets" group, and
`_load_asset_operations` through it. Pure refactor + fallbacks; no UI change.

## Phase 3 — Slots-per-interface rendering + per-slot binding
- Asset nodes generate one slot per interface, labelled with the interface name
  (reuse the subgraph slot-from-ports generation).
- `property_editor._connected_asset_operations()` already prefers the connected
  slot's operations (added now) — feed it real per-slot operation lists from the
  registry so the edge sub-type is restricted to that interface's operations.
- Edge `type` set from the connected interface/slot on creation.

## Phase 4 — Property panel (read-only interface view)
Instance panel shows interfaces → operations (+ protecting controls) as a locked
expandable tree; per-instance scalar fields stay editable.

## Phase 5 — Asset Editor (authoring UI)
Manager + Type Editor: add/delete/reorder interfaces, per-interface operation
editing (leaf + compound steps), color/shape; Save writes a descriptor and
live-refreshes the registry (toolbox, schema, edge ops).

## Phase 6 — Controls-protect-interface + conformance + edge groups
- Link a security-control to an interface slot; per-interface coverage
  validation ("unprotected interface"); interface-scoped threat↔mitigation.
- Conformance matches runtime syscalls to interfaces by `path`.
- Edge-group auto-expansion (see `edge-group-design.md`) once interfaces exist.

## Descriptor format (built now)
`template/security/asset/<type>.asset.json`:
```jsonc
{
  "kind": "asset-type", "name": "Device Memory", "type": "device memory",
  "class": "security asset", "shape": "Box", "color": "#f2994a",
  "properties": { "type": {"default":"device memory","readonly":true}, "owner": "" },
  "interfaces": [
    { "name": "MYDEV device node", "path": "/dev/mydev", "actor": "user process",
      "direction": "in",
      "operations": [ {"op":"Allocate","steps":[{"call":"open","role":"acquire"},
                                                 {"call":"ioctl:MYDEV_IOC_ALLOC","role":"operate"}]},
                      "ioctl:MYDEV_IOC_FREE" ] },
    { "name": "Device virtual address", "path": "dev-va", "actor": "device hardware",
      "direction": "bidir", "operations": ["memory-read","memory-write"] }
  ]
}
```

## Compatibility guarantees
- No descriptors present → everything falls back to today's split templates +
  `asset_operations.json` (each asset = one default interface).
- Existing projects load unchanged; edges keep their slots. Re-authoring into
  named interfaces uses the subgraph rename-preserving slot sync.
