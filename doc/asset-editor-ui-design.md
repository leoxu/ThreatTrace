# Asset Editor UI — Concrete Design

Implementation-ready UI for authoring asset types, built on the now-implemented
model (`node_editor/asset_types.py`: `AssetType` / `Interface` / `Operation`)
and registry (`node_editor/asset_registry.py`). This is Phase 5 of
`doc/asset-interface-impl-plan.md`.

## Entry points
- **Tools → Asset Types…** → the Asset Manager.
- Right-click a security-asset node on canvas → **"Save as new asset type…"**
  (pre-fills the editor from that node's class/props/slots).

## Screen 1 — Asset Manager (list + actions)
```
┌ Asset Types ─────────────────────────────────────────────┐
│  ■ #f2994a  Device Memory        device memory     [descriptor] │
│  ■ #f2994a  Shared Memory     shared memory  [built-in]   │
│  ■ #f2994a  File              file           [built-in]   │
│  …                                                        │
│                                                           │
│  [ New ]  [ Edit ]  [ Duplicate ]  [ Delete ]   [ Close ] │
└───────────────────────────────────────────────────────────┘
```
- Each row: colour swatch, display name, `type` id, source badge
  (`descriptor` = user `*.asset.json`, `built-in` = legacy template).
- **Delete/Duplicate** enabled for descriptor types; a built-in edited via
  **Edit** is saved as a descriptor **override** (built-in stays pristine;
  "Reset to built-in" removes the override).
- Populated from `asset_registry` (descriptors) + legacy specs.

## Screen 2 — Asset Type Editor (add / edit one type)
```
┌ Edit Asset Type ──────────────────────────────────────────────────────┐
│ Identity                                                               │
│   Name   [ Device Memory        ]   Type id [ device memory ]  Shape [Box ▾] │
│   Colour [■ #f2994a]                                                    │
│                                                                        │
│ Interfaces                          Operations (of selected interface) │
│  ┌────────────────────────────┐    ┌────────────────────────────────┐ │
│  │▸ MYDEV device node   in    │    │ Allocate      open → ioctl:ALLOC│ │
│  │  Device virtual address bidir │    │ Map           ioctl:MMAP → mmap │ │
│  │                            │    │ ioctl:MYDEV_IOC_FREE  (leaf)    │ │
│  │ [+ Interface] [− ] [↑][↓]  │    │ [+ Op] [+ Compound] [− ] [Edit] │ │
│  └────────────────────────────┘    └────────────────────────────────┘ │
│   Selected interface:                                                   │
│     Name [MYDEV device node]  Path [/dev/mydev]  Actor [user process]  │
│     Direction ( ) in  ( ) out  (•) bidir                               │
│                                                                        │
│ Properties (schema)                                                     │
│   name        kind        default     options                          │
│   type        choice(ro)  device memory  —                                │
│   owner       text        —           —                                │
│   size        text        —           —                                │
│   [+ Field] [− ]                                                        │
│                                                                        │
│                                            [ Save ]   [ Cancel ]       │
└────────────────────────────────────────────────────────────────────────┘
```

### Interfaces panel (left)
- List of interfaces (name + direction). **+ / − / ↑ / ↓** add/delete/reorder
  (maps to `AssetType.interfaces`). Selecting a row loads it into the fields
  below and its operations on the right.
- Interface fields: **Name**, **Path**, **Actor**, **Direction** (in/out/bidir).
  Direction drives the generated slot kind; renaming an interface renames its
  slot and preserves connected edges (subgraph `apply_interface` pattern).

### Operations panel (right, per selected interface)
- Table of `Operation`s: leaf syscalls (one line) and compounds (shown with
  their step chain `open → ioctl:…`).
- **+ Op** adds a leaf (free-text syscall, e.g. `ioctl:MYDEV_IOC_FREE`).
- **+ Compound / Edit** opens the **Operation Editor** (below).
- Restricts the sub-type dropdown of any edge connected to this interface slot.

#### Operation Editor (compound steps)
```
┌ Operation ─────────────────────────────┐
│ Name [ Allocate ]                       │
│  step  call                     role    │
│   1    open                     acquire │
│   2    ioctl:MYDEV_IOC_ALLOC    operate │
│  [+ Step] [− ] [↑][↓]        [OK][Cancel]│
└─────────────────────────────────────────┘
```
Each step = `{call, role}` (`acquire` = handle grant, `operate` = action) —
exactly `OpStep`. Role defaults from the call name (open/shm_open… → acquire).

### Properties panel (schema)
- Table of security-property fields → `PropDef`: **name**, **kind**
  (text / choice / bool), **default**, **options** (choice reveals an options
  editor; bool fixes true/false). The `type` field is present and read-only.
- Maps to `AssetType.properties` (the schema dict).

## Save flow
On **Save**:
1. Build an `AssetType` from the dialog and write its descriptor via
   `AssetType.to_descriptor()` → `<type_id>.asset.json` in the **user asset
   dir** (built-in override) or `template/security/asset/` (project built-in).
2. **Live-refresh** the registry and rebind the app — no restart:
   - rebuild `sec_prop_defs_by_class`, `asset_operations`, toolbox specs;
   - push them to `self.prop_editor` (schema + operations) and refresh the
     toolbox dock.
   - `MainWindow.reload_asset_types()` centralises this (calls the same loaders
     `__init__` uses, then re-pushes to the property editor / toolbox).
3. If the `type_id` was renamed, offer to update matching instances in the open
   project (search by old `type`), else leave them on the generic schema.

## Validation (before save)
- Non-empty, unique interface names; non-empty `type_id`; unique field names;
  each compound step has a non-empty `call`. Errors shown inline; Save blocked.

## Widgets / files
- `node_editor/ui/asset_editor.py` (new): `AssetManagerDialog`,
  `AssetTypeEditorDialog`, `OperationEditorDialog`. Reuses the interface-table
  idiom from `ui/subgraph_dialogs.py` and the prop-def rows from
  `ui/property_editor.py`.
- `node_editor/asset_registry.py`: add `user_asset_dir()`, `save_descriptor(at)`,
  `delete_descriptor(type_id)`, and make discovery scan user dir with precedence
  user > built-in.
- `node_editor/app.py`: menu action + `reload_asset_types()` live-refresh +
  "Save as new asset type…" context action.

## The two required flows
1. **Add & save**: New → fill Identity / Interfaces (+operations) / Properties →
   Save → descriptor written, registry refreshed, type appears in the toolbox
   with per-interface slots. Drag it out to place instances.
2. **Edit existing**: Edit → dialog pre-loaded from the `AssetType` → change
   interfaces / operations / fields / colour → Save (descriptor override for a
   built-in; in place for a descriptor).

## Read-only at instance level (consistency)
Authoring happens **only** here. An instance's property panel shows the
interfaces/operations as a locked, expandable view (Phase 4). This dialog is the
single place the contract is editable.

## Why this layout
- **Interfaces-first, operations-per-interface** mirrors the model exactly, so
  the dialog is a direct editor over `AssetType` with no impedance mismatch.
- **Live-refresh** makes authoring feel immediate (new type usable at once).
- **Descriptor overrides** keep built-ins pristine and every change reversible.
- **Reuses existing table/dialog idioms** (subgraph interface editor, prop-def
  rows), so it is small to build and consistent with the rest of the UI.
```
