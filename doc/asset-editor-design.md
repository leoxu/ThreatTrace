# Asset Editor — Design

## Goal
Let users **define and manage asset types** from the UI instead of hand-editing
JSON — (1) add a new asset type and save it so it appears in the toolbox, and
(2) edit an existing asset type's fields/operations/appearance. An "asset type"
is the reusable template (e.g. *Shared Memory*, *Socket*), not a single node on
the canvas (those are already edited in the property panel).

## Why it's needed (today's friction)
Adding one asset type currently means editing **five** places by hand:
1. `template/security/asset/<type>.json` — the node template (shape, class, default props).
2. `template/security/asset/<type>_props.json` — the security-property schema.
3. `template/toolbox.json` — a toolbox entry.
4. `template/security/asset_operations.json` — the operation list.
5. `app.py::_load_sec_prop_defs_by_class()` — a **hardcoded** `class → props-file` map.

Step 5 is a code change, so a non-developer cannot add an asset type at all.

## Core idea: one descriptor + a registry (kill the hardcoded map)
Introduce a single, self-contained **asset-type descriptor** that carries
everything about a type, and a **registry** that auto-discovers descriptors from
a folder — so a new type "just works" with no code edits.

`template/security/asset/<type>.asset.json`:
```jsonc
{
  "kind": "asset-type",
  "name": "Shared Memory",
  "class": "security asset",          // node class (always "security asset" for assets)
  "type": "shared memory",            // security-properties.type value (the identity)
  "shape": "Box",
  "color": "#f2994a",
  "slots": { "inputs": ["in", "in-2", "in-3", "in-4"], "outputs": [] },
  "properties": {                     // security-properties schema (field -> PropDef)
    "type":       { "default": "shared memory", "readonly": true },
    "name":       "",
    "owner":      "",
    "mode":       { "default": "0600", "options": ["0400","0440","0600","0640","0660"] },
    "size":       "",
    "encryption": { "default": "none", "options": ["none","encrypted"] }
  },
  "operations": [                     // reuses the compound-operation format
    "shm_open", "shm_unlink", "mmap", "ftruncate", "shmctl",
    { "op": "MapBuffer", "steps": [ {"call":"shm_open","role":"acquire"},
                                    {"call":"mmap","role":"operate"} ] }
  ]
}
```
This descriptor is a superset of today's split files, so a loader can build all
of: the `NodeSpec` (template), the `sec_prop_defs` (schema), the toolbox entry,
and the operation catalog — from one file.

**Registry** (`node_editor/asset_registry.py`, Qt-free):
```python
def discover_asset_types(dir) -> Dict[str, AssetType]      # by 'type' value
def prop_defs_by_class() -> Dict[str, Dict[str, PropDef]]  # replaces the hardcoded map
def operations_by_type() -> Dict[str, List[AssetOp]]       # replaces asset_operations.json load
def as_toolbox_specs() -> List[NodeSpec]                    # for the toolbox "Security Assets" group
```
Backward-compatible: if no `*.asset.json` descriptors are present, fall back to
the existing split `*.json`/`*_props.json` files + `asset_operations.json`, so
nothing breaks during migration. `_load_sec_prop_defs_by_class()` becomes a thin
wrapper over `prop_defs_by_class()` (built-in element props like security-control
stay as-is).

## UI

### Asset Manager (list + actions)
**Tools → Asset Types…** opens a manager listing all discovered asset types with
their color swatch, name, and `type` id. Buttons: **New**, **Edit**, **Duplicate**,
**Delete** (delete/duplicate only for user descriptors, not built-ins unless
"Allow editing built-ins" is on — edits then save a user override copy).

### Asset Type Editor (add / edit one type)
A dialog with sections:

- **Identity**: display name, `type` id (the security-properties.type value —
  the stable key; renaming warns it won't match existing instances), shape
  (Box/Circle/…), color swatch.
- **Properties** (table): one row per security-property field —
  `name | kind (text | choice | bool) | default | options`. "choice" reveals the
  options editor; "bool" fixes options to true/false. Reorderable; the `type`
  field is present and read-only. This is the schema instances render from.
- **Operations** (table): leaf syscalls and compound operations (reuses the
  compound-operation editor from `doc/compound-asset-operation-design.md` —
  each compound has ordered `acquire`/`operate` steps). Restricts an
  asset-connected edge's sub-type dropdown.
- **Slots**: default input/output port names.

**Save** writes `<type>.asset.json` to the user asset dir and **live-refreshes**
the registry so the new/edited type immediately appears in the toolbox, the
property panel schema, and the edge sub-type list — no restart.

### Where the "New" action can be reached from
- The Asset Manager **New** button, and
- A right-click **"Save as new asset type…"** on any security-asset node on the
  canvas — pre-fills the editor from that node's current class/props/slots, so a
  user can turn a customized instance into a reusable type in one step (covers
  requirement 1 naturally).

## Add vs Edit (the two required flows)
1. **Add & save**: New → fill Identity/Properties/Operations/Slots → Save →
   descriptor written, registry refreshed, type appears in toolbox. Drag it out
   to place instances.
2. **Edit existing**: Edit → editor pre-loaded from the descriptor → change
   fields/options/operations/color → Save (in place). For built-ins, Save writes
   a user-dir override that shadows the built-in (built-ins stay pristine).

## Editing & existing instances (migration)
Instances store their own `security-properties` values, so editing a type's
schema is mostly additive-safe:
- **Added field** → appears with its default on next render; stored instances are
  unaffected until edited.
- **Removed field** → hidden in the editor; existing instance values are kept in
  the node's dict (not destroyed) unless the user opts into "prune removed
  fields on save".
- **Renamed `type` id** → offer to update matching instances in the open project
  (search by old `type` value) or leave them (they'll fall back to the generic
  `security asset` schema). Never silently orphan data.

## Persistence & precedence
- **Built-in** descriptors: `template/security/asset/*.asset.json` (shipped).
- **User** descriptors: a user dir (e.g. `~/.threattrace/assets/` or a project-
  local `assets/`), which **override** built-ins with the same `type`.
- Precedence: user > project-local > built-in. The manager shows the source and
  lets you "Reset to built-in" (delete the override).

## Phasing
1. **Registry + descriptor loader** (`asset_registry.py`, `*.asset.json` schema)
   with fallback to today's split files; rewire `_load_sec_prop_defs_by_class`,
   toolbox assets, and operations through it. No UI yet — pure refactor + tests.
2. **Asset Manager + Asset Type Editor** dialogs; Save writes a descriptor and
   live-refreshes; "Save as new asset type…" from a node. ← the requested UI.
3. **Compound-operation editing** inside the Operations table (depends on the
   compound-asset-operation feature).
4. **Instance migration helpers** (rename/prune with project update).

## Why this design
- **One descriptor + registry** removes the hardcoded code path, so users (not
  just developers) can add asset types — the crux of requirement 1.
- **Backward-compatible** — existing split templates keep working; migration to
  descriptors is optional and incremental.
- **Reuses existing primitives** — `PropDef` for the schema, the compound-op
  format for operations, `NodeSpec`/toolbox for placement — no parallel system.
- **User overrides shadow built-ins**, so shipping updates never clobber a user's
  customizations and "reset to built-in" is always available.
```
