# Asset Editor — enhancements

**Status: phase 1 implemented; phases 2–3 TODO.** The Asset Editor exists and works
(`node_editor/ui/asset_editor.py`, 452 lines, reached from **Tools → Asset
Types…**). This note records what it does today, where it can lose or orphan a
user's data, and a small phased set of changes. It is the detail behind the
asset-editor task in `threattrace-design.md` §12 M0.

Background: `asset-editor-design.md` (intent), `asset-editor-ui-design.md`
(screens), `asset-definition-design.md` (the descriptor format it edits).

## What exists today

| Piece | Where | State |
|---|---|---|
| **Asset Manager** — list of types with New / Edit / Duplicate / Delete | `AssetManagerDialog` | works; shows `(descriptor)` vs `(built-in)` |
| **Asset Type Editor** — identity, interfaces, operations, property schema | `AssetTypeEditorDialog` | works |
| **Operation editor** — compound operation with ordered steps and roles | `OperationEditorDialog` | works, validates name + non-empty calls |
| **Persistence** | `asset_registry.save_descriptor / delete_descriptor` | writes `template/security/asset/<slug>.asset.json` |
| **Live refresh** | `MainWindow.reload_asset_types()` | re-reads schema, operations, `asset_types_by_id`, rebuilds the toolbox |

Editing a **built-in** type is allowed and writes a descriptor that overrides it —
the intended behaviour, and the reason `Delete` refuses on built-ins.

## Gaps

Ordered by what they cost the user.

| # | Gap | Consequence |
|---|---|---|
| 1 | **Renaming `type_id` orphans instances.** `save_descriptor` writes a file named from the new id; the old descriptor stays and every existing node keeps the old `type` value. | Two types appear in the toolbox, and existing assets silently fall back to the generic `security asset` schema. `asset-editor-design.md` says "never silently orphan data" — this is the one place that promise is broken. |
| 2 | **Saving over an existing type is silent.** `New` with a `type_id` that already exists overwrites that descriptor without a word. | A built-in or a colleague's type disappears. |
| 3 | **Delete ignores usage.** No check whether the open project contains instances of the type. | Nodes left with a dangling type. |
| 4 | **Validation stops early.** Save checks name, `type_id` and interface names. It does not check duplicate property fields, duplicate operation names, colour format, or that `type_id` is not blank after slugging. | Malformed descriptors reach disk; a bad colour silently becomes the default. |
| 5 | **No "Save as new asset type…" from a node.** Promised in `asset-editor-ui-design.md`; not implemented. | Authoring a type means re-typing what is already on the canvas. |
| 6 | **Nothing shows which types are in use.** | No safe way to know what deleting will break. |
| 7 | **Colour is a hex text field; shape is Box/Circle/Ellipse only.** | Trial and error; no preview of the node the type produces. |
| 8 | **Operations cannot be reordered or duplicated**, and a leaf operation is added through a bare `QInputDialog`. | Tedious for assets with many similar operations. |
| 9 | **No revert-to-built-in.** Once a built-in is overridden, the only way back is deleting the descriptor by hand. | |
| 10 | **No import/export of a descriptor.** | Sharing a type means copying files out of the install tree. |

## Proposed changes

### Phase 1 — data safety (the M0 task) — S — **done**

Everything here prevents losing or orphaning data. No new screens.

> **Found while implementing:** a descriptor's filename is only *by convention* a
> slug of its type id, and four shipped ones break it —
> `foo-channel.asset.json` defines type `device channel`. The registry
> resolved files by slug alone, so editing such a type wrote a **second**
> descriptor for the same id, deleting it deleted nothing, and the overwrite
> guard never fired. `_descriptor_for_type()` now resolves by content and
> `save_descriptor` updates the existing file in place.

1. **Rename is a rename.** When `type_id` changes on an existing type, ask:
   *"Rename this type and update N instance(s) in the open project?"* Then
   rewrite matching nodes' `security-properties.type`, delete the old descriptor,
   and write the new one. Offer "keep both" (save-as-copy) as the alternative;
   never do both silently.
2. **Overwrite is confirmed.** `save_descriptor` gains an `overwrite=False`
   guard; the dialog asks before replacing an existing type, naming whether the
   target is a descriptor or a built-in it will shadow.
3. **Delete counts instances.** *"3 node(s) in this project use it; they will
   fall back to the generic asset schema."* Confirm or cancel.
4. **Finish the validation pass.** Duplicate property field names, duplicate
   operation names within an interface, `#rrggbb` colour format, non-blank slug.
   All shown as one message, Save blocked.
5. **Usage column in the manager**: `(descriptor · 3 in use)`.

*Done when:* renaming a type in the manager leaves no orphaned instance and no
duplicate descriptor; deleting a type in use warns first; and a descriptor with a
duplicate field name cannot be saved.

### Phase 2 — authoring speed — M

6. **"Save as new asset type…"** in the canvas context menu of a security asset:
   pre-fill identity from the node's class/name and interfaces from its slots.
7. **Colour picker** (`QColorDialog`) plus a small **preview** of the node —
   shape, colour and one slot per interface, drawn with the real `NodeItem`.
8. **Operation list ergonomics**: reorder (↑/↓), duplicate, and a proper
   add-leaf-operation row instead of a free-text prompt.
9. **Interface duplicate** (many assets have near-identical channels).

### Phase 3 — sharing and recovery — S

10. **Revert to built-in** on an overridden type (delete the descriptor, confirm).
11. **Import / export descriptor** (`.asset.json`) from the manager.

## Notes on implementation

- `save_descriptor` / `delete_descriptor` are the only writers; the guards belong
  there (Qt-free, testable) with the dialogs asking the questions.
- Instance rewriting needs the open project, so the rename step lives in
  `MainWindow._open_asset_manager`'s `_save` callback, which already has both
  the registry and the scene. Route it through the undo stack so a rename can be
  undone like any other model edit.
- Counting instances is `security-properties.type == type_id` over
  `self._project_nodes` plus the live scene — the same pair
  `_known_control_names()` already walks.
- `reload_asset_types()` already live-refreshes the toolbox, schema and operation
  lists; the rename path must call it *after* rewriting instances so the panel
  re-renders against the new schema.

## Deliberately not doing

- A general schema-migration engine. Instances keep their own values; adding a
  field is additive and removing one leaves the stored value untouched. That is
  enough, and it is what `asset-editor-design.md` already specifies.
- Editing built-in template files in place. Overriding by descriptor keeps the
  install tree pristine and the override visible.
