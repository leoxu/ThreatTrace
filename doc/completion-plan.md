# Completion Plan

## What the project is

A **software security architecture diagramming tool** for embedded/driver/RTOS engineers (QNX, Linux KMD, device drivers). It goes deeper than standard DFD tools — modeling dynamic libraries inside processes, kernel modules, IPC paths — and annotates those diagrams with threat data and call-path sequences.

---

## What's already solid

- **Canvas**: full PySide6 scene with bezier edges, slot-connect drag, multi-select, resize handles, breadcrumb drill-down into composite sub-diagrams
- **Node types**: all security shapes — Process, Host App, Dynamic Library, QNX ResMgr, Linux KMD, Trust Boundary, Proxy, asset types
- **Property editor**: live-updating dock for nodes, edges, slots, labels; security-property combo boxes
- **Sequences**: step list, per-step properties, pick mode, colored overlays, numbered badges on edges
- **Serialization**: full round-trip JSON including threats, sequences, composites
- **Import tools**: `merge_proxy.py` (sub-diagram merging)
- **Parent-child containment**: nodes auto-assign parent-id when dragged inside a container

---

## Gaps, by priority

### P1 — Blocking: no way to author threats

The `Threat` model (title, category, priority, status, description, mitigations) is complete and displays in the property editor. But there is **zero UI to create, edit, or delete a threat**. Threats only enter the system via imported files. This is the single biggest functional hole.

**Work needed:**
- Threat create/edit dialog (modal form: title, STRIDE category dropdown, priority, status, description, mitigations textarea)
- "Add Threat" button on edge property panel
- Edit / delete buttons on each `_ThreatCard`
- Threat list panel or dock (optional but useful for overview)

### P2 — Serious UX gaps

| Gap | Notes |
|---|---|
| No **Ctrl+S / Save** | Only "Save As" exists — every save prompts for filename |
| No **undo/redo** | Deletes and moves are irreversible |
| `Browse…` in Composite uses **save dialog** instead of open dialog | Wrong `QFileDialog` mode |
| `process_props.json` and `dynamic-library_props.json` templates **never loaded** | Process and dynamic-library nodes get no schema-driven dropdowns, unlike assets |

### P3 — Missing infrastructure

| Gap | Notes |
|---|---|
| No **report export** | No PDF/HTML/CSV threat report output |
| No **grid / snap** | Pure free-drag positioning |
| No **keyboard shortcuts** | Only Delete/Backspace and Escape work |
| Old toolbar duplicates toolbox sidebar | Dead UI clutter |

### P4 — Design-doc features not yet built

`doc/security-model-design.md` describes a `palettes/` system with control node types (Preventive/Detective/Corrective Controls, External Actor, Data Asset) and a richer schema. That vocabulary and palette format does not exist yet.

---

## Recommended implementation order

### Phase 1 — Threat authoring (completes the core workflow)

1. `ThreatDialog` — modal form widget for create/edit (title, STRIDE category dropdown, priority, status, description, mitigations)
2. "Add Threat" button in edge property panel → opens `ThreatDialog`
3. Edit / delete buttons on each `_ThreatCard`
4. Wire new/edited threats back into `ThreatRegistry` and mark scene dirty

### Phase 2 — Essential UX

5. Ctrl+S Save — track current file path in `MainWindow`, skip dialog if already saved
6. `QUndoStack` — wrap node add/delete/move and edge add/delete in `QUndoCommand`; add Ctrl+Z / Ctrl+Y
7. Fix `Browse…` dialog mode in Composite property editor (one-line fix)
8. Wire `process_props.json` and `dynamic-library_props.json` into `_load_sec_prop_defs_by_class()`

### Phase 3 — Report export

9. Threat report generator — iterate all edges, collect their `threat_guids`, output structured HTML or PDF (e.g. via `jinja2` + `weasyprint`), or plain CSV

### Phase 4 — Polish

10. Remove legacy toolbar (or repurpose as a quick-access strip for common actions)
11. Optional grid / snap toggle
12. Keyboard shortcuts (Ctrl+N, Ctrl+O, Ctrl+A select-all, arrow-key nudge)
