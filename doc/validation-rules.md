# Diagram Validation Rules

Triggered via **Tools → Validate Diagram** (Ctrl+Shift+V). Each rule produces an
**Error** (must fix) or a **Warning** (should review). The dialog's **Select**
button highlights the offending node or edge in the canvas.

---

## R1 — Unconnected Edge · Error

An edge exists in the scene but is missing its source or destination slot
connection. This can happen when a node is deleted after an edge was connected to
it, or when an edge is dragged from the toolbox but never attached.

**Fix:** Connect both ends of the edge, or delete it.

---

## R2 — Node Outside Trust Boundary · Error

A security node of one of the following classes is not visually contained inside
any Trust Boundary shape:

- `security host-app`
- `security process`
- `security dynamic-library`
- `security linux-kmd`
- `security qnx-resmgr`
- `security proxy`

Every executable component must be assigned to a trust domain so that
cross-boundary data flows can be identified and threat-modelled correctly.

**Fix:** Drag the node inside an existing Trust Boundary, or add a new Trust
Boundary that covers it.

---

## R3 — Func Call / IPC Call Crosses Trust Boundary · Warning

An edge of type `func call` or `ipc call` connects nodes that sit in **different**
trust boundaries (or one inside and one outside any boundary).

Direct function calls across a privilege boundary are unusual and may indicate a
missing abstraction layer, a privilege escalation path, or a modelling mistake.

**Fix:** Verify the call is intentional. If it crosses a genuine privilege
boundary, consider replacing it with an explicit IPC edge type and ensure the
corresponding trust-boundary threats are captured.

---

## R4 — Ioctl Call Within Same Boundary · Warning

An edge of type `ioctl call` connects two nodes that are **both** inside the same
trust boundary (or both outside any boundary).

Ioctl calls target kernel-mode drivers (`security linux-kmd`) or QNX resource
managers (`security qnx-resmgr`), which should reside in a separate, more
privileged trust boundary from the user-space caller.

**Fix:** Place the kernel/resmgr node in a separate trust boundary from its
caller, or re-examine whether the edge type is correct.

---

## R5 — Dangling Slot Reference · Error

An edge's source or destination slot is set, but its parent item is not a
`NodeItem`. This indicates internal model corruption — the slot's owning node was
removed without properly cleaning up the edge.

**Fix:** Delete the edge and recreate it between valid nodes.

---

## R6 — Isolated Node · Warning

A security node (any node whose class starts with `security`) has no edges at
all. Isolated nodes contribute nothing to the data-flow diagram and will never
appear in sequence diagrams or threat generation.

**Not flagged:** a **security control** or a **trust boundary**. Neither is ever
connected by an edge — a control is placed *over* the asset interfaces it
protects and its scope is read from that geometry, and a boundary *contains*
nodes rather than linking to them. Having no edges is their normal state, so
warning about it trained people to ignore the rule.

**Fix:** Connect the node to the diagram or remove it if it is a leftover.

---

## R7 — Duplicate Edge · Warning

Two edges share exactly the same source slot and destination slot. The second edge
is redundant; having duplicates can inflate threat counts and confuse sequence
modelling.

**Fix:** Delete the redundant edge.

---

## Configuration

The sets of node classes and edge types that drive rules R2–R4 are defined as
module-level constants in [`node_editor/validation.py`](../node_editor/validation.py):

| Constant | Used by |
|---|---|
| `_MUST_BE_IN_BOUNDARY` | R2 |
| `_MUST_CROSS_BOUNDARY` | R4 |
| `_MUST_NOT_CROSS_BOUNDARY` | R3 |
