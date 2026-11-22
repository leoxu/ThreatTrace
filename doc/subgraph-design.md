# Subgraph (Placeholder → Import → Replace) Feature Design

## 1. Motivation

Large threat models are built by several people. A lead architect lays out the
top-level system but does not yet know the internals of every component. They
want to drop a **placeholder** for "the device driver stack" or "the crypto
service", agree on its **interface** (how it connects to the rest of the
model), and hand that contract to whoever owns that component. That owner
builds a detailed model in isolation, saves it as a normal project `.json`, and
later the placeholder is **replaced** by the real model — without breaking any
of the connections already drawn around it.

This is a "black box now, fill in later" workflow. The unit of work is a
**Subgraph**.

## 2. Existing building blocks we reuse

- **Composite node** (`shape_kind == "Composite"`) already drills into a
  separate JSON via its `source` property and `navigate_into()` / a scene
  stack. The Subgraph feature generalizes this: Composite is "link and drill
  in"; Subgraph adds a *typed interface contract* and an *import-and-replace*
  operation.
- **Project format v2**: `{version, nodes: {id: {...}}, diagrams: [{id, name,
  placements, edges, threats, sequences}]}`. A subgraph's contents are just a
  normal project file, so it is authored with the exact same tool, validated
  the same way, and can itself contain further subgraphs.
- **Slots** (`inputs`/`outputs`) are the natural anchor for the interface: the
  placeholder's slots ARE its ports.
- **Trust boundaries** already express "everything inside this box"; a replaced
  subgraph is naturally wrapped in a boundary.

## 3. Core concept: the Interface Contract

A subgraph is defined by its **interface** — an ordered list of named
**ports**. A port is one slot on the placeholder node:

```
port := { "name": str, "dir": "in" | "out", "expects": <optional class/type hint> }
```

The interface is the *contract* between the outer model and the component
owner. Everything about replacement is driven by matching port names, so the
contract must be explicit and stable.

Two sides must agree on the same port names:

- **Outer model**: the placeholder node exposes ports as its slots. External
  edges connect to those slots.
- **Inner model** (the component's own `.json`): it marks certain nodes/slots
  as **boundary interface points** that publish the same port names. We do this
  with a small marker on a node's `security-properties`:
  `"interface-port": "<port name>"`. A node carrying that marker is the inner
  endpoint that the corresponding outer edge should attach to after
  replacement.

Matching is **by port name**, direction-checked. Anything unmatched is surfaced
as a binding warning rather than silently dropped.

## 4. Data model

### 4.1 The placeholder node

A new template `template/security/element/subgraph.json`, `class == "security
subgraph"`, `shape_kind == "Subgraph"` (rendered like a Composite box with a
distinct "stacked pages" glyph and a status badge). Its properties:

```jsonc
{
  "name": "Driver Stack",
  "class": "security subgraph",
  "security-properties": {
    "state": "unbound",          // unbound | bound | stale | missing
    "source": "",                // path to the imported component .json (relative to project)
    "source-hash": "",           // sha256 of the file at bind time (staleness detection)
    "bound-at": "",              // ISO timestamp
    "interface": [               // the contract — the single source of truth for ports
      { "name": "ctrl", "dir": "in",  "expects": "security process" },
      { "name": "irq",  "dir": "out", "expects": "" }
    ]
  },
  "inputs":  ["ctrl"],           // slots are generated from interface ports (dir==in)
  "outputs": ["irq"]             // dir==out
}
```

Slots are always regenerated from `interface`, so the ports and the visible
connection points can never drift apart.

### 4.2 States

- **unbound** — placeholder only; no source assigned. Drawn dashed/greyed.
- **bound** — a source file is linked and its hash matches. Drawn solid with a
  "▣" badge; double-click drills in (read-only reference view).
- **stale** — source file changed on disk since bind (hash mismatch). Drawn
  with an orange badge; user can re-sync.
- **missing** — source path no longer resolves. Red badge; connections
  preserved, contents unavailable.

State is derived on load/refresh, so it self-heals.

## 5. Two replacement modes

The user picks per subgraph (a `mode` in security-properties):

### Mode A — Reference (default, non-destructive)
The subgraph stays a single node in the outer diagram; the imported model lives
in its own file and is **linked** by `source`. Drilling in shows it read-only
(you edit it by opening the file itself). Threats generated inside the
component live in the component file. This is Composite-node behavior plus the
interface contract + staleness tracking.

Pros: outer diagram stays small; the component is reusable across several
models; each team owns its file. Cons: cross-boundary threats between outer and
inner need the interface edges (see §6).

### Mode B — Inline expansion (destructive, one-time)
The placeholder is **replaced** by the actual imported nodes, dropped into the
current diagram inside a trust boundary named after the subgraph. External edges
are rebound to the matching inner interface nodes. After expansion the subgraph
node is gone; it is now real content.

Pros: single flattened model, one threat set, everything visible. Cons: loses
the reusable-component boundary; re-importing an updated component means
re-expanding (we keep the original placeholder's interface as an
`expanded-from` annotation to allow re-collapse — see §8).

## 6. Edge / interface binding — the hard part

When a subgraph is replaced (or its contents are shown), every **external edge**
touching the placeholder must be re-attached to the correct **inner** node.

Algorithm (`bind_interface(placeholder, inner_project)`):

1. Collect the placeholder's external edges, each tagged with the **port name**
   = the slot it connects to on the placeholder.
2. Index the inner project's nodes by their `interface-port` marker →
   `inner_endpoint[port_name]`.
3. For each external edge:
   - Find `inner_endpoint[port_name]`. If found and direction matches, rebind
     the edge's placeholder-end to that inner node's matching slot (create the
     slot if the inner node declares the port but has no free slot).
   - Preserve the edge's `id`, `properties` (type/sub-type/description),
     `threat_guids`, and label — only the endpoint reference changes.
   - If **not found**: leave the edge dangling to a generated **stub node**
     inside the boundary named `⚠ unbound: <port>`, and emit a validation
     issue. Nothing is silently lost.
4. Ports on the inner model that no external edge uses are fine (internal-only).
5. Report a **binding summary**: matched N, unmatched M, direction-mismatched K.

Because binding is name-based and idempotent, re-syncing an updated component
re-runs the same algorithm; edges that still match keep their threats.

## 7. Authoring the interface (both directions)

- **From the placeholder**: an "Edit Interface…" dialog on the subgraph node
  lets you add/rename/remove ports (name + direction + optional expected class).
  Renaming a port renames its slot and updates any attached edges. You can
  **export the contract**: writes a skeleton component `.json` containing one
  pre-marked interface node per port, so the component owner starts from a stub
  that already satisfies the contract.
- **From the component model**: any node's property editor gets an
  `interface-port` field (free text). Setting it publishes that node as the
  inner endpoint for that port name. A component's interface is the set of its
  `interface-port` markers; we can lint that it matches the placeholder's
  contract before binding.

## 8. Round-tripping (collapse / re-expand)

To keep Mode B from being a dead end:

- On inline expansion, tag the created boundary with
  `expanded-from: {name, interface, source, source-hash}`.
- Provide **Collapse to Subgraph**: select such a boundary → it is serialized
  back out to its `source` file (or a new one), its external edges are rebound
  to a fresh placeholder carrying the stored interface, and the inner nodes are
  removed from the diagram. This is the inverse of §6.

## 9. Feature list (what the user gets)

Placeholder authoring
- Create a Subgraph placeholder node from the toolbox.
- Define/edit its interface (ports: name, direction, expected class).
- Connect other nodes to its ports like any node.
- Export an interface skeleton `.json` for a component owner to fill in.

Binding / import
- **Bind to file…**: link a component `.json` (Mode A reference) with staleness
  tracking.
- **Import & Replace…**: expand a component inline (Mode B), auto-wrapping it in
  a trust boundary and rebinding all external edges by port name.
- **Re-sync**: when a bound file changes (stale badge), re-run binding; edges
  that still match keep their threats and CVSS.
- **Collapse to Subgraph**: turn an expanded/real boundary back into a reusable
  placeholder + file.

Safety / visibility
- Live state badge (unbound / bound / stale / missing).
- Binding summary dialog (matched / unmatched / direction-mismatch).
- Unmatched external edges are preserved as visible ⚠ stub connections, never
  dropped.
- New validation rules: "subgraph has unbound ports with external edges",
  "component missing interface-port for connected port", "stale subgraph".

Analysis integration
- Attack-surface panel treats every subgraph port that crosses a trust boundary
  as an entry point even while unbound (so you can threat-model the interface
  before the internals exist).
- Threat generation on interface edges works pre-binding (the contract is
  enough context); post-binding, generation descends into the real nodes.
- Reports show subgraphs as collapsible sections with a "not yet modeled"
  marker when unbound.

## 10. Implementation sketch (where the code goes)

- `template/security/element/subgraph.json` + `subgraph_props.json` — node
  template and its property schema (state/source/interface fields).
- `node_editor/subgraph.py` (new): `Interface`, `Port` dataclasses;
  `bind_interface()`, `expand_inline()`, `collapse_to_subgraph()`,
  `interface_diff()`; hashing/staleness helpers. Pure logic, unit-testable
  without Qt.
- `node_editor/graphics/items.py`: `NodeItem` paint branch for
  `shape_kind == "Subgraph"` (glyph + state badge); slots generated from
  interface.
- `node_editor/ui/subgraph_dialogs.py` (new): Edit-Interface dialog, Bind/Import
  dialog, binding-summary dialog.
- `node_editor/app.py`: menu/toolbar actions (Bind, Import & Replace, Re-sync,
  Collapse); reuse `navigate_into`/scene-stack for reference drill-in;
  extend `_deserialize_into` for the rebind step. Automation commands
  (`subgraph-bind <node> <file>`, `subgraph-expand <node> <file>`) so the
  headless CLI can assemble models in a pipeline.
- `node_editor/validation.py`: the new rules in §9.

## 11. Why this design

- **Interface-first, name-based binding** is what makes "someone else builds it
  later" actually work: the two sides only need to agree on port names, not on
  internal structure or IDs.
- **Reuses the existing project/diagram/slot/boundary/Composite machinery** —
  a subgraph's contents are just a project file, so no parallel format and no
  new validation/threat/report pipeline.
- **Nothing is ever silently lost**: unmatched edges become visible stubs and
  validation issues.
- **Reversible** (collapse/expand) and **re-syncable**, so it fits an iterative,
  multi-author process rather than a one-shot import.
```
