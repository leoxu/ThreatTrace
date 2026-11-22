# Security Model Tool — Design Document

## 1. Overview

Extend the existing node-editor with a **security modeling vocabulary**:
predefined node types that let engineers draw security architecture diagrams,
threat models, and control mappings using a shared visual language.

Node types are defined entirely in JSON **palette files** — no Python changes
needed to introduce a new concept. The editor loads one or more palette files
at startup and presents them in a dedicated "Security" toolbar section.

---

## 2. Core Concepts

| Concept | Purpose |
|---------|---------|
| **Security Asset** | Something worth protecting — data, secrets, keys, PII |
| **Software Component** | A running process — service, API, database engine |
| **Trust Boundary** | A perimeter separating trust zones — network segment, process boundary, account boundary |
| **Security Control** | A safeguard placed on a path — firewall, auth gate, encryption, monitor |

These four types are enough to express the questions threat modeling asks:
*What are we protecting? Who/what handles it? Where are the perimeters? What controls are in place?*

---

## 3. Visual Language

### 3.1 Shape → Concept mapping

Each concept maps to one of the editor's existing shapes so no new rendering
code is needed.

| Node Type | Shape | Color | Rationale |
|-----------|-------|-------|-----------|
| `data-asset` | Box | `#2471a3` steel-blue | Rectangular = storage, bounded value |
| `software-component` | Circle | `#1e8449` forest-green | Round = process, living thing |
| `external-actor` | Ellipse | `#7d3c98` purple | Wider oval = actor with broader reach |
| `trust-boundary` | Boundary | `#888888` dashed | Already a dashed container — fits perfectly |
| **Preventive control** | Hexagon | `#b7950b` dark-gold | Stop-sign family — "this blocks passage" |
| **Detective control** | Circle | `#1a6fa8` teal-blue | Eye shape evokes watching |
| **Corrective control** | Diamond | `#c0392b` red | Decision/response shape — "react and fix" |

> **Why hexagon for preventive controls?**
> The hexagon is the natural "enforcement point" shape — it has no clear
> left/right orientation, suggesting it intercepts flow from any direction.
> It is also visually distinct from both assets (box) and components (circle),
> so it stands out on a crowded diagram.

### 3.2 Slot semantics

Slots carry the relationship type. Edge labels make the relationship explicit.

| Relationship | From → To | Typical edge label |
|---|---|---|
| Data flow | component `out` → component `in` | `sends`, `reads`, `writes` |
| Access | actor `accesses` → asset/component `accessed_by` | `HTTP`, `SQL`, `SSH` |
| Protection | control `enforces` → asset/component `protected_by` | `encrypts`, `authenticates`, `filters` |
| Observation | detective-control `observes` → any `monitored_by` | `logs`, `alerts on` |
| Containment | trust-boundary has no slots — membership is spatial |  |

### 3.3 Control placement pattern

A control node is placed **inline on a data path**, not beside it.
This is the key visual idea: the control intercepts the flow.

```
[Actor]  ──access──►  [Auth Gate]  ──authorized──►  [Service]
                          │
                    logs-to│
                          ▼
                       [SIEM]
```

Instead of a single edge from Actor → Service, the path runs through the
control node. This makes it immediately visible when a flow is **uncontrolled**
(direct edge between two nodes with no control in between).

---

## 4. Palette File Format

Each palette is a JSON file under `palettes/`. The editor discovers all
`palettes/*.json` files on startup.

```json
{
  "palette": "security-controls",
  "label": "Security Controls",
  "nodes": [
    {
      "name": "Preventive Control",
      "shape": "Hexagon",
      "color": "#b7950b",
      "description": "Blocks or filters — firewall, WAF, auth gate, encryption",
      "properties": {
        "mechanism": "firewall",
        "type": "preventive"
      },
      "inputs": [
        { "name": "protected_by", "kind": "input" }
      ],
      "outputs": [
        { "name": "enforces",  "kind": "output" },
        { "name": "logs_to",   "kind": "output" }
      ]
    },
    {
      "name": "Detective Control",
      "shape": "Circle",
      "color": "#1a6fa8",
      "description": "Observes and alerts — IDS, SIEM, audit log",
      "properties": {
        "mechanism": "SIEM",
        "type": "detective"
      },
      "inputs": [
        { "name": "observes", "kind": "input" }
      ],
      "outputs": [
        { "name": "alerts", "kind": "output" }
      ]
    },
    {
      "name": "Corrective Control",
      "shape": "Diamond",
      "color": "#c0392b",
      "description": "Responds and recovers — circuit breaker, incident response, revocation",
      "properties": {
        "mechanism": "circuit-breaker",
        "type": "corrective"
      },
      "inputs": [
        { "name": "triggered_by", "kind": "input" }
      ],
      "outputs": [
        { "name": "remediates", "kind": "output" }
      ]
    }
  ]
}
```

All four palette files follow the same schema. See `palettes/` for the full set.

---

## 5. Palette Files (planned)

```
palettes/
  security-assets.json        # data-asset, system-asset, secret
  software-components.json    # service, database, queue, external-api
  trust-boundaries.json       # network-zone, process-boundary, account-boundary
  security-controls.json      # preventive, detective, corrective
```

---

## 6. How the Editor Loads Palettes

1. On startup, scan `palettes/*.json` relative to the working directory.
2. Parse each file into `NodeSpec` objects (adding a `shape` field to
   `NodeSpec` so the logical name can differ from the rendering shape).
3. Group toolbar actions by `palette.label` — one toolbar section per palette.
4. Serialization saves `node_type` (the logical name, e.g. `"Preventive Control"`)
   alongside `shape_kind` so round-trips preserve security semantics.

---

## 7. Modeling Workflow

A typical threat model session:

1. **Drop Trust Boundaries** — draw the network perimeters first.
2. **Place Software Components** inside boundaries — services, databases.
3. **Add Assets** — attach data assets to the components that hold them.
4. **Connect flows** — draw edges for data movement and access.
5. **Insert Controls inline** — for each flow, insert the control(s) that
   govern it. An edge without a control is a gap.
6. **Add External Actors** — outside the outermost boundary.
7. **Label edges** — protocol, data classification, or STRIDE category.

---

## 8. Example: Login Flow Diagram

```
[Internet Zone]─────────────────────────────────────────────
│  [Browser/User]                                           │
│       │ HTTPS POST                                        │
│       ▼                                                   │
│  [WAF] (Preventive)                                       │
│       │ filtered request                                  │
└───────┼───────────────────────────────────────────────────
        │            [DMZ Zone]───────────────────────────
        ▼            │                                    │
   [Auth Service] ───┼──writes──► [Session Store (Asset)] │
        │            │                                    │
        │ JWT         └────────────────────────────────────
        ▼
   [App Service]
        │
   [Audit Log] (Detective) ◄── observes
```

Nodes used:
- 2 × Trust Boundary (Internet Zone, DMZ Zone)
- 1 × External Actor (Browser/User)
- 1 × Preventive Control (WAF)
- 2 × Software Component (Auth Service, App Service)
- 1 × Data Asset (Session Store)
- 1 × Detective Control (Audit Log)

---

## 9. Design Decisions & Trade-offs

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Shape reuse vs new shapes | Reuse existing 7 shapes | No new rendering code; consistent look |
| Control as node vs edge decoration | Node (inline) | Makes uncontrolled paths visually obvious |
| Palette as JSON vs Python | JSON | Domain experts can define new types without touching code |
| Detective control shape | Circle (same as Service) | Differentiated by color only — acceptable; could use a distinct icon later |
| Trust Boundary | Spatial container (Boundary shape) | Containment is clearer than a connecting edge |
