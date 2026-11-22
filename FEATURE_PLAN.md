# Security Model Editor — Feature Implementation Plan

## Recommended Implementation Order

**1 → 2 → 8 → 6 → 3 → 4 → 5 → 7**

Rationale: CVSS and mitigation are highest-value model changes (affect every threat). PNG/SVG export is a quick win. Layout and minimap are UI polish. Attack surface and report depend on earlier data being populated. Compliance is last because it restructures the threat dialog with QTabWidget.

---

## Dependency Map

```
Phase 1 (CVSS)
    └─→ Phase 4 (report CVSS column)
    └─→ Phase 5 (compliance ties to CVSS priority)

Phase 2 (Mitigation Linking)
    └─→ Phase 3 (surface panel "mitigated" column)
    └─→ Phase 4 (report mitigation column)

Phase 3 (Attack Surface)
    └─→ Phase 4 (report entry-points section)

Phase 8 (PNG/SVG Export)  ← independent
Phase 6 (Auto-Layout)     ← independent
Phase 7 (Minimap)         ← independent
```

---

## Phase 1 — CVSS v3 Risk Scoring

### Files
| Action | Path |
|--------|------|
| Create | `node_editor/cvss.py` |
| Modify | `node_editor/threat.py` |
| Modify | `node_editor/ui/threat_dialogs.py` |
| Modify | `node_editor/ui/threat_panel.py` |

### Data model changes (`threat.py`)
Add 9 new fields to `Threat` dataclass, all defaulting to `""` (backward-compatible):
```python
cvss_av: str = ""   # Attack Vector:        N / A / L / P
cvss_ac: str = ""   # Attack Complexity:    L / H
cvss_pr: str = ""   # Privileges Required:  N / L / H
cvss_ui: str = ""   # User Interaction:     N / R
cvss_s:  str = ""   # Scope:                U / C
cvss_c:  str = ""   # Confidentiality:      N / L / H
cvss_i:  str = ""   # Integrity:            N / L / H
cvss_a:  str = ""   # Availability:         N / L / H
cvss_vector: str = ""  # computed+stored, e.g. "CVSS:3.1/AV:N/AC:L/..."
```
Update `to_dict()` and `from_dict()` to include all 9 fields.

### New module: `cvss.py`
```python
def cvss_base_score(av, ac, pr, ui, s, c, i, a) -> float:
    # Full CVSS 3.1 formula (FIRST.org specification)
    AV  = {"N":0.85, "A":0.62, "L":0.55, "P":0.2}[av]
    AC  = {"L":0.77, "H":0.44}[ac]
    PR  = ({"N":0.85,"L":0.50,"H":0.50} if s=="C"
           else {"N":0.85,"L":0.62,"H":0.27})[pr]
    UI  = {"N":0.85, "R":0.62}[ui]
    ISC = {"N":0.0, "L":0.22, "H":0.56}
    ISS = 1 - (1-ISC[c]) * (1-ISC[i]) * (1-ISC[a])
    Impact = (7.52*(ISS-0.029) - 3.25*(ISS-0.02)**15
              if s == "C" else 6.42*ISS)
    Exploitability = 8.22 * AV * AC * PR * UI
    if Impact <= 0:
        return 0.0
    base = (min(1.08*(Impact+Exploitability), 10) if s == "C"
            else min(Impact+Exploitability, 10))
    return round_up(base, 1)   # CVSS round-up to 1 decimal

def cvss_severity(score: float) -> str:
    if score == 0.0: return "None"
    if score < 4.0:  return "Low"
    if score < 7.0:  return "Medium"
    if score < 9.0:  return "High"
    return "Critical"

def cvss_vector_string(av, ac, pr, ui, s, c, i, a) -> str:
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

def cvss_from_vector(vector: str) -> dict:
    # parse "CVSS:3.1/AV:N/AC:L/..." back to metric dict
```

### `ThreatDialog` changes
Add new section between "Classification" and "Asset":
```
─── CVSS v3 Score ──────────────────────────────────
Attack Vector  [N/A/L/P ▼]   Attack Complexity [L/H ▼]
Privileges Req [N/L/H   ▼]   User Interaction  [N/R ▼]
Scope          [U/C     ▼]   Confidentiality   [N/L/H ▼]
Integrity      [N/L/H   ▼]   Availability      [N/L/H ▼]
                   [ CVSS 9.8  CRITICAL ]  ← live-updating label
```
- 8 `QComboBox` widgets in a `QGridLayout` (2 columns)
- Live `_compute_and_display_cvss()` connected to `currentIndexChanged` on all combos
- Severity badge colored: Critical=#7b1fa2, High=#c0392b, Medium=#e67e22, Low=#27ae60

### `ThreatPanel` changes
- Show `CVSS {score:.1f}` label on each threat card (after priority badge)
- Secondary sort key: CVSS score descending when scores are present

---

## Phase 2 — Mitigation Linking

### Files
| Action | Path |
|--------|------|
| Modify | `node_editor/threat.py` |
| Modify | `node_editor/ui/threat_dialogs.py` |
| Modify | `node_editor/app.py` |
| Modify | `node_editor/graphics/items.py` |
| Modify | `node_editor/ui/threat_panel.py` |

### Data model changes (`threat.py`)
```python
mitigation_sc_ids: List[str] = field(default_factory=list)
# List of security-control node_id values that mitigate this threat
```
Update `to_dict()` / `from_dict()`.

### `app.py` changes
```python
def _collect_sc_nodes(self) -> list[tuple[str, str]]:
    return sorted(
        [(n.node_id, str(n.properties().get("name", "")))
         for n in self.scene.items()
         if isinstance(n, NodeItem)
         and str(n.properties().get("class","")) == "security control"],
        key=lambda x: x[1]
    )
```
Pass `sc_nodes=self._collect_sc_nodes()` to `ThreatDialog` on open.

### `ThreatDialog` changes
Add "Mitigation Controls" section with a `QScrollArea` of checkboxes:
```
─── Mitigation Controls ─────────────────────────────
[x] Encryption HSM
[ ] File Permission Guard
[ ] Firewall Rule
```
`result_threat()` / `apply_to_threat()` collect checked node IDs.

### `EdgeItem.paint()` changes
After the arrowhead: if **all** threats on the edge have non-empty `mitigation_sc_ids`, draw a small green **M** badge near the arrow tip:
```python
painter.setBrush(QColor("#27ae60"))
painter.drawEllipse(QRectF(tip.x()+10, tip.y()-8, 14, 14))
painter.setPen(QPen(QColor("#fff"), 1))
painter.drawText(..., "M")
```

### `ThreatPanel` changes
Add `QCheckBox("Show only unmitigated")` in the header toolbar.

---

## Phase 8 — PNG / SVG Export  *(quick win)*

### Files
| Action | Path |
|--------|------|
| Modify | `node_editor/app.py` |

### Menu additions
- File > **Export Diagram as PNG…** (Ctrl+Shift+P)
- File > **Export Diagram as SVG…** (Ctrl+Shift+E)

### Implementation
```python
def _render_scene_to_image(self, margin=40) -> QImage:
    bounding = self.scene.itemsBoundingRect().adjusted(-margin,-margin,margin,margin)
    img = QImage(int(bounding.width()*2), int(bounding.height()*2),
                 QImage.Format_ARGB32)
    img.setDevicePixelRatio(2.0)
    img.fill(Qt.white)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    self.scene.render(p, source=bounding)
    p.end()
    return img

def _export_png(self):
    path, _ = QFileDialog.getSaveFileName(self, "Export as PNG", "diagram.png",
                                          "PNG Images (*.png)")
    if path:
        self._render_scene_to_image().save(path, "PNG")

def _export_svg(self):
    from PySide6.QtSvg import QSvgGenerator  # requires PySide6-Addons
    path, _ = QFileDialog.getSaveFileName(self, "Export as SVG", "diagram.svg",
                                          "SVG Files (*.svg)")
    if not path:
        return
    bounding = self.scene.itemsBoundingRect().adjusted(-40,-40,40,40)
    gen = QSvgGenerator()
    gen.setFileName(path)
    gen.setViewBox(bounding)
    gen.setSize(bounding.size().toSize())
    p = QPainter(gen)
    p.setRenderHint(QPainter.Antialiasing)
    self.scene.render(p, source=bounding)
    p.end()
```

**Note:** `PySide6.QtSvg` is in `PySide6-Addons`. Wrap import in `try/except ImportError` with a user-facing error message.

---

## Phase 6 — Auto-Layout

### Files
| Action | Path |
|--------|------|
| Create | `node_editor/layout.py` |
| Modify | `node_editor/commands.py` |
| Modify | `node_editor/app.py` |

### Menu addition
- Tools > **Auto Layout** (Ctrl+Shift+L)
- Tools > **Hierarchical Layout**

### `layout.py` (new)
```python
def force_directed_layout(nodes, edges, iterations=200,
                          spring_k=0.01, repulsion_k=5000,
                          rest_len=250.0) -> dict[str, QPointF]:
    # nodes: list of (node_id, width, height)
    # edges: list of (src_id, dst_id)
    pos = {nid: QPointF(random()*800, random()*600) for nid,_,_ in nodes}
    vel = {nid: QPointF(0, 0) for nid,_,_ in nodes}
    for _ in range(iterations):
        forces = {nid: QPointF(0,0) for nid,_,_ in nodes}
        # Repulsion between all pairs
        for i,(a,wa,ha) in enumerate(nodes):
            for b,wb,hb in nodes[i+1:]:
                d = pos[b] - pos[a]
                dist = max(d.manhattanLength(), 1)
                f = repulsion_k / (dist*dist)
                unit = QPointF(d.x()/dist, d.y()/dist)
                forces[a] -= unit * f;  forces[b] += unit * f
        # Spring attraction along edges
        for src, dst in edges:
            d = pos[dst] - pos[src]
            dist = max(d.manhattanLength(), 1)
            f = spring_k * (dist - rest_len)
            unit = QPointF(d.x()/dist, d.y()/dist)
            forces[src] += unit * f;  forces[dst] -= unit * f
        # Integrate with damping
        for nid,_,_ in nodes:
            vel[nid] = (vel[nid] + forces[nid]) * 0.85
            pos[nid] += vel[nid]
    return pos
```

### `commands.py` — `AutoLayoutCommand`
```python
class AutoLayoutCommand(QUndoCommand):
    def __init__(self, node_items, old_positions, new_positions):
        super().__init__("Auto Layout")
        self._items = node_items
        self._old = old_positions   # {node_id: QPointF}
        self._new = new_positions
    def redo(self):
        for item in self._items:
            if item.node_id in self._new:
                item.setPos(self._new[item.node_id])
    def undo(self):
        for item in self._items:
            if item.node_id in self._old:
                item.setPos(self._old[item.node_id])
```

---

## Phase 3 — Attack Surface Summary Panel

### Files
| Action | Path |
|--------|------|
| Create | `node_editor/ui/attack_surface_panel.py` |
| Modify | `node_editor/app.py` |

### Dock placement
Bottom dock area, `QTableWidget` with columns: Entry Point Edge | Source | Destination | Boundary | Threats

```
┌──────────────────────┬──────────┬──────────┬──────────┬─────────┐
│ Edge                 │ Source   │ Dest     │ Boundary │ Threats │
├──────────────────────┼──────────┼──────────┼──────────┼─────────┤
│ IPC call             │ ProcessA │ AssetX   │ Kernel   │   3 🔴  │
│ syscall open         │ ProcessB │ FileY    │ User     │   0     │
└──────────────────────┴──────────┴──────────┴──────────┴─────────┘
```
Clicking a row selects and centers the edge on the canvas.

### Core scan logic
```python
@dataclass
class EntryPoint:
    edge_id: str
    edge_label: str
    src_node_name: str
    dst_node_name: str
    boundary_name: str
    threat_count: int

def scan_attack_surface(scene, threats) -> list[EntryPoint]:
    edge_threat_count = {}
    for t in threats.values():
        edge_threat_count[t.edge_guid] = edge_threat_count.get(t.edge_guid, 0) + 1

    results = []
    for item in scene.items():
        if not isinstance(item, EdgeItem) or not item.src or not item.dst:
            continue
        src_node = item.src.parentItem()
        dst_node = item.dst.parentItem()
        if not isinstance(src_node, NodeItem) or not isinstance(dst_node, NodeItem):
            continue
        if getattr(src_node, "boundary", None) is getattr(dst_node, "boundary", None):
            continue  # same boundary — not an entry point
        kind = item.properties().get("kind", "")
        if kind not in ("IPC", "Asset Operation", "syscall"):
            continue
        boundary = getattr(dst_node, "boundary", None) or getattr(src_node, "boundary", None)
        results.append(EntryPoint(
            edge_id=item.edge_id,
            edge_label=item.label.name if item.label else "",
            src_node_name=str(src_node.properties().get("name", "")),
            dst_node_name=str(dst_node.properties().get("name", "")),
            boundary_name=str(boundary.properties().get("name", "External")) if boundary else "External",
            threat_count=edge_threat_count.get(item.edge_id, 0),
        ))
    return sorted(results, key=lambda e: e.boundary_name)
```

Call `attack_surface_panel.refresh()` from `_switch_diagram()` and whenever the threat registry changes.

---

## Phase 4 — Report Generation

### Files
| Action | Path |
|--------|------|
| Create | `node_editor/report.py` |
| Modify | `node_editor/app.py` |

### Menu additions
- File > **Export Report (Markdown)…**
- File > **Export Report (PDF)…**

### `report.py`
```python
def capture_scene_png(scene, margin=40) -> bytes:
    items_rect = scene.itemsBoundingRect()
    export_rect = items_rect.adjusted(-margin, -margin, margin, margin)
    img = QImage(int(export_rect.width()*2), int(export_rect.height()*2),
                 QImage.Format_ARGB32)
    img.setDevicePixelRatio(2.0)
    img.fill(Qt.white)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    scene.render(p, source=export_rect)
    p.end()
    buf = QBuffer();  buf.open(QBuffer.WriteOnly)
    img.save(buf, "PNG")
    return bytes(buf.data())

def export_markdown(scene, threats, diag_name, out_path: Path):
    png_bytes = capture_scene_png(scene)
    png_path = out_path.with_suffix(".png")
    png_path.write_bytes(png_bytes)
    md = [f"# Threat Model: {diag_name}\n",
          f"Generated: {datetime.now().strftime('%Y-%m-%d')}\n\n",
          f"![diagram]({png_path.name})\n\n"]
    by_boundary = _group_threats_by_boundary(scene, threats)
    for boundary_name, threat_list in sorted(by_boundary.items()):
        md.append(f"## Boundary: {boundary_name}\n\n")
        md.append(_build_threat_table(threat_list))
    entry_points = scan_attack_surface(scene, threats)
    md.append("## Entry Points\n\n")
    md.append("| Edge | Source | Destination | Boundary | Threats |\n")
    md.append("|------|--------|-------------|----------|---------|\n")
    for ep in entry_points:
        md.append(f"| {ep.edge_label} | {ep.src_node_name} | "
                  f"{ep.dst_node_name} | {ep.boundary_name} | {ep.threat_count} |\n")
    out_path.write_text("".join(md), encoding="utf-8")

def export_pdf(scene, threats, diag_name, out_path: Path):
    from PySide6.QtPrintSupport import QPrinter
    from PySide6.QtGui import QTextDocument
    # Build markdown, convert to HTML via QTextDocument, print to PDF
    md_path = out_path.with_suffix(".md")
    export_markdown(scene, threats, diag_name, md_path)
    printer = QPrinter(QPrinter.HighResolution)
    printer.setOutputFormat(QPrinter.PdfFormat)
    printer.setOutputFileName(str(out_path))
    doc = QTextDocument()
    doc.setMarkdown(md_path.read_text())
    doc.print_(printer)
```

### Report structure
```markdown
# Threat Model: <diagram name>
Generated: <date>

![diagram](diagram.png)

## Boundary: <name>
| ID | Title | Category | CVSS | Status | Mitigations |
|----|-------|----------|------|--------|-------------|
| .. | ...   | ...      | 9.8  | Open   | SC-Firewall |

## Entry Points
| Edge | Source | Destination | Boundary | Threats |
...
```

---

## Phase 5 — Compliance Mapping

### Files
| Action | Path |
|--------|------|
| Modify | `node_editor/threat.py` |
| Create | `node_editor/ui/compliance_data.py` |
| Modify | `node_editor/ui/threat_dialogs.py` |
| Modify | `node_editor/ui/threat_panel.py` |

### Data model changes (`threat.py`)
```python
cwe_ids: List[str] = field(default_factory=list)         # ["CWE-79", "CWE-89"]
nist_controls: List[str] = field(default_factory=list)   # ["AC-3", "SI-10"]
owasp_categories: List[str] = field(default_factory=list)# ["A01:2021-Broken Access Control"]
```

### `ThreatDialog` changes
⚠ **Structural change**: wrap the existing scrollable form in a `QTabWidget`:
- **Tab "Details"**: all existing content (unchanged)
- **Tab "Compliance"**: new compliance fields

```
─── Compliance ──────────────────────────────────────
CWE ID(s)       [ CWE-200, CWE-732              ]
NIST Controls   [ AC-3, AU-10                   ]
OWASP Category  [ A01:2021-Broken Access Control ▼ ]
```

Do this **after** the Phase 1 CVSS section is stable to avoid layout conflicts.

### `ThreatPanel` changes
Add framework filter dropdown in header:
```
[All ▼]  [x] Unmitigated only
```
Options: All | No Compliance Tag | CWE | NIST | OWASP

Gap analysis: threats with all 3 fields empty are highlighted with an orange border on their card.

---

## Phase 7 — Minimap

### Files
| Action | Path |
|--------|------|
| Create | `node_editor/ui/minimap.py` |
| Modify | `node_editor/app.py` |

### UI placement
Overlay `QWidget` inside `NodeGraphicsView.viewport()`, bottom-right corner, 160×120 px, 8 px margin, opacity ~0.85.

### `minimap.py`
```python
class MinimapView(QGraphicsView):
    def __init__(self, scene, main_view, parent=None):
        super().__init__(scene, parent)
        self._main_view = main_view
        self.setFixedSize(160, 120)
        self.setRenderHints(QPainter.Antialiasing)
        self.setInteractive(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # Cyan viewport indicator rect drawn over the minimap
        self._vp_rect = QGraphicsRectItem()
        self._vp_rect.setPen(QPen(QColor("#00e5ff"), 2))
        self._vp_rect.setBrush(QBrush(QColor(0, 229, 255, 40)))
        self._vp_rect.setZValue(999)
        scene.addItem(self._vp_rect)

    def update_viewport_rect(self):
        mv = self._main_view
        tl = mv.mapToScene(mv.viewport().rect().topLeft())
        br = mv.mapToScene(mv.viewport().rect().bottomRight())
        self._vp_rect.setRect(QRectF(tl, br))
        self.fitInView(
            self.scene().itemsBoundingRect().adjusted(-50,-50,50,50),
            Qt.KeepAspectRatio
        )

    def mousePressEvent(self, event):
        self._main_view.centerOn(self.mapToScene(event.pos()))

    def mouseMoveEvent(self, event):
        if event.buttons() & Qt.LeftButton:
            self._main_view.centerOn(self.mapToScene(event.pos()))
```

Connect `update_viewport_rect()` to main view's scrollbar `valueChanged` signals and override `NodeGraphicsView.resizeEvent()`.

---

## Summary Table

| Phase | Feature | New Files | Key Modified Files | Effort |
|-------|---------|-----------|-------------------|--------|
| 1 | CVSS v3 Scoring | `cvss.py` | `threat.py`, `threat_dialogs.py`, `threat_panel.py` | Medium |
| 2 | Mitigation Linking | — | `threat.py`, `threat_dialogs.py`, `app.py`, `items.py`, `threat_panel.py` | Medium |
| 8 | PNG/SVG Export | — | `app.py` | Small |
| 6 | Auto-Layout | `layout.py` | `commands.py`, `app.py` | Medium |
| 3 | Attack Surface Panel | `ui/attack_surface_panel.py` | `app.py` | Medium |
| 4 | Report Generation | `report.py` | `app.py` | Medium |
| 5 | Compliance Mapping | `ui/compliance_data.py` | `threat.py`, `threat_dialogs.py`, `threat_panel.py` | Large |
| 7 | Minimap | `ui/minimap.py` | `app.py` | Small |
