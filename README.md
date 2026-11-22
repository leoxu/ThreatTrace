# ThreatTrace

A PySide6 security threat modelling tool. Diagram a system's assets, processes, trust
boundaries and data flows; generate, score and track threats directly on the diagram;
then **trace each mitigation to its evidence** — cited in the source and exercised by a
test on target.

![ThreatTrace](screenshots/threattrace.png)

## Features
- Diagramming: assets, processes, trust boundaries, and typed data-flow edges, with drag/move, multi-select, pan, grid/snap, undo/redo, and a minimap
- Threat generation: rule-based or LLM-assisted threat suggestions per edge, with a threat registry linking each threat to its source/destination/edge
- CVSS v3.1 scoring for threats (FIRST.org specification)
- Mitigation linking and compliance mapping (e.g. OWASP Top 10) for threats
- Attack surface panel listing all trust-boundary-crossing edges
- Sequence diagram view generated from the model
- Diagram validation with an issues dialog
- Report export, plus PNG/SVG/PDF diagram export

## Project Layout
- `main.py`: entry point
- `node_editor/app.py`: main window, scene/view, toolbar, property dock
- `node_editor/graphics/items.py`: `NodeItem`, `SlotItem`, `EdgeItem`
- `node_editor/nodes.py`: node specifications + factory
- `node_editor/threat.py`, `threat_gen.py`: threat model + generation
- `node_editor/cvss.py`: CVSS v3.1 scoring
- `node_editor/validation.py`: diagram validation rules
- `node_editor/sequence.py`: sequence diagram model
- `node_editor/report.py`: report and diagram export
- `node_editor/ui/`: panels and dialogs (property editor, threat panel, attack surface panel, sequence panel, settings, validation dialog, minimap, toolbox)
- `template/`: built-in node, edge, and security-control templates

## Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python main.py
```

## Extend
- Add a new node/asset: create a template under `template/` (see `template/security/`) or a `NodeSpec` in `node_editor/nodes.py` and include it in `builtin_nodes()`.
- Add more properties: extend `default_properties` and wire UI in `PropertyEditor`.
- Add threat generation rules: extend `node_editor/threat_rules.json` and `threat_gen.py`.
- Custom draw: in `create_node`, extend the `custom_paint` block for your node.
