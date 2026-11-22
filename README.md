# ThreatTrace

ThreatTrace is a desktop **security threat modelling tool** for embedded, driver and
RTOS-style software stacks (Linux, QNX, …). You draw a system's processes, assets, trust
boundaries and data flows; ThreatTrace generates, scores and tracks threats directly on
the diagram, links each one to the mitigations that cover it, and then **traces every
mitigation to its evidence** — cited in the source code and exercised by a test.

It is built with Python and [PySide6](https://doc.qt.io/qtforpython-6/) (Qt 6).

![ThreatTrace main window](screenshots/overview.png)

## Features

- **Diagramming** — processes, assets, trust boundaries and typed data-flow edges, with
  drag/move, multi-select, pan/zoom, grid/snap, undo/redo and a minimap
- **Threat generation** — rule-based or LLM-assisted (Claude / Codex CLI) threat
  suggestions per edge, each linked to its source, destination and edge
- **Risk scoring** — CVSS v3.1 scoring for threats
- **Mitigations and compliance** — link security controls to threats and map them to
  standards such as the OWASP Top 10
- **Attack surface** — a panel listing every trust-boundary-crossing edge, with its open threats
- **Sequence view** — step-by-step sequences over the model, with sequence-level threats
- **Asset editor** — define asset types with interfaces and operations in the UI
- **Verification** — check mitigations against source code and runtime logs, and diff
  design against implementation
- **Review** — review notes, layers and model diff
- **Validation** — diagram validation rules with an issues dialog
- **Export** — Markdown/PDF reports, threats CSV, and PNG/SVG/PDF diagram export

## Security asset design

Most threat-modelling tools treat an asset as a box with a label. In ThreatTrace the
**asset is the unit of analysis**, and it is modelled the way systems code actually
exposes it: one logical resource, reachable through several distinct *interfaces*, each
with its own calls, threats, controls and evidence.

```
Asset  (one logical resource, e.g. "Device Memory")
 └─ Interface  (a distinct access channel — device node, address space, socket, MMIO …)
     ├─ category + fields   (what kind of channel; path, ioctl family, owning driver …)
     ├─ access-class        (who may use it: software.*, hardware.* …)
     └─ Operation           (what it exposes: Allocate, Map, Free …)
         └─ Steps           (the concrete syscalls: open → ioctl:… , role acquire / operate)
```

- **Interfaces, not boxes.** An asset exposes any number of interfaces, and each one
  appears as its own slot on the node. Connecting an edge to a slot means *"access the
  asset through this channel"*. A device buffer reached through a `/dev` node by a
  user process and through a device address by hardware is **one asset with two
  interfaces**, so threats, controls and runtime evidence are tracked per interface and
  never blurred together.
- **Typed channels.** Every interface belongs to a category — ioctl, mmap, filesystem,
  sysfs, local or network socket, message passing, pipe, signal/event, hypercall,
  SMC/TEE, MMIO, DMA, firmware, bus (UART/USB/PCIe) and more. A category declares the
  fields an interface of that kind needs (path, ioctl family, owning driver, …) and the
  **security controls relevant to it**, so the right questions are asked for the channel
  at hand.
- **Operations that match the code.** An analyst draws a readable operation such as
  *Allocate*; it is defined as an ordered list of syscall **steps** underneath, so the
  design stays faithful to what the implementation really does.
- **Access rules checked for you.** Each interface carries an *access-class* filter
  (for example `software.*` or `hardware.device`). Validation rejects an edge whose
  source isn't allowed on that interface, and an edge that crosses a trust boundary must
  land on an asset — its interface — not on a process.
- **Controls guard interfaces.** A file-permission or capability check protects the
  device-node interface; an MMU/IOMMU control protects the address-space interface. A
  control covers a specific interface, and mitigation is judged per interface.
- **One model, all the phases.** Because an interface knows its path and its syscalls,
  the same description drives threat generation (design), per-control source checks
  (coding) and runtime log matching (target): a syscall observed on `/dev/…` maps back
  to the interface and operation that were modelled, and anything observed but never
  modelled is reported.
- **Assets are data.** Asset types are `*.asset.json` descriptors in
  `template/security/asset/`. Add one by hand, or use **Tools → Asset Types…** (the Asset
  Editor) to define interfaces, operations and steps, with data-safety checks (renaming a
  type updates its instances; deleting one reports how many nodes use it).

Planned, and described in `doc/` but not yet built: relationship edges that separate
*ownership* from *lease* (a process holds a revocable handle to a buffer, it doesn't own
it) and **edge groups**, where one drawn operation expands into its syscall edges
automatically. See `doc/asset-interface-model-design.md`, `doc/asset-definition-design.md`,
`doc/asset-relationships-design.md` and `doc/edge-group-design.md`.

## Screenshots

**Properties** — security properties of the selected node, including its operations:

![Properties panel](screenshots/properties.png)

**Attack surface** — trust-boundary-crossing edges and their open threats:

![Attack surface panel](screenshots/attack-surface.png)

## Requirements

- Python 3.9 or newer
- PySide6 6.6.3 (installed from `requirements.txt`)
- Optional, for LLM-assisted threat generation and verification: the
  [`claude`](https://docs.claude.com/en/docs/claude-code) and/or `codex` command-line tool
  on your `PATH`. Rule-based threat generation works without them.

## Setup

```bash
git clone https://github.com/leoxu/ThreatTrace.git
cd ThreatTrace
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python main.py                   # start with an empty diagram
python main.py my-model.json     # open a project file on startup
```

## Workflow: design → verification → code → verification

ThreatTrace follows one claim from the whiteboard to the running target: *a threat is
mitigated by a control, the control is implemented in named code, and a test on target
shows it behaves that way.* Each phase adds evidence to the same model, and a human
accepts or rejects whatever an agent proposes.

### 1. Design phase — model the system and its threats

1. **Draw the system.** Drag elements from the **Toolbox** onto the canvas: *trust
   boundaries*, *processes* (host apps, libraries, kernel modules, …) and *assets*
   (sockets, files, shared memory, registers, …). Set each node's security properties in
   the **Properties** panel.
2. **Connect them.** Draw edges for the data flows and operations between elements. An
   edge that crosses a trust boundary must end on an asset — its *interface*. Use
   **Tools → Validate Diagram** to catch modelling mistakes early.
3. **Generate threats.** Use **Tools → Generate Threats** (*From Local Template Rules*
   needs nothing extra; *From Claude* / *From Codex* use the CLI). Threats are attached
   to the edges they concern and listed in the **Threats** panel. Review each one, score
   it with CVSS, and set its status. Check the **Attack Surface** panel for every
   boundary-crossing entry point and its open threats.
4. **Add security controls.** Drop a *Security Control* from the Toolbox over the part of
   the diagram it protects (file permission, encryption, secure boot, …).

### 2. Design verification — do the controls actually cover the threats?

1. Run **Tools → Apply Security Controls…**. Every control is assessed against the
   threats it covers; the ones it mitigates are linked, with a rationale and residual
   risk. Accept or reject each proposed link.
2. Right-click a security control and choose **Check Mitigation Coverage…** to assess just
   that control against the connections it covers.
3. Export **File → Export Design Verification Report…** for the design review. Threats
   with no covering control, or with controls that don't hold, are called out.

### 3. Coding phase — is each control implemented in the source?

1. Set the diagram's **Source Root** (Properties panel, with the diagram selected) to the
   checkout that implements the design.
2. Run **Tools → Static Verification (Source Code)…**, pick the controls to check, and
   start the run. For each control the agent looks in the source and reports
   *Implemented*, *Not implemented* or *Insufficient evidence* — and must cite
   `file:line` for anything it claims.
3. Review the findings and drop any you disagree with before they are recorded. Accepted
   findings become evidence on the threats those controls mitigate.

### 4. Runtime verification — does it behave that way on target?

1. Run **Tools → Generate Runtime Tests…**. ThreatTrace writes a test specification per
   control and covered interface (negative tests first: an unprivileged actor must be
   *refused*), harness skeletons, and a **manifest** linking each test to its control and
   the observable it expects.
2. Have the tests run on the target while a syscall log is captured. Executing the tests
   on target is your harness's job; ThreatTrace stops at specs, skeletons and the manifest.
3. Run **Tools → Import Test Results (Runtime)…** with the manifest and the captured log.
   Each test is decided *Pass*, *Fail* or *Not exercised*, and the evidence is recorded
   on the threats the controls mitigate.
4. Optionally close the loop on the architecture itself: **Tools → Import Runtime Log…**
   builds an implementation model from a log, and **Tools → Verify Against Runtime Log…**
   reports interfaces that were observed but never modelled, and modelled ones never seen.

After any phase, **Tools → Compare With File…** diffs the current model against an earlier
version, and **File → Export Threats Report…** produces the project's threat register, ranked by
risk, with what is still open and the evidence behind each threat.

### Automation / headless use

The app can run commands without any interaction, for example in CI:

```bash
python main.py model.json \
  -c "generate-threats rules" \
  -c "export-report-md report.md" \
  -c "export-threats-csv threats.csv" \
  --headless
```

`-c/--command` can be repeated, `-f/--commands-file` reads one command per line, and
`--headless` exits when the commands finish. Available commands: `new`, `open`, `save`,
`save-as`, `import`, `export-png`, `export-svg`, `export-selection`,
`export-threats-csv`, `export-report-md`, `export-report-pdf`, `validate`,
`generate-threats <claude|codex|rules|all>`, `diff`, `import-log`, `verify-impl`, `quit`.

On a machine without a display, set `QT_QPA_PLATFORM=offscreen`.

## Project Layout

- `main.py` — entry point
- `node_editor/app.py` — main window, scene/view, toolbar, docks, automation commands
- `node_editor/graphics/items.py` — `NodeItem`, `SlotItem`, `EdgeItem`
- `node_editor/nodes.py` — node specifications and factory
- `node_editor/threat.py`, `threat_gen.py`, `threat_rules.json` — threat model and generation
- `node_editor/cvss.py` — CVSS v3.1 scoring
- `node_editor/mitigation.py`, `controls.py` — controls and mitigation coverage
- `node_editor/validation.py` — diagram validation rules
- `node_editor/sequence.py` — sequence model
- `node_editor/verification.py`, `codeverify.py`, `runtime_tests.py`, `conformance.py` — verification
- `node_editor/report.py`, `design_report.py`, `threats_report.py` — reports and export
- `node_editor/ui/` — panels and dialogs
- `template/` — built-in node, edge, asset and security-control templates
- `doc/` — design documents
- `merge_proxy.py` — standalone tool to merge proxy nodes with their sub-diagrams

## Documentation

Start with [`doc/threattrace-design.md`](doc/threattrace-design.md), which links to the
detailed design notes (security model, validation rules, assets and interfaces, sequence
threats, verification lifecycle, review).

## Extend

- **New node or asset** — add a template under `template/` (see `template/security/`) or
  a `NodeSpec` in `node_editor/nodes.py`.
- **New asset type** — add a `*.asset.json` descriptor to `template/security/asset/`, or
  author one in the Asset Editor.
- **New properties** — extend `default_properties` and wire the UI in `PropertyEditor`.
- **New threat rules** — extend `node_editor/threat_rules.json` and `threat_gen.py`.
- **New security control** — add a `security-control-*.json` file to
  `template/security/element/`.
