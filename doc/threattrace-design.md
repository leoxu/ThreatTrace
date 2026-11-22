# ThreatTrace — Design & Implementation Plan

**One document, consolidating the 24 design notes in `doc/`.** Each of those was
written to answer one question at one moment; this is the whole thing in one
place: what the tool is, how the model works, what is built, what is planned, and
in what order to build the rest. The originals stay as detail references and are
listed under [Sources](#sources).

Status labels used throughout:

| | meaning |
|---|---|
| **Built** | implemented and in use |
| **Partial** | works, with a named gap |
| **Planned** | designed here, not implemented |

---

## 1. What the tool is

A desktop threat-modelling tool for **software security architecture** —
embedded, driver and RTOS stacks (Linux, QNX) rather than enterprise web
systems. An engineer draws the system once; the tool then generates threats
against it, judges the security controls placed on it, and produces the evidence
a reviewer or auditor needs.

The loop:

```
model the system → generate threats → apply security controls → verify & report
```

**What makes it different.** Three things, and they should stay the centre of
gravity:

1. **The interface is the unit, not the box.** An asset exposes named
   interfaces, each with a real path, an actor, an access-class filter and
   operations decomposed into syscalls. A threat is about *one channel*, not
   "the driver".
2. **Nothing is asserted without evidence.** A threat is accepted by a human. A
   control mitigates a threat only when an agent judged it against the control's
   actual configuration and a human accepted the verdict, with rationale and
   residual risk stored on the threat.
3. **The model is checked against reality.** A runtime syscall log is imported as
   an implementation model and diffed against the design.

**What it is not.** Not an automotive TARA suite, not a compliance-clause
checklist tool, not a diagram-only STRIDE editor. See §11 for what was
deliberately declined and why.

---

## 2. The model

### 2.1 Vocabulary — Built

| Element | Meaning |
|---|---|
| **Component** | Something that runs: process, host app, dynamic library, Linux KMD, QNX resource manager, proxy, hardware block |
| **Security asset** | One logical resource worth protecting, exposed through one or more **interfaces** |
| **Trust boundary** | A privilege/authority domain, drawn as a dashed container; membership is geometric |
| **Security control** | A container placed over what it protects, holding one or more control definitions |
| **Connection (edge)** | A typed operation from a component to an asset interface, or between components |
| **Sequence** | An ordered list of connections — a multi-step flow |
| **Review note** | A speech bubble anchored to what it questions, on its own layer |
| **Subgraph placeholder** | An interface contract standing in for a component modelled elsewhere |

A model is a **single JSON file**: nodes, per-diagram placements and edges,
threats, sequences. It diffs and reviews like code, which is the reason for
every "one file" decision below.

### 2.2 Assets: three levels — Built

The core modelling insight. An asset is almost never reached one way:

| Level | What it is | In the tool |
|---|---|---|
| **Asset** | one logical resource, stable `type` id, schema of security properties | a node |
| **Interface** | one access channel: `path`, `actor`, `direction`, `access-class`, colour | **one slot per interface** |
| **Operation** | a semantic action (Allocate, Map, Free) broken into syscall **steps** with `acquire`/`operate` roles | the connection's `sub-type`, and the step list on the connection |

Asset types are **authored, not hard-coded**: one `*.asset.json` descriptor in
`template/security/asset/`, from which the registry derives the toolbox entry,
the node's slots, the property schema, the operation drop-down and the paths used
later to match a runtime log — with no code change. The Asset Editor authors
them; legacy split templates still load.

### 2.3 Interface categories — Built

23 predefined categories in `template/security/interface_categories.json` say
*how* a channel works — ioctl, mmap, hypercall, SMC, MMIO, DMA, message passing,
one per physical bus (UART/USB/PCIe/I²C/SPI/CAN), and so on. Each declares its
own **fields** (an ioctl needs a device node; CAN needs an interface and message
ids), a default access-class, a starter operation list, the failure modes that
mechanism is known for, and the controls that could plausibly apply. The failure
modes go into the generation prompt, so a hypercall and a CAN bus are not asked
the same questions.

### 2.4 Who may reach a channel — Built

Every component carries a dotted **access class** (`software.application`,
`software.library`, `software.kernel`, `hardware.device`, …); every interface
declares the glob it accepts. A connection whose component does not match is a
**validation error**, not a note. The software/hardware split becomes a checkable
property of the diagram.

### 2.5 Ownership, leases and address space — Partial

*(model designed; ownership slot and owner edges built, lease semantics not yet
enforced)*

| Relationship | Meaning |
|---|---|
| **owns** (component → asset) | lifecycle authority: allocate, free, **revoke** — only the owner may revoke |
| **part-of** (asset → asset) | carved from a parent, drawn as nesting |
| **maps-to** (asset → asset) | two names for the same bytes in different address spaces |
| **leases** (owner → holder) | revocable, scoped access |

An **address space** is a separate axis from the trust boundary: a boundary is a
privilege domain (who may revoke), an address space is a naming domain (in which
namespace the bytes are addressed). Keeping them apart is what makes
use-after-revoke, over-grant, illegal re-delegation and aliasing visible on the
diagram.

### 2.6 Structure at scale — Partial

- **Subgraph placeholders** (Built, phase 1): agree an interface contract, hand
  it to whoever owns the component, replace by reference later without breaking
  the connections drawn around it.
- **Edge groups** (Planned): one authored connection auto-derives the per-syscall
  edges of a compound operation, and the group behaves as a unit for selection,
  threats and conformance.
- **Composite / diagram nesting** (Built).

---

## 3. Threats

### 3.1 Where they live — Built

A threat belongs to the **connection** that carries it. A sequence additionally
owns threats that no single connection can show — TOCTOU windows, replay,
ordering. Sequence generation produces both kinds:

- `edge_guid` set → pinned to that step; listed on the connection *and* the
  sequence;
- `edge_guid` empty → the flow as a whole; listed on the sequence only.

### 3.2 The prompt is built from the model — Built

Both endpoints with class, containing component, trust boundary and every
security property; the operation; the interface path and operations behind each
slot; the boundaries crossed. For a sequence, every step in order plus the
participants. Cosmetics never enter it.

### 3.3 Generate vs Update — Built

The two operations differ in what they may do to the threat set, and that is the
contract:

| | Generate (⚡) | Update (↻) |
|---|---|---|
| Purpose | re-derive threats from scratch | keep the threats, re-check their mitigation status |
| Deletes? | **yes** — replaces the scope's threats, confirmed first, and only after the new ones are accepted | **never** |
| Scope | a connection's threats; a sequence's own previous run (by `sequence_guid`) | the same threats, plus their control links |
| Agent call | always | only when something changed |

`threat_sync.classify()` decides what an update should do, from two stamps on
each threat:

- `context_hash` — the connection's *facts* (endpoints, classes, components,
  boundaries, security properties, operation, slot interfaces/paths/operations).
  Not the prompt text: re-wording a prompt must not invalidate a model's threats,
  and moving a node must not either.
- `controls_hash` — each covering control's id, name, type, requirement id,
  description **and the interfaces it covers**, so moving a circle counts.

| what changed | decision |
|---|---|
| the connection | `generate` — offers re-generation (which replaces) |
| only the controls | `assess` — re-check mitigation status, no threat added or deleted |
| neither | `up-to-date` — asks before spending an agent call |
| no threats yet | `no-threats` — says so |

Empty hashes mean "produced before this bookkeeping existed" and are adopted
rather than forcing a re-generation of old models.

### 3.4 Nothing is added behind your back — Built

Every generated threat passes a review dialog; unchecked candidates are
discarded. **Planned:** each proposal should also carry a `confidence` value and
a structured `evidence` list (the model facts the agent used), so a reviewer can
check the reasoning rather than trust it.

---

## 4. Security controls

### 4.1 Scope is geometric, and per interface — Built

One visible **container** (a circle) holds any number of control definitions —
stacking one circle per control made the diagram unreadable. The circle provides
geometry; each definition is judged, linked and reported on its own, and a threat
links to the *definition*.

- covered region = the control node's own size (ellipse for a circle, rectangle
  otherwise), so resizing changes scope;
- a slot counts when it overlaps that region, its node is an asset, and it is one
  of that asset's **interfaces** (the ownership slot is skipped);
- candidates = the threats on the connections attached to those slots.

Twelve control types ship (File Permission, Linux Capability, QNX Ability,
Firewall Rule, Encryption, Integrity Check, Audit Logging, Secure Boot,
TrustZone/TEE, HSM, CPU Address Space Isolation). A control definition is a
**type**, a **requirement id** and a **description of its actual configuration** —
that description is what the agent judges against, and a control that says
nothing mitigates nothing.

### 4.2 Verdicts — Built

Per control, the agent receives the control, the covered interfaces with paths
and operations, and the threats in batches; it answers `mitigated` + rationale +
residual risk. Verdicts are merged **conservatively** (every backend that
answered must agree), reviewed by a human, and stored on the threat
(`mitigation_sc_ids`, `mitigation_notes`). Unchecking removes an earlier link.
An offline rule-based fallback deliberately under-claims.

`prune_stale_links` drops links the geometry no longer supports, naming controls
that are no longer in the diagram.

---

## 5. Validation — Built

| Rule | Severity |
|---|---|
| R1 unconnected edge | Error |
| R2 node outside a trust boundary | Error |
| R3 func/IPC call crosses a boundary | Warning |
| R4 ioctl within the same boundary | Warning |
| R5 dangling slot reference | Error |
| R6 isolated node (not controls or boundaries — neither is ever connected) | Warning |
| R6b component not allowed on interface (access class) | Error |
| R7 duplicate edge | Warning |

Generation refuses to run on a connection with validation errors — a threat
model built on an invalid diagram is worth nothing.

---

## 6. Evidence and reports

### 6.1 Today — Built

- **Design verification report** — verdict first (validation errors, threats,
  how many mitigated, open by priority, controls applied, open review threads),
  blocking items by name, then the diagram, the threats and the controls.
- **Threats report** — the risk register: counts by priority, STRIDE category and
  mitigation status, ranked by risk (`priority × mitigation discount`), full
  detail per threat. PDF default; Markdown and CSV available.
- **Model diff** — two versions matched by stable id, curated to a noise-free
  change list.
- **Implementation model + conformance** — a runtime syscall log becomes a normal
  project model; the design↔implementation diff reports *conforming*,
  *violation* (undocumented access, unexpected boundary crossing) and
  *unrealized* (allowed but never exercised).

### 6.2 The evidence ledger — Planned

The structure that makes the four phases one system rather than four features:

```
Claim    — attached to a model element, one verifiable statement
Evidence — phase (design | static | dynamic), source, detail, citation, provenance
Verdict  — derived: VERIFIED / PARTIAL / UNVERIFIED / REFUTED / STALE
```

Rules: absence of evidence is `UNVERIFIED`, never a pass; contradicting evidence
beats supporting evidence (a failing test is not outvoted by an agent). Every
report becomes a view over the ledger, and the **coverage matrix** —
*designed / mitigated / implemented / tested / observed* per interface — is what
the whole lifecycle is aiming at.

Evidence carries provenance and goes **stale** rather than silently wrong:
design evidence on `context_hash`/`controls_hash`, static on the source revision,
dynamic on the build id and test-manifest hash.

### 6.3 Verification status per mitigation — Built (static) / Planned (dynamic)

A threat is *mitigated by* a control once a reviewer accepted that verdict. That
is a design-phase claim. Whether the control exists in the built system is a
separate question, asked twice and recorded per **(threat, control) link** in
`Threat.verification`:

| Phase | Asked by | Recorded when |
|---|---|---|
| **static** | an agent reading the source (`codeverify.py`) | it finds the control implemented **and cites file:line** |
| **dynamic** | a test written for the control, run on target | the runtime log shows the promised behaviour *(planned)* |

The label is **derived, never stored**, so it cannot drift from the evidence:

```
Not verified → Verified in source code → Verified in source code + runtime
                                       ↘ Not found in source code
                                       ↘ Evidence inconclusive
```

Two bars a positive verdict must clear to count: confidence ≥ 0.6, and — for the
static phase — at least one citation. "Verified" with nothing to check is
recorded but reads as *inconclusive*. Absence of evidence is **Not verified**,
never a pass.

Shown on the threat card under each linked control (with the citations and
revision in the tooltip), in the Threats panel row, and in both reports: the
design verification report prints the status and its evidence under each applied
control, and the threats report adds a *…of those, verified* summary row.

### 6.4 Code and test phases — Planned

- **Static**: a control gains an implementation binding (`repo`, `rev`, `files`,
  `symbols`). "Is the interface defined?" is answered by deterministic search;
  "is this control implemented?" by an agent that must **cite `file:line` or
  return INSUFFICIENT EVIDENCE**, scoped to the bound symbols.
- **Dynamic**: generate a **test spec** per control — the negative assertion (the
  thing that must fail), a skeleton for the team's harness, and a **manifest**
  mapping test → control → expected observable in the runtime log. Log import
  then decides pass/fail per control, alongside the existing conformance diff.

### 6.5 Attack paths — Planned

The largest gap. Everything needed is modelled: boundaries, access classes,
interfaces, ownership. `attackpath.py` would pick entry points (outside every
boundary, or on an interface admitting untrusted callers), walk existing edges,
score each hop from facts the model knows (boundary crossing, privilege change,
uncovered interface, recorded threats), and report ranked
`AttackPath{entry, steps, target, crossings, uncovered hops}`. This upgrades
every threat from "this connection is risky" to "here is how someone reaches it".

---

## 7. The AI backends

### 7.1 Ownership — Built

**One supervisor thread owns every agent process** (`agent_runner.py`). It keeps
a task list and a parallelism cap, starts up to N processes, records their
**pids**, drains their pipes, and starts the next task as each exits; when the
list is empty it sleeps.

- Synchronisation is one mutex + one condition variable + task counters
  (`_outstanding`, `Batch.remaining`). Completion is the counter reaching zero,
  re-checked on every wake — not a notification that could be missed.
- Cancelling is exact: kill the recorded process groups.
- The cap is structural: no permit to leak.
- A supervisor that dies **fails its tasks loudly** rather than leaving callers
  waiting forever, and waiters refuse to wait on an unhealthy runner.
- Daemon threads: a wedged CLI call can never stop the app exiting.

### 7.2 Cancellation and diagnosis — Built

Cancel is bounded at every level: process-group kill with a capped wait; the
caller returns whether or not tasks cooperate; the GUI waits 5 s for a worker
then detaches it; and the busy dialog offers **Close anyway** if a cancel does
not take effect. `diagnostics.py` installs a SIGUSR1 handler (C-level, so it
works when the GUI is wedged inside Qt) that dumps every thread's stack plus the
runner's state to a file — no ptrace, no sudo.

### 7.3 Model and speed — Built

Claude CLI is the default backend, **Sonnet** the default model (~20 s per
connection against ~47 s for Opus on the same prompt), with `--strict-mcp-config
--no-session-persistence` to skip startup cost. Independent calls run
concurrently: four connections in the time of one. Codex, both, or a local
rule-based generator are selectable; the rules also serve as the offline
fallback.

---

## 8. Collaboration — Partial

- **Review notes and layers** (Built): a speech bubble with an adjustable tail,
  a comment thread (reviewer question, author replies, resolve), living on a
  *comment layer* that can be switched off so the diagram stays clean in reports.
- **Online multi-person review** (Planned, `online-review-design.md`): comments
  move to a sidecar file so several people can review a frozen revision without
  co-editing; later a static browser bundle for reviewers who do not run the app.
  Deliberately not CRDT co-editing.

---

## 9. UI conventions — Built

Consistency across the three places threats appear is a feature, not polish:

- **Foldable sections everywhere** (`CollapsibleSection`), fold state remembered
  across rebuilds.
- **Threats are grouped Open / Mitigated**, each group foldable and colour-coded,
  in the Threats panel, the connection's Properties tab and the Sequences tab —
  open threats are work to do, mitigated ones are evidence to review.
- **The same button row** in every threats section:
  `+ Add · ⚡ Generate · ↻ Update … 🗑 · ⌃`.
- Cards fold individually; a widget that changes its own height invalidates its
  ancestor layouts (`invalidate_layout_chain`), because Qt caches
  height-for-width per item.
- A control container **draws no text**: it sits on top of what it protects, so
  anything it writes covers exactly what the reader came to see.

---

## 10. File formats — Built

| File | Contents |
|---|---|
| project `.json` | nodes, diagrams (placements + edges), threats, sequences, hidden layers |
| `template/security/asset/*.asset.json` | asset type: identity, property schema, interfaces, operations, steps |
| `template/security/element/*.json` | component and control templates |
| `template/toolbox.json` | palette grouping |
| settings `~/.config/node-editor/settings.json` | backend, model, rules file |

Everything is JSON, everything diffs, nothing is hidden in a binary.

---

## 11. Deliberately out of scope

From the review of the "Security Knowledge Graph Platform" proposal
(`design-review-security-graph.md`):

| Declined | Why |
|---|---|
| Automotive TARA vocabulary (CAN/ECU/gateway) | trades a defensible niche (OS/driver internals) for a crowded market |
| Re-platforming onto a graph database | the model is already a typed graph; the proposal's motivating queries need a *traversal layer*, not a new store |
| Seven-factor risk formula | uncalibrated factors multiply into false precision; risk should stay explainable |
| Autonomous "AI red team" | plausible attack stories without evidence — the opposite of the ledger's direction; revisit after attack paths exist |
| Variants, compliance graph, SBOM/CVE, Copilot chat | real work, but justified by a customer rather than a document, and they want the ledger underneath first |

---

## 12. Implementation plan

Ordered so that each milestone is independently useful and nothing depends on
work that has not shipped. Sizes are rough: **S** ≈ a day, **M** ≈ a few days,
**L** ≈ a week or more.

### M0 — Land what exists (S) ← do first

The last stretch of work is uncommitted: the agent runner, generate/update
semantics, threat grouping, diagnostics, the UI fixes and 17 design docs.

1. Commit in coherent groups: (a) threat generate/update semantics, (b) agent
   runner + cancellation + diagnostics, (c) UI grouping/folding/stylesheet fixes,
   (d) documentation.
2. Merge to `main`; confirm the Pages job for `doc/intro.html`.
3. Regenerate `doc/images` so the published tour shows the grouped threat lists.
4. **Asset editor — data-safety pass** (`asset-editor-enhancements.md` phase 1):
   renaming a type updates its instances instead of orphaning them, saving over
   an existing type is confirmed, deleting one reports how many nodes use it, and
   the save validation is completed. Small, self-contained, and it protects the
   authoring path everything else in §2.2 depends on.

*Done when:* `git status` is clean, the tour renders from `main`, and renaming an
asset type leaves no orphaned instance and no duplicate descriptor.

### M1 — Attack paths (L)

The biggest capability gap, buildable on today's model.

1. `attackpath.py` (Qt-free): entry-point selection, edge traversal, hop scoring,
   `AttackPath` records, ranking.
2. Panel: paths listed, click to highlight the route on the canvas.
3. Report section in the design verification report; CLI `verify-paths`.
4. Cross-link: a threat shows the paths it sits on; a path shows uncovered hops.

*Done when:* on `open-channel.json`, the tool reports a ranked path from an
untrusted entry point to the Device channel and names the hop with no covering
control.

### M2 — Evidence ledger + coverage matrix (M)

No new analysis; make what exists countable.

1. `ledger.py`: claim/evidence/verdict types and derivation rules.
2. Migrate current state into design-phase evidence (accepted threats, accepted
   mitigation verdicts, with their existing hashes as provenance).
3. Coverage panel + report section; staleness shown amber.

*Done when:* the matrix shows, per interface, designed/mitigated counts, and
flags every threat whose evidence is stale.

### M3 — Confidence and evidence on AI proposals (S)

1. `Threat.confidence: float` and `Threat.evidence: List[str]`; prompt and
   parser updated to ask for them.
2. Review dialog shows both; reports print them; ledger stores them.

*Done when:* a generated threat displays "confidence 0.9 — crossed boundary,
no covering control, interface `/dev/mydev0`".

### M4 — Control implementation binding (M)

1. `ControlDef.implementation` (`repo`, `rev`, `files`, `symbols`); editor rows.
2. Validation finding: **unbound control**.
3. Agent-assisted *propose the binding, human confirms*, from the interface path.

*Done when:* every control in the example model either names its code or appears
in the unbound list.

### M5 — Static verification (L)

1. Deterministic locate (ripgrep + tree-sitter/ctags) for "is the interface
   defined?", producing the citation.
2. Agent judgement for "is this control implemented?", scoped to the binding,
   **cite-or-fail**, reusing the mitigation pass's threading and review.
3. Static verification report; CLI `verify-static`; ledger entries.

*Done when:* a control verdict cites `file:line` or is reported as insufficient
evidence, and re-running after the repo moves marks it stale.

### M6 — Test specs and dynamic verification (L)

1. Generate a negative **test spec** per control; export a harness skeleton.
2. Emit the **manifest** (test → control → claim → expected observable).
3. Manifest-aware log import: per-control pass/fail, alongside the existing
   conformance diff (**Asserted** and **Discovered** sections).

*Done when:* importing a log with a manifest turns a control's claim
`VERIFIED (dynamic)` or `REFUTED`.

### M7 — Regression gate (M)

1. `verify-design | verify-static | verify-dynamic | verify-report` as headless
   commands with useful exit codes.
2. Threat/risk diff between two model revisions.
3. Suggested gate: **no High-priority threat mitigated without fresh evidence at
   every phase that applies**.

*Done when:* a CI job fails a model change that adds an unmitigated High.

### Continuous, alongside the above

- **Tests.** The Qt-free core (`threat_sync`, `mitigation`, `controls`,
  `parallel`, `agent_runner`, `ledger`, `attackpath`) deserves a real test file
  each; today's checks are ad-hoc scripts. **M**, and it pays for itself at M5.
- **Edge groups** (S–M) when compound operations start being modelled in anger.
- **Online review phase 0** (M) when a second reviewer actually needs it.

### Dependency order

```
M0 ─┬─▶ M1 attack paths ────────────────┐
    ├─▶ M2 ledger ──┬─▶ M4 binding ──▶ M5 static ──▶ M6 dynamic ──▶ M7 gate
    └─▶ M3 evidence ┘
```

M1 is independent of the verification chain and can run in parallel with M2–M3;
M4 onward is strictly sequential.

---

## Sources

| Area | Documents merged here |
|---|---|
| Model & vocabulary | `security-model-design.md`, `validation-rules.md`, `completion-plan.md` |
| Assets | `asset-definition-design.md`, `asset-interface-model-design.md`, `asset-relationships-design.md`, `asset-editor-design.md`, `asset-editor-ui-design.md`, `asset-interface-impl-plan.md`, `compound-asset-operation-design.md`, `edge-group-design.md` |
| Structure | `subgraph-design.md` |
| Threats | `sequence-threats-design.md` |
| Controls | `mitigation-coverage-design.md` |
| Reports | `design-verification-report-design.md`, `threats-report-design.md`, `model-diff-design.md` |
| Verification | `impl-verification-design.md`, `verification-lifecycle-design.md` |
| Collaboration | `review-notes-and-layers-design.md`, `online-review-design.md` |
| Positioning | `design-review-security-graph.md`, `intro.md`, `intro-slide.md` |
