# Mitigation Coverage — design

Once threats have been generated for a connection and accepted by the reviewer,
the next modelling step is to place a **security control** that mitigates them.
This feature closes that loop: it works out which threats a control actually
covers, asks the AI backends to judge each one, and marks the mitigated threats
in green throughout the UI.

## Scope: what a control covers

A security control node is a **container**: one circle drawn *on top of* what it
protects (`template/security/element/security-control.json`,
`class: security control`), holding any number of control definitions in
`security-properties.controls` (see `node_editor/controls.py`). One circle per
control made overlapping controls on the same asset unreadable, so the circle is
the only visible object and the controls live inside it — listed on the node and
managed in the properties panel (*Security Controls (N)* → `+ Add Control`,
`✎`, `−`). The per-type templates (`security-control-*.json`) are no longer
dropped on the canvas; they are the presets that pre-fill a new control's name
and description.

Every control inside a container shares the container's geometry but is judged,
linked and reported on its own: `control_scopes(node, …)` returns one
`CoverageScope` per definition, and `Threat.mitigation_sc_ids` stores the
**control definition id**, not the node id.

Legacy models keep working: a node saved with the old scalar `control_type` /
`description` / `requirement_id` reads back as a single control **whose id is
the node id** — exactly what its existing threat links point at — and is
rewritten into the list form the first time a control is added or edited.

Coverage is computed geometrically, per **slot**, not per node:

1. `mitigation.control_region(node)` — the area the control occupies, taken
   from the node's own size (its shape rect in scene coordinates): an ellipse
   for `Circle`/`Ellipse` controls, a rectangle for any other shape. Resizing
   the control widens or narrows its scope in both axes.
2. `covered_asset_slots(control, scene)` — every `SlotItem` whose rectangle
   overlaps that region, where:
   - the slot's node is an asset (`security asset*` or `process memory`), and
   - the slot is one of that asset's **interfaces**. Descriptor-driven assets
     tag interface slots with their `interface` name; legacy template assets
     just use slot names. The one slot that is not an interface is the asset's
     dedicated `owner` slot (`owner-slot: true`), which carries the ownership
     link — it is skipped.

   Covering one interface of a multi-interface asset therefore scopes the
   analysis to that interface only.
3. `edges_for_slots(scene, slots)` — every non-alias, non-virtual edge attached
   to one of those slots.
4. The threats on those edges (`edge.threat_guids`) are the candidate set.

Each covered interface contributes its name, path and operation list to the
prompt, so the agent judges the control against the concrete access channel it
sits on rather than the asset as a whole.

`build_coverage_scope()` returns all of the above as a Qt-free `CoverageScope`,
which is also what the properties panel renders as a summary.

## Assessment

`assess_combined_detailed(scope)` sends the control (name, control type,
description, requirement id) together with the covered interfaces and a batch
of threats to each selected backend — the same Claude / Codex CLI runners used
by threat generation, reused from `threat_gen`. **Claude is the default**
(`threat_gen.DEFAULT_BACKENDS`); Settings → *Default backend* switches to Codex,
both, or the local rules, and the same choice drives generation and assessment. Threats are sent in batches of 8 so each
answer stays focused. The model returns, per threat,
`{index, mitigated, rationale, residual_risk}`.

The call runs in a worker thread behind `ui/async_task.BusyDialog` (shared with
threat generation), so the window keeps repainting and shows progress plus
elapsed time instead of freezing for the length of the CLI call.

**Speed.** A backend call is a CLI subprocess that spends nearly all of its wall
clock waiting, and every pass makes several of them, so:

- the default model is **Sonnet**, not Opus (`threat_gen.DEFAULT_CLAUDE_MODEL`).
  This is structured extraction against a short, fully specified prompt —
  measured on a representative connection, ~20 s against ~47 s for the same 6–8
  threats. Opus stays in the Settings list for a model worth waiting for;
- the claude runner passes `--strict-mcp-config --no-session-persistence`: one
  self-contained question with no tools and no follow-up has no use for the
  project's MCP servers or a saved transcript, both pure startup cost;
- independent calls run **concurrently** (`node_editor/parallel.py`): the
  connections of an all-edges generation, the controls of a coverage pass, and
  the threat batches within one control. Measured: four connections in 26 s
  instead of 106 s.

`parallel.MAX_PARALLEL_CALLS` (4) is enforced as a global semaphore held around
each CLI call rather than as a per-site worker count, because these passes nest —
controls in parallel, batches inside each. Whatever the nesting, four calls are
in flight. Progress therefore counts completions ("Checked 3 of 7 control(s)…")
instead of narrating a single current item, which stops meaning anything once
several run at once. Cancellation still works: the token is thread-local, so
`run_parallel` republishes the caller's token in every worker, and a cancelled
run kills what is running and starts nothing new.

**Cancelling.** The dialog has a Cancel button (Esc works too). It is bounded at
every level, because a cancel that hangs is worse than no cancel at all — the
dialog is modal and has no close button, so a worker that never returns takes
the application with it:

- the CLI call is killed by **process group**, and the wait for its output pipes
  to close is capped (5 s). Killing only the CLI would leave a grandchild
  holding those pipes open and the wait would never end;
- `parallel.run_parallel` stops at the *first* task to raise rather than
  collecting results in order, so a cancellation from the fourth call is not sat
  on until the first one happens to finish. It then waits for the running tasks
  to unwind — capped at 10 s — and drops the rest;
- `run_task_with_progress` waits **5 s** for the worker thread and then
  *detaches* it: signals disconnected, results dropped, the reference kept in
  `_ORPHANS` until it really finishes (deleting a running QThread crashes the
  process). The editor comes back either way;
- if a cancel has not taken effect within 5 s the dialog offers **Close anyway**,
  so the user is never trapped in a modal dialog whose only button is disabled.

Cancellation itself is cooperative and real, not just a hidden dialog:
`cancel.CancelToken` is published per worker thread — and republished by
`run_parallel` in each of its workers, since the token is thread-local — the CLI
runners poll it and **kill the running subprocess**,
and every loop boundary (per backend, per batch, per control, per edge) calls
`cancel.check()` so nothing further is started. Work already applied is kept —
an all-edges run reports `Cancelled after 2 of 4 connection(s)` and keeps the
threats from the connections that finished. A cancellation is never recorded as
a backend failure: the `except Exception` handlers re-raise `CancelledError`.

Backend verdicts are merged **conservatively**: a threat is only proposed as
mitigated when every backend that answered agrees. A single sceptical reviewer
keeps the threat open, and both rationales are kept.

When every backend fails (no CLI installed, offline, timeout), `assess_rules()`
provides an offline fallback that matches the control type against the threat's
STRIDE category *and* requires the threat text to mention the control's
mechanism — deliberately strict, so the fallback under-claims rather than
over-claims.

## Review and marking

Nothing is linked automatically. `MitigationReviewDialog` lists every verdict
(mitigated first) with its rationale and residual risk, pre-checked to the
model's answer. On Apply, `apply_assessments()` writes the accepted verdicts to
each threat:

- `Threat.mitigation_sc_ids` — the linked control node ids (existing field, also
  written by the manual check-boxes in `ThreatDialog`).
- `Threat.mitigation_notes` — `{control node id: rationale + residual risk +
  backend}`, so the reasoning survives a save/load round trip.

Unchecking a row *removes* an earlier link, so re-running the check after
changing the control's configuration corrects a stale verdict.

Mitigated threats are then marked in green:

- edge properties panel — green left border, `MITIGATED` badge, and a
  `✓ Mitigated by <control>` line with the rationale underneath. The Threats
  block is one collapsible section and every threat card folds on its own
  (collapsed = priority, category, mitigated badge and title on one line;
  expanded = status, description, mitigations, linked controls and the
  edit/delete actions), with a `Collapse all` / `Expand all` toggle. Fold state
  is remembered per threat across panel rebuilds;
- Threats panel — green left border and a `Mitigated by <controls>` badge whose
  tooltip carries the rationale;
- canvas — the existing green `M` badge on an edge whose threats are *all*
  mitigated.

## Where it runs in the pipeline

The modelling loop is *generate threats → apply controls*, so the control pass
is the second half of every generation flow rather than a separate chore:

- edge threat generation (`_on_threats_generate`),
- sequence threat generation (`_on_sequence_threats_generate`), and
- all-edges generation (`generate_threats_all_edges`, interactive runs only —
  `show_progress=False` stays a pure generation call for scripted use)

each end by calling `MainWindow._run_mitigation_pass(new_guids)`. That builds a
scope for **every** security control in the scene
(`mitigation.scopes_for_all_controls`), restricted to the threats just accepted
so earlier verdicts are not re-litigated, assesses them control by control
(`assess_scopes`, one progress step per control, per-control rule fallback), and
shows a single review dialog with the verdicts grouped under each control. If no
control covers any of the new threats the pass is silent — generation behaves
exactly as before.

## Generate vs. update: deciding what an update should do

Threats are produced from two independent inputs, and each goes stale on its
own:

**Generate replaces; update never does.** The two operations are deliberately
different in what they may do to the threat set:

* **Generate** re-derives a scope's threats from scratch, so it **deletes the
  threats it is replacing** — the old set was written about an earlier version of
  the connection, and keeping it would leave a mixture of two models' findings.
  For a connection that is every threat on it; for a sequence it is exactly the
  threats stamped with that sequence's guid (its previous run's output, whether
  they ended up on the sequence or pinned to a step), so per-connection threats
  are left alone. The deletion is confirmed up front, and then happens **only
  after the new threats are accepted** — a cancelled run, a dead backend or a
  rejected review leaves the existing threats exactly as they were. The threats
  on their way out are also removed from the prompt's "already identified" list,
  or the agent would omit findings that are about to be deleted.
* **Update** never adds or deletes a threat. It re-checks mitigation status and
  drops mitigation *links* the geometry no longer supports. The one case it
  cannot repair is a changed connection, where it hands over to Generate — after
  asking, and Generate's own confirmation is then skipped rather than asked
  twice.

| what changed | what the existing threats are worth | what Update does |
|---|---|---|
| the **connection** — source, destination, operation, interface, trust boundary, a security property of either endpoint | they describe a system that no longer exists | offers to **re-generate**, which replaces them |
| only the **controls** covering the destination asset's interface — one added, removed, edited, or the circle moved | still valid; only their mitigation status is in question | **re-assesses** (prune + coverage pass) — no threat is added or removed |
| neither | current | asks before spending an agent call |
| there are no threats yet | — | says so; generate first |

`node_editor/threat_sync.py` (Qt-free) makes that call. Each threat records what
it was produced under:

* `Threat.context_hash` — `context_hash(ctx)`, over the connection's *facts*:
  each endpoint's name, class, containing component, trust boundary and every
  security property; the edge type and description; and the name, interface,
  path, operations and details of each slot. Deliberately **not** the prompt
  text — re-wording a prompt must not invalidate every model's threats — and
  deliberately nothing cosmetic, so moving or recolouring a node changes
  nothing. Stamped over the whole connection when generated threats are
  accepted.
* `Threat.controls_hash` — `controls_hash(scopes)`, over each covering control's
  id, name, type, requirement id, description **and the interfaces it covers**,
  so moving a circle counts as a change. Stamped when a coverage pass completes:
  after an accepted review, and also when the pass found nothing to assess —
  "no control at all" is a real, current state, and not recording it would make
  every later update re-offer the same check.

`classify(threats, ctx, scopes)` returns a `Decision` with one of
`generate` / `assess` / `up-to-date` / `no-threats`, plus the reason shown to
the user and logged. An **empty** recorded hash means "produced before this
bookkeeping existed": it is treated as current rather than forcing every threat
in an older model to be re-generated on first open.

`MainWindow._on_edge_threats_update` branches on that decision. Only `assess`
runs without asking; `generate` confirms first (existing threats are kept and
the agent is told not to repeat them — 🗑 gives a clean slate), and `up-to-date`
offers a re-check rather than silently doing nothing.

Sequence updates stay a plain prune + assess: a sequence's context spans every
step, so a per-connection context hash does not describe it.

## Updating threats when the controls change

A verdict is only true of the diagram that produced it. When a control is
deleted, moved off an interface, resized, or a new one is added, existing
threats carry stale links. **Update Threats** re-syncs them in two halves:

1. `mitigation.prune_stale_links(scene, threats, sequences, only_guids)` —
   offline and immediate. For every linked control it drops the link when the
   control is no longer in the diagram, or when the threat is no longer in that
   control's coverage scope, removing its `mitigation_notes` entry too, and
   returns a `StaleLink` per removal with the reason. Controls that were deleted
   are still named, via `known_names` from the project's node registry.
2. the normal coverage pass over the same threats, so any control that *now*
   covers them (including one just added) is assessed and reviewed.

A control that currently covers nothing is a normal state, not an error: the
pass logs it (`MainWindow.log()` — Python logging plus a transient status-bar
line), returns 0 and lets the update finish, so moving a control off an
interface and running **Update Threats** drops its now-unsupported links instead
of stopping at a dialog. The same applies when no backend produced a verdict.
The caller's summary repeats the note at the end.

Entry points:

- edge properties → Threats section → **↻ Update** (that connection's threats;
  disabled when it has none);
- sequence panel → **↻ Update Threats** (the sequence's own threats *and* the
  threats on every one of its steps);
- Tools → **Apply Security Controls…** prunes first as well, so the whole-model
  pass self-heals.

Pruning is deliberately explicit rather than automatic on delete: a deletion can
be undone, and silently rewriting threat records during an undoable command
would lose the links for good.

Explicit entry points for a control-by-control or whole-model pass:

- Properties panel → select a security control → **Mitigation Coverage**
  section (shows the covered interfaces / connections / threat counts) →
  **⚡ Check Mitigation Coverage** (`_on_mitigation_check`, that control only).
- Canvas context menu on a security control → **Check Mitigation Coverage…**
- Tools → **Apply Security Controls…** — every control against every threat in
  its scope, including ones already linked, so a re-run corrects stale verdicts.

Nothing runs merely from dragging a control over an asset: the assessment costs
LLM calls, so it is always tied to an explicit generation or menu action.
