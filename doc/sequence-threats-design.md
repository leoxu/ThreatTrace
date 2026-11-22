# Sequence threats — design

A threat model has two kinds of threat: those that belong to **one connection**
(a single call across a boundary) and those that only exist because of an
**ordered flow** — a TOCTOU window between two steps, a replayable transaction,
a privilege gained in step 1 and used in step 4. The first kind belongs to an
edge; the second belongs to the sequence itself and to no single edge.

## Ownership

| `edge_guid` | `sequence_guid` | Meaning |
|---|---|---|
| set | "" | plain edge threat (unchanged behaviour) |
| set | set | found while analysing a sequence but pinned to one step — owned by the edge, **also listed under the sequence** |
| "" | set | multi-step threat — owned by the sequence alone |

- `Threat.sequence_guid` records the sequence a threat came from or belongs to.
- `Sequence.threat_guids` lists everything the sequence owns or produced, so the
  panel can show a flow's full analysis in one place. It is serialised with the
  rest of the sequence, and pruned of dangling guids on refresh.
- For a sequence-wide threat, `source_guid` / `dest_guid` span the flow: the
  first step's source and the last step's destination.

## The prompt

Before calling the agent, `build_sequence_context` gathers the full context and
`_format_sequence_message` renders it in four blocks:

1. **Participants** — every distinct node in the flow, described once and in
   full: class, kernel-mode flag, asset role, trust boundary, containing
   component, and *every* authored security property (uid, gids, path,
   capabilities/abilities, asset type, owner, and whatever a template adds) —
   not a hand-picked subset, so a property added to a template reaches the model
   without touching this code.
2. **Trust boundaries involved** — the set crossed anywhere in the flow.
3. **Flow** — the ordered steps, each with from/to (participant + slot), the
   operation, whether it crosses a boundary, the asset interface behind each
   slot with its path and allowed operations, slot details, and the per-step
   properties authored in the sequence panel (`Sequence.step_props`).
4. **Already identified** — existing threats, tagged `[sequence]` or `[step]`,
   so a re-run adds new findings instead of repeating.

`EdgeContext` carries `src_/dst_slot_interface`, `_path` and `_operations` for
this; `SequenceContext` carries `step_props` (kept aligned with the steps that
survived validation) and `existing_sequence_threat_titles`.

## Generation

`generate_threats_for_sequence*` already asks the model for a `step` index per
threat. `_parse_sequence_threats` now maps it:

- `0 ≤ step < len(steps)` → that step's edge (`edge_guid`), plus `sequence_guid`;
- `step == -1` (or out of range) → `edge_guid = ""`, `sequence_guid` set.

Previously a sequence-wide threat was silently attached to the *first* step's
edge, which made multi-step findings look like single-call findings. The
completion message now reports the split, e.g.
`Threats generated: 5 (2 on the sequence, 3 on individual steps)`.

## UI

- **Sequence panel** — laid out like the Properties tab: *Sequences (N)*,
  *Steps (N)* and *Threats (N)* are collapsible sections
  (`ui/collapsible.CollapsibleSection`, shared with the properties panel) with
  the selected sequence's name/colour ungrouped between them, so any block can
  be folded away to make room for another. A folded section shrinks to its
  header — its size policy drops to `Fixed`, the panel's stretch moves off it,
  and a trailing zero-factor spacer collects the slack — while Steps and
  Threats share the spare height whenever both are open. Each title tracks its
  count. The Threats section shows the same foldable
  `ui/threat_card.ThreatCard` the edge properties panel uses: priority badge,
  category, `MITIGATED` badge and title when folded; scope (`whole sequence` /
  `one step`), status, description, mitigations, the linked controls with their
  rationale, and Edit/Delete when open — plus a `Collapse all` / `Expand all`
  toggle and `+` to add. A manual add is always sequence-wide
  (`edge_guid = ""`).
- **Threats panel** — a threat with no edge shows
  `Sequence: <name> (n steps)` instead of a blank connection, and clicking its
  card no longer tries to select an edge.
- **Design verification report** — the column is *Connection / Sequence*; the
  detail record gains a `Scope` field (`Connection` / `Sequence step` /
  `Whole sequence`), and a step-pinned threat's location reads
  `Host App → Device Channel (submit cmdbuf) — step of Submit + wait (2 steps)`.

## Mitigation coverage

`build_coverage_scope(control, scene, threats, sequences)` takes the sequence
registry. After collecting the threats on covered edges it adds sequence-wide
threats whose flow runs over at least one covered edge — a control sitting on
one step can still mitigate a multi-step threat, and the agent is told the item
is a `multi-step sequence` so it judges it as such. Without the registry the
behaviour is exactly as before, so other callers are unaffected.

## Deletion

Deleting a threat from any panel removes it from the registry, from the owning
edge and from every sequence that lists it, then refreshes the sequence panel.
