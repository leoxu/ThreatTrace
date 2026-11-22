# Online Multi-Person Review — design + TODO

**Status: TODO — not implemented.** Nothing in this document exists in the code
yet, except the single-author review notes it builds on
(`doc/review-notes-and-layers-design.md`). Phases ship independently; each one
leaves the app working.

Goal: several people review a threat model together — a reviewer asks questions
anchored to a specific node, edge, threat or control; the author replies; the
thread resolves; the revision gets approved. Reviewers who do not run the
desktop app must still be able to take part.

## Scope: review, not co-editing

| | Review (this doc) | Co-editing (out of scope) |
|---|---|---|
| Timing | asynchronous, hours–days | real-time, sub-second |
| Target | a frozen revision | the live document |
| Conflicts | comments are append-only → set union | needs CRDT/OT |
| Cost | small | large |

The hard problems here are **anchoring, identity and workflow**, not
concurrency. No CRDT, no operational transform. If live co-editing is ever
wanted it is a separate project, not an extension of this one.

## Architecture options

| | A. Git/PR + sidecar | B. Static web bundle | C. Review service |
|---|---|---|---|
| Infra | none (existing git) | static hosting | FastAPI + DB + SSO |
| Reviewer needs the app | yes | no (browser) | no |
| Live updates | no | no | yes (WebSocket) |
| Auth / permissions | git's | host's | SSO |
| Notifications | PR email | none | Slack / Teams / @mention |
| Effort | ~days | ~1 week | ~4–6 weeks |

They stack: A's data model is B's payload is C's database schema. **Recommended:
Phase 0 + Phase 1 (A + B).** Phase 2 (C) only earns its keep with live presence,
push notifications or compliance-grade approvals.

## Core decision: comments move to a sidecar file

Today a review thread lives inside the node's properties, in the model file.
Fine for one author, wrong for many: every reviewer's comment collides with the
author's edits in the same JSON.

```
mydev.json           # the model — the author writes it
mydev.review.json    # threads + approvals — everyone writes, append-only
```

```jsonc
{
  "schema": 1,
  "model_id": "…",                     // stable across revisions
  "revision": "sha256:ab12…",          // the snapshot under review
  "threads": [{
    "id": "uuid",
    "anchor": {
      "kind": "node|edge|threat|control|diagram|report-section",
      "id": "node_id / edge_id / threat guid",
      "diagram_id": "…",
      "hint": {"x": 120, "y": 340}     // fallback placement only, never identity
    },
    "status": "open|answered|resolved",
    "resolved_by": "alice@example.com",
    "comments": [
      {"id": "uuid", "author": "alice@example.com", "at": "2026-08-21T09:30Z",
       "role": "reviewer", "text": "Should this go through the proxy?"}
    ]
  }],
  "approvals": [
    {"revision": "sha256:ab12…", "by": "bob@example.com", "at": "…",
     "verdict": "approved|changes-requested"}
  ]
}
```

Why this shape:

- **Append-only** — merging two reviewers' files is a union keyed by uuid; a
  ~30-line merge driver, no conflicts. `status` / `resolved_by` are the only
  mutable fields: last-write-wins by timestamp.
- **Anchored by stable ID**, never by coordinates, so a thread survives moving
  or re-laying-out the diagram. `node_id`, `edge_id` and threat `guid` already
  exist and are stable.
- **Revision-pinned**, so "approved" means approved *of something specific*.
- Anchors cover **threats and controls**, not just canvas objects. Most review
  comments on a threat model are "is this threat real?" / "does this control
  really mitigate it?" — today those have nowhere to live.

### Model drift while review is in flight

At load, diff the reviewed revision against the current model with
`modeldiff.py` (already matches by stable ID) and classify each thread:

- target unchanged → **current**;
- target changed → **stale**: show the field-level diff inline in the thread
  ("sub-type changed `mem read` → `mem write` after this comment");
- target deleted → **orphaned**: park in a "needs re-anchoring" list, never drop
  silently.

Getting this right in Phase 0 is what makes everything after it mechanical.

## Phase 0 — file-based multi-person review (no server)   ← start here

- [ ] `node_editor/review_store.py` (Qt-free): load/save `*.review.json`,
      `Thread`/`Comment`/`Approval` dataclasses, `union_merge(a, b)`,
      `revision_hash(project_dict)`.
- [ ] Migrate existing in-node threads → sidecar on first open; keep the bubble
      node as the *rendering* of a canvas-anchored thread (drop the
      `comments`/`review-status` node properties after migration).
- [ ] Anchor resolution: `resolve(anchor, scene) -> item | None` plus
      stale/orphan classification via `modeldiff`.
- [ ] **Review Mode** toggle: model read-only, comment layer editable — stops a
      reviewer accidentally editing the design.
- [ ] **Review panel** dock: all threads with open/answered/resolved/stale
      filters, click to jump to the anchor, reply, resolve. Resolution is the
      reviewer's call, not the author's.
- [ ] Right-click a threat or a control → *Add review comment* (anchor kinds
      `threat` / `control`).
- [ ] Identity from `git config user.email`, overridable in settings; stamp
      every comment.
- [ ] `merge-review.py` + `.gitattributes` (`*.review.json merge=reviewmerge`).
- [ ] `--export-review-summary`: Markdown for a PR body — `modeldiff` summary +
      open threads + approvals.
- [ ] Design verification report: read threads from the sidecar, add the
      approvals block; keep "open threads block PASS".

Flow: author pushes a branch → reviewers pull, open in the app, comment, push →
author replies and resolves → report shows approvals → merge gate is "no open
threads + one approval".

## Phase 1 — browser reviewers (static bundle)

Not everyone who must review will install a PySide6 app.

- [ ] Tag exported SVG elements with `data-node-id` / `data-edge-id` during SVG
      export.
- [ ] `export_review_bundle()` → `index.html`, `diagram.svg`, `model.json`,
      `review.json`.
- [ ] Static page: comment pins overlaid on the SVG by anchor id, thread
      sidebar, and the threat/control tables from the verification report.
- [ ] Write path without a backend: the page commits `*.review.json` to a branch
      through the GitHub/GitLab API with the reviewer's token. Zero infra, real
      write path, history for free.
- [ ] Fallback for hosts without an API token: "download comments as JSON" that
      the author imports (`union_merge`).

## Phase 2 — review service (only if live/notifications are needed)

- [ ] FastAPI + Postgres; entities mirror the sidecar schema 1:1 so the desktop
      storage layer is the same code pointed at HTTP instead of a file.
- [ ] REST: `POST /projects/{id}/revisions`, `GET /revisions/{hash}/threads`,
      `POST /revisions/{hash}/threads`, `POST /threads/{id}/comments`,
      `PATCH /threads/{id}`, `POST /revisions/{hash}/approvals`.
- [ ] `WS /ws/revisions/{hash}` — thread events + presence.
- [ ] Desktop: `Review → Connect…` (URL + token), background sync, "3 reviewers
      online".
- [ ] SSO identity — this is where "who approved" becomes legally meaningful.
- [ ] Slack / Teams webhooks, `@mention` parsing.

## Phase 3 — live co-editing (explicitly not planned)

Recorded only so it is not confused with the above. Would need a CRDT
(Yjs/Automerge) over the model graph and a rewrite of how the Qt scene applies
mutations. Review does not need it.

## Risks

- **Anchor stability** is the whole game; if `{kind, id}` resolution or the
  stale/orphan path is weak, threads rot and people stop trusting the tool.
- **Two sources of truth** during migration (in-node threads vs sidecar) — do
  the migration once, on open, and delete the old keys.
- **Identity by git config** is spoofable; acceptable for internal review, not
  for compliance sign-off. That is the trigger for Phase 2 + SSO.
- **One big model JSON** still conflicts on concurrent *model* edits. The
  sidecar fixes comments only; splitting the model per diagram is a separate
  piece of work if authoring ever goes parallel.

## Open questions (answer before starting Phase 0)

1. Can we run an internal service (even a small one), or must this stay
   file/git-based?
2. Are the models already in git per team, and is GitHub/GitLab reachable from
   the review page (for the Phase 1 write path)?
3. Do approvals need to be compliance-grade (SSO identity, immutable store), or
   is "git history + verification report" enough?

Answers to 1 and 3 decide whether Phase 2 is in scope at all; 2 decides whether
Phase 1 gets a real write path or the download/import fallback.
