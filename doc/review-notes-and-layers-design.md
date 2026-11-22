# Review notes and layers — design

## Review notes

A review note is a speech bubble the reviewer drops next to whatever they are
questioning (`template/review-comment.json`, `class: review comment`,
`type: Bubble`). It carries a thread, not a single string:

```json
"subject": "Review question",
"review-status": "open",
"comments": [
  {"text": "...", "author": "alice", "role": "reviewer", "at": "2026-08-20 17:19"}
]
```

`review.py` is the Qt-free model over that dict: `read_thread`, `add_comment`,
`set_status` / `toggle_status`, `summary`, `canvas_text`. Because the thread
lives in the node's own properties it is saved, copied, undone and diffed with
the rest of the model — no side registry.

**Roles.** The first entry defaults to `reviewer` (the question), later ones to
`author` (the replies); the author name comes from `$USER`. Reviewer entries are
tinted amber, author entries blue.

**Shape.** `Bubble` is a node shape kind of its own: `_bubble_path()` unions a
rounded balloon (the padded node box) with a tail triangle. The same path is the
hit region (`shape()`), so only the balloon and its tail are clickable.

**Adjustable anchor.** The tail tip is stored in the note's own properties as
`tail-anchor: [x, y]` in node-local coordinates (default: just below the
balloon, left of centre) and is dragged by `BubbleTailHandleItem`, a round
handle shown with the resize handles when the note is selected.
`_bubble_tail_triangle()` picks the side the tail leaves from — bottom, top,
left or right — from where the anchor sits, keeps the base off the rounded
corners, and returns `None` when the anchor is inside the balloon (no tail
drawn).

**Moving the note keeps the anchor.** The tail points at something in the
diagram, so dragging the note leaves the anchor where it is: on an interactive
move `itemChange` compensates the node-local anchor by the movement delta, and
the tail stretches into a leader line. This applies only to a direct drag of the
note itself (`_user_moving`, set in `mousePressEvent`) — a parent/group move
carries the target along so the anchor moves with the note, and programmatic
`setPos` during load, paste or layout must never shift a stored anchor. `tail-anchor` is in `review.MANAGED_KEYS`, so like the thread it is
never rendered or stringified by the generic property rows.

**Geometry split.** The tail may stick out of the node's box, so `boundingRect()`
is the box united with the anchor while the new `node_rect()` (0, 0, w, h) is
what resize handles, boundary membership and parent containment use. Anything
that means "the node's own box" must use `node_rect()`.

**Reload.** Diagrams persist `node.shape_kind` as the node type and resolve it
against the built-in template specs by name, so a shape kind only survives a
save/load cycle if a template named after it exists — hence `template/bubble.json`
(a plain `Bubble` shape), which `review-comment.json` extends.

**On the canvas** (`NodeItem._paint_review_note`) a note shows a status stripe
(amber open / green resolved), the subject, the latest entry wrapped and
elided to fit (`_fit_text`), and a `N comments · status` footer.

**In the properties panel** a *Review Thread* section renders each entry as a
card, plus a reply box and an `Add Comment`/`Reply` button and a
`Resolve`/`Reopen` toggle. The thread keys are in `review.MANAGED_KEYS`, so the
generic property rows neither render nor stringify them, and `_collect()` always
carries them through untouched.

**In the design verification report** open threads are a blocking item, and
section 8 lists every thread with its full history — an unanswered review
question stops the design from reading as PASS.

## Layers

Every node has a `layer` property; missing means the base `model` layer. Review
notes ship with `"layer": "comment"`.

`layers.py` provides `node_layer`, `scene_layers` (built-ins first, then any
custom layer found on a node) and `apply_visibility(scene, hidden)`. Hiding is
pure view state: nodes on a hidden layer get `setVisible(False)`, and an edge
hides when either endpoint (or, for alias edges, either linked node) is hidden.

**View → Layers** is rebuilt on `aboutToShow`, so a layer introduced by editing
a node's `layer` property appears without a restart; each entry is a checkable
toggle and `Show All Layers` clears the set. The hidden set survives diagram
switches (re-applied at the end of `_deserialize_scene`), applies to nodes
dropped while a layer is off, and is persisted in the project file under
`hidden-layers`.

Because `QGraphicsScene.render` skips invisible items, turning the comment layer
off before exporting a report or PNG removes the notes from the image — the
intended way to produce a clean artifact without deleting the review history.
