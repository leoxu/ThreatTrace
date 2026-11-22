# Verification Lifecycle — design + TODO

**Status: TODO — mostly not implemented.** The design phase exists today
(threats, controls, mitigation coverage, design verification report) and so does
the raw material for the runtime phase (`implmodel.py` log import,
`conformance.py` design↔implementation diff, `modeldiff.py`). What this document
adds is the **code phase**, the **test phase**, and — the part that turns four
features into one system — the **evidence ledger** they all write to.

Goal: every claim the model makes can be verified, and carries the evidence for
why anyone should believe it. A threat is mitigated by a control; the control is
implemented in named code; the code is exercised by a named test; the test ran on
target and produced the observable the control promised. Design → code → test →
verification, in one model, with the links intact in both directions.

## The four phases

| Phase | Question it answers | Evidence it produces | State today |
|---|---|---|---|
| **1. Model & threats** | What are we building, and what can go wrong? | threats per connection and per sequence, reviewed | **done** |
| **2. Design mitigation** | What stops each threat, and does it? | control ↔ threat verdicts with rationale + residual risk; design verification report | **done** |
| **3. Code** | Is the interface actually defined, and is each control actually implemented? | per-control static findings with `file:line` citations; static verification report | **TODO** |
| **4. Test & runtime** | Does it behave that way on target? | per-control test specs; runtime-log evidence; dynamic verification report | **partly** — log import and conformance diff exist; test specs and manifest-driven verdicts do not |

Phases 3 and 4 are not new analyses bolted on the side. They answer the same
question the design phase answers — *is this claim true?* — with a different kind
of evidence.

## Core decision: an evidence ledger

Today each report re-derives its verdict from whatever it can see at the time.
With four phases, evidence about one claim arrives months apart, from different
people and different machines. So evidence becomes a first-class record and the
verdict becomes a **function of it**, never a stored opinion.

```
Claim      — attached to a model element, one verifiable statement
Evidence   — attached to a claim: phase, source, detail, citation, provenance
Verdict    — derived: VERIFIED / PARTIAL / UNVERIFIED / REFUTED / STALE
```

```jsonc
{ "claim_id": "CL-14",
  "subject": { "kind": "control", "id": "c-9f2…", "element": "File Permission (ACL)" },
  "statement": "implemented on interface device address-space (SW ioctl)",
  "evidence": [
    { "phase": "design", "source": "claude-cli", "verdict": "supports",
      "detail": "Mitigates T-3: unprivileged open is refused by the device node ACL",
      "accepted_by": "alice", "at": "2026-08-14T10:22Z",
      "provenance": { "controls_hash": "6b1f…" } },

    { "phase": "static", "source": "claude-cli", "verdict": "supports",
      "detail": "mydrv_as_dev_open() rejects callers failing inode_permission()",
      "citation": [ { "repo": "mydrv", "rev": "a4f19c",
                      "file": "drivers/mydrv/ioctl_as.c",
                      "lines": [214, 231] } ],
      "accepted_by": "alice", "at": "2026-09-20T09:03Z" },

    { "phase": "dynamic", "source": "runtime-log", "verdict": "supports",
      "detail": "SEC-C14-neg: open(/dev/mydrv/dev0/as) as uid 1000 → EACCES",
      "provenance": { "build": "6.0.4-rel", "log": "vksc_01tri-linux.log",
                      "manifest_hash": "b77e…" } }
  ] }
```

Claim subjects, and what they mean:

| Subject | Claim |
|---|---|
| interface | "this access channel exists in the implementation" |
| control | "this control is implemented on the interface it covers" |
| control | "this control behaves as specified at runtime" |
| threat | "this threat is mitigated" (aggregates its controls' claims) |
| operation | "these syscall steps are what the code actually does" |

**Verdict rules.** A threat is only `VERIFIED` when every control it depends on
is verified at every phase that applies. Absence of evidence is `UNVERIFIED`, not
a pass. Contradicting evidence (`refutes`) beats supporting evidence — a failing
test is not outvoted by an agent's opinion.

### The coverage matrix

The ledger's main view, and the artifact the whole lifecycle is aiming at:

| Element | designed | mitigated | implemented | tested | observed |
|---|---|---|---|---|---|
| `…/dev0/as` (SW ioctl) | ✓ | 3 controls | 3/3 | 4 tests | ✓ |
| Device virtual address | ✓ | 1 control | 0/1 ⚠ | — | ✓ |
| `…/dev0/ctrl` | — ⚠ | — | — | — | ✓ observed, never modelled |

Each existing report becomes a filter over the same ledger, which is what keeps
the four phases consistent instead of four opinions about the same system.

## Phase 3 — code-level verification

### What the model gains

Controls gain an implementation binding. Interfaces already carry the anchor
(`path`, and each operation's `steps` with the real syscalls), so the binding
only has to name where the code lives:

```jsonc
"implementation": {
  "repo": "mydrv", "rev": "a4f19c",
  "files":   ["drivers/mydrv/ioctl_as.c"],
  "symbols": ["mydrv_as_dev_open", "mydrv_as_ioctl"]
}
```

A control with no binding is a **finding** ("unbound control"), not a reason to
scan the whole tree.

### Two questions, answered differently

**3.1 Is the interface defined?** Largely deterministic — a device-node
registration, a file-operations table, an ioctl switch on the command the model
names. Answer it with search (ripgrep + tree-sitter/ctags), not an agent: cheap,
fast, reproducible, and it produces the citation for free.

**3.2 Is each control implemented there?** A judgement call, so an agent — with
two rules that keep it honest:

- **Locate deterministically, judge with the model.** The scan is scoped to the
  bound files and symbols and their callees, never the repository.
- **Cite or fail.** A verdict without a `file:line` span is not a pass, it is
  `INSUFFICIENT EVIDENCE`. This is the rule that stops the feature becoming a
  machine that says "looks good" about code it never read.

The plumbing is the mitigation pass with a different question: worker thread,
cancellation, batching, `parallel.MAX_PARALLEL_CALLS`, conservative merge across
backends, and a review dialog where a human accepts each verdict.
*Does this control mitigate this threat?* becomes *does this code implement this
control?* — same shape, same code paths (`mitigation.py` is the template).

### Output

`node_editor/codeverify.py` (Qt-free) → `StaticFinding{claim, status, citation,
rationale, backend}`, a review dialog, ledger entries, and a **static
verification report** in the existing report family: per interface, per control,
what was found and where, and an explicit list of the unbound and the uncited.

## Phase 4 — tests as evidence

### Generate the assertion, not the happy path

A security control's test is almost always **negative** — the thing that must
fail. Generation therefore starts from the control's configuration and produces a
declarative spec:

```jsonc
{ "test_id": "SEC-C14-neg",
  "control_id": "c-9f2…",
  "claim_id": "CL-14",
  "intent": "a process outside group `dev` cannot open the AS device node",
  "setup":  ["run as uid 1000, groups=[users]"],
  "action": "open(\"/dev/mydrv/dev0/as\", O_RDWR)",
  "expect": { "syscall": "open", "path": "/dev/mydrv/dev0/as", "ret": -13 } }
```

The tool emits three things:

1. the **spec** (stored in the model, reviewable, diffable);
2. a **skeleton** in the harness SQA actually uses — generated, then owned by
   them;
3. a **manifest**: `test id → control id → claim id → expected observable`.

**The tool stops at the spec and skeleton.** Owning an on-target harness,
toolchain and flake budget is a different project; the manifest is the contract
between the model and whoever runs the tests.

### Manifest-driven log import

Today's log import builds an implementation model and diffs it against the design
(`implmodel.py` + `conformance.py`), which finds what nobody thought to test:
undocumented access, unexpected boundary crossings, unrealized allowances. That
stays. The manifest adds the other half: with `expected observable` in hand, the
import can decide **per control** whether the runtime did what the control
promised, and write `supports` / `refutes` evidence into the ledger.

So the dynamic verification report has two sections that answer different
questions:

- **Asserted** — every control with a test: passed / failed / not exercised.
- **Discovered** — the conformance diff: what ran that the design never described.

## Staleness — the thing that will quietly rot this

Evidence decays faster than models, and stale evidence shown as a green tick is
worse than no evidence. The pattern already exists in `threat_sync.py` and
generalises:

| Evidence | Provenance stamp | Goes stale when |
|---|---|---|
| design | `context_hash`, `controls_hash` | the connection or the controls change |
| static | repo `rev` + control config hash | the code moves or the control is re-specified |
| dynamic | build id + manifest hash | the build or the test spec changes |

A stale entry reads `VERIFIED (stale: code moved 3 revs)` and the matrix shows it
amber. Re-verification is then a targeted re-run of one claim, not a full sweep.

## CI and gating

Everything above is headless-capable (`commands.py`, `run_commands`), so the
lifecycle can be a pipeline rather than a habit:

```
verify-design  <model.json>                 → design verdict + gaps
verify-static  <model.json> --repo <path>   → static findings, per control
verify-dynamic <model.json> <log> [manifest]→ asserted + discovered
verify-report  <model.json> --format pdf    → the coverage matrix
```

Suggested gate: **no High-priority threat may be marked mitigated without fresh
evidence at every phase that applies to it.** That is a single query over the
ledger, and it is the sentence that makes the whole thing worth building.

## Risks, and the answers

- **An agent that says yes.** Cite-or-fail; scope-bounded scans; conservative
  merge across backends; and for a High-priority control, a **human attestation**
  field — an audit trail that answers "an agent, once, in August" is worthless.
- **Scanning does not scale by brute force.** No binding, no scan: report it.
- **Test generation over-reach.** Spec + skeleton + manifest only.
- **Log fidelity.** Dynamic evidence is only as good as the instrumentation; the
  manifest must record which hook/build produced the log, or "not exercised" and
  "not observable" become indistinguishable.
- **Ledger bloat.** Evidence is append-only per claim but superseded entries
  collapse: keep the latest per (claim, phase, source) plus anything a human
  accepted.

## Phased plan

### Phase A — the ledger and the matrix (no new analysis)   ← start here
`node_editor/ledger.py` (Qt-free): claim/evidence/verdict types, derivation
rules, and a migration that turns today's mitigation verdicts into design
evidence. A **Coverage** panel and a report section. Immediately useful: it shows
the design-phase gaps in one table, and every later phase just adds rows.

### Phase B — implementation binding
`ControlDef.implementation` + the interface's existing `path`/`symbols`, editing
in the control dialog, "unbound control" validation finding, and an agent-assisted
*propose the binding, human confirms* flow (same pattern as threats).

### Phase C — static verification
`codeverify.py`: deterministic locate → agent judge with citations → review →
ledger + static report. CLI `verify-static`.

### Phase D — test specs and manifest-driven dynamic verification
Spec generation from controls, skeleton export, manifest, manifest-aware log
import, dynamic report with **Asserted** and **Discovered** sections.

### Phase E — CI gating and staleness surfacing
The verify-* commands as a pipeline, amber staleness in the matrix, targeted
re-verification.

Each phase is independently useful, which matters because C and D depend on
access and workflow (source tree, SQA harness) that the tool does not control.

## Open questions (answer before starting Phase B)

1. **Where does the binding come from** — typed by hand, or proposed by an agent
   from the interface path and confirmed? (Recommend: proposed, human confirms.)
2. **What harness does SQA run** — gtest, a shell harness, something internal?
   That decides what "generate a test" produces.
3. **Is the source tree on the same machine as the model**, or must the static
   scan run elsewhere and post evidence back? Menu action vs CI job.
4. **Which requirement system is authoritative** — `ControlDef.requirement_id`
   already points at one; the ledger should carry that id so the matrix can be
   read as requirement coverage.
5. **Who may attest**, and does an attestation expire with the code revision?

## Related

- `doc/impl-verification-design.md` — log → implementation model, conformance diff.
- `doc/mitigation-coverage-design.md` — the design-phase verdict machinery this
  reuses (scope, batching, review, cancellation, staleness hashes).
- `doc/design-verification-report-design.md` — the report family this extends.
- `doc/asset-definition-design.md` — interfaces, paths and operation steps: the
  anchor that ties a model element to code and to a runtime log.
