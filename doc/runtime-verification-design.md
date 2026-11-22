# Runtime (dynamic) verification — design

**Status: design + phase 1 implementation.** Static verification asks whether a
control exists in the source; this asks whether it *behaves* that way on target.
The answer comes from a test that SQA runs and a log the tool reads back.

Companion to `doc/verification-lifecycle-design.md` (the four phases and the
ledger) and `doc/codeverify`-side notes in `threattrace-design.md` §6.

## The shape of it

```
control type → test template        (shipped data, one per control type)
control instance × covered interface → test spec   (placeholders filled from the model)
        ↓                                   ↓
  harness skeleton                    manifest: test → control → expected observable
        ↓                                   ↓
   SQA runs it on target ──▶ syscall log ──▶ matcher ──▶ Verified in runtime
```

Two things make this tractable:

* **The test template belongs to the control type.** A File Permission control is
  always verified the same way — an unprivileged actor must be refused. Writing
  that once per *type*, as data, means every instance of that control in every
  model gets a test for free. Templates live in
  `template/security/control_tests.json`, exactly like
  `interface_categories.json`.
* **The expectation is written in the log's own vocabulary.** The runtime capture
  (`implmodel.parse_log`) yields records of `op`, `resource` (a path or an fd's
  link), `cmd` (the ioctl) and the raw fields including `ret`. An expectation is
  a filter over those four, so matching is deterministic — no agent is asked to
  interpret a log.

## Negative first

A control that is working is usually invisible in a log: the happy path looks the
same whether or not anything is enforcing it. What proves a control is the
attempt that must **fail**:

| Control | The test that proves it |
|---|---|
| File Permission (ACL) | a process outside the owning group opens the node → `EACCES` |
| QNX Ability | a process without the ability performs the guarded devctl → refused |
| Address Space Isolation | client A dereferences a device VA belonging to client B → fault, not data |
| Secure Boot | an unsigned image is offered → rejected before use |

So every template declares its `kind`: `negative` (must be refused) or
`positive` (must work — for controls whose absence would break the feature, and
as a control against a target that refuses everything because it is broken).

## The test template

```jsonc
{ "control_type": "File Permission (ACL)",
  "tests": [
    { "id": "unprivileged-open-denied",
      "kind": "negative",
      "title": "Unprivileged process cannot open {path}",
      "applies_to": ["ioctl", "filesystem", "sysfs", "socket-local", "pipe"],
      "requires": ["drop-privileges"],
      "intent": "Only members of the owning group may open the node.",
      "steps": [
        "Run as a user that is not in the node's owning group",
        "open(\"{path}\", O_RDWR)"
      ],
      "expect": { "op": "open", "resource": "{path}", "ret": "EACCES" },
      "evidence": "A denied open proves the permission is enforced by the OS." } ] }
```

* `applies_to` — interface categories the test makes sense on. A file-permission
  test on a **DMA** interface is nonsense: nothing opens anything. Instantiation
  skips those rather than emitting a test nobody can run.
* `requires` — what the target environment must allow (`drop-privileges`,
  `second-client`, `unsigned-image`). Surfaced so SQA knows what the run needs,
  and so a spec that the environment cannot satisfy is visible rather than
  silently failing.
* `expect` — the observable, in log vocabulary. `ret` accepts an errno name
  (`EACCES`), a number (`-13`), or `"!=0"` / `"0"` for "failed" / "succeeded".
* Placeholders are filled from the model: `{path}`, `{device}`, `{asset}`,
  `{interface}`, `{control}`, `{config}`, `{ioctl}`, `{operation}`.

## Instantiation

`runtime_tests.build_specs(scene)` walks the same coverage as mitigation and
static verification — control definition × the asset interfaces its circle
covers — and for each pair emits one spec per applicable template. A spec is
concrete: a real device path, the real ioctl names from the interface's
operation steps, and the control's own configuration text quoted for the person
who has to run it.

## The manifest is the contract

The tool produces three artifacts and stops:

1. **specs** — reviewable, stored in the model so they diff;
2. **skeletons** — a runnable stub per spec in the harness SQA uses (shell by
   default; the harness is a setting, not an assumption);
3. **manifest** — `test id → control id → expected observable`, the only thing
   the matcher needs later.

Owning an on-target harness, toolchain and flake budget is a different project.
The manifest is the contract between the model and whoever runs the tests.

## Matching a run

`match_log(specs, log_text)` parses the capture once and, per spec, looks for a
record satisfying `expect`:

| Outcome | Meaning |
|---|---|
| **pass** | a matching record was found (for a negative test: the refusal happened) |
| **fail** | the opposite happened — e.g. the unprivileged open *succeeded* |
| **not-exercised** | nothing in the log touched that path/ioctl at all |

`not-exercised` is deliberately not a failure: it means the test did not run, and
a report that conflates "not run" with "broken" trains people to ignore it.

## What it writes back

A pass records **dynamic evidence** on every (threat, control) link that relies
on the control — the same per-link record static verification writes, in the
other phase — so the status becomes *Verified in runtime*, or *Verified in source
code + runtime* when both agree. A fail records `RESULT_FAILED`, which the label
logic reports as **Failed in runtime** and which beats any positive static
evidence: code that exists but does not behave is not a mitigation.

## Deliberately not doing

* **No LLM in the matcher.** The observable is exact; an agent adds only doubt.
  (An agent *may* later draft a spec for a control type with no template — and
  that draft is reviewed like a generated threat.)
* **No test execution.** No target access, no flake ownership.
* **No new log format.** If a platform's capture differs, it needs a reader, not
  a new pipeline.
