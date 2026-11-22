# Design Review — "Security Knowledge Graph Platform"

**What this reviews.** A 19-page product design (`安全建模工具设计`, ChatGPT
session exported to PDF, read locally) arguing that a new security modelling
tool should not be "another diagram + STRIDE tool" but a **Security Knowledge
Graph Platform**, positioned as *Continuous Security Modeling*:

> "Your architecture changes. Your security model changes automatically."

**Status: review, not a plan of record.** Nothing here is committed work. It
records what the proposal asks for, what ThreatTrace already does, where I think
the proposal is wrong for *this* tool, and the three things I would take from it.
Where it agrees with `doc/verification-lifecycle-design.md`, I say so rather than
duplicating the plan.

## What it proposes

Seven modules, in a pipeline that ends in an auditable artifact:

```
Architecture ──▶ Security Graph ──▶ Threat / Attack Graph / Risk engines
                      ▲                          │
              CVE · SBOM · Code ─────────────────┘
                      ▼
        Controls ──▶ Requirements ──▶ Security Case
```

1. **Architecture modelling** — components (ECU, CPU, process, VM, …),
   interfaces (CAN, Ethernet, PCIe, BLE, …), per-component security attributes
   (C/I/A, authenticity, authorization, non-repudiation, safety, privacy) and
   trust boundaries.
2. **Security Graph** — the core claim: stop storing "node + edge + properties"
   and store a typed graph whose nodes include *component, asset, interface,
   credential, data, threat, vulnerability, control, requirement* and whose edges
   include *communicates_with, trusts, accesses, authenticates, attacks,
   mitigates, satisfies, derived_from*. Then questions like "can an attacker on
   the internet reach the device?" become graph queries.
3. **AI threat generation** — the agent proposes; the engineer disposes. The
   proposal carries a **confidence** score, a **reason**, and an **evidence**
   list, with Accept / Modify / Reject. Explicitly: *"AI 不能直接决定"* — the AI
   must not decide by itself, or enterprises will not use it.
4. **Attack graph** — not "Spoofing exists" but "the attacker enters at WiFi and
   reaches the ADAS ECU in 7 steps", with feasibility, impact and risk per path.
5. **Risk engine** — multi-factor rather than impact × likelihood:
   `impact × exposure × attack feasibility × privilege distance × attack surface
   × exploitability × propagation`.
6. **CVE / SBOM / SAST hooked onto the graph** — a component version maps to
   CVEs, which extend the attack graph, turning the model from a static document
   into a *living* one.
7. **Code → security model** — source → AST → CFG → call graph → data-flow →
   security graph, plus **bidirectional architecture ↔ code navigation**: click a
   component to see its files; open `dev_ioctl()` to see its threats, attack
   paths, requirements and CVEs.

Then: an **AI Security Copilot** ("what is the biggest risk in this system?"),
**autonomous attack simulation** (an AI red team given "assume physical USB
access"), **security regression** (architecture diff → threat diff → risk diff →
CI gate PASS/FAIL), **variant management** (one base model, per-market/trim
variants, recompute only the diff) and a **compliance graph**
(ISO 21434 / UNECE R155 / IEC 62443 / ISO 27001 / NIST / CRA →
threat → goal → requirement → control → test → evidence).

Its five priority bets: AI architecture→threat, the graph itself, attack graphs,
architecture→code→CVE, and security regression.

## Where ThreatTrace already stands

| Module in the proposal | Here today |
|---|---|
| Architecture modelling, trust boundaries, security attributes | **Have.** Deeper than the sketch on interfaces: an asset exposes named interfaces with a path, an actor, a direction, an access-class filter and per-interface operations broken into syscall steps (`doc/asset-definition-design.md`). |
| Typed security graph as the store | **Partly.** The model *is* nodes + typed edges with threats and controls attached, and ownership/lease/part-of/maps-to relationships are designed (`doc/asset-relationships-design.md`). What is missing is a **query/traversal layer**, not a new store. |
| AI proposes, engineer disposes | **Have.** `ThreatReviewDialog` gates every generated threat; the mitigation verdicts get their own review with rationale and residual risk. Missing: a **confidence** value and a structured **evidence** list on each proposal. |
| Controls and mitigation | **Have, and further along than the proposal.** Coverage is geometric and per interface, judged per control definition, merged conservatively across backends, with rationale and residual risk stored on the threat (`doc/mitigation-coverage-design.md`). |
| Attack graph / attack paths | **Missing.** The Attack Surface panel rolls threats up by entry point; there is no path search. |
| Multi-factor risk engine | **Partly.** `threats_report.risk_score` is priority with a mitigation discount; CVSS fields exist on `Threat` but were deliberately left unused. |
| CVE / SBOM / SAST | **Missing.** |
| Code → model, architecture ↔ code | **Planned, narrower, stricter.** `doc/verification-lifecycle-design.md` Phases B–C: bind a control to files/symbols, then verify with deterministic location plus an agent judgement that must cite `file:line` or return INSUFFICIENT EVIDENCE. |
| Security regression → CI gate | **Partly.** `modeldiff.py` (model diff), `conformance.py` (design↔implementation), headless `commands.py`; the gate itself is Phase E of the verification doc. |
| Variant management, compliance graph, security case | **Missing.** Threats carry CWE/NIST/OWASP tags and controls carry a `requirement_id`, which is the hook a compliance mapping would use. |
| Runtime evidence | **Have — and the proposal never mentions it.** `implmodel.py` builds a model from a real syscall log and `conformance.py` diffs it against the design. |

## What it gets right

- **The disconnection diagnosis.** Architecture, threats, controls, code and
  evidence living in separate artifacts *is* the problem worth solving, and it is
  the same conclusion `verification-lifecycle-design.md` reached independently.
- **"AI must not decide."** Confidence + reason + evidence + explicit accept is
  exactly the right shape, and it is already how generation and mitigation work
  here. The missing half is that our proposals do not carry their confidence or
  their evidence in a structured field.
- **Regression over re-analysis.** "This architecture change added two Critical
  risks" is far more useful than re-running a whole TARA, and it is achievable
  with what is already in the repo.
- **Attack paths beat isolated findings.** A path from an entry point to an asset
  is a better unit of review than a threat on one connection.

## Where I disagree, and why

**1. The framing is automotive TARA; our depth is OS and driver internals.**
The proposal's vocabulary is CAN/LIN/ECU/gateway and its competitive set is
medini, CycurRISK, EnCo SOX. This tool's actual advantage is the layer below
that: device-node interfaces with real paths, operations decomposed into
syscalls, QNX abilities and Linux capabilities, ownership and lease semantics for
buffers, and conformance against runtime syscall logs. Adopting the ECU
vocabulary wholesale would trade a defensible niche for a crowded one.

**2. "Rewrite the store as a Security Graph" is a big-bang refactor for little
gain.** The model is already a typed graph; the proposal's own motivating
example — "can the internet reach the device?" — needs *traversal and queries*, not
a new persistence format. A query layer over the current model is days of work
and keeps every existing feature (diff, reports, conformance, undo, JSON review)
working. Re-platforming risks all of it for the same answer.

**3. The multi-factor risk formula invents precision.**
`impact × exposure × feasibility × privilege distance × attack surface ×
exploitability × propagation` has seven uncalibrated factors; small errors
multiply into a number that looks authoritative and is not. CVSS was deferred
here for the same reason. If risk grows, it should grow toward things the model
*knows* — boundary crossings, privilege distance measured in graph hops, whether
a covering control exists — and each factor should be explainable in the report.

**4. Autonomous attack simulation is the wrong thing to build early.** An AI red
team over an unverified model produces plausible attack stories with no evidence
behind them — the opposite of the direction the verification ledger takes. It
becomes interesting only *after* attack paths are computed from the model itself,
where the agent's job is judging feasibility of a concrete path rather than
inventing one.

## What I would take from it

### A. Attack paths (the real gap)

Everything needed is already modelled: trust boundaries, components with an
access class, assets with interfaces, and ownership/lease edges. A Qt-free
`attackpath.py` would:

- pick **entry points** — nodes outside every trust boundary, or on an interface
  whose access-class filter admits untrusted callers;
- walk the existing edges, crossing into a component only where a connection
  exists, scoring each hop by what the model knows: a trust-boundary crossing, a
  privilege change, an interface with no covering control, threats already
  recorded on that connection;
- report `AttackPath{entry, steps[], target asset, crossings, uncovered hops}`,
  ranked, with each step naming the connection and its threats.

This upgrades every existing threat from "this connection is risky" to "here is
how someone reaches it", and it needs no new data. It also gives the coverage
matrix a column worth having: *is any hop on this path uncovered?*

### B. Confidence and evidence on every AI proposal

Add to the generated `Threat`: `confidence` (0–1) and `evidence: List[str]` — the
specific model facts the agent used (crossed boundary, missing control, interface
path, security property). The review dialog shows them; the reports print them.
Small change, and it turns "the agent said so" into something a reviewer can
check. It is also exactly the shape the verification ledger wants for design-phase
evidence.

### C. Regression as a gate, not a report

`modeldiff.py` + the threat/control state already allow: diff two model versions
→ new/changed connections → threats affected → risk delta → non-zero exit. Wire
it to the `verify-*` commands from the verification doc so a CI job can fail a
change that adds an unmitigated High. This is the proposal's strongest enterprise
argument and the cheapest of the three to build here.

## What I would defer

Variant management, the compliance graph, SBOM/CVE ingestion, the Security Case
document and the Copilot chat. Each is real work justified by a customer, not by
a design document — and three of them (compliance, security case, variants) only
pay off once the evidence ledger exists to hang them on.

## Open questions

1. **Who is the user?** The proposal targets an automotive TARA buyer. If that is
   the goal, the roadmap changes (ISO 21434 clause coverage, variants, attack
   feasibility scoring). If the user is a platform security engineer working on
   Linux/QNX stacks, attack paths + code/runtime evidence matter far more.
2. **Is CVE/SBOM in scope at all?** It is the proposal's fourth bet, and it needs
   component→version→CPE identity resolution that this model does not have today.
3. **Does risk need to be a number?** Priority + mitigation state + path exposure
   may serve reviewers better than a computed score, and it cannot be gamed.

## Related

- `doc/verification-lifecycle-design.md` — design → code → test → evidence, the
  ledger, and the phased plan this review defers to.
- `doc/mitigation-coverage-design.md` — controls, coverage and the
  generate/update rules.
- `doc/asset-definition-design.md`, `doc/asset-relationships-design.md` — the
  interface and ownership model the attack-path search would traverse.
- `doc/impl-verification-design.md` — runtime log → implementation model →
  conformance, the piece the reviewed proposal does not have.
