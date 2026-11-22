# Asset Relationships — Ownership, Lease, Containment, Mapping

Refines the asset model (`doc/asset-interface-model-design.md`). Introduces a
small vocabulary of **relationship edges** so the model can say *what is true*
about authority over assets — separate from the operation/IPC edges that say
*what happens*.

## Motivating example (device buffer sharing)
- **mydev owns** a memory pool; **MC** (a device buffer) is *part of* it.
- **mydrv owns** MG (a device virtual-memory range); **MG maps to MC**.
- Process **A owns nothing** — it holds a **handle** (a *lease* of MC) and a
  **device VA** (a *lease* of MG). Both are **revocable grants**, not ownership.

The security story is entirely about that distinction, so the model must make
ownership vs. lease first-class.

## Two layers of edge
- **Operation edges** (transient): the `ioctl`/syscall calls — *how* things
  happen. (Existing typed edges.)
- **Relationship edges** (durable facts): who owns / contains / maps / leases
  what — *what is true* about authority. **(New, this doc.)**

A relationship is usually the durable *result* of an operation:
`ioctl MYDEV_IOC_ALLOC` (operation) **mints** `lease(MC → A)` (relationship).

## The relationship vocabulary
| Relationship | From → To | Meaning | Render |
|---|---|---|---|
| **owns** | component → asset | lifecycle authority: allocate / free / **revoke** | solid line, filled ◆ at owner (UML-composition); asset in owner's boundary |
| **part-of** | asset → asset | MC is carved from the Pool | **nesting** (child asset inside parent) |
| **maps-to** (aliases) | asset → asset | MG translates to MC (same bytes, two names) | double-headed dashed line |
| **leases** (grants) | owner → holder | revocable, scoped access to an asset | **dashed arrow** owner ⇢ holder, labelled `lease: MC [rw]` |

## Address space — a separate axis from trust boundary
A **trust boundary** and an **address space** answer different questions and must
not be collapsed into each other:
- **Trust boundary** = a *privilege / authority domain* — **who owns and can
  control/revoke** an asset (security).
- **Address space** = a *naming / addressing domain* — **in which namespace the
  memory is addressed** (structure). A physical address is only meaningful in CPU
  space; a device VA only in device space.

They are orthogonal, but an address space is **owned and managed by exactly one
component**, so it lives *inside* that component's trust boundary. The model
therefore **nests** them:

```
trust boundary (privilege domain)
  └─ component (owner)
  └─ address space (asset, owned by that component)     ← "how it's addressed"
       └─ asset  (part-of the address space)            ← e.g. MC, MG
```

Modelling:
- An **address space** is a first-class **container asset** (`class: security
  asset`, `asset-kind: address-space`), e.g. *CPU Physical Space* owned by mydev,
  *Device VA Space* owned by mydrv.
- It sits **inside its owner's trust boundary** (the owner's privilege domain).
- Memory assets are **part-of** an address space (containment / nesting).
- Each asset has a **home space** = the one address space it is part-of.

### Which container does the CPU memory asset go in? → **both, nested**
Put MC in the **CPU Physical Space**, and put that space **inside mydev's trust
boundary**: `mydev boundary ⊃ CPU Physical Space ⊃ Pool ⊃ MC`. The address
space is a *finer* container **within** the owner's boundary — not an alternative
to it. Rule of thumb:
- owner / revoke authority / isolation → **trust boundary**,
- how the bytes are addressed / named → **address space** (nested inside it).

### maps-to is a cross-address-space translation
`MG ↦ MC` crosses **two address spaces** (device VA ↔ CPU physical) **and** two
trust boundaries — exactly the SMMU/IOMMU translation surface. A `maps-to` edge
whose endpoints have different home spaces is flagged **cross-space** and is a
prime location for aliasing / unauthorized-DMA / stale-translation threats.

### Shared-in-two-spaces (dma-buf) stays single-home
A buffer visible in both CPU and device space is **one asset with one home space**
(where it was allocated) plus **N `maps-to` edges** into the other spaces — not a
second containment. Keeps the invariant: *one asset, one owner, one home space,
N mappings.*

## Lease = a capability
A lease is a capability object carried by the holder:
```
Lease {
  asset      MC              # what is leased
  issuer     mydev           # the owner that granted it (only the owner may)
  holder     Process A       # who holds it now
  rights     [read, write]   # scope of the grant
  revocable  true
  lifetime   "until free"    # or a bound / session
  minted_by  <operation>     # e.g. MYDEV_IOC_ALLOC (an acquire-role op)
}
```
The **handle** is `lease(MC)`; the **device VA** is `lease(MG)`. Leases are minted by
`acquire`-role operations (the handle-producing syscalls).

## The ownership rule (the point of this doc)
**Only the owner of an asset may allocate, free, or REVOKE it.** Corollaries the
tool enforces/surfaces:
- A **lease** can only be **issued by the asset's owner** (`lease.issuer ==
  asset.owner`). A component leasing an asset it doesn't own is a violation.
- A **revoke** action is valid only from the owner. A non-owner "freeing" or
  invalidating an asset is a violation (privilege / confused-deputy).
- A holder may **use** a leased asset (within its rights) but may **not** revoke
  it, and (by default) may **not re-delegate** it (re-lease) unless explicitly
  granted that right.
- Ownership tells you *who can revoke*; leases tell you *who can currently
  touch it*. The gap between them is where the vulnerabilities live.

## Security payoff — threats become lease properties
With ownership/lease explicit, classic buffer-sharing bugs are visible on the
diagram instead of hidden in prose:
- **Use-after-revoke / dangling VA** — holder keeps `lease(MG)` after the owner
  frees MG (lease outlives the asset).
- **Over-grant** — `rights` wider than the holder needs → tampering surface.
- **Lease leak / illegal re-delegation** — the lease fans out to a third party
  the owner never authorised.
- **Confused deputy** — a component acts on a holder's lease without checking the
  holder actually holds it (redeem without validation).
- **Owner spoofing** — a non-owner issues or revokes a lease.
- **Aliasing / isolation break** — two leases onto overlapping regions of a
  parent asset (part-of + overlapping leases).

## Security checkpoint: owner-only operations must be unreachable by lessees
Operations on an asset split into two privilege classes:
- **use** operations — `read`, `write`, `map`, query — a **holder** may perform
  these *within the rights of its lease*.
- **owner-only** operations — `allocate`, `free`, **`revoke`**, `resize`,
  `reassign-owner` — only the **owner** may perform these.

**Checkpoint (design flaw if violated):** a non-owner must not be able to invoke
an owner-only operation on an asset. Two ways it shows up, both flagged:
1. An **operation edge** from a non-owner carrying an owner-only op
   (e.g. `A → MC : ioctl MYDEV_IOC_FREE`).
2. A **lease** whose `rights` include an owner-only op granted to a non-owner
   holder (e.g. `lease(MC → A)` with `rights = [rw, free]`).

Concretely: **if Process A can use its handle to `free`/`revoke` MC, that is a
critical design vulnerability** — A holds a *lease*, not ownership; the interface
that issued the handle must not expose free/revoke to the lessee. The model
makes this checkable: `op ∈ owner-only ∧ actor ≠ asset.owner  ⇒  violation`.

This is a real, high-value checkpoint: it catches confused-deputy and
privilege-escalation-via-handle bugs at design time, before any code exists.

Each operation in an asset interface therefore carries a **privilege class**
(`use` | `owner-only`); the asset editor lets the author mark it, and threat
generation seeds a High threat wherever an owner-only op is reachable by a
non-owner.

## Validation rules (new)
- **Owner-only op by non-owner** — an operation edge (or a lease right) exposing
  an owner-only op (`free`/`revoke`/`resize`/…) to a non-owner → **Error**
  (the handle-can-free-memory case).
- **Lease not from owner** — a `leases` edge whose source is not the asset's
  owner → Error.
- **Dangling lease** — a `leases` edge to an asset with no owner, or to a freed
  asset → Warning.
- **Re-delegation without right** — a holder issues a `leases` edge for an asset
  it only holds (doesn't own) and lacks a `may-delegate` right → Warning.

## Diagram (ownership + leases + address spaces)
```
                 Process A ── holds ──▶ lease(MC)=handle [rw]   lease(MG)=dev_va [rw]
                    ▲   ▲
                    ┊   ┊  leases (dashed = revocable grant; only owner may issue/revoke)
╔═ mydev boundary ══╪═══╪═══╗          ╔═ mydrv boundary ═════════════╗
║  mydev ◆owns      ┊   ┊   ║          ║  mydrv ◆owns                 ║
║  ┌ CPU Physical Space ─┐  ║          ║  ┌ Device VA Space ───────────┐ ║
║  │  Pool               │  ║          ║  │  MG  ◀╌╌ maps-to ╌╌┐     │ ║
║  │    └ MC (part-of) ┘ │◀╌╫╌╌╌╌╌╌╌╌╌╌╫╌╌┼╌╌╌ cross-space ╌╌╌┘     │ ║
║  └─────────────────────┘  ║          ║  └────────────────────────┘ ║
╚═══════════════════════════╝          ╚══════════════════════════════╝
   boundary ⊃ addr-space ⊃ asset          MG ↦ MC crosses BOTH spaces
```

## How it maps to the tool
- **owns / part-of / maps-to / leases** = a new **relationship-edge category**,
  visually distinct from operation/IPC edges (no arrowhead / dashed / diamond
  markers per the table). `type: "relationship"`, `sub-type` = the relation.
- **owns**: an asset gains an `owner` (component node id); the asset lives in the
  owner's trust boundary; draw the ◆ link. Default owner = the component whose
  `acquire`-role op mints the asset, if unset.
- **address space**: a container asset (`asset-kind: address-space`) nested inside
  its owner's trust boundary; memory assets are **part-of** it (reuse node
  containment). Each asset records its **home space**; `maps-to` between
  different home spaces is tagged **cross-space**.
- **part-of**: reuse existing node containment (parent-id / children).
- **maps-to**: asset↔asset edge, sub-type `maps-to`; cross-space when endpoints'
  home spaces differ.
- **leases**: owner→holder edge carrying the Lease capability
  ({asset, rights, revocable, lifetime}); minted by an acquire-role operation.
- **revoke**: an operation flagged `revoke` on the asset; validation checks the
  actor equals the owner.

## Why this design
- **Ownership ≠ possession.** Making the two separate relationships is what lets
  the model express leases, delegation, and revocation — the core of any
  sharing/IPC security story.
- **Only-owner-revokes** is a single, enforceable invariant that catches a whole
  class of privilege/confused-deputy bugs.
- **Small vocabulary (4 relations)** layered over the existing asset/interface
  model — no parallel system; operation edges stay as they are.
- **Leases carry rights + lifetime**, so use-after-revoke, over-grant and leak
  are checkable, not just drawable.
```
