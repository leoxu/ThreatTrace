# Asset Interface Model — Design

Refines `doc/asset-editor-design.md`. An asset is not a single access point —
it is **one logical resource exposed through several interfaces**, each a
distinct channel with its own syscall sequence. This is the core asset rework.

## The concept
Example — **Device Memory** is one asset, accessed two completely different ways:

| Interface | Who uses it | How (syscalls) |
|---|---|---|
| **MYDEV device node** (`/dev/mydev`) | user process | `fd = open("/dev/mydev")`, `ioctl(fd, MYDEV_IOC_ALLOC)`, … |
| **Device virtual address** | device hardware | direct access via a mapped device VA |

Both interfaces reach the **same** underlying memory. Threats, mitigations and
runtime evidence differ per interface, so the model must represent them
separately while keeping them attached to one asset.

## Model: Asset → Interfaces → Operations
```
Asset
  name        "Device Memory"
  class       "security asset"
  interfaces  [ Interface, Interface, ... ]      # one or more

Interface
  name        "MYDEV device node"
  path        "/dev/mydev"                        # identifier / resource path
  actor       "user process"                      # optional: who accesses via this interface
  direction   "in" | "out" | "bidir"              # drives the slot kind
  operations  [ Operation, ... ]                  # the syscalls exposed here

Operation  (reuses the compound-asset-operation format)
  name        "Allocate"
  steps       [ {call:"open",  role:"acquire"},
                {call:"ioctl:MYDEV_IOC_ALLOC", role:"operate"} ]
```
An Operation is one syscall (leaf) or an ordered compound (`open`→`ioctl`…),
carrying the acquire/operate roles from
`doc/compound-asset-operation-design.md`.

## Slots ARE interfaces
When an asset node is drawn, it generates **one slot per interface**, labelled
with the interface name (not generic `in`/`in-2`). Connecting an edge to a slot
therefore says "this actor accesses the asset *through this specific
interface*." Consequences:
- The edge's operation (sub-type) is restricted to **that interface's**
  operations (a tighter version of today's per-asset operation list).
- Slot kind comes from the interface `direction` (a device node the process
  calls into = input; a device-VA the hardware reads = could be output/bidir).
- This mirrors the **subgraph interface** mechanism (ports = slots), reused for
  assets — same slot-generation and rename-preserves-edges machinery.

## Descriptor (extends the asset-type descriptor)
`template/security/asset/<type>.asset.json`:
```jsonc
{
  "kind": "asset-type",
  "name": "Device Memory",
  "class": "security asset",
  "type": "device memory",
  "shape": "Box",
  "color": "#f2994a",
  "properties": { "type": {"default":"device memory","readonly":true}, "owner":"" },
  "interfaces": [
    {
      "name": "MYDEV device node",
      "path": "/dev/mydev",
      "actor": "user process",
      "direction": "in",
      "operations": [
        { "op": "Allocate", "steps": [ {"call":"open","role":"acquire"},
                                       {"call":"ioctl:MYDEV_IOC_ALLOC","role":"operate"} ] },
        { "op": "Free",     "steps": [ {"call":"ioctl:MYDEV_IOC_FREE","role":"operate"} ] }
      ]
    },
    {
      "name": "Device virtual address",
      "path": "dev-va",
      "actor": "device hardware",
      "direction": "bidir",
      "operations": [ "memory-read", "memory-write" ]
    }
  ]
}
```
Slots are generated from `interfaces` (like the subgraph generates slots from
ports); the old flat `slots`/`asset_operations` fields become derived data.

## Property panel — read-only presentation
Once an asset type is authored in the editor, an **instance's** property panel
shows the interface structure **read-only** (per the requirement "after editing
is done, all these properties are read only"):

```
Asset: Device Memory
Interfaces
  ▸ MYDEV device node   (/dev/mydev, user process, in)
      Allocate: open → ioctl:MYDEV_IOC_ALLOC
      Free:     ioctl:MYDEV_IOC_FREE
  ▸ Device virtual address (dev-va, device hardware, bidir)
      memory-read, memory-write
```
Editing the interfaces/operations happens **only** in the Asset Editor (type
level); the instance panel is a locked, expandable view. Any genuinely
per-instance fields (e.g. a concrete owner) stay editable; the interface
definition does not.

## Asset Editor UI (interface authoring)
The Asset Type Editor (from `asset-editor-design.md`) gains an **Interfaces**
section replacing the flat properties/operations tables:

- **Interfaces list** — add / delete / reorder interfaces. Each row: name, path,
  actor, direction.
- **Per-interface Operations table** — add / delete syscalls; each operation is
  a leaf syscall or a compound with ordered acquire/operate steps (the
  compound-operation editor).
- Adding/removing an interface adds/removes the corresponding slot; renaming an
  interface renames its slot and preserves connected edges (subgraph
  `apply_interface` pattern).
- **Save** writes the descriptor and live-refreshes toolbox / property schema /
  edge operation lists.

## Access-class filter — who is allowed on an interface
Each interface declares an **access-class filter**: a glob pattern (or
comma-separated patterns) over the *access class* of components allowed to
connect to it. Each component carries a hierarchical dotted **access-class**.

- **Component access-class** (dotted taxonomy): `software.application`,
  `software.library`, `software.kernel`, `hardware.device`, `hardware.engine`, …
  (the `software.*` / `hardware.*` split separates who runs code from what is
  wired in silicon).
- **Interface access-class filter** (glob): e.g. Device Memory —
  - interface[0] *MYDEV device node* (SW ioctl: allocate/map) → `software.*`
  - interface[1] *Device virtual address* (HW direct access) → `hardware.device`

**Rule (enforced in validation):** an edge from a component to an asset
interface is allowed **only if the component's access-class matches the
interface's filter** (`fnmatch` against each pattern). So a `software.library`
can call the MYDEV interface but **cannot** appear on the device-VA interface
(that's `hardware.device` only); a stray hardware block cannot drive the SW ioctl
path. Empty/unclassified components fail a restricted interface.

Storage:
- Interface descriptor: `"access-class": "software.*"`.
- The generated interface **slot** carries `access-class` in its properties, so
  validation reads it directly off the scene (no registry lookup).
- Component nodes carry an editable `access-class` property (templates set
  sensible defaults: host-app → `software.application`, dynamic-library →
  `software.library`, …).

This turns "only the right actor may reach this channel" into a checkable
diagram rule — the software/hardware access boundary is enforced per interface.

## Security controls protect interfaces
A security control is not attached to the asset as a whole — it **protects a
specific interface** (the channel is what you actually harden). E.g. a
file-permission / capability check guards the **MYDEV device node** interface
(who may `open`/`ioctl` `/dev/mydev`), while an MMU/SMMU control guards the
**Device virtual address** interface (what the device may read/write). The same asset
can have different controls on different interfaces.

Model:
- A security-control node carries `protects: [{asset_type, interface}]` (or an
  edge/link from the control to the interface's slot). The control thus binds to
  one or more interfaces, not the bare asset.
- **Coverage** is per interface: an interface with threats but no protecting
  control is an *unprotected interface* (a new validation finding). An interface
  with a control is covered.
- **Threat ↔ mitigation** already links a threat to control nodes
  (`mitigation_sc_ids`); now both are scoped to the interface — a threat on the
  MYDEV interface is mitigated only by controls that protect that interface, so
  "mitigated?" is computed correctly instead of asset-wide.
- **Rendering**: a control protecting an interface is drawn attached to that
  interface's slot (a small shield/badge on the slot, or a control node linked
  to it), so the diagram shows *which channel* is hardened.

### Editor / UI hooks
- In the Asset Editor, each interface row shows its **required/expected control
  kinds** (advisory), so an author can state "this interface must be behind a
  permission check."
- On the canvas, linking a security-control node to an asset targets a **specific
  interface slot** (not the asset centre); the property panel lists, per
  interface, the controls protecting it (read-only at instance level, consistent
  with the rest of the interface view).

## Verification payoff (design ↔ implementation)
Interfaces make conformance precise. The runtime log (`implmodel.py`) shows
`ioctl` on `/dev/mydev`; that maps to the **MYDEV device node** interface of the
Device Memory asset by `path`. Conformance can then report per-interface:
- observed operations vs the interface's declared operations,
- an interface declared but never exercised (unrealized),
- an undocumented interface/path touched at runtime (violation).
This is strictly sharper than matching an asset as a whole.

## Migration / compatibility
- An asset with today's flat `security-properties` + `asset_operations` entry is
  read as a **single default interface** (name = asset name, operations = its
  current list, slots = its current inputs). So existing models keep working and
  render unchanged until re-authored.
- Existing edges (connected to `in`/`in-2`…) map onto the default interface's
  slot; re-authoring into named interfaces uses the rename-preserving slot sync.

## Phasing
1. **Model + descriptor loader**: `Interface`/`Operation` dataclasses; extend the
   asset registry to read `interfaces`; derive slots + per-slot operation lists;
   single-default-interface fallback for legacy assets. Qt-free + tests.
2. **Rendering + binding**: asset slots generated per interface and labelled;
   edge sub-type restricted to the connected interface's operations.
3. **Property panel**: read-only interfaces view (expandable), instance fields
   still editable.
4. **Asset Editor**: interfaces add/delete/reorder + per-interface operation
   editing + save/live-refresh.
5. **Conformance**: per-interface matching by `path`.
6. **Security controls → interfaces**: link a control to an interface slot;
   per-interface coverage validation ("unprotected interface"); scope
   threat↔mitigation to the interface.

## Why this design
- **One asset, many interfaces** matches reality (same memory, different access
  paths with different threat surfaces) instead of forcing one asset per device
  node or losing the distinction.
- **Slots = interfaces** makes the diagram express *which channel* an actor uses,
  and reuses the proven subgraph slot/interface machinery.
- **Interfaces own their syscalls** unifies with compound operations, and gives
  conformance per-interface precision against the runtime log.
- **Read-only at instance level** keeps a type's contract authoritative — you
  author once in the editor, everywhere else it's a locked, faithful view.
- **Controls protect interfaces, not assets** — hardening applies to the channel
  that is actually attacked, so coverage and "is this threat mitigated?" are
  computed per interface instead of smeared across the whole asset.
```
