# Asset Definition — Design & Reference

Defines how a **security asset type** is described in ThreatTrace: the
`*.asset.json` descriptor, its interface/operation model, and how each field is
used by the tool. This is the authoritative reference for authoring assets (by
hand or via the Asset Editor). It reflects the implemented model in
`node_editor/asset_types.py` and `node_editor/asset_registry.py`.

## Concept
An asset is **one logical resource** (e.g. a memory buffer, a device) exposed
through **one or more interfaces**. Each interface is a distinct *access channel*
(a device node, an address space, a hardware port) with:
- who may use it (an **access-class** filter),
- what it exposes (an ordered list of **operations**),
- where each operation's **steps** are the concrete syscalls.

Slots on the asset node map 1:1 to interfaces, so connecting an edge to a slot
means "access the asset through *this* channel."

## Descriptor format (`template/security/asset/<type>.asset.json`)
```jsonc
{
  "kind": "asset-type",          // required marker
  "name": "Pool Memory",   // display name (toolbox + node title)
  "type": "pool memory",     // stable type_id = security-properties.type
  "class": "security asset",      // node class (always this for assets)
  "shape": "Box",                 // node shape (Box | Circle | Ellipse | …)
  "color": "#8e7cc3",             // node fill colour
  "properties": {                 // security-properties schema (field -> PropDef)
    "type":  { "default": "pool memory" },   // present, identifies the type
    "owner": { "default": "mydev KMD", "options": ["mydev KMD", "mydev ResMgr"] },
    "size":  ""                   // plain string = free-text field
  },
  "interfaces": [ Interface, … ]  // one or more; each becomes a slot
}
```

### Interface
```jsonc
{
  "name": "Alloc",               // interface name = slot name (unique per asset)
  "category": "ioctl",           // HOW the channel works — see below
  "fields": { "driver": "mydev" },  // values for the fields that category declares
  "path": "/dev/mydev",          // resource path / identifier (used by conformance)
  "actor": "user process",       // who accesses via this channel (informational)
  "direction": "in",             // in | out | bidir  → drives slot kind(s)
  "access-class": "software.*",  // glob filter over allowed component access-classes
  "color": "#1e88e5",            // slot colour (auto-assigned from a palette if omitted)
  "operations": [ Operation, … ] // what this interface exposes
}
```

### Operation
An operation is a **semantic action** whose **steps are the syscalls** that
realize it. Two forms:
```jsonc
"open"                                   // leaf: op name == the single call
{ "op": "Alloc",                         // compound: named, ordered steps
  "steps": [
    { "call": "fd = open(\"/dev/mydev\", O_RDONLY | O_CLOEXEC)", "role": "acquire" },
    { "call": "ioctl(fd, MYDEV_IOC_GET_FD, &op)",                "role": "operate" }
  ] }
```
- `call` — the concrete syscall (with example signature). Prefix `ioctl:` /
  `open:` are conventional but the string is free-form.
- `role` — **`acquire`** (obtains a handle/capability, e.g. `open`, `shm_open`)
  or **`operate`** (acts on the held handle, e.g. `ioctl`, `mmap`, `close`).
  Role defaults from the call name when omitted.

## Field-by-field usage
| Field | Used for |
|---|---|
| `name` / `color` / `shape` | toolbox entry + node rendering |
| `type` (type_id) | the `security-properties.type` value; the stable key for schema, operations, matching. **Keep stable** — renaming orphans instances. |
| `properties` | the editable **Security** section schema in the property panel (`PropDef`: `""`, `"default"`, or `{default, options}`) |
| interface `name` | the generated **slot** name |
| interface `direction` | `in` → input slot, `out` → output slot, `bidir` → both |
| interface `color` | the **slot colour** (each interface visually distinct; auto from a palette if unset) |
| interface `access-class` | **validation filter**: an edge from a component is allowed only if the component's `access-class` matches this glob (`fnmatch`, comma-separated). Empty = allow all. |
| interface `path` | conformance matching against a runtime log (e.g. `/dev/mydev`) |
| `operations` | the **Operation** list in the panel + the per-syscall **owner-operation edges** |
| operation `steps` / `role` | the syscall breakdown shown in the panel; roles drive acquire/operate (capability) analysis and the only-owner-revokes checkpoint |

## Interface categories (`template/security/interface_categories.json`)

An interface already says **where** it is (`path`), **who** may use it
(`access-class`) and **what** it exposes (`operations`). The **category** says
*how the channel works* — and that is what decides which threats are worth
asking about and which controls could plausibly apply. A file permission cannot
mitigate a DMA path; an SMMU cannot mitigate an ioctl argument bug.

23 categories ship, grouped: OS interfaces (ioctl — which covers plain
character-device read/write too —, mmap, filesystem, sysfs, kernel ABI), IPC and
network (network socket, local socket, message passing, pipe, signal/event,
service API), privilege crossings (hypercall, secure monitor call), hardware
(MMIO, DMA), maintenance (debug, firmware) and one per physical bus (UART, USB,
PCIe, I²C, SPI, CAN).

Each category **declares its own fields**, so the editor asks for what that
mechanism actually needs:

```jsonc
{ "id": "ioctl", "label": "Device node (ioctl / read / write)",
  "access-class": "software.*",                    // default, still editable
  "fields": [
    { "name": "dev-node", "label": "Device node", "required": true,
      "maps-to": "path", "placeholder": "/dev/mydev0", "pattern": "^/dev/.+" },
    { "name": "driver", "label": "Owning driver", "required": false } ],
  "default-operations": ["open", "ioctl", "close"],
  "threat-hints": ["command code validation", "user-pointer TOCTOU", … ],
  "relevant-controls": ["File Permission (ACL)", "Linux Capability", … ] }
```

- `maps-to: path` keeps a field in the interface's existing `path` instead of
  duplicating it — the editor relabels the row ("Device node \*") rather than
  asking twice.
- Required fields and `pattern` are checked when an asset type is saved.
- Picking a category fills in the access-class and a starter operation list, and
  never overwrites what the author already chose.
- `threat-hints` are appended to the generation prompt as *failure modes to
  consider* for that channel type; `relevant-controls` is the shortlist a
  coverage pass can use.
- An unknown category id loads fine — a model authored against a newer catalogue
  is not rejected, it simply has no schema to check.

`node_editor/interface_categories.py` (Qt-free) loads the catalogue and provides
`all_categories()`, `get()`, `describe()`, `problems()` and `prune()`.

## Derived data (built by the registry)
From a descriptor the registry (`asset_registry.py`) produces, with no code edits:
- a **toolbox NodeSpec** — one slot per interface, each slot's properties carry
  `interface`, `path`, `access-class`, `color`, `operations` (names) and
  `op_steps` (`{op_name: [calls]}`);
- **prop-defs by class** (`security asset <type>`) for the schema;
- **operations by type** for the sub-type dropdown.
Descriptors override / extend legacy split templates; when absent everything
falls back to the old `<type>.json` + `<type>_props.json` + `asset_operations.json`.

## How the tool uses a definition
- **Placement**: dragging the type creates a node with per-interface slots.
- **Connecting**: an edge to an interface slot locks `type` to `Asset Operation`
  and restricts `sub-type` to that interface's operations; the access-class
  filter validates the component (rule *Component Not Allowed On Interface*).
- **Property panel**: selecting the node shows a read-only **Interfaces** tree
  (interfaces → operations → steps); selecting a connection shows the
  **Operation** list (pick one → dotted virtual edges to the asset's owner, one
  per syscall step); clicking a slot shows that interface's details.
- **Ownership**: the asset's owner is a component sharing its **Container**, or
  the `security-properties.owner` value; used for the owner-operation edges and
  the only-owner-revokes checkpoint.
- **Conformance**: interface `path` + operation `steps` match the runtime
  syscall log per interface.

## Authoring guidance
- One asset = one resource; use **interfaces** for its distinct access channels
  (SW ioctl vs HW port; different device nodes; different address spaces).
- Keep `type` (type_id) stable; rename `name` freely.
- Set `access-class` on every interface (`software.*`, `hardware.device`, …) so the
  right actors are enforced; give each interface a distinct `color`.
- Make `operations` semantic (Alloc, Map, Free); put the real syscalls in
  `steps` with accurate `role`s.
- Built-ins live in `template/security/asset/`; user edits/overrides are written
  as descriptors by the Asset Editor and live-refresh the registry.

## Example — Pool Memory (abbreviated)
```jsonc
{ "kind": "asset-type", "name": "Pool Memory", "type": "pool memory",
  "class": "security asset", "color": "#8e7cc3",
  "properties": { "type": {"default":"pool memory"},
                  "owner": {"default":"mydev KMD","options":["mydev KMD","mydev ResMgr"]} },
  "interfaces": [
    { "name":"Alloc","path":"/dev/mydev","access-class":"software.*","color":"#1e88e5",
      "operations":[ {"op":"open","steps":[{"call":"fd = open(\"/dev/mydev\", O_RDONLY|O_CLOEXEC)","role":"acquire"}]},
                     {"op":"get_handle","steps":[{"call":"ioctl(fd, MYDEV_IOC_GET_FD, &op)","role":"acquire"}]} ] },
    { "name":"Map","access-class":"software.*","color":"#43a047",
      "operations":[ {"op":"mmap","steps":[{"call":"addr = mmap(NULL,size,prot,MAP_SHARED,dmabuf_fd,offset)","role":"operate"}]} ] },
    { "name":"Unmap","access-class":"software.*","color":"#fb8c00",
      "operations":[ {"op":"munmap","steps":[{"call":"munmap(addr,size)","role":"operate"}]} ] },
    { "name":"Free","access-class":"software.*","color":"#e53935",
      "operations":[ {"op":"close","steps":[{"call":"close(fd)","role":"operate"}]} ] }
  ] }
```

## Related
- `doc/asset-interface-model-design.md` — interfaces, access-class, controls.
- `doc/asset-relationships-design.md` — owns / leases / part-of / maps-to,
  address space, only-owner-revokes.
- `doc/compound-asset-operation-design.md` — operation steps & roles.
- `doc/asset-editor-ui-design.md` — the authoring UI.
