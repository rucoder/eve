# Monitor service implementation

The monitor service is a simple IPC server which uses a unix socket to communicate with external [rust client](../../monitor/Dockerfile) located at `pkg/monitor`. The server can send asynchronous updates about EVE status to the
connected client. The information is then used by rust client to display a TUI or, on a device with a GPU, a graphical console for the user.

## Client requests

Following requests are supported at the moment:

* `SetDPC` - sets a the current DPC with a key  set to `manual`. It is used to apply a network configuration specified by local user through TUI. `NIM` service has a special handling of `manual` DPC
* `SetServer` - updates server URL in `/config/server` file. The request fails if the node is already onboarded.
* `SetDebugOption` - changes one debug option; see below.

## Debug options

The console's Debug page sets local debugging switches without a controller.
The catalogue - keys, labels, descriptions, kinds, defaults - lives in
`types/debugoptions.go`; the console draws whatever it is sent, so a new
option needs no console change unless the console applies it itself.

The monitor agent validates `SetDebugOption` against the catalogue, publishes
the result as `DebugOptionValues` (persistent, key `global`, holding only
values that differ from their default) and sends the console `DebugOptions` -
on connect and after every change, accepted or not.

* `console.*` options are applied by the console when `DebugOptions` arrives:
  the readback probe, its log level, zbus logging.
* `vm.*` options are applied by domainmgr, which hands `DebugOptionValues` to
  the hypervisor package; they reach an application on its next start. For a
  domain with a virtual GPU, `KvmContext.Setup` sets `INTEL_DEBUG=noccs` (on
  by default), `MESA_DEBUG=1` and `VREND_DEBUG`, and adds `vm.qemu_trace` to
  `debug.qemu.trace.events`.

## Request/response representation

All requests and responses are sent in JSON format. Some internal EVE structures e.g. DPCList are serialized into JSON as-is and deserialized on the rust application side.
It introduces a problem in case a structure is updated on EVE side, but the rust application is not updated.
To avoid this problem a proxy structures should be created  on EVE side in future.
