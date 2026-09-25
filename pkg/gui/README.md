# eve-gui

A graphical console for EVE. Each guest's framebuffer is rendered into a tab,
drawn directly onto the physical screen through DRM/KMS.

It exists to remove **iGPU passthrough**. Passing an Intel iGPU through to a
guest is a large source of bugs; giving the guest a *virtual* GPU and
compositing its framebuffer on the host avoids the whole class of them.

## How it is put together

```
guest ──virtio-gpu──> QEMU ──D-Bus display──> eve-gui ──DRM/KMS──> screen
                                                  ^
                                 libinput ────────┘   (evdev, no udev/seat)
```

* **No Wayland, no X, no seat manager.** EVE has none of them. This is plain
  root on a VT, using [smithay](https://github.com/Smithay/smithay) purely as a
  library for DRM/KMS, GBM, EGL and libinput. The UI is
  [egui](https://github.com/emilk/egui) painted with `egui_glow` onto smithay's
  GL context.
* **The guest framebuffer arrives over QEMU's D-Bus display** (`-display dbus`),
  which is a peer-to-peer socket QEMU authenticates itself — no bus daemon.

### Two framebuffer paths, and why you want the first

| | how | cost |
|---|---|---|
| **dmabuf** | `ScanoutDMABUF` hands us an fd for a buffer the host GPU already holds; we import it as a texture | zero copy |
| **copy** | `Scanout`/`Update` carry the pixels in the message | 4 MB at 1280x800, 8 MB at 1920x1080, **per frame** |

Start guests with `gl=on` so they take the dmabuf path. The copy path cannot
keep up with a busy guest, and the backlog is bounded (`max_queued`) precisely
because an unbounded one grew at ~150 MB/s and got the process OOM-killed.

This applies to Windows too: `virtio-vga-gl` with `gl=on` exports a dmabuf even
though Windows has no 3D guest driver — only the host side changes.

### QEMU configuration that matters

A guest must end up with exactly **one** DRM card. `q35` adds an implicit
default VGA adapter, so a guest given `virtio-gpu-gl-pci` alongside it sees
*two* (`bochs-drm` and virtio) and may render to the one we are not watching —
which looks like a rendering bug, and additionally denies it a hardware cursor
plane.

On EVE this is already handled: `domainmgr` passes `-nodefaults`, which
suppresses the implicit adapter, so `-vga none` is unnecessary there. Pass
`-vga none` when starting QEMU by hand.

## Configuration

All optional; a positional argument overrides `GUI_CARD`.

| variable | default | meaning |
|---|---|---|
| `GUI_VMS` | – | `name=<d-bus addr>` pairs, **semicolon** separated (an address contains a comma) |
| `GUI_CARD` | probed | DRM device; unset, `card0..card3` are probed and the first with a connected output wins |
| `GUI_ORIENT` | `1` | 0=none 1=flipY 2=flipX 3=rot180 |
| `GUI_PTR_SCALE` | `1.0` | pointer sensitivity; motion is otherwise raw 1:1 |
| `GUI_FRAMES` | `0` | frame limit, 0 = run until signalled |
| `GUI_LOG` | `info` | `error\|warn\|info\|debug\|trace` |
| `GUI_LOG_DEPS` | `warn` | same, for libraries |
| `GUI_LOG_FILE` | `/run/eve-gui.log` | logging is asynchronous; a hot path never does I/O |
| `GUI_PROBE` | – | read the blit target back and count non-black pixels |
| `GUI_VT_KBD` | – | `0` leaves the VT keyboard to the kernel |

## Using it

Click in a guest to grab input; **Ctrl+Alt+G** releases. **Ctrl+Alt+1..9**
switches tab and works while grabbed. **Ctrl+Alt+Del** reaches the guest rather
than rebooting the host, because the VT keyboard is put in `K_OFF` — there is
also a button for it, which is what you need at a Windows logon screen where you
are not grabbed yet.

**Wake** taps Shift in the active guest. If a guest's display is blanked when we
attach, QEMU sends no scanout at all and every later update refers to a buffer
we were never given, so the screen stays black; a keystroke provokes the
scanout, pointer motion does not reliably.

## Known gaps

* **`GUI_VMS` is a development path only.** On EVE the tabs come from pillar
  over `/run/monitor.sock`, and each one attaches to its app's QMP socket. A
  tab named in `GUI_VMS` is kept whatever pillar says, and is never rebuilt if
  its guest dies, because nothing else knows about it.
* **No input hotplug.** libinput devices are enumerated once at startup, so a
  keyboard or mouse plugged in later is not seen.
* **The kernel needs DRM.** `CONFIG_DRM` is unset in EVE's stock 6.12 kernel;
  the core flavor on the `drm-core` branch enables `DRM`, `DRM_I915` and
  `DRM_VIRTIO_GPU`. Build with `KERNEL_TAG` pointing at that kernel.
* Windows has no 3D guest driver, so its desktop is still software-rendered.
  That is a guest-side gap, unrelated to the transport.
