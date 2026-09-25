// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

mod actions;
mod application;
mod diff;
mod efi;
mod events;
mod frontend;
mod gui;
mod ipc;
mod model;
mod tcg;
mod terminal;
mod traits;
mod ui;

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

use anyhow::Result;
use application::{AppConfig, Application};
use libc::{EXIT_FAILURE, EXIT_SUCCESS};
use log::{info, warn, LevelFilter};
use terminal::TerminalWrapper;

const EVE_MONITOR_BASE_DIR_EVE: &str = "/persist/monitor/";
const EVE_MONITOR_BASE_DIR_PC: &str = "./persist/monitor/";

/// Where pillar's monitor agent listens. `XDG_RUNTIME_DIR` set means a
/// desktop dev box, not the device; mirrors `get_base_dir` below.
fn get_ipc_socket_path() -> String {
    if let Ok(xdg_runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
        format!("{xdg_runtime_dir}/monitor.sock")
    } else {
        ipc::MONITOR_SOCKET.to_string()
    }
}

fn get_base_dir() -> PathBuf {
    // we use XDG_RUNTIME_DIR to detect the fact that we are running on desktop linux
    // FIXME: is there a better way?
    if let Ok(_dir) = std::env::var("XDG_RUNTIME_DIR") {
        EVE_MONITOR_BASE_DIR_PC.into()
    } else {
        EVE_MONITOR_BASE_DIR_EVE.into()
    }
}

fn get_base_log_dir() -> PathBuf {
    let base_dir = get_base_dir();
    base_dir.join("log")
}

fn remove_old_log_sessions<T: AsRef<Path>>(log_dir: T, rotate_count: usize) -> Result<()> {
    // go over log directory and remove old sessions
    // starting from the oldest one while we do not reach rotate_count
    // subdirectories in format %Y-%m-%d-%H-%M-%S

    // use walkdir to go over all subdirectories. get directory name and convert to date time object
    let mut dirs = std::fs::read_dir(log_dir.as_ref())?
        // ignot not directories
        .filter(|entry| entry.as_ref().map(|e| e.path().is_dir()).unwrap_or(false))
        .filter_map(|entry| {
            entry.ok().and_then(|entry| {
                entry
                    .file_name()
                    .into_string()
                    .ok()
                    .and_then(|name| {
                        chrono::NaiveDateTime::parse_from_str(&name, "%Y-%m-%d-%H-%M-%S").ok()
                    })
                    .map(|dt| (entry.path(), dt))
            })
        })
        .collect::<Vec<_>>();
    // then sort by date time and remove oldest directories
    dirs.sort_by_key(|(_, dt)| *dt);
    while dirs.len() > rotate_count - 1 {
        let (dir, _) = dirs.remove(0);
        std::fs::remove_dir_all(dir)?;
    }
    Ok(())
}

fn init_logging(log_level: &str) -> log2::Handle {
    let base_log_dir = get_base_log_dir();

    let log_level = LevelFilter::from_str(log_level).unwrap_or(LevelFilter::Info);

    // remove old log directories. store result until we initialize logging
    let remove_result = remove_old_log_sessions(&base_log_dir, 3);

    // get current data and time and use it as a subdirectory name for logs
    let current_dir = chrono::Local::now().format("%Y-%m-%d-%H-%M-%S").to_string();
    let log_dir = base_log_dir.join(current_dir);
    std::fs::create_dir_all(&log_dir).expect("Failed to create log directory");
    // set EVE_MONITOR_LOG_DIR to the created folder. it is used later in panic handler
    std::env::set_var("EVE_MONITOR_LOG_DIR", log_dir.to_string_lossy().to_string());

    let log_file = log_dir.join("monitor.log").to_string_lossy().to_string();

    let handle = log2::open(&log_file)
        .size(1024 * 1024)
        .rotate(10)
        .tee(false) // no console output
        .module(true)
        .level(log_level)
        .start();

    info!("Logging initialized: [{}] {:?}", log_level, log_file);

    if let Err(e) = remove_result {
        warn!("Failed to remove old log sessions: {}", e);
    }

    handle
}

pub fn initialize_panic_handler() -> Result<()> {
    let (panic_hook, eyre_hook) = color_eyre::config::HookBuilder::default()
        .panic_section(format!(
            "This is a bug. Consider reporting it at {}",
            env!("CARGO_PKG_REPOSITORY")
        ))
        .display_location_section(true)
        .display_env_section(true)
        .into_hooks();
    eyre_hook.install()?;
    std::panic::set_hook(Box::new(move |panic_info| {
        let _ = TerminalWrapper::close_terminal();

        let msg = format!("{}", panic_hook.panic_report(panic_info));

        eprintln!("{msg}");
        use human_panic::{handle_dump, print_msg, Metadata};
        let support = format!(
            "You can open a bug report at {}",
            env!("CARGO_PKG_REPOSITORY")
        );
        let meta = Metadata::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
            .authors("LF-EDGE EVE OS project")
            .support(support);

        // FIXME: set TMPDIR to value of EVE_MONITOR_LOG_DIR before calling handle_dump
        // or panic report won't be saved on EVE
        // we can remove it when human-panic is fixed
        // see https://github.com/rust-cli/human-panic/issues/167
        let _ = std::env::var("EVE_MONITOR_LOG_DIR").map(|log_dir| {
            std::env::set_var("TMPDIR", log_dir);

        });

        let file_path = handle_dump(&meta, panic_info);
        print_msg(file_path, &meta).expect("human-panic: printing error message to console failed");

        log::error!("Error: {}", strip_ansi_escapes::strip_str(msg));

        #[cfg(debug_assertions)]
        {
            // Better Panic stacktrace that is only enabled when debugging.
            // we do not have space on real TTY to display it
            better_panic::Settings::auto()
                .most_recent_first(false)
                .lineno_suffix(true)
                .verbosity(better_panic::Verbosity::Full)
                .create_panic_handler()(panic_info);
        }

        std::process::exit(EXIT_FAILURE);
    }));
    Ok(())
}

fn log_system_info() {
    // log monitor version
    info!("Starting monitor version: {}", env!("CARGO_PKG_VERSION"));
    info!(
        "Git version: {}",
        option_env!("GIT_VERSION")
            .unwrap_or("GIT_VERSION is not set, no .git directory or git is not installed?")
    );

    // get current user UID and GID
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self")
        .map(|m| {
            info!("Current process UID: {}, GID: {}", m.uid(), m.gid());

        })
        .unwrap_or_else(|e| {
            info!("Failed to get current process UID and GID: {}", e);
        });
}

/// How often the GPU-handover watchers below re-check `PillarState` while a
/// frontend session is already running. This is a control-plane path bounded
/// by domainmgr's 5s ack timeout (see `gpuReleaseTimeout` in
/// pkg/pillar/cmd/domainmgr/gpuconsole.go), not the render hot path - it has
/// nothing to do with the per-frame `switch`/`vt::running()` checks in
/// gui::run.
const GPU_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(50);

/// How long `spawn_tui_gpu_watcher` keeps retrying its DRM probe after a
/// restore whose first probe found nothing. i915 rebind is racy enough that
/// a connector can still read `Unknown` rather than `Connected` (which
/// `pick_card` requires) right at the moment pillar says the GPU is
/// available again, or the driver can hit `-EPROBE_DEFER` - a single probe
/// on the restore tick can lose that race and leave the console stuck on
/// the TUI, silently and permanently, until some other restore happens to
/// arrive later (which may be never).
const RESTORE_RETRY_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// Sends the console's answer to a GPURequest, echoing its `request_id`
/// unchanged - pillar matches acks by that id and drops any that does not
/// match the request it is waiting on (see PillarState::pending_gpu_ack and
/// handleGPUAck in pkg/pillar/cmd/monitor/gpu.go). Never called before the
/// change `req` asked for has actually happened; see the two call sites.
///
/// Returns whether it actually queued something, so a caller that is about
/// to exit can decide whether waiting a moment for the background IPC
/// thread to flush it is worth it.
fn ack_gpu_request(
    outbox: &tokio::sync::mpsc::UnboundedSender<ipc::message::IpcMessage>,
    req: ipc::monitorapi::GpuRequest,
) -> bool {
    let id = req.request_id;
    let ack = ipc::monitorapi::GpuAck {
        domain: req.domain,
        released: req.release,
        request_id: req.request_id,
    };
    let msg = ipc::message::IpcMessage::Request { request: ipc::message::Request::GPUAck(ack), id };
    match outbox.send(msg) {
        Ok(()) => true,
        Err(_) => {
            log::warn!("gpu: outbox closed, dropping ack for request {id}");
            false
        }
    }
}

/// Runs alongside a live GUI session. A restore that arrives while the GUI
/// already holds the card has nothing to wait for and is answered here; a
/// release cannot be answered yet - the GUI still holds DRM master - so this
/// only asks `switch` to hand control back, and the caller answers it once
/// `gui::run` has actually returned (see `shutdown` in src/gui/mod.rs, which
/// drops DRM master before `run` does). Stops once `stop` is set, which the
/// caller does right after `gui::run` returns for any reason.
fn spawn_gui_gpu_watcher(
    state: ipc::Shared,
    outbox: tokio::sync::mpsc::UnboundedSender<ipc::message::IpcMessage>,
    switch: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use std::sync::atomic::Ordering;
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            // One lock, one decision: taking `pending_gpu_ack` for a release
            // and then just returning would drop it on the floor instead of
            // leaving it for the caller, and reading availability in a
            // separate lock from the take could race a fresh release landing
            // in between the two. apply() only ever pairs
            // `gpu_available: true` with a restore, so anything taken in
            // that branch is always safe to answer immediately - it has
            // nothing to wait for.
            let (should_switch, pending) = {
                let mut st = state.lock().unwrap();
                if st.gpu_available {
                    (false, st.pending_gpu_ack.take())
                } else {
                    (true, None)
                }
            };
            if let Some(req) = pending {
                ack_gpu_request(&outbox, req);
            }
            if should_switch {
                switch.store(true, Ordering::SeqCst);
                return;
            }
            std::thread::sleep(GPU_POLL_INTERVAL);
        }
    })
}

/// Runs alongside a live TUI session. The TUI never holds DRM master, so any
/// GPURequest - release or restore - can be answered as soon as it arrives.
///
/// `capable` gates whether an available GPU ever asks `switch` to hand
/// control to the GUI: a device with no GPU (see `Console::new`) must stay on
/// the TUI regardless of what pillar reports, or this would fight
/// `Console::want()` and restart the TUI session in a tight loop.
///
/// `capable` can be a stale "no" from the boot-time probe, though - a device
/// that booted with the iGPU already in vfio-pci (e.g.
/// `debug.enable.vga=false`) has no card to find at startup - so this
/// re-probes with `probe` once up front, and again for up to
/// `RESTORE_RETRY_WINDOW` after every restore (a restore is the one moment
/// that stale answer needs rechecking; a release never changes whether a
/// card exists). The retry window covers a first restore-tick probe losing
/// the race with a still-rebinding driver - see `RESTORE_RETRY_WINDOW`'s own
/// doc for why one probe isn't enough. It does *not* probe on every tick
/// otherwise: `PillarState::gpu_available` defaults to `true` with no pillar
/// involvement at all (see `PillarState::default`), so an always-on
/// GPU-less device would otherwise drive a DRM scan and a `frontend::choose`
/// log line 20 times a second, forever - `choose` is for logging the
/// boot-time decision once, not for a polling predicate, hence `probe()` is
/// called directly here instead.
///
/// Returns the `capable` this watcher ends up believing, so the caller can
/// hand it to `Console` directly (`Console::adopt_capable`) instead of
/// probing DRM a second time, which could disagree with this watcher on a
/// card that flaps between the two probes.
///
/// Stops once `stop` is set, which the caller does right after the TUI
/// session ends for any reason.
fn spawn_tui_gpu_watcher(
    state: ipc::Shared,
    outbox: tokio::sync::mpsc::UnboundedSender<ipc::message::IpcMessage>,
    mut capable: bool,
    probe: impl Fn() -> Option<String> + Send + 'static,
    switch: tokio_util::sync::CancellationToken,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<bool> {
    use std::sync::atomic::Ordering;
    std::thread::spawn(move || {
        if !capable {
            capable = probe().is_some();
        }
        // Set on a restore that didn't immediately find a card; cleared once
        // the window closes. A GPU-less device never receives a restore, so
        // this never gets set and the loop below never probes past the
        // up-front check above.
        let mut retry_until: Option<std::time::Instant> = None;
        while !stop.load(Ordering::SeqCst) {
            let (available, pending) = {
                let mut st = state.lock().unwrap();
                (st.gpu_available, st.pending_gpu_ack.take())
            };
            if let Some(req) = pending {
                if !capable && !req.release {
                    retry_until = Some(std::time::Instant::now() + RESTORE_RETRY_WINDOW);
                }
                ack_gpu_request(&outbox, req);
            }
            if !capable {
                if let Some(deadline) = retry_until {
                    if std::time::Instant::now() < deadline {
                        capable = probe().is_some();
                    } else {
                        retry_until = None;
                    }
                }
            }
            if available && capable {
                switch.cancel();
                return capable;
            }
            std::thread::sleep(GPU_POLL_INTERVAL);
        }
        capable
    })
}

/// Joins a watcher thread, logging rather than silently swallowing a panic -
/// a poisoned lock or a bug in the watcher itself would otherwise stop the
/// GPU handover for the rest of this session with no trace of why. Returns
/// whatever the watcher returned, or `None` if it panicked.
fn join_watcher<T>(handle: std::thread::JoinHandle<T>, name: &str) -> Option<T> {
    match handle.join() {
        Ok(v) => Some(v),
        Err(e) => {
            log::error!("{name} panicked: {e:?}");
            None
        }
    }
}

/// Applies pillar's latest `gpu_available` to `console` after a GUI session,
/// re-probing DRM first if the device isn't currently believed capable.
/// `Console::capable` is otherwise fixed at the boot-time probe, so without
/// this a device that booted with the iGPU already in vfio-pci would never
/// get the GUI back after a restore.
///
/// GUI-arm only: `Console::try_upgrade_capable` is safe to call here because
/// nothing else is probing DRM concurrently in that arm. The TUI arm instead
/// hands `console.adopt_capable` the result its own watcher already found -
/// see `spawn_tui_gpu_watcher`'s doc comment for why probing independently
/// there could disagree with that watcher on a flapping card.
fn sync_console_after_gui(console: &mut frontend::Console, available: bool) {
    if available {
        console.try_upgrade_capable(&frontend::probe_drm);
    }
    console.set_gpu_available(available);
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load_or_create_app_config(&get_base_dir());
    let _log2 = init_logging(&config.log_level);
    initialize_panic_handler()?;
    log_system_info();

    // Pillar's monitor agent accepts exactly one client connection per
    // process (see crate::ipc's module doc). This is the only client for the
    // whole process: it is created once here, before either frontend starts,
    // and `client` is kept alive for the rest of main() - across every
    // frontend switch below, not just the first frontend - so its `outbox`
    // sender never closes early and triggers a reconnect, and `spawn()` is
    // never called a second time.
    let mut client = ipc::spawn(&get_ipc_socket_path());

    let mut console = frontend::Console::new(frontend::choose(&frontend::probe_drm));

    // Whether the last thing this loop did was successfully queue a GpuAck -
    // read after the loop to decide whether the final process::exit below is
    // worth delaying for. `Application::new(...)?` and
    // `TerminalWrapper::close_terminal()?` in the TUI arm can return out of
    // main() entirely on failure, bypassing both this and the loop - this
    // flag is a best-effort nicety, not a delivery guarantee.
    let mut acked_last;

    // Which frontend is showing changes only at the top of this loop, so
    // asking for the one already running is a no-op: the match below simply
    // is not re-entered until the running one returns control.
    loop {
        match console.want() {
            frontend::Frontend::Gui => {
                // Fresh per session: a CancellationToken cannot be
                // un-cancelled, and each GUI run needs its own "please stop"
                // signal. `gui::run` always tears down DRM/GL/input state
                // before returning, however it returns.
                let switch = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stop_watcher = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let watcher = spawn_gui_gpu_watcher(
                    client.state.clone(),
                    client.outbox.clone(),
                    switch.clone(),
                    stop_watcher.clone(),
                );

                if let Err(e) = gui::run(client.state.clone(), switch.clone()) {
                    log::error!("Gui error: {e}");
                }
                stop_watcher.store(true, std::sync::atomic::Ordering::SeqCst);
                join_watcher(watcher, "gui gpu watcher");

                // By the time gui::run returns, this process is not holding
                // DRM master: either it never acquired it (an early `?`
                // return before the frame loop - pick_card, drm::open,
                // discover_heads, Painter::new and input::spawn can all fail
                // before a scanout surface ever opens), or its shutdown() has
                // already called drm::drop_master. Only now is it safe to
                // tell pillar the GPU is released - acking any sooner could
                // let domainmgr bind vfio while this process still holds the
                // card.
                let pending = client.state.lock().unwrap().pending_gpu_ack.take();
                acked_last = pending.is_some_and(|req| ack_gpu_request(&client.outbox, req));
                sync_console_after_gui(&mut console, client.state.lock().unwrap().gpu_available);

                // `switch` set means main asked the GUI to hand back control
                // (console.want() no longer wants it); anything else - the VT
                // going away, an unrecoverable error - is a real shutdown.
                if !switch.load(std::sync::atomic::Ordering::SeqCst) {
                    break;
                }
            }
            frontend::Frontend::Tui => {
                let switch = tokio_util::sync::CancellationToken::new();
                let stop_watcher = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let watcher = spawn_tui_gpu_watcher(
                    client.state.clone(),
                    client.outbox.clone(),
                    console.capable(),
                    frontend::probe_drm,
                    switch.clone(),
                    stop_watcher.clone(),
                );

                // Borrows client.events/outbox for this session only, so
                // main.rs still owns them - unconsumed - the moment this
                // returns and can lend them again next time the TUI runs.
                let mut app = Application::new(config.clone(), &mut client.events, client.outbox.clone())?;
                let result = app.run(switch.clone()).await;
                if let Err(e) = &result {
                    log::error!("Application error: {}", e);
                }
                // FIXME: this is a workaround for malfunctioning terminal event stream
                // Terminal must be dropped and restored automatically but one of the threads doesn't exit
                // and await? on a main function never finishes. Drops are executed later.
                TerminalWrapper::close_terminal()?;

                stop_watcher.store(true, std::sync::atomic::Ordering::SeqCst);
                // Adopt what the watcher already found rather than probing
                // DRM again here - see spawn_tui_gpu_watcher's doc comment
                // for why probing twice independently could disagree on a
                // flapping card and restart this session in a loop.
                if let Some(found) = join_watcher(watcher, "tui gpu watcher") {
                    console.adopt_capable(found);
                }

                // Symmetric with the GUI arm above: the watcher could still
                // be mid-sleep when `stop_watcher` was set and miss a request
                // that landed in that last window. The TUI never holds DRM
                // master, so answering it here is always safe.
                let pending = client.state.lock().unwrap().pending_gpu_ack.take();
                acked_last = pending.is_some_and(|req| ack_gpu_request(&client.outbox, req));
                console.set_gpu_available(client.state.lock().unwrap().gpu_available);

                if !switch.is_cancelled() {
                    break;
                }
            }
        }
    }
    if acked_last {
        // A GpuAck was just queued on `client.outbox` (a release that
        // arrived right as this process was told to shut down) and the
        // background IPC thread may not have had a chance to write it to the
        // socket yet - process::exit below is immediate and does not wait
        // for that. This is the same "console never answers" symptom the
        // whole handshake exists to avoid, just at shutdown instead of at a
        // frontend switch, so give it a brief window rather than none at
        // all; skipped entirely in the common case where nothing was queued.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    std::process::exit(EXIT_SUCCESS);
}

#[cfg(test)]
mod gpu_handover_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use ipc::monitorapi::GpuRequest;

    fn a_request(domain: &str, release: bool, request_id: u64) -> GpuRequest {
        GpuRequest { domain: domain.into(), release, request_id }
    }

    /// A watcher tick or two - long enough for GPU_POLL_INTERVAL (50ms) to
    /// fire at least once, short enough not to slow the suite down.
    const A_FEW_TICKS: Duration = Duration::from_millis(180);

    /// `ack_gpu_request` must echo the id it was given (pillar drops any ack
    /// whose id doesn't match what it's waiting on) and must set `released`
    /// from the request's `release`, not hardcode it.
    #[test]
    fn ack_gpu_request_echoes_a_release() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ack_gpu_request(&tx, a_request("vm1", true, 42));

        let msg = rx.try_recv().expect("an ack must have been queued");
        let json = serde_json::to_value(&msg).expect("serializes");
        assert_eq!(json["RequestType"], "GPUAck");
        assert_eq!(json["RequestData"]["domain"], "vm1");
        assert_eq!(json["RequestData"]["released"], true);
        assert_eq!(json["RequestData"]["request_id"], 42);
        assert_eq!(json["id"], 42, "the envelope id pillar matches on must be the same id");
    }

    /// The restore direction, checked separately: `released` must flip with
    /// it, not be pinned to `true`.
    #[test]
    fn ack_gpu_request_echoes_a_restore() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        ack_gpu_request(&tx, a_request("", false, 8));

        let msg = rx.try_recv().expect("an ack must have been queued");
        let json = serde_json::to_value(&msg).expect("serializes");
        assert_eq!(json["RequestData"]["released"], false);
        assert_eq!(json["id"], 8);
    }

    /// Regression test for the bug caught during fix round 1: an earlier
    /// version of this watcher took `pending_gpu_ack` unconditionally, so a
    /// pending release was silently discarded instead of being left for
    /// main() to ack once gui::run actually returns. The GUI still holds DRM
    /// master here, so nothing may be acked and `pending_gpu_ack` must still
    /// be there when the watcher gives up and asks to switch.
    #[test]
    fn gui_watcher_leaves_a_pending_release_for_the_caller() {
        let state: ipc::Shared = Default::default();
        {
            let mut st = state.lock().unwrap();
            st.gpu_available = false;
            st.pending_gpu_ack = Some(a_request("vm1", true, 7));
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        // sleep -> stop -> join, not a bare join: if the switch decision this
        // test guards ever regresses so the watcher stops noticing
        // `!available`, a bare join would hang the whole suite instead of
        // failing it.
        let handle = spawn_gui_gpu_watcher(state.clone(), tx, switch.clone(), stop.clone());
        std::thread::sleep(A_FEW_TICKS);
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("watcher must not panic");

        assert!(switch.load(Ordering::SeqCst), "must ask to hand back control");
        assert!(
            state.lock().unwrap().pending_gpu_ack.is_some(),
            "the release must still be pending - main() acks it after gui::run returns"
        );
        assert!(rx.try_recv().is_err(), "nothing may be acked before DRM master is dropped");
    }

    /// The other direction: a restore that arrives while the GUI already
    /// holds the card has nothing to wait for and must be acked immediately,
    /// without ever asking to switch (the GUI is already showing).
    #[test]
    fn gui_watcher_acks_a_restore_without_switching() {
        let state: ipc::Shared = Default::default(); // gpu_available: true by default
        {
            state.lock().unwrap().pending_gpu_ack = Some(a_request("", false, 9));
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));

        let handle = spawn_gui_gpu_watcher(state.clone(), tx, switch.clone(), stop.clone());
        std::thread::sleep(A_FEW_TICKS);
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("watcher must not panic");

        assert!(!switch.load(Ordering::SeqCst));
        let msg = rx.try_recv().expect("the restore should have been acked");
        let json = serde_json::to_value(&msg).expect("serializes");
        assert_eq!(json["RequestData"]["released"], false);
        assert_eq!(json["id"], 9);
    }

    /// A device with no GPU (`capable: false`, boot-time probe confirms it)
    /// must still answer a stray GPURequest, but never ask to switch to the
    /// GUI - that would fight `Console::want()` and restart the TUI session
    /// in a tight loop (the exact bug `frontend::tests::
    /// a_tui_only_device_ignores_gpu_messages` guards one layer down).
    #[test]
    fn tui_watcher_answers_but_does_not_switch_when_genuinely_not_capable() {
        let state: ipc::Shared = Default::default(); // gpu_available: true by default
        {
            state.lock().unwrap().pending_gpu_ack = Some(a_request("", false, 11));
        }
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = tokio_util::sync::CancellationToken::new();
        let stop = Arc::new(AtomicBool::new(false));

        let handle = spawn_tui_gpu_watcher(state.clone(), tx, false, || None, switch.clone(), stop.clone());
        std::thread::sleep(A_FEW_TICKS);
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("watcher must not panic");

        assert!(!switch.is_cancelled(), "a device confirmed to have no GPU must never be asked to switch");
        let msg = rx.try_recv().expect("the pending request must still be acked");
        assert_eq!(serde_json::to_value(&msg).unwrap()["id"], 11);
    }

    /// A device that starts `capable: true` switches back to the GUI as soon
    /// as the GPU is available again.
    #[test]
    fn tui_watcher_switches_when_already_capable() {
        let state: ipc::Shared = Default::default();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = tokio_util::sync::CancellationToken::new();
        let stop = Arc::new(AtomicBool::new(false));

        // sleep -> stop -> join: a regression that stopped switching would
        // otherwise hang this test instead of failing it.
        let handle = spawn_tui_gpu_watcher(state, tx, true, || None, switch.clone(), stop.clone());
        std::thread::sleep(A_FEW_TICKS);
        stop.store(true, Ordering::SeqCst);
        let found_gpu = handle.join().expect("watcher must not panic");

        assert!(switch.is_cancelled());
        assert!(found_gpu);
    }

    /// The bug from review round 1: a device that booted with the iGPU
    /// already in vfio-pci (`debug.enable.vga=false`) has `capable: false`
    /// from the boot-time probe with no way to update it on its own. Without
    /// a re-probe here, a restore would set `gpu_available: true` and the
    /// watcher would still never switch, because it never rechecks whether a
    /// real card exists now - the console would be stuck on the TUI until
    /// the process restarts.
    #[test]
    fn tui_watcher_reprobes_and_switches_when_a_gpu_appears_after_boot() {
        let state: ipc::Shared = Default::default();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = tokio_util::sync::CancellationToken::new();
        let stop = Arc::new(AtomicBool::new(false));

        // sleep -> stop -> join: a regression that dropped the up-front
        // re-probe would otherwise hang this test instead of failing it.
        let handle = spawn_tui_gpu_watcher(
            state,
            tx,
            false, // the stale boot-time answer
            || Some("/dev/dri/card0".into()), // but a probe now finds a card
            switch.clone(),
            stop.clone(),
        );
        std::thread::sleep(A_FEW_TICKS);
        stop.store(true, Ordering::SeqCst);
        let found_gpu = handle.join().expect("watcher must not panic");

        assert!(switch.is_cancelled(), "must re-probe rather than trust the boot-time answer");
        assert!(found_gpu);
    }

    /// The reprobe must be bounded to the first tick plus every restore, not
    /// every tick - a GPU-less device (`gpu_available` defaults to `true`
    /// with no pillar involvement at all) would otherwise drive a DRM scan
    /// and a log line 20 times a second, forever. `probe_count` counts every
    /// call the watcher makes to the injected probe over several ticks with
    /// nothing arriving; it must be exactly one (the up-front check), not one
    /// per tick.
    #[test]
    fn tui_watcher_does_not_reprobe_every_tick() {
        let state: ipc::Shared = Default::default(); // gpu_available: true, nothing pending
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = tokio_util::sync::CancellationToken::new();
        let stop = Arc::new(AtomicBool::new(false));
        let probe_count = Arc::new(std::sync::atomic::AtomicU32::new(0));

        let counted_probe = {
            let probe_count = probe_count.clone();
            move || {
                probe_count.fetch_add(1, Ordering::SeqCst);
                None
            }
        };
        let handle = spawn_tui_gpu_watcher(state, tx, false, counted_probe, switch.clone(), stop.clone());
        // Several ticks' worth of waiting, with nothing ever arriving.
        std::thread::sleep(A_FEW_TICKS * 3);
        stop.store(true, Ordering::SeqCst);
        handle.join().expect("watcher must not panic");

        assert!(!switch.is_cancelled());
        assert_eq!(probe_count.load(Ordering::SeqCst), 1, "must probe once up front, not once per tick");
    }

    /// The regression this retry window exists for: i915 rebind is racy, so
    /// the first probe right on the restore tick can still find nothing even
    /// though the card is about to become usable moments later. A
    /// single-shot probe would give up here and leave the console on the TUI
    /// permanently; this must keep retrying within RESTORE_RETRY_WINDOW and
    /// still switch once the card shows up.
    #[test]
    fn tui_watcher_retries_the_restore_probe_within_the_window() {
        let state: ipc::Shared = Default::default();
        {
            state.lock().unwrap().pending_gpu_ack = Some(a_request("", false, 20));
        }
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let switch = tokio_util::sync::CancellationToken::new();
        let stop = Arc::new(AtomicBool::new(false));

        // The first couple of probes see the not-yet-rebound driver; a later
        // one, still well inside the retry window, finds the card.
        let calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let flaky_probe = {
            let calls = calls.clone();
            move || {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                if n < 2 { None } else { Some("/dev/dri/card0".into()) }
            }
        };

        let handle = spawn_tui_gpu_watcher(state, tx, false, flaky_probe, switch.clone(), stop.clone());
        // A handful of ticks - enough for the retries to land, nowhere near
        // RESTORE_RETRY_WINDOW (2s).
        std::thread::sleep(A_FEW_TICKS * 2);
        stop.store(true, Ordering::SeqCst);
        let found_gpu = handle.join().expect("watcher must not panic");

        assert!(
            switch.is_cancelled(),
            "must keep retrying within the window rather than giving up after one probe"
        );
        assert!(found_gpu);
    }
}
