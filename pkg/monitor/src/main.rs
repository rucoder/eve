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

/// Sends the console's answer to a GPURequest, echoing its `request_id`
/// unchanged - pillar matches acks by that id and drops any that does not
/// match the request it is waiting on (see PillarState::pending_gpu_ack and
/// handleGPUAck in pkg/pillar/cmd/monitor/gpu.go). Never called before the
/// change `req` asked for has actually happened; see the two call sites.
fn ack_gpu_request(
    outbox: &tokio::sync::mpsc::UnboundedSender<ipc::message::IpcMessage>,
    req: ipc::monitorapi::GpuRequest,
) {
    let id = req.request_id;
    let ack = ipc::monitorapi::GpuAck {
        domain: req.domain,
        released: req.release,
        request_id: req.request_id,
    };
    let msg = ipc::message::IpcMessage::Request { request: ipc::message::Request::GPUAck(ack), id };
    if outbox.send(msg).is_err() {
        log::warn!("gpu: outbox closed, dropping ack for request {id}");
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
/// `capable` gates whether an available GPU ever asks `switch` to hand
/// control to the GUI: a device with no GPU (see `Console::new`) must stay on
/// the TUI regardless of what pillar reports, or this would fight
/// `Console::want()` and restart the TUI session in a tight loop. Stops once
/// `stop` is set, which the caller does right after the TUI session ends for
/// any reason.
fn spawn_tui_gpu_watcher(
    state: ipc::Shared,
    outbox: tokio::sync::mpsc::UnboundedSender<ipc::message::IpcMessage>,
    capable: bool,
    switch: tokio_util::sync::CancellationToken,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<()> {
    use std::sync::atomic::Ordering;
    std::thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            let (available, pending) = {
                let mut st = state.lock().unwrap();
                (st.gpu_available, st.pending_gpu_ack.take())
            };
            if let Some(req) = pending {
                ack_gpu_request(&outbox, req);
            }
            if capable && available {
                switch.cancel();
                return;
            }
            std::thread::sleep(GPU_POLL_INTERVAL);
        }
    })
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

    // `capable` is fixed at startup, same as inside Console: a device with
    // no usable DRM device never gets a GUI, whatever pillar reports.
    let initial = frontend::choose(&frontend::probe_drm);
    let capable = initial == frontend::Frontend::Gui;
    let mut console = frontend::Console::new(initial);

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
                let _ = watcher.join();

                // gui::run's shutdown() has already dropped DRM master by the
                // time it returns, whatever the reason - so only now is it
                // safe to tell pillar the GPU is released. Acking any sooner
                // would let domainmgr bind vfio while this process still
                // holds the card.
                let pending = client.state.lock().unwrap().pending_gpu_ack.take();
                if let Some(req) = pending {
                    ack_gpu_request(&client.outbox, req);
                }
                console.set_gpu_available(client.state.lock().unwrap().gpu_available);

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
                    capable,
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
                let _ = watcher.join();
                console.set_gpu_available(client.state.lock().unwrap().gpu_available);

                if !switch.is_cancelled() {
                    break;
                }
            }
        }
    }
    std::process::exit(EXIT_SUCCESS);
}
