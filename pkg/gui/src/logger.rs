// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Asynchronous logging.
//!
//! The rule this exists to enforce: **no thread that has a latency budget may
//! perform I/O to log.** The input thread in particular runs at device rate and
//! must never take the stdout lock or issue a `write(2)`.
//!
//! So a log call does at most:
//!   1. an atomic load of the global max level (`log` does this in the macro,
//!      before the arguments are even evaluated), then
//!   2. format into a `String` and push it onto a channel.
//!
//! A dedicated writer thread owns the file handle and does every syscall. It
//! batches whatever has queued up and flushes once per batch, so a burst of
//! records costs one write, not one per record.
//!
//! Levels, via `GUI_LOG` (`error|warn|info|debug|trace`, default `info`):
//!   error/warn  something is wrong
//!   info        lifecycle: modes, devices, VMs, per-2s frame reports
//!   debug       per-event detail (input events, guest scanouts)
//!   trace       firehose; will itself perturb timing
//!
//! `GUI_LOG_FILE` overrides the destination (default `/run/eve-gui.log`).
//! We also mirror warn/error to stderr, since the app owns a VT and the file is
//! usually the only way to see anything.

use std::io::Write;
use std::sync::mpsc::{channel, Sender};
use std::sync::OnceLock;

enum Msg {
    Rec(String),
    /// Flush and acknowledge, so shutdown can wait for the queue to drain.
    Sync(Sender<()>),
}

struct Async {
    tx: Sender<Msg>,
    start: std::time::Instant,
    /// Level for our own code.
    ours: log::LevelFilter,
    /// Level for everything else. smithay and friends log through `tracing`,
    /// which bridges into this logger and is extremely chatty at info - every
    /// EGL extension string, every span enter/exit. Kept at warn by default.
    deps: log::LevelFilter,
}

static LOGGER: OnceLock<Async> = OnceLock::new();

impl log::Log for Async {
    fn enabled(&self, m: &log::Metadata) -> bool {
        // Must be checked here, not left to max_level: the tracing bridge calls
        // enabled() itself, so a permissive answer leaks library TRACE records.
        let lim = if m.target().starts_with("eve_gui") { self.ours } else { self.deps };
        m.level() <= lim
    }
    fn flush(&self) {}

    fn log(&self, r: &log::Record) {
        if !self.enabled(r.metadata()) { return; }
        // Formatting allocates, but only for records that passed the level
        // check. The send is a channel push - no syscall, no file lock.
        let t = self.start.elapsed();
        let _ = self.tx.send(Msg::Rec(format!(
            "[{:7.3}] {:5} {:<8} {}",
            t.as_secs_f64(),
            r.level(),
            std::thread::current().name().unwrap_or("-"),
            r.args()
        )));
    }
}

/// Install the logger. Call once, early.
fn parse(var: &str, dflt: log::LevelFilter) -> log::LevelFilter {
    match std::env::var(var).unwrap_or_default().to_lowercase().as_str() {
        "off"   => log::LevelFilter::Off,
        "error" => log::LevelFilter::Error,
        "warn"  => log::LevelFilter::Warn,
        "info"  => log::LevelFilter::Info,
        "debug" => log::LevelFilter::Debug,
        "trace" => log::LevelFilter::Trace,
        _       => dflt,
    }
}

/// Cap for the log file. /run is tmpfs on EVE, so every byte here is RAM the
/// device cannot use for anything else.
const LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Largest single write, and so the most the file may overshoot its cap.
const MAX_BATCH_BYTES: usize = 256 * 1024;

pub fn init() {
    let ours = parse("GUI_LOG", log::LevelFilter::Info);
    let deps = parse("GUI_LOG_DEPS", log::LevelFilter::Warn);
    let path = std::env::var("GUI_LOG_FILE").unwrap_or_else(|_| "/run/eve-gui.log".into());
    let (tx, rx) = channel::<Msg>();
    let dest = path.clone();

    std::thread::Builder::new().name("log".into()).spawn(move || {
        // Never silently lose the log: if the file cannot be opened, say so
        // on stderr rather than dropping every record on the floor.
        let mut file = match std::fs::OpenOptions::new()
            .create(true).append(true).open(&dest) {
            Ok(f) => Some(f),
            Err(e) => {
                let _ = writeln!(std::io::stderr(), "logger: cannot open {dest}: {e}");
                None
            }
        };
        // Bytes in the current file, so the cap survives a restart appending
        // to an existing one.
        let mut written: u64 = file
            .as_ref()
            .and_then(|f| f.metadata().ok())
            .map_or(0, |m| m.len());
        // Blocks on recv - no polling. Wakes only when there is something.
        while let Ok(first) = rx.recv() {
            let mut buf = String::new();
            let mut acks = Vec::new();
            let mut msg = first;
            loop {
                match msg {
                    Msg::Rec(s) => { buf.push_str(&s); buf.push('\n'); }
                    Msg::Sync(a) => acks.push(a),
                }
                // Drain whatever else queued while we were busy: one write for
                // the whole burst - but a bounded one. An unbounded drain lets
                // a backlog become a single write, which both holds the whole
                // backlog in memory and skips past the file cap in one go.
                if buf.len() >= MAX_BATCH_BYTES { break; }
                match rx.try_recv() { Ok(m) => msg = m, Err(_) => break }
            }
            if !buf.is_empty() {
                if let Some(f) = file.as_mut() {
                    // /run is tmpfs, so this file is RAM. An error on a
                    // per-frame path - a head that lost master, input against a
                    // dead guest - writes at the frame rate, and filling /run
                    // breaks writes for pillar and everything else on the box
                    // long before anyone looks at the log. Start over at the
                    // cap rather than rotating: the recent lines are the ones
                    // worth having, and a rename needs somewhere to put the old
                    // file.
                    written += buf.len() as u64;
                    if written > LOG_MAX_BYTES {
                        // The file is open in append mode, so writes go to
                        // the end regardless of the offset - truncating alone
                        // is enough, no seek needed.
                        match f.set_len(0) {
                            Ok(_) => {
                                written = buf.len() as u64;
                                let _ = writeln!(f, "--- log restarted at {LOG_MAX_BYTES} bytes ---");
                            }
                            Err(e) => {
                                let _ = writeln!(std::io::stderr(), "logger: cannot truncate: {e}");
                                written = 0; // do not spin on a failing truncate
                            }
                        }
                    }
                    let _ = f.write_all(buf.as_bytes());
                    let _ = f.flush();
                }
                for line in buf.lines() {
                    if line.contains("WARN") || line.contains("ERROR") {
                        let _ = writeln!(std::io::stderr(), "{line}");
                    }
                }
            }
            for a in acks { let _ = a.send(()); }
        }
    }).expect("log thread");

    let me = Async { tx, start: std::time::Instant::now(), ours, deps };
    if LOGGER.set(me).is_err() { return; }
    let _ = log::set_logger(LOGGER.get().unwrap());
    // The coarse gate the macros check first; enabled() then splits ours/deps.
    log::set_max_level(ours.max(deps));
    log::info!("logging to {path}: ours={ours} deps={deps}");
}

/// Block until everything queued has hit the file. For the exit path, so a
/// crash or a SIGTERM does not lose the last records.
pub fn drain() {
    if let Some(l) = LOGGER.get() {
        let (tx, rx) = channel();
        if l.tx.send(Msg::Sync(tx)).is_ok() {
            let _ = rx.recv_timeout(std::time::Duration::from_secs(2));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    /// /run is tmpfs, so an unbounded log is RAM the device cannot use. A
    /// per-frame error path writes at the frame rate; filling /run breaks
    /// writes for pillar too, long before anyone reads the log.
    /// Flush every so often without pulling in a dependency.
    fn fastrand_ish() -> bool {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        N.fetch_add(1, Ordering::Relaxed) % 97 == 0
    }

    #[test]
    fn the_log_file_is_capped() {
        let dir = std::env::temp_dir().join(format!("eve-gui-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        std::env::set_var("GUI_LOG_FILE", &path);
        super::init();

        // Three times the cap: a per-frame error path reaches this in minutes.
        let spam = "x".repeat(4096);
        for _ in 0..(3 * super::LOG_MAX_BYTES / 4096) {
            log::info!("{spam}");
            // Let the writer keep up, so this exercises many bursts rather
            // than one enormous one.
            if fastrand_ish() { super::drain(); }
        }
        super::drain();

        let len = std::fs::metadata(&path).unwrap().len();
        let allowed = super::LOG_MAX_BYTES + super::MAX_BATCH_BYTES as u64;
        assert!(
            len <= allowed,
            "log grew to {len} bytes, past the {allowed}-byte ceiling"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::io::stderr().flush();
    }
}
