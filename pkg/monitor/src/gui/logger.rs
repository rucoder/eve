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
//! `GUI_LOG_FILE` overrides the destination (default
//! `/persist/eve-gui.log`). /persist and not /run: /run is tmpfs, so the log
//! dies with the machine, and a console that has just rebooted is exactly when
//! you need the previous boot's log.
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

/// Level for our own code, as a `LevelFilter as usize`. Atomic because
/// pillar changes it at runtime (`TUIConfig`) from the IPC thread while the
/// render and input threads are logging.
static OURS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(
    log::LevelFilter::Info as usize,
);

/// What `log` calls a record from this crate. `module_path!()` here is
/// `monitor::gui::logger`, so the crate name is everything before the first
/// `::` - taking it from the source rather than spelling it out, because
/// spelling it out is how this came to read "eve_gui" and quietly judge every
/// one of our own records by the dependency filter.
fn ours_prefix() -> &'static str {
    module_path!().split("::").next().unwrap_or("monitor")
}

/// What pillar's console.log_level debug option asks for. It only raises the
/// level: whatever config.json or TUIConfig set in `OURS` stays the floor.
static DEBUG: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(log::LevelFilter::Off as usize);

/// Whether zbus may log below WARN; pillar's console.zbus_log.
static ZBUS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set the level for our own code. Dependencies keep whatever they were given
/// at startup: a request for debug output from us is not a request for every
/// EGL span from smithay, and at trace those alone fill the log's byte cap in
/// about two minutes, taking the history with them.
pub fn set_ours(level: log::LevelFilter) {
    OURS.store(level as usize, std::sync::atomic::Ordering::Relaxed);
    apply_levels();
}

/// Pillar's console.log_level.
pub fn set_debug_level(level: log::LevelFilter) {
    if DEBUG.swap(level as usize, std::sync::atomic::Ordering::Relaxed) != level as usize {
        apply_levels();
        log::info!("console.log_level {level}: logging at {}", log::max_level());
    }
}

/// Pillar's console.zbus_log.
pub fn set_zbus(on: bool) {
    if ZBUS.swap(on, std::sync::atomic::Ordering::Relaxed) != on {
        log::info!("console.zbus_log {on}");
    }
}

fn apply_levels() {
    let deps = LOGGER.get().map_or(log::LevelFilter::Warn, |l| l.deps);
    log::set_max_level(ours_level().max(deps));
    // The tracing bridge's level hint is cached per callsite.
    tracing::callsite::rebuild_interest_cache();
}

fn level_at(slot: &std::sync::atomic::AtomicUsize) -> log::LevelFilter {
    match slot.load(std::sync::atomic::Ordering::Relaxed) {
        0 => log::LevelFilter::Off,
        1 => log::LevelFilter::Error,
        2 => log::LevelFilter::Warn,
        3 => log::LevelFilter::Info,
        4 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    }
}

fn ours_level() -> log::LevelFilter {
    level_at(&OURS).max(level_at(&DEBUG))
}

/// Send what zbus and smithay log through `tracing` on to `log`.
///
/// tracing does that by itself while nothing has claimed it, but filters on
/// nothing but the global level then, and zbus opens an INFO span for every
/// D-Bus call it dispatches - at least one per guest frame. This holds zbus at
/// WARN unless console.zbus_log is on. A span is logged once, when it is
/// created, as tracing's own fallback does; entering and leaving it is not.
pub fn route_tracing() {
    let bridge = TracingBridge { next_span: std::sync::atomic::AtomicU64::new(1) };
    if let Err(e) = tracing::subscriber::set_global_default(bridge) {
        log::warn!("tracing bridge: {e}");
    }
}

struct TracingBridge {
    next_span: std::sync::atomic::AtomicU64,
}

fn log_level_of(l: &tracing::Level) -> log::Level {
    match *l {
        tracing::Level::ERROR => log::Level::Error,
        tracing::Level::WARN => log::Level::Warn,
        tracing::Level::INFO => log::Level::Info,
        tracing::Level::DEBUG => log::Level::Debug,
        _ => log::Level::Trace,
    }
}

impl tracing::Subscriber for TracingBridge {
    // Decided per record: the levels and console.zbus_log change at runtime.
    fn register_callsite(&self, _: &'static tracing::Metadata<'static>) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }

    fn enabled(&self, m: &tracing::Metadata<'_>) -> bool {
        let level = log_level_of(m.level());
        level <= log::max_level()
            && (level <= log::Level::Warn
                || !m.target().starts_with("zbus")
                || ZBUS.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        use tracing::level_filters::LevelFilter;
        Some(match log::max_level() {
            log::LevelFilter::Off => LevelFilter::OFF,
            log::LevelFilter::Error => LevelFilter::ERROR,
            log::LevelFilter::Warn => LevelFilter::WARN,
            log::LevelFilter::Info => LevelFilter::INFO,
            log::LevelFilter::Debug => LevelFilter::DEBUG,
            log::LevelFilter::Trace => LevelFilter::TRACE,
        })
    }

    fn new_span(&self, a: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        let mut line = Fields(format!("++ {}", a.metadata().name()));
        a.record(&mut line);
        forward(a.metadata(), &line.0);
        tracing::span::Id::from_u64(self.next_span.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, e: &tracing::Event<'_>) {
        let mut line = Fields(String::new());
        e.record(&mut line);
        forward(e.metadata(), &line.0);
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// A record's fields as one line: the message as is, the rest as name=value.
struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if !self.0.is_empty() {
            self.0.push(' ');
        }
        let _ = match f.name() {
            "message" => write!(self.0, "{v:?}"),
            name => write!(self.0, "{name}={v:?}"),
        };
    }
}

fn forward(m: &tracing::Metadata<'_>, msg: &str) {
    log::logger().log(
        &log::Record::builder()
            .level(log_level_of(m.level()))
            .target(m.target())
            .module_path(m.module_path())
            .file(m.file())
            .line(m.line())
            .args(format_args!("{msg}"))
            .build(),
    );
}

struct Async {
    tx: Sender<Msg>,
    start: std::time::Instant,
    /// Startup level for our own code; the live value is in `OURS`.
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
        let lim = if m.target().starts_with(ours_prefix()) { ours_level() } else { self.deps };
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

/// Cap for the log file. /persist is a real filesystem, but it is shared with
/// everything else EVE keeps, so the console does not get to grow without
/// bound there either.
const LOG_MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Largest single write, and so the most the file may overshoot its cap.
const MAX_BATCH_BYTES: usize = 256 * 1024;

pub fn init() {
    let ours = parse("GUI_LOG", log::LevelFilter::Info);
    let deps = parse("GUI_LOG_DEPS", log::LevelFilter::Warn);
    let path = std::env::var("GUI_LOG_FILE").unwrap_or_else(|_| "/persist/eve-gui.log".into());
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
    OURS.store(ours as usize, std::sync::atomic::Ordering::Relaxed);
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
