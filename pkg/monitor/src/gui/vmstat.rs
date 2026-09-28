// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Live memory for the running guests, sampled from the host.
//!
//! A guest is killed by the memory cgroup, not by anything it can see, so
//! the numbers that matter are the host's: what the cgroup has charged, and
//! how much of that is GPU memory. The guest's own `free` shows none of it.
//! Three OOM kills in one evening were diagnosed by reading these files by
//! hand over ssh; this is that, on the panel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// One reading, in bytes.
#[derive(Clone, Copy, Default)]
pub struct Sample {
    pub usage: u64,
    /// Charged as shmem, which on an integrated GPU is virglrenderer's
    /// textures and scanout buffers. Tracks the DRM figure to within a
    /// megabyte, and is the part no other tool attributes to the guest.
    pub shmem: u64,
}

/// A guest's recent history and its worst moment.
pub struct Series {
    pub limit: u64,
    /// Oldest first. Bounded, so a long-running console cannot grow it.
    pub samples: Vec<Sample>,
    pub peak: Sample,
    pub peak_age: Duration,
    peak_at: Instant,
}

impl Series {
    pub fn latest(&self) -> Sample {
        self.samples.last().copied().unwrap_or_default()
    }
    /// Fraction of the limit currently charged, for the colour of the trace.
    pub fn headroom(&self) -> f32 {
        if self.limit == 0 {
            return 0.0;
        }
        self.latest().usage as f32 / self.limit as f32
    }
}

pub type Shared = Arc<Mutex<HashMap<String, Series>>>;

/// Samples kept, one per second: twenty minutes, which covers a boot and a
/// desktop settling without the plot becoming unreadable.
const KEEP: usize = 1200;
const PERIOD: Duration = Duration::from_secs(1);

fn read_u64(path: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// `shmem` out of the cgroup's own accounting. Not `total_shmem`: that
/// includes children, and this cgroup has none.
fn read_shmem(dir: &str) -> u64 {
    let Ok(s) = std::fs::read_to_string(format!("{dir}/memory.stat")) else {
        return 0;
    };
    s.lines()
        .find_map(|l| l.strip_prefix("shmem ")?.trim().parse().ok())
        .unwrap_or(0)
}

/// The app's memory cgroup, reached through qemu's own mount namespace.
///
/// The console runs in a container with its own cgroup namespace, so the
/// host's `/sys/fs/cgroup/memory/eve-user-apps/<domain>` does not exist for
/// it - it sees only its own cgroup as the root. qemu, however, is IN the
/// app's cgroup, so through `/proc/<pid>/root` that same cgroup is simply
/// the mounted one. Measured on the device: this yields the limit domainmgr
/// set, to the byte.
fn cgroup_of(pid: u32) -> String {
    format!("/proc/{pid}/root/sys/fs/cgroup/memory")
}

/// Sample every guest cgroup once a second, off the render thread.
///
/// Reading six small sysfs files per guest per second is far below the cost
/// of a frame, but it is still a syscall storm to put in the paint path, and
/// a cgroup can disappear mid-read when a guest dies.
pub fn spawn() -> Shared {
    let shared: Shared = Default::default();
    let out = shared.clone();
    let _ = std::thread::Builder::new()
        .name("vmstat".into())
        .spawn(move || loop {
            // The domain directory is the identity, and it carries the
            // pid of the qemu that serves it.
            let found: Vec<(String, u32)> = std::fs::read_dir("/run/hypervisor/kvm")
                .into_iter()
                .flatten()
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().into_string().ok()?;
                    let pid = read_u64(&format!("/run/hypervisor/kvm/{name}/pid"))? as u32;
                    Some((name, pid))
                })
                .collect();

            {
                let mut m = out.lock().unwrap();
                // A guest that went away must not leave its last reading on
                // screen looking live.
                m.retain(|k, _| found.iter().any(|(d, _)| d == k));

                for (d, pid) in &found {
                    let dir = cgroup_of(*pid);
                    let Some(usage) = read_u64(&format!("{dir}/memory.usage_in_bytes")) else {
                        continue;
                    };
                    let limit = read_u64(&format!("{dir}/memory.limit_in_bytes")).unwrap_or(0);
                    let s = Sample { usage, shmem: read_shmem(&dir) };

                    let e = m.entry(d.clone()).or_insert_with(|| Series {
                        limit,
                        samples: Vec::with_capacity(KEEP),
                        peak: s,
                        peak_age: Duration::ZERO,
                        peak_at: Instant::now(),
                    });
                    // The limit changes when the instance is resized in the
                    // controller, without the domain name changing.
                    e.limit = limit;
                    if s.usage > e.peak.usage {
                        e.peak = s;
                        e.peak_at = Instant::now();
                    }
                    e.peak_age = e.peak_at.elapsed();
                    if e.samples.len() == KEEP {
                        e.samples.remove(0);
                    }
                    e.samples.push(s);
                }
            }
            std::thread::sleep(PERIOD);
        });
    shared
}
