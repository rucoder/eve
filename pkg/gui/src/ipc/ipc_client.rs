// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use async_inotify::Watcher;
use inotify::EventMask;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::{net::UnixStream, task::JoinHandle};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Default timeout for establishing an IPC connection (socket appear + connect).
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct IpcClient {}
impl IpcClient {
    async fn try_connect(path: &str, attempts: u32) -> Result<UnixStream> {
        for i in 0..attempts {
            match UnixStream::connect(path).await {
                Ok(unix_stream) => {
                    return Ok(unix_stream);
                }
                Err(e) => {
                    log::debug!(
                        "Failed to connect to socket: {}. Retrying {}/{}",
                        e,
                        i + 1,
                        attempts
                    );
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        Err(anyhow!(
            "Failed to connect to socket after {} attempts",
            attempts
        ))
    }
    pub async fn connect(path: &str) -> Result<Framed<UnixStream, LengthDelimitedCodec>> {
        Self::connect_with_timeout(path, IPC_CONNECT_TIMEOUT).await
    }

    pub async fn connect_with_timeout(
        path: &str,
        timeout: Duration,
    ) -> Result<Framed<UnixStream, LengthDelimitedCodec>> {
        match tokio::time::timeout(timeout, Self::connect_inner(path)).await {
            Ok(result) => result,
            Err(_) => Err(anyhow!(
                "Timed out after {:?} waiting for IPC connection at {}",
                timeout,
                path
            )),
        }
    }

    /// Wait for the socket to exist, then connect.
    ///
    /// The waiting is an inotify watch, not a poll, and that distinction is
    /// load-bearing. Every accepted connection makes pillar's monitor agent
    /// re-activate its subscriptions, which leaks an inotify watcher per
    /// subscription on its side; a client that reconnects on a timer walks the
    /// agent into "too many open files" and the watchdog then reboots the
    /// device. Connect once, when there is something to connect to.
    async fn connect_inner(path: &str) -> Result<Framed<UnixStream, LengthDelimitedCodec>> {
        let socket_path = PathBuf::from(path);
        if !socket_path.exists() {
            let task: JoinHandle<Result<(), anyhow::Error>> =
                tokio::spawn(async move { Self::wait_for_socket_file(&socket_path).await });
            log::info!("waiting for {path} to appear");
            task.await??;
        }

        let stream = Self::try_connect(path, 30).await?;

        // The Go side is github.com/getlantern/framed, which writes the length
        // as a 4-byte LITTLE-endian field. tokio's default codec is big-endian,
        // so the default silently misreads every frame.
        Ok(LengthDelimitedCodec::builder()
            .little_endian()
            .length_field_type::<u32>()
            .new_framed(stream))
    }

    async fn wait_for_socket_file(path: &Path) -> Result<()> {
        let dir = path
            .parent()
            .ok_or_else(|| anyhow!("socket path {} has no parent", path.display()))?;
        let mut watcher = Watcher::init();
        let wd = match watcher.add(dir, &async_inotify::WatchMask::CREATE) {
            Ok(wd) => wd,
            // The directory may not exist yet; the caller retries.
            Err(e) => return Err(anyhow!("watch {}: {e}", dir.display())),
        };
        while let Some(event) = watcher.next().await {
            if *event.mask() == EventMask::CREATE && event.path() == path {
                log::info!("{} appeared", path.display());
                break;
            }
        }
        let _ = watcher.remove(wd);
        Ok(())
    }
}
