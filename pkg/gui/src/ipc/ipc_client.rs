// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use log::warn;
use std::time::Duration;
use tokio::net::UnixStream;
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
                    warn!(
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

    /// Connect, retrying briefly. The caller reconnects for the life of the
    /// process, so there is no need to watch the filesystem for the socket to
    /// appear - pillar starting after us is an ordinary case, not an error.
    async fn connect_inner(path: &str) -> Result<Framed<UnixStream, LengthDelimitedCodec>> {
        let stream = Self::try_connect(path, 10).await?;
        Ok(Framed::new(stream, LengthDelimitedCodec::new()))
    }
}
