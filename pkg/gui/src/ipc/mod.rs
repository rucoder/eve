// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Device state from pillar, over the same socket and message types the TUI
//! monitor uses. The client is copied from `pkg/monitor`: each linuxkit package
//! builds in its own Docker context, so a path dependency is impossible, and
//! this code becomes ours outright once the TUI is removed.

pub mod ipc_client;
pub mod message;

// Generated contract types — source of truth is the Go package
// pkg/pillar/types/monitorapi.
#[path = "monitorapi.gen.rs"]
pub mod monitorapi;

use message::IpcMessage;
use monitorapi::{AppInstance, DeviceStatus, NetworkStatus};

/// The default socket pillar serves the monitor contract on.
pub const MONITOR_SOCKET: &str = "/run/monitor.sock";

/// The latest of each message pillar sends. The render loop reads it, the
/// client thread writes it; neither waits for the other, because the console
/// must draw whether or not pillar is up — it may well start first.
#[derive(Default)]
pub struct PillarState {
    pub device: Option<DeviceStatus>,
    pub network: Option<NetworkStatus>,
    pub apps: Vec<AppInstance>,
    /// False until a message has arrived, so the UI can say so rather than
    /// showing empty fields as though they were facts.
    pub connected: bool,
}

pub type Shared = std::sync::Arc<std::sync::Mutex<PillarState>>;

/// Start the client. Returns immediately and reconnects for the life of the
/// process; pillar restarting is normal, not an error.
pub fn spawn(socket: &str) -> Shared {
    let state: Shared = Default::default();
    let (out, path) = (state.clone(), socket.to_string());
    let _ = std::thread::Builder::new()
        .name("pillar".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    log::error!("pillar: runtime: {e}");
                    return;
                }
            };
            rt.block_on(async move {
                loop {
                    if let Err(e) = run(&path, &out).await {
                        log::warn!("pillar: {e}; reconnecting");
                    }
                    out.lock().unwrap().connected = false;
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            });
        });
    state
}

async fn run(path: &str, out: &Shared) -> anyhow::Result<()> {
    use futures::StreamExt;
    let mut framed = ipc_client::IpcClient::connect(path)
        .await
        .map_err(|e| anyhow::anyhow!("connect {path}: {e}"))?;
    log::info!("pillar: connected on {path}");
    out.lock().unwrap().connected = true;

    while let Some(frame) = framed.next().await {
        let frame = frame?;
        let msg: IpcMessage = match serde_json::from_slice(&frame) {
            Ok(m) => m,
            Err(e) => {
                log::warn!("pillar: undecodable message: {e}");
                continue;
            }
        };
        let mut s = out.lock().unwrap();
        match msg {
            IpcMessage::DeviceStatus(d) => s.device = Some(d),
            IpcMessage::NetworkStatus(n) => s.network = Some(n),
            IpcMessage::AppsList(a) => s.apps = a.instances,
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // IpcMessage is adjacently tagged: {"type": ..., "message": ...}. The
    // payloads below are the real ones from
    // pkg/pillar/types/monitorapi/testdata, which is the contract's own
    // fixture set - do not hand-simplify them.
    // Copied from pkg/pillar/types/monitorapi/testdata/device_status.json.
    // Inlined rather than include_str!'d because pkg/gui is its own Docker
    // build context and cannot read files outside it.
    const DEVICE_STATUS: &str = r#"{
      "server": "zedcloud.example.com:443",
      "nodeUuid": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "onboarded": true,
      "nodeName": "edge-node-01",
      "serial": "ABC123XYZ",
      "hardwareModel": "QEMU Standard PC",
      "configStatus": "success",
      "deviceState": "online",
      "bootReason": "rebootCmd",
      "rebootReason": "scheduled",
      "maintenanceMode": false,
      "attestState": "complete",
      "attestError": "",
      "vault": { "state": "unlocked", "tpmUsed": true }
    }"#;

    #[test]
    fn decodes_a_device_status() {
        let wire = format!(r#"{{"type":"DeviceStatus","message":{DEVICE_STATUS}}}"#);
        match serde_json::from_str::<IpcMessage>(&wire).expect("decode") {
            IpcMessage::DeviceStatus(d) => {
                assert_eq!(d.server, "zedcloud.example.com:443");
                assert_eq!(d.node_name, "edge-node-01");
                assert_eq!(d.serial, "ABC123XYZ");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// The field added for the console: an app must carry where its display is.
    #[test]
    fn decodes_an_app_with_its_qmp_socket() {
        let wire = r#"{"type":"AppsList","message":{"instances":[
            {"uuid":"9c1f2e3a-4b5c-6d7e-8f90-a1b2c3d4e5f6","name":"vm1",
             "version":"1","state":"running","error":"",
             "qmpSocket":"/run/hypervisor/kvm/vm1.1.1/qmp"}]}}"#;
        match serde_json::from_str::<IpcMessage>(wire).expect("decode") {
            IpcMessage::AppsList(a) => {
                assert_eq!(a.instances.len(), 1);
                assert_eq!(a.instances[0].qmp_socket, "/run/hypervisor/kvm/vm1.1.1/qmp");
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// An app with no virtual GPU omits the field entirely; it must still decode.
    #[test]
    fn decodes_an_app_without_a_qmp_socket() {
        let wire = r#"{"type":"AppsList","message":{"instances":[
            {"uuid":"9c1f2e3a-4b5c-6d7e-8f90-a1b2c3d4e5f6","name":"vm1",
             "version":"1","state":"running","error":""}]}}"#;
        match serde_json::from_str::<IpcMessage>(wire).expect("decode") {
            IpcMessage::AppsList(a) => assert!(a.instances[0].qmp_socket.is_empty()),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
