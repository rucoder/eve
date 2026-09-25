// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

pub mod ipc_client;
pub mod message;

// Generated contract types — source of truth is the Go package
// pkg/pillar/types/monitorapi. Regenerate via `go generate` there.
#[path = "monitorapi.gen.rs"]
pub mod monitorapi;

// Hand-written helpers on the generated contract types.
mod tpm;

#[cfg(test)]
mod monitorapi_tests;

// Pillar's monitor agent accepts exactly ONE client connection per process;
// see docs/monitor.md and the 2026-09-25 reboot-loop incident (a second
// connection makes pillar re-activate its subscriptions and leak an inotify
// watcher per subscription, eventually killing the agent and triggering the
// watchdog). `ipc_client::IpcClient::connect` must therefore only ever be
// called from the `spawn` below - main.rs calls it exactly once at startup
// and hands the pieces out to whichever frontend(s) it runs. See
// crate::frontend for the startup choice.
use message::IpcMessage;
use monitorapi::{AppInstance, DeviceStatus, NetworkStatus};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

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

/// The single IPC client and the ends each frontend needs from it.
///
/// The GUI only ever reads `state`. The TUI's Elm-style loop reads `events`
/// (every decoded message, plus the synthetic Connecting/Ready/
/// ConnectionFailed/ConnectionLost status events its connection popup is
/// driven by) in place of owning the socket, and writes requests to `outbox`
/// in place of a sink it would otherwise own.
///
/// Keep this value alive for as long as its `outbox` should stay open: once
/// every sender is dropped, the background thread treats that as shutdown
/// and stops reconnecting.
pub struct Client {
    pub state: Shared,
    pub events: UnboundedReceiver<IpcMessage>,
    pub outbox: UnboundedSender<IpcMessage>,
}

/// Start the one client this process is allowed to have. Returns immediately;
/// the background thread reconnects for the life of the process, because
/// pillar restarting is normal, not an error.
pub fn spawn(socket: &str) -> Client {
    let state: Shared = Default::default();
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    let (outbox_tx, outbox_rx) = tokio::sync::mpsc::unbounded_channel();

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
            rt.block_on(run_forever(&path, &out, events_tx, outbox_rx));
        });

    Client { state, events: events_rx, outbox: outbox_tx }
}

/// Connect, pump frames until disconnected, wait, and try again - forever.
/// Only returns (early) once every `outbox` sender has been dropped, which
/// main.rs treats as "process is shutting down" and never happens in
/// practice, since it holds `Client` for the life of the process.
async fn run_forever(
    path: &str,
    out: &Shared,
    events: UnboundedSender<IpcMessage>,
    mut outbox: UnboundedReceiver<IpcMessage>,
) {
    let mut has_connected = false;
    loop {
        let _ = events.send(IpcMessage::Connecting);
        match ipc_client::IpcClient::connect(path).await {
            Ok(stream) => {
                log::info!("pillar: connected on {path}");
                has_connected = true;
                out.lock().unwrap().connected = true;
                let _ = events.send(IpcMessage::Ready);
                pump(stream, out, &events, &mut outbox).await;
                out.lock().unwrap().connected = false;
                let _ = events.send(IpcMessage::ConnectionLost);
            }
            Err(e) => {
                log::warn!("pillar: connect {path}: {e}");
                out.lock().unwrap().connected = false;
                let _ = events.send(if has_connected {
                    IpcMessage::ConnectionLost
                } else {
                    IpcMessage::ConnectionFailed
                });
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

/// Read frames (updating `out` and forwarding to `events`) and write whatever
/// arrives on `outbox`, until the connection drops or every `outbox` sender
/// is gone.
async fn pump(
    stream: tokio_util::codec::Framed<tokio::net::UnixStream, tokio_util::codec::LengthDelimitedCodec>,
    out: &Shared,
    events: &UnboundedSender<IpcMessage>,
    outbox: &mut UnboundedReceiver<IpcMessage>,
) {
    use futures::{SinkExt, StreamExt};
    let (mut sink, mut stream) = stream.split();
    // Anything queued while disconnected is stale by now.
    while outbox.try_recv().is_ok() {}

    loop {
        tokio::select! {
            msg = outbox.recv() => {
                match msg {
                    Some(msg) => {
                        if let Err(e) = sink.send(msg.into()).await {
                            log::warn!("pillar: send: {e}");
                            return;
                        }
                    }
                    None => return,
                }
            }
            frame = stream.next() => {
                match frame {
                    Some(Ok(bytes)) => {
                        let msg = IpcMessage::from(bytes);
                        update_state(out, &msg);
                        let _ = events.send(msg);
                    }
                    Some(Err(e)) => {
                        log::warn!("pillar: read: {e}");
                        return;
                    }
                    None => {
                        log::warn!("pillar: connection closed by peer");
                        return;
                    }
                }
            }
        }
    }
}

fn update_state(out: &Shared, msg: &IpcMessage) {
    let mut s = out.lock().unwrap();
    match msg {
        IpcMessage::DeviceStatus(d) => s.device = Some(d.clone()),
        IpcMessage::NetworkStatus(n) => s.network = Some(n.clone()),
        IpcMessage::AppsList(a) => s.apps = a.instances.clone(),
        _ => {}
    }
}

#[cfg(test)]
mod gui_client_tests {
    use super::*;

    // IpcMessage is adjacently tagged: {"type": ..., "message": ...}. The
    // payloads below are the real ones from
    // pkg/pillar/types/monitorapi/testdata, which is the contract's own
    // fixture set - do not hand-simplify them.
    // Copied from pkg/pillar/types/monitorapi/testdata/device_status.json.
    // Inlined rather than include_str!'d because pkg/gui was its own Docker
    // build context and could not read files outside it; kept inline here
    // since it still exercises this module's own decode path.
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

    /// Go marshals a nil slice as `null`, not as `[]`. #[serde(default)] alone
    /// does not accept an explicit null - serde reports "invalid type: null,
    /// expected a sequence" and the WHOLE message is dropped, not just the
    /// field. Every Vec in the contract can arrive this way.
    #[test]
    fn decodes_a_null_slice_as_empty() {
        let wire = r#"{"type":"NetworkStatus","message":{"dpcKey":"manual","interfaces":[
            {"name":"eth0","label":"uplink","mac":"00:11:22:33:44:55","up":true,
             "isMgmt":true,"cost":0,"media":{"kind":"ethernet"},
             "network":{"isDhcp":true,"ipv4":null,"ipv6":null,"subnet":null,
                        "routes":null,"dnsServers":null,"ntpServers":null,
                        "domain":"","proxy":{"mode":"none"},"errors":null},
             "vlans":null}]}}"#;
        match serde_json::from_str::<IpcMessage>(wire).expect("a null slice must decode") {
            IpcMessage::NetworkStatus(n) => {
                assert_eq!(n.interfaces.len(), 1);
                assert!(n.interfaces[0].network.dns_servers.is_empty());
                assert!(n.interfaces[0].network.routes.is_empty());
                assert!(n.interfaces[0].network.errors.is_empty());
                assert!(n.interfaces[0].vlans.is_empty());
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
