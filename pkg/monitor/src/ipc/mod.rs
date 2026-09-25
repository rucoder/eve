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
use std::sync::atomic::{AtomicU64, Ordering};

use message::IpcMessage;
use monitorapi::{AppInstance, DeviceStatus, GpuRequest, NetworkStatus};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender};

/// Capacity of the `events` channel (see `Client::events`). Deliberately
/// small: it exists to hand a frontend a live feed, not to buffer history.
const EVENTS_CAPACITY: usize = 256;

/// The default socket pillar serves the monitor contract on.
pub const MONITOR_SOCKET: &str = "/run/monitor.sock";

/// The latest of each message pillar sends. The render loop reads it, the
/// client thread writes it; neither waits for the other, because the console
/// must draw whether or not pillar is up — it may well start first.
pub struct PillarState {
    pub device: Option<DeviceStatus>,
    pub network: Option<NetworkStatus>,
    pub apps: Vec<AppInstance>,
    /// False until a message has arrived, so the UI can say so rather than
    /// showing empty fields as though they were facts.
    pub connected: bool,
    /// Whether the console frontend loop may put the GUI on screen right
    /// now. main.rs's frontend loop reads this (via `Console::set_gpu_available`)
    /// to decide GUI vs TUI, both at the top of a session and, through a
    /// watcher, while one is already running.
    pub gpu_available: bool,
    /// The most recent GPURequest not yet answered with a GpuAck, so the id
    /// pillar is waiting on travels with the flag it caused, rather than
    /// main.rs having to generate one. A release and a restore both land
    /// here; like pillar's own `pendingGPURequestID`, this is a single slot,
    /// not a queue - a request superseded before it is acked is simply
    /// never acked, which is fine, because pillar would have dropped that
    /// ack as stale anyway.
    pub pending_gpu_ack: Option<GpuRequest>,
}

impl Default for PillarState {
    fn default() -> Self {
        Self {
            device: None,
            network: None,
            apps: Vec::new(),
            connected: false,
            // Nobody has taken the GPU until pillar says so.
            gpu_available: true,
            pending_gpu_ack: None,
        }
    }
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
/// `events` is bounded and lossy by design - see `send_event`. `outbox` is
/// the shutdown handle: keep it (or `Client` as a whole) alive for as long
/// as this client should keep running. Once every `outbox` sender is
/// dropped, the background thread finishes pumping the current connection
/// (if any), then stops instead of reconnecting.
pub struct Client {
    pub state: Shared,
    pub events: Receiver<IpcMessage>,
    pub outbox: UnboundedSender<IpcMessage>,
}

/// Start the one client this process is allowed to have. Returns immediately;
/// the background thread reconnects for the life of the process, because
/// pillar restarting is normal, not an error.
pub fn spawn(socket: &str) -> Client {
    let state: Shared = Default::default();
    let (events_tx, events_rx) = tokio::sync::mpsc::channel(EVENTS_CAPACITY);
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

/// How many events `send_event` has dropped because `events` was full (or,
/// on the GUI path, never drained at all). Logged at a low rate - this sits
/// on the connection's read path and must not turn into a log line per
/// message.
static EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Hand `msg` to whichever frontend is reading `events`, without blocking.
///
/// Every `IpcMessage` pillar sends is a full snapshot, not a delta (see
/// `PillarState`), so a frontend that is not currently reading - the GUI
/// never reads `events` at all; the TUI might be slow for a moment - loses
/// nothing but staleness: the next message it does read is current. Nothing
/// here needs to be replayed, so dropping on a full queue is correct, and
/// blocking would be worse than wrong - it would stall this connection's
/// read loop (and therefore `PillarState`) for as long as nobody drains
/// `events`, which for the GUI path is the entire run.
fn send_event(events: &Sender<IpcMessage>, msg: IpcMessage) {
    if events.try_send(msg).is_err() {
        let n = EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed) + 1;
        if n.is_power_of_two() {
            log::warn!("pillar: dropped {n} events so far (no reader, or reader too slow)");
        }
    }
}

/// Why `pump` returned.
enum PumpExit {
    /// The connection itself went away; reconnect.
    Disconnected,
    /// Every `outbox` sender was dropped: no frontend can send requests or
    /// wants events any more. Stop instead of reconnecting.
    ShuttingDown,
}

/// Connect, pump frames until disconnected, wait, and try again - until
/// `outbox` closes, which main.rs treats as "process is shutting down" and
/// which does not happen in practice, since it holds `Client` for the life
/// of the process.
async fn run_forever(
    path: &str,
    out: &Shared,
    events: Sender<IpcMessage>,
    mut outbox: UnboundedReceiver<IpcMessage>,
) {
    let mut has_connected = false;
    loop {
        send_event(&events, IpcMessage::Connecting);
        match ipc_client::IpcClient::connect(path).await {
            Ok(stream) => {
                log::info!("pillar: connected on {path}");
                has_connected = true;
                out.lock().unwrap().connected = true;
                send_event(&events, IpcMessage::Ready);
                let exit = pump(stream, out, &events, &mut outbox).await;
                out.lock().unwrap().connected = false;
                if matches!(exit, PumpExit::ShuttingDown) {
                    log::info!("pillar: outbox closed; stopping client");
                    return;
                }
                send_event(&events, IpcMessage::ConnectionLost);
            }
            Err(e) => {
                log::warn!("pillar: connect {path}: {e}");
                out.lock().unwrap().connected = false;
                send_event(&events, if has_connected {
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
    events: &Sender<IpcMessage>,
    outbox: &mut UnboundedReceiver<IpcMessage>,
) -> PumpExit {
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
                            return PumpExit::Disconnected;
                        }
                    }
                    None => return PumpExit::ShuttingDown,
                }
            }
            frame = stream.next() => {
                match frame {
                    Some(Ok(bytes)) => {
                        let msg = IpcMessage::from(bytes);
                        // `apply` hands back anything it didn't need to store
                        // (untouched, not cloned - large variants like TpmLogs
                        // pass straight through) so it can still be forwarded
                        // to `events`.
                        if let Some(msg) = apply(&mut out.lock().unwrap(), msg) {
                            send_event(events, msg);
                        }
                    }
                    Some(Err(e)) => {
                        log::warn!("pillar: read: {e}");
                        return PumpExit::Disconnected;
                    }
                    None => {
                        log::warn!("pillar: connection closed by peer");
                        return PumpExit::Disconnected;
                    }
                }
            }
        }
    }
}

/// Applies one decoded message to `state`. Pulled out of the read loop in
/// `pump` so the GPU handover can be unit-tested without a socket - see
/// `gui_client_tests` below.
///
/// Returns `msg` back when `state` didn't need to consume it (every variant
/// but the four below), so the caller can still forward it to `events`
/// without having to clone a message that can be arbitrarily large (e.g.
/// `TpmLogs`) just to keep a copy neither side ends up using.
pub fn apply(state: &mut PillarState, msg: IpcMessage) -> Option<IpcMessage> {
    match msg {
        IpcMessage::DeviceStatus(d) => {
            state.device = Some(d.clone());
            Some(IpcMessage::DeviceStatus(d))
        }
        IpcMessage::NetworkStatus(n) => {
            state.network = Some(n.clone());
            Some(IpcMessage::NetworkStatus(n))
        }
        IpcMessage::AppsList(a) => {
            state.apps = a.instances.clone();
            Some(IpcMessage::AppsList(a))
        }
        // Pillar asking the console to give up the GPU (release) or telling
        // it the GPU is available again (restore). Flip the flag the
        // frontend loop reads immediately, and remember the request id so
        // the eventual GpuAck echoes it rather than a fresh or zero one -
        // pillar drops any ack whose id does not match what it is waiting
        // on (see PillarState::pending_gpu_ack).
        IpcMessage::GPURequest(r) => {
            state.gpu_available = !r.release;
            state.pending_gpu_ack = Some(r.clone());
            Some(IpcMessage::GPURequest(r))
        }
        other => Some(other),
    }
}

#[cfg(test)]
mod gui_client_tests {
    use super::*;
    use message::Request;

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

    /// The release request pillar sends before it binds the GPU to vfio.
    #[test]
    fn decodes_a_gpu_release_request() {
        let wire = r#"{"type":"GPURequest","message":{"domain":"vm1","release":true,"request_id":7}}"#;
        match serde_json::from_str::<IpcMessage>(wire).expect("decode") {
            IpcMessage::GPURequest(r) => {
                assert_eq!(r.domain, "vm1");
                assert!(r.release);
                assert_eq!(r.request_id, 7);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// And the message that gives it back.
    #[test]
    fn decodes_a_gpu_restore_request() {
        let wire = r#"{"type":"GPURequest","message":{"domain":"","release":false,"request_id":8}}"#;
        match serde_json::from_str::<IpcMessage>(wire).expect("decode") {
            IpcMessage::GPURequest(r) => {
                assert!(!r.release);
                assert_eq!(r.request_id, 8);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// GPUAck travels console -> pillar, so unlike GPURequest it goes through
    /// the Request envelope (RequestType/RequestData/id) that ipc_server.go's
    /// `request` struct decodes, not IpcMessage's adjacently-tagged
    /// type/message envelope. A GPUAck wrongly encoded as
    /// {"type":"GPUAck","message":{...}} would arrive at pillar as an empty
    /// RequestType and be rejected by request.validate(), hanging the
    /// handshake until domainmgr's timeout.
    #[test]
    fn decodes_a_gpu_ack_as_a_request() {
        let wire = r#"{"RequestType":"GPUAck","RequestData":{"domain":"vm1","released":true,"request_id":7},"id":7}"#;
        match serde_json::from_str::<IpcMessage>(wire).expect("decode") {
            IpcMessage::Request { request: Request::GPUAck(ack), id } => {
                assert_eq!(ack.domain, "vm1");
                assert!(ack.released);
                assert_eq!(ack.request_id, 7);
                assert_eq!(id, 7);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// A fresh PillarState must start with the GPU considered available - a
    /// `#[derive(Default)]` bool would start every device in TUI mode, which
    /// is wrong for a device that has never heard from pillar at all.
    #[test]
    fn a_fresh_state_assumes_the_gpu_is_available() {
        assert!(PillarState::default().gpu_available);
    }

    /// A release request must flip the shared flag the frontend loop reads,
    /// so the console switches to the TUI before pillar binds vfio.
    #[test]
    fn a_release_request_marks_the_gpu_unavailable() {
        let mut st = PillarState::default();
        apply(&mut st, IpcMessage::GPURequest(monitorapi::GpuRequest {
            domain: "vm1".into(),
            release: true,
            request_id: 7,
        }));
        assert!(!st.gpu_available);

        apply(&mut st, IpcMessage::GPURequest(monitorapi::GpuRequest {
            domain: String::new(),
            release: false,
            request_id: 8,
        }));
        assert!(st.gpu_available);
    }

    /// The id pillar is waiting on must travel with the flag it caused, not
    /// be invented later - main.rs echoes this in the GpuAck it sends once
    /// the frontend has actually acted on it, and pillar drops any ack whose
    /// id does not match what it is waiting on.
    #[test]
    fn a_gpu_request_is_remembered_for_the_eventual_ack() {
        let mut st = PillarState::default();
        assert!(st.pending_gpu_ack.is_none());

        apply(&mut st, IpcMessage::GPURequest(monitorapi::GpuRequest {
            domain: "vm1".into(),
            release: true,
            request_id: 42,
        }));
        let pending = st.pending_gpu_ack.as_ref().expect("a request is pending");
        assert_eq!(pending.request_id, 42);
        assert!(pending.release);

        // A later request - even a restore - replaces it: this is a single
        // slot mirroring pillar's own pendingGPURequestID, not a queue.
        apply(&mut st, IpcMessage::GPURequest(monitorapi::GpuRequest {
            domain: String::new(),
            release: false,
            request_id: 43,
        }));
        let pending = st.pending_gpu_ack.as_ref().expect("a request is pending");
        assert_eq!(pending.request_id, 43);
        assert!(!pending.release);
    }

    /// A message unrelated to the GPU must not disturb it.
    #[test]
    fn unrelated_messages_leave_the_gpu_flag_alone() {
        let mut st = PillarState::default();
        st.gpu_available = false;
        apply(&mut st, IpcMessage::AppsList(monitorapi::AppsList { instances: Vec::new() }));
        assert!(!st.gpu_available);
        assert!(st.pending_gpu_ack.is_none());
    }
}
