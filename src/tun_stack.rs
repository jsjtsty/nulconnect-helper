//! User-space transport termination for managed IPv4 TCP and UDP flows.
//!
//! The TUN device carries IP packets, while the libreatrust transport APIs carry
//! byte streams/datagrams.  This module is the boundary between the two.  TCP
//! state is handled by smoltcp (including sequence numbers, retransmission and
//! FIN/RST handling); the old L3 path remains the fallback for ICMP, unknown
//! protocols, and resources that are not managed by the VPN.

use crate::error::{AtrError, AtrResult};
use crate::vpn_engine::{TunIo, add_packet_information};
use reatrust::{AtrClient, L3Tunnel, RouteDecision, TcpTunnel, UdpTunnel};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const SOCKET_BUFFER: usize = 256 * 1024;
const MAX_UDP_FLOWS: usize = 512;
/// Bounded capacity for channels between flow threads and the stack loop, so
/// a stalled peer cannot grow an in-memory queue without limit.
const FLOW_CHANNEL_CAPACITY: usize = 8;
/// UDP flows without traffic in either direction for this long are reaped,
/// so one-shot senders cannot exhaust the flow table permanently.
const UDP_FLOW_IDLE_TIMEOUT_MS: u64 = 60_000;

pub(crate) struct TunProtocolStack {
    input: Sender<Vec<u8>>,
    client: AtrClient,
    close: Arc<AtomicBool>,
    worker: std::sync::Mutex<Option<thread::JoinHandle<()>>>,
}

impl TunProtocolStack {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        client: AtrClient,
        local_ip: Ipv4Addr,
        device: Arc<dyn TunIo>,
        close: Arc<AtomicBool>,
        l3: Arc<L3Tunnel>,
        packet_information: bool,
        upload_bytes: Arc<AtomicU64>,
        upload_packets: Arc<AtomicU64>,
        download_bytes: Arc<AtomicU64>,
        download_packets: Arc<AtomicU64>,
    ) -> AtrResult<Self> {
        let (input, input_rx) = mpsc::channel();
        let worker_close = close.clone();
        let worker_client = client.clone();
        let worker = thread::Builder::new()
            .name("nulconnect-tun-transports".into())
            .spawn(move || {
                run_transport_stack(
                    worker_client,
                    local_ip,
                    device,
                    worker_close,
                    l3,
                    packet_information,
                    input_rx,
                    upload_bytes,
                    upload_packets,
                    download_bytes,
                    download_packets,
                )
            })
            .map_err(|err| {
                AtrError::Internal(format!("failed to start TUN transport stack: {err}"))
            })?;
        Ok(Self {
            input,
            client,
            close,
            worker: std::sync::Mutex::new(Some(worker)),
        })
    }

    /// Returns true when the packet was accepted by the protocol stack.  A false
    /// result means the caller must send it through the raw L3 fallback.
    pub(crate) fn accept_packet(&self, packet: Vec<u8>) -> bool {
        let Some((protocol, destination, port)) = ipv4_protocol_and_port(&packet) else {
            return false;
        };
        let managed = match protocol {
            6 => matches!(
                self.client.route_tcp(&destination.to_string(), port),
                RouteDecision::Managed(_)
            ),
            17 => matches!(
                self.client.route_udp(&destination.to_string(), port),
                RouteDecision::Managed(_)
            ),
            _ => false,
        };
        if !managed {
            return false;
        }
        self.input.send(packet).is_ok()
    }

    pub(crate) fn stop(&self) {
        self.close.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.lock().unwrap().take() {
            let _ = worker.join();
        }
    }
}

impl Drop for TunProtocolStack {
    fn drop(&mut self) {
        self.stop();
    }
}

struct StackDevice {
    incoming: VecDeque<Vec<u8>>,
    output: Arc<dyn TunIo>,
    packet_information: bool,
}

impl StackDevice {
    fn enqueue(&mut self, packet: Vec<u8>) {
        self.incoming.push_back(packet);
    }
}

impl Device for StackDevice {
    type RxToken<'a>
        = StackRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = StackTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        _timestamp: SmoltcpInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.incoming.pop_front().map(|packet| {
            (
                StackRxToken { packet },
                StackTxToken {
                    output: self.output.clone(),
                    packet_information: self.packet_information,
                },
            )
        })
    }

    fn transmit(&mut self, _timestamp: SmoltcpInstant) -> Option<Self::TxToken<'_>> {
        Some(StackTxToken {
            output: self.output.clone(),
            packet_information: self.packet_information,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 65_535;
        capabilities.max_burst_size = Some(1);
        capabilities
    }
}

struct StackRxToken {
    packet: Vec<u8>,
}

impl RxToken for StackRxToken {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.packet)
    }
}

struct StackTxToken {
    output: Arc<dyn TunIo>,
    packet_information: bool,
}

impl TxToken for StackTxToken {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut packet = vec![0u8; len];
        let result = f(&mut packet);
        let packet = add_packet_information(&packet, self.packet_information);
        let _ = self.output.send_packet(&packet);
        result
    }
}

struct TcpFlow {
    remote: Option<Arc<TcpTunnel>>,
    remote_rx: Receiver<Vec<u8>>,
    remote_tx: Option<Sender<Vec<u8>>>,
    remote_write_rx: Option<Receiver<Vec<u8>>>,
    connect_rx: Option<Receiver<AtrResult<Arc<TcpTunnel>>>>,
    /// Upload chunks queued for the writer thread; gates how much the stack
    /// loop drains from the app-facing socket.
    upload_pending: Arc<AtomicUsize>,
    closed: Arc<AtomicBool>,
}

struct UdpFlow {
    local: Ipv4Addr,
    local_port: u16,
    remote: Option<Arc<UdpTunnel>>,
    remote_rx: Receiver<Vec<u8>>,
    connect_rx: Option<Receiver<AtrResult<Arc<UdpTunnel>>>>,
    pending: VecDeque<Vec<u8>>,
    /// Epoch milliseconds of the last datagram in either direction.
    last_activity: u64,
    closed: Arc<AtomicBool>,
}

#[allow(clippy::too_many_arguments)]
fn run_transport_stack(
    client: AtrClient,
    local_ip: Ipv4Addr,
    device: Arc<dyn TunIo>,
    close: Arc<AtomicBool>,
    l3: Arc<L3Tunnel>,
    packet_information: bool,
    input_rx: Receiver<Vec<u8>>,
    upload_bytes: Arc<AtomicU64>,
    upload_packets: Arc<AtomicU64>,
    download_bytes: Arc<AtomicU64>,
    download_packets: Arc<AtomicU64>,
) {
    let mut phy = StackDevice {
        incoming: VecDeque::new(),
        output: device,
        packet_information,
    };
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut phy,
        SmoltcpInstant::from_millis(0),
    );
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::v4(
                local_ip.octets()[0],
                local_ip.octets()[1],
                local_ip.octets()[2],
                local_ip.octets()[3],
            ),
            32,
        ));
    });
    iface.set_any_ip(true);
    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_listeners = HashMap::<(Ipv4Addr, u16), SocketHandle>::new();
    let mut tcp_flows = HashMap::<SocketHandle, TcpFlow>::new();
    let mut udp_listeners = HashMap::<(Ipv4Addr, u16), SocketHandle>::new();
    let mut udp_flows = HashMap::<(SocketHandle, Ipv4Addr, u16), UdpFlow>::new();
    let mut managed_ports = HashSet::<(u8, Ipv4Addr, u16)>::new();
    let mut tcp_recv_buffer = vec![0u8; 64 * 1024];

    while !close.load(Ordering::SeqCst) {
        let mut received = false;
        while let Ok(packet) = input_rx.try_recv() {
            if let Some((protocol, destination, port)) = ipv4_protocol_and_port(&packet) {
                let managed = match protocol {
                    6 => matches!(
                        client.route_tcp(&destination.to_string(), port),
                        RouteDecision::Managed(_)
                    ),
                    17 => matches!(
                        client.route_udp(&destination.to_string(), port),
                        RouteDecision::Managed(_)
                    ),
                    _ => false,
                };
                if managed {
                    managed_ports.insert((protocol, destination, port));
                    if protocol == 6 {
                        ensure_tcp_listener(&mut sockets, &mut tcp_listeners, destination, port);
                    } else {
                        ensure_udp_listener(&mut sockets, &mut udp_listeners, destination, port);
                    }
                    phy.enqueue(packet);
                    received = true;
                    upload_packets.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        let now = SmoltcpInstant::from_millis(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
        );
        let _ = iface.poll(now, &mut phy, &mut sockets);
        process_tcp(
            &client,
            local_ip,
            &mut sockets,
            &mut tcp_listeners,
            &mut tcp_flows,
            &mut tcp_recv_buffer,
            &close,
            &upload_bytes,
            &download_bytes,
        );
        process_udp(
            &client,
            &mut sockets,
            &mut udp_listeners,
            &mut udp_flows,
            &close,
            &upload_bytes,
            &download_bytes,
        );
        let _ = iface.poll(now, &mut phy, &mut sockets);
        if !received {
            thread::sleep(Duration::from_millis(2));
        }
    }
    for flow in tcp_flows.values() {
        flow.closed.store(true, Ordering::SeqCst);
        if let Some(remote) = &flow.remote {
            let _ = remote.close();
        }
    }
    for flow in udp_flows.values() {
        flow.closed.store(true, Ordering::SeqCst);
        if let Some(remote) = &flow.remote {
            let _ = remote.close();
        }
    }
    let _ = l3;
    let _ = managed_ports;
    let _ = download_packets;
}

fn ensure_tcp_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<(Ipv4Addr, u16), SocketHandle>,
    target: Ipv4Addr,
    port: u16,
) {
    if listeners.contains_key(&(target, port)) {
        return;
    }
    let mut socket = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
        tcp::SocketBuffer::new(vec![0; SOCKET_BUFFER]),
    );
    // Interactive TCP flows (ssh/tmux keystrokes, etc.) are small and latency
    // sensitive. smoltcp's Nagle algorithm combined with the peer's delayed
    // ACKs can stall single-keystroke segments for tens to hundreds of
    // milliseconds, so disable it for this locally-terminated socket.
    socket.set_nagle_enabled(false);
    let handle = sockets.add(socket);
    let socket = sockets.get_mut::<tcp::Socket>(handle);
    if socket
        .listen(IpListenEndpoint {
            addr: Some(IpAddress::v4(
                target.octets()[0],
                target.octets()[1],
                target.octets()[2],
                target.octets()[3],
            )),
            port,
        })
        .is_ok()
    {
        listeners.insert((target, port), handle);
    } else {
        let _ = sockets.remove(handle);
    }
}

fn ensure_udp_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<(Ipv4Addr, u16), SocketHandle>,
    target: Ipv4Addr,
    port: u16,
) {
    if listeners.contains_key(&(target, port)) {
        return;
    }
    let socket = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; SOCKET_BUFFER]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 64], vec![0; SOCKET_BUFFER]),
    );
    let handle = sockets.add(socket);
    let socket = sockets.get_mut::<udp::Socket>(handle);
    if socket
        .bind(IpListenEndpoint {
            addr: Some(IpAddress::v4(
                target.octets()[0],
                target.octets()[1],
                target.octets()[2],
                target.octets()[3],
            )),
            port,
        })
        .is_ok()
    {
        listeners.insert((target, port), handle);
    } else {
        let _ = sockets.remove(handle);
    }
}

#[allow(clippy::too_many_arguments)]
fn process_tcp(
    client: &AtrClient,
    _local_ip: Ipv4Addr,
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<(Ipv4Addr, u16), SocketHandle>,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    recv_buffer: &mut [u8],
    close: &Arc<AtomicBool>,
    upload_bytes: &Arc<AtomicU64>,
    download_bytes: &Arc<AtomicU64>,
) {
    let handles: Vec<_> = sockets.iter().map(|(h, _)| h).collect();
    for handle in handles {
        if listeners.values().any(|h| *h == handle) {
            let accepted = {
                let socket = sockets.get::<tcp::Socket>(handle);
                if socket.is_active() {
                    Some((socket.local_endpoint(), socket.remote_endpoint()))
                } else {
                    None
                }
            };
            if let Some((Some(target_endpoint), Some(_client_endpoint))) = accepted {
                let IpAddress::Ipv4(target_ip) = target_endpoint.addr;
                let target_port = target_endpoint.port;
                if let Some(key) = listeners
                    .iter()
                    .find_map(|(key, value)| (*value == handle).then_some(*key))
                {
                    listeners.remove(&key);
                }
                let (connect_tx, connect_rx) = mpsc::channel();
                let client = client.clone();
                let target = target_ip.to_string();
                thread::spawn(move || {
                    let result = match client.route_tcp(&target, target_port) {
                        RouteDecision::Managed(_) => {
                            TcpTunnel::connect(&client, &target, target_port)
                                .map(Arc::new)
                                .map_err(|e| AtrError::NetworkFailed(e.to_string()))
                        }
                        RouteDecision::Direct => Err(AtrError::NotFound(format!(
                            "resource not managed for {target}:{target_port}"
                        ))),
                    };
                    let _ = connect_tx.send(result);
                });
                let (remote_tx, remote_write_rx) = mpsc::channel();
                let (_remote_incoming_tx, remote_rx) = mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
                let closed = Arc::new(AtomicBool::new(false));
                flows.insert(
                    handle,
                    TcpFlow {
                        remote: None,
                        remote_rx,
                        remote_tx: Some(remote_tx),
                        remote_write_rx: Some(remote_write_rx),
                        connect_rx: Some(connect_rx),
                        upload_pending: Arc::new(AtomicUsize::new(0)),
                        closed,
                    },
                );
                ensure_tcp_listener(sockets, listeners, target_ip, target_port);
            }
            continue;
        }
        let Some(flow) = flows.get_mut(&handle) else {
            continue;
        };
        if let Some(connect_rx) = &flow.connect_rx {
            match connect_rx.try_recv() {
                Ok(Ok(remote)) => {
                    let reader_remote = remote.clone();
                    let reader_closed = flow.closed.clone();
                    let (incoming_tx, incoming_rx) = mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
                    flow.remote_rx = incoming_rx;
                    thread::spawn(move || {
                        let mut buf = vec![0u8; 64 * 1024];
                        while !reader_closed.load(Ordering::SeqCst) {
                            match reader_remote.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if incoming_tx.send(buf[..n].to_vec()).is_err() {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    });
                    if let Some(write_rx) = flow.remote_write_rx.take() {
                        let writer_remote = remote.clone();
                        let writer_closed = flow.closed.clone();
                        let writer_pending = flow.upload_pending.clone();
                        thread::spawn(move || {
                            while !writer_closed.load(Ordering::SeqCst) {
                                match write_rx.recv_timeout(Duration::from_millis(100)) {
                                    Ok(data) => {
                                        if writer_remote.write(&data).is_err() {
                                            break;
                                        }
                                        writer_pending.fetch_sub(1, Ordering::Relaxed);
                                    }
                                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                                }
                            }
                        });
                    }
                    flow.remote = Some(remote);
                    flow.connect_rx = None;
                }
                Ok(Err(_)) => {
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    flow.connect_rx = None;
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => flow.connect_rx = None,
            }
        }
        if let Some(remote) = &flow.remote {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            // The writer thread paces itself on the tunnel socket, so stop
            // draining the app-facing socket once too much upload data is
            // queued: the TCP window closes instead of buffering here.
            if flow.upload_pending.load(Ordering::Relaxed) < FLOW_CHANNEL_CAPACITY
                && let Some(tx) = &flow.remote_tx
                && let Ok(n) = socket.recv_slice(recv_buffer)
                && n > 0
            {
                flow.upload_pending.fetch_add(1, Ordering::Relaxed);
                if tx.send(recv_buffer[..n].to_vec()).is_ok() {
                    upload_bytes.fetch_add(n as u64, Ordering::Relaxed);
                } else {
                    // The writer thread is gone; the upload direction is dead.
                    flow.upload_pending.fetch_sub(1, Ordering::Relaxed);
                    flow.remote_tx = None;
                    flow.closed.store(true, Ordering::SeqCst);
                }
            }
            while let Ok(data) = flow.remote_rx.try_recv() {
                if socket.can_send() {
                    let _ = socket.send_slice(&data);
                    download_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                } else {
                    break;
                }
            }
            if !socket.may_recv() && !socket.may_send() {
                flow.closed.store(true, Ordering::SeqCst);
            }
            let _ = remote;
        }
    }
    let dead: Vec<_> = flows
        .iter()
        .filter_map(|(h, f)| {
            if f.closed.load(Ordering::SeqCst) {
                Some(*h)
            } else {
                None
            }
        })
        .collect();
    for handle in dead {
        if let Some(flow) = flows.remove(&handle)
            && let Some(remote) = flow.remote
        {
            let _ = remote.close();
        }
        let _ = sockets.remove(handle);
    }
    let _ = close;
}

fn process_udp(
    client: &AtrClient,
    sockets: &mut SocketSet<'static>,
    listeners: &mut HashMap<(Ipv4Addr, u16), SocketHandle>,
    flows: &mut HashMap<(SocketHandle, Ipv4Addr, u16), UdpFlow>,
    close: &Arc<AtomicBool>,
    upload_bytes: &Arc<AtomicU64>,
    download_bytes: &Arc<AtomicU64>,
) {
    for (&(target, target_port), &handle) in listeners.iter() {
        let socket = sockets.get_mut::<udp::Socket>(handle);
        let mut datagrams = Vec::new();
        while let Ok((data, meta)) = socket.recv() {
            let IpAddress::Ipv4(source_ip) = meta.endpoint.addr;
            datagrams.push((source_ip, meta.endpoint.port, data.to_vec()));
        }
        for (source_ip, source_port, data) in datagrams {
            let key = (handle, source_ip, source_port);
            if !flows.contains_key(&key) && flows.len() < MAX_UDP_FLOWS {
                let (connect_tx, connect_rx) = mpsc::channel();
                let client = client.clone();
                let target_string = target.to_string();
                thread::spawn(move || {
                    let result = match client.route_udp(&target_string, target_port) {
                        RouteDecision::Managed(_) => {
                            UdpTunnel::connect(&client, &target_string, target_port)
                                .map(Arc::new)
                                .map_err(|e| AtrError::NetworkFailed(e.to_string()))
                        }
                        RouteDecision::Direct => Err(AtrError::NotFound(format!(
                            "resource not managed for {target_string}:{target_port}"
                        ))),
                    };
                    let _ = connect_tx.send(result);
                });
                let (_tx, rx) = mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
                let closed = Arc::new(AtomicBool::new(false));
                flows.insert(
                    key,
                    UdpFlow {
                        local: source_ip,
                        local_port: source_port,
                        remote: None,
                        remote_rx: rx,
                        connect_rx: Some(connect_rx),
                        pending: VecDeque::new(),
                        last_activity: now_millis(),
                        closed,
                    },
                );
            }
            if let Some(flow) = flows.get_mut(&key) {
                flow.last_activity = now_millis();
                if let Some(remote) = &flow.remote {
                    if remote.write(&data).is_ok() {
                        upload_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                } else if flow.pending.len() < 32 {
                    flow.pending.push_back(data);
                }
            }
        }
        let keys: Vec<_> = flows
            .keys()
            .filter(|(flow_handle, _, _)| *flow_handle == handle)
            .copied()
            .collect();
        for key in keys {
            if let Some(flow) = flows.get_mut(&key) {
                if let Some(connect_rx) = &flow.connect_rx {
                    match connect_rx.try_recv() {
                        Ok(Ok(remote)) => {
                            let reader_remote = remote.clone();
                            let reader_closed = flow.closed.clone();
                            let (incoming_tx, incoming_rx) =
                                mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
                            flow.remote_rx = incoming_rx;
                            thread::spawn(move || {
                                let mut buf = vec![0u8; 65_535];
                                while !reader_closed.load(Ordering::SeqCst) {
                                    match reader_remote.read(&mut buf) {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            if incoming_tx.send(buf[..n].to_vec()).is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                            flow.remote = Some(remote);
                            flow.connect_rx = None;
                        }
                        Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                            flow.closed.store(true, Ordering::SeqCst);
                            flow.connect_rx = None;
                        }
                        Err(TryRecvError::Empty) => {}
                    }
                }
                if let Some(remote) = &flow.remote {
                    while let Some(data) = flow.pending.pop_front() {
                        if remote.write(&data).is_ok() {
                            upload_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                        }
                    }
                }
                while let Ok(data) = flow.remote_rx.try_recv() {
                    flow.last_activity = now_millis();
                    let _ = socket.send_slice(
                        &data,
                        IpEndpoint::new(
                            IpAddress::v4(
                                flow.local.octets()[0],
                                flow.local.octets()[1],
                                flow.local.octets()[2],
                                flow.local.octets()[3],
                            ),
                            flow.local_port,
                        ),
                    );
                    download_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
        }
    }
    // Reap closed and idle flows so the table stays below MAX_UDP_FLOWS and
    // memory does not accumulate for finished one-shot senders.
    let now = now_millis();
    let dead: Vec<_> = flows
        .iter()
        .filter(|(_, flow)| {
            udp_flow_expired(flow.closed.load(Ordering::SeqCst), flow.last_activity, now)
        })
        .map(|(key, _)| *key)
        .collect();
    for key in dead {
        if let Some(flow) = flows.remove(&key) {
            flow.closed.store(true, Ordering::SeqCst);
            if let Some(remote) = flow.remote {
                let _ = remote.close();
            }
        }
    }
    let _ = close;
}

fn ipv4_protocol_and_port(packet: &[u8]) -> Option<(u8, Ipv4Addr, u16)> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    let protocol = packet[9];
    if !matches!(protocol, 6 | 17) || packet.len() < header_len + 4 {
        return Some((
            protocol,
            Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
            0,
        ));
    }
    Some((
        protocol,
        Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]),
    ))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn udp_flow_expired(closed: bool, last_activity: u64, now: u64) -> bool {
    closed || now.saturating_sub(last_activity) >= UDP_FLOW_IDLE_TIMEOUT_MS
}

#[cfg(test)]
mod tests {
    use super::UDP_FLOW_IDLE_TIMEOUT_MS;
    use super::ipv4_protocol_and_port;
    use super::udp_flow_expired;
    use std::net::Ipv4Addr;

    #[test]
    fn parses_tcp_destination() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[9] = 6;
        packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        assert_eq!(
            ipv4_protocol_and_port(&packet),
            Some((6, Ipv4Addr::new(192, 0, 2, 10), 443))
        );
    }

    #[test]
    fn malformed_transport_packet_is_not_claimed_as_a_flow() {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[9] = 6;
        assert_eq!(
            ipv4_protocol_and_port(&packet),
            Some((6, Ipv4Addr::new(0, 0, 0, 0), 0))
        );
    }

    #[test]
    fn udp_flow_expires_only_after_idle_timeout() {
        let now = 1_000_000u64;
        assert!(!udp_flow_expired(
            false,
            now - UDP_FLOW_IDLE_TIMEOUT_MS + 1,
            now
        ));
        assert!(udp_flow_expired(false, now - UDP_FLOW_IDLE_TIMEOUT_MS, now));
        assert!(udp_flow_expired(false, 0, now));
    }

    #[test]
    fn udp_flow_expiry_handles_closed_and_clock_rollback() {
        let now = 1_000_000u64;
        assert!(!udp_flow_expired(false, now, now));
        assert!(udp_flow_expired(true, now, now));
        // A wall-clock rollback must not expire an active flow.
        assert!(!udp_flow_expired(false, now + 60_000, now));
    }
}
