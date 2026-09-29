//! User-space transport termination for managed IPv4 TCP and UDP flows.
//!
//! The TUN device carries IP packets, while the libreatrust transport APIs carry
//! byte streams/datagrams.  This module is the boundary between the two.  TCP
//! state is handled by smoltcp (including sequence numbers, retransmission and
//! FIN/RST handling); the old L3 path remains the fallback for ICMP, unknown
//! protocols, and resources that are not managed by the VPN.

use crate::error::{AtrError, AtrResult};
use crate::fake_dns::FakeIpPool;
use crate::vpn_engine::{TunIo, add_packet_information};
use reatrust::{AtrClient, L3Tunnel, RouteDecision, TcpTunnel, UdpTunnel};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmoltcpInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SOCKET_BUFFER: usize = 256 * 1024;
const MAX_UDP_FLOWS: usize = 512;
/// Bounded capacity for channels between flow threads and the stack loop, so
/// a stalled peer cannot grow an in-memory queue without limit.
const FLOW_CHANNEL_CAPACITY: usize = 8;
/// UDP flows without traffic in either direction for this long are reaped,
/// so one-shot senders cannot exhaust the flow table permanently.
const UDP_FLOW_IDLE_TIMEOUT_MS: u64 = 60_000;
/// Datagrams buffered per UDP flow while connecting or waiting for the
/// tunnel writer.
const UDP_PENDING_DATAGRAMS: usize = 32;
/// Upper bound for the idle wait of the stack loop; also bounds how late the
/// close flag and UDP idle reaping are noticed.
const MAX_IDLE_WAIT: Duration = Duration::from_millis(250);
/// Listeners for destinations without traffic for this long are dropped to
/// release their buffers; they are re-created by the next packet.
const LISTENER_IDLE_TIMEOUT_MS: u64 = 5 * 60_000;
const LISTENER_SWEEP_INTERVAL_MS: u64 = 30_000;

enum StackEvent {
    Packet(Vec<u8>),
    Wake,
}

pub(crate) struct TunProtocolStack {
    input: Sender<StackEvent>,
    client: AtrClient,
    fake_pool: Option<Arc<FakeIpPool>>,
    close: Arc<AtomicBool>,
    worker: std::sync::Mutex<Option<thread::JoinHandle<()>>>,
}

impl TunProtocolStack {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        client: AtrClient,
        fake_pool: Option<Arc<FakeIpPool>>,
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
        let waker = StackWaker {
            tx: input.clone(),
            armed: Arc::new(AtomicBool::new(false)),
        };
        let worker_close = close.clone();
        let worker_client = client.clone();
        let worker_pool = fake_pool.clone();
        let worker = thread::Builder::new()
            .name("nulconnect-tun-transports".into())
            .spawn(move || {
                run_transport_stack(
                    local_ip,
                    device,
                    worker_close,
                    l3,
                    packet_information,
                    input_rx,
                    waker,
                    worker_client,
                    worker_pool,
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
            fake_pool,
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
        // Fake addresses stand for domain resources and are never routable
        // by address. TCP goes to the stack, which resolves the domain when
        // the connection is opened and resets it if the domain is not
        // managed for that port. Nothing else can be carried by name.
        if self.fake_pool.is_some() && FakeIpPool::contains(destination) {
            if protocol == 6 {
                return self.input.send(StackEvent::Packet(packet)).is_ok();
            }
            reatrust::log_write(&format!(
                "[NulConnect][FakeDNS] dropped protocol {protocol} packet to fake address {destination}:{port}"
            ));
            return true;
        }
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
        self.input.send(StackEvent::Packet(packet)).is_ok()
    }

    pub(crate) fn stop(&self) {
        self.close.store(true, Ordering::SeqCst);
        let _ = self.input.send(StackEvent::Wake);
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

/// Signals the stack loop that a flow thread produced work (data, a connect
/// result, free upload capacity). Repeated wakes before the loop runs again
/// collapse into one event.
#[derive(Clone)]
struct StackWaker {
    tx: Sender<StackEvent>,
    armed: Arc<AtomicBool>,
}

impl StackWaker {
    fn wake(&self) {
        if !self.armed.swap(true, Ordering::SeqCst) {
            let _ = self.tx.send(StackEvent::Wake);
        }
    }

    fn rearm(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }
}

struct TcpFlow {
    remote: Option<Arc<TcpTunnel>>,
    /// Data read from the tunnel; `None` until the tunnel is connected.
    remote_rx: Option<Receiver<Vec<u8>>>,
    /// A chunk only partly written into the app-facing socket.
    download_pending: Option<(Vec<u8>, usize)>,
    /// The tunnel reached end of stream; send FIN once everything received
    /// before it has been delivered.
    remote_eof: bool,
    fin_sent: bool,
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
    remote_rx: Option<Receiver<Vec<u8>>>,
    /// Datagrams for the writer thread, which keeps a slow tunnel from
    /// blocking the stack loop.
    upload_tx: Option<SyncSender<Vec<u8>>>,
    connect_rx: Option<Receiver<AtrResult<Arc<UdpTunnel>>>>,
    pending: VecDeque<Vec<u8>>,
    /// Epoch milliseconds of the last datagram in either direction.
    last_activity: u64,
    closed: Arc<AtomicBool>,
}

/// Listening sockets keyed by destination. A listener is re-created on
/// demand for every packet, so unused ones can be dropped to release their
/// buffers.
#[derive(Default)]
struct Listeners {
    by_target: HashMap<(Ipv4Addr, u16), SocketHandle>,
    by_handle: HashMap<SocketHandle, (Ipv4Addr, u16)>,
    last_used: HashMap<(Ipv4Addr, u16), u64>,
}

impl Listeners {
    fn insert(&mut self, target: (Ipv4Addr, u16), handle: SocketHandle) {
        self.by_target.insert(target, handle);
        self.by_handle.insert(handle, target);
    }

    fn remove_handle(&mut self, handle: SocketHandle) -> Option<(Ipv4Addr, u16)> {
        let target = self.by_handle.remove(&handle)?;
        self.by_target.remove(&target);
        Some(target)
    }

    fn touch(&mut self, target: (Ipv4Addr, u16), now: u64) {
        self.last_used.insert(target, now);
    }
}

#[allow(clippy::too_many_arguments)]
fn run_transport_stack(
    local_ip: Ipv4Addr,
    device: Arc<dyn TunIo>,
    close: Arc<AtomicBool>,
    l3: Arc<L3Tunnel>,
    packet_information: bool,
    input_rx: Receiver<StackEvent>,
    waker: StackWaker,
    client: AtrClient,
    fake_pool: Option<Arc<FakeIpPool>>,
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
    // smoltcp timers need a monotonic clock; the wall clock can jump on
    // sleep/wake or NTP adjustments.
    let started = Instant::now();
    let smoltcp_now = || SmoltcpInstant::from_millis(started.elapsed().as_millis() as i64);
    let mut iface = Interface::new(Config::new(HardwareAddress::Ip), &mut phy, smoltcp_now());
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
    let mut tcp_listeners = Listeners::default();
    let mut tcp_flows = HashMap::<SocketHandle, TcpFlow>::new();
    let mut udp_listeners = Listeners::default();
    let mut udp_flows = HashMap::<(SocketHandle, Ipv4Addr, u16), UdpFlow>::new();
    let mut tcp_recv_buffer = vec![0u8; 64 * 1024];
    let mut next_listener_sweep = now_millis() + LISTENER_SWEEP_INTERVAL_MS;
    let mut next_event: Option<StackEvent> = None;

    while !close.load(Ordering::SeqCst) {
        waker.rearm();
        let now_ms = now_millis();
        // Everything in the channel was already classified as managed by
        // `accept_packet`; only the destination is needed here.
        let events = next_event
            .take()
            .into_iter()
            .chain(std::iter::from_fn(|| input_rx.try_recv().ok()));
        for event in events {
            let StackEvent::Packet(packet) = event else {
                continue;
            };
            if let Some((protocol, destination, port)) = ipv4_protocol_and_port(&packet) {
                match protocol {
                    6 => {
                        ensure_tcp_listener(&mut sockets, &mut tcp_listeners, destination, port);
                        tcp_listeners.touch((destination, port), now_ms);
                    }
                    17 => {
                        ensure_udp_listener(&mut sockets, &mut udp_listeners, destination, port);
                        udp_listeners.touch((destination, port), now_ms);
                    }
                    _ => continue,
                }
                phy.enqueue(packet);
                upload_packets.fetch_add(1, Ordering::Relaxed);
            }
        }

        let _ = iface.poll(smoltcp_now(), &mut phy, &mut sockets);
        process_tcp(
            &client,
            fake_pool.as_deref(),
            &mut sockets,
            &mut tcp_listeners,
            &mut tcp_flows,
            &mut tcp_recv_buffer,
            &waker,
            &upload_bytes,
            &download_bytes,
        );
        process_udp(
            &client,
            &mut sockets,
            &udp_listeners,
            &mut udp_flows,
            &waker,
            &upload_bytes,
            &download_bytes,
        );
        let now = smoltcp_now();
        let _ = iface.poll(now, &mut phy, &mut sockets);

        if now_ms >= next_listener_sweep {
            next_listener_sweep = now_ms + LISTENER_SWEEP_INTERVAL_MS;
            sweep_idle_listeners(
                &mut sockets,
                &mut tcp_listeners,
                &mut udp_listeners,
                &udp_flows,
                now_ms,
            );
        }

        // Sleep until smoltcp needs a timer, a packet arrives or a flow
        // thread has work; never spin while idle.
        let wait = iface
            .poll_delay(now, &sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()))
            .unwrap_or(MAX_IDLE_WAIT)
            .min(MAX_IDLE_WAIT);
        match input_rx.recv_timeout(wait) {
            Ok(event) => next_event = Some(event),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    for flow in tcp_flows.into_values() {
        flow.closed.store(true, Ordering::SeqCst);
        close_in_background(flow.remote);
    }
    for flow in udp_flows.into_values() {
        flow.closed.store(true, Ordering::SeqCst);
        if let Some(remote) = flow.remote {
            let _ = remote.close();
        }
    }
    let _ = l3;
    let _ = download_packets;
}

/// `TcpTunnel::close` joins the tunnel worker, which can take as long as a
/// stalled write; never do that on the stack loop.
fn close_in_background(remote: Option<Arc<TcpTunnel>>) {
    if let Some(remote) = remote {
        let _ = thread::Builder::new()
            .name("nulconnect-tun-close".into())
            .spawn(move || {
                let _ = remote.close();
            });
    }
}

fn sweep_idle_listeners(
    sockets: &mut SocketSet<'static>,
    tcp: &mut Listeners,
    udp: &mut Listeners,
    udp_flows: &HashMap<(SocketHandle, Ipv4Addr, u16), UdpFlow>,
    now: u64,
) {
    let idle = |listeners: &Listeners, target: &(Ipv4Addr, u16)| {
        listeners
            .last_used
            .get(target)
            .is_none_or(|used| now.saturating_sub(*used) >= LISTENER_IDLE_TIMEOUT_MS)
    };

    let stale_tcp: Vec<_> = tcp
        .by_handle
        .iter()
        .filter(|(handle, target)| {
            idle(tcp, target) && sockets.get::<tcp::Socket>(**handle).state() == tcp::State::Listen
        })
        .map(|(handle, _)| *handle)
        .collect();
    for handle in stale_tcp {
        if let Some(target) = tcp.remove_handle(handle) {
            tcp.last_used.remove(&target);
        }
        sockets.remove(handle);
    }

    let stale_udp: Vec<_> = udp
        .by_handle
        .iter()
        .filter(|(handle, target)| {
            idle(udp, target)
                && !udp_flows
                    .keys()
                    .any(|(flow_handle, _, _)| flow_handle == *handle)
        })
        .map(|(handle, _)| *handle)
        .collect();
    for handle in stale_udp {
        if let Some(target) = udp.remove_handle(handle) {
            udp.last_used.remove(&target);
        }
        sockets.remove(handle);
    }
}

fn ensure_tcp_listener(
    sockets: &mut SocketSet<'static>,
    listeners: &mut Listeners,
    target: Ipv4Addr,
    port: u16,
) {
    if listeners.by_target.contains_key(&(target, port)) {
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
    listeners: &mut Listeners,
    target: Ipv4Addr,
    port: u16,
) {
    if listeners.by_target.contains_key(&(target, port)) {
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
    fake_pool: Option<&FakeIpPool>,
    sockets: &mut SocketSet<'static>,
    listeners: &mut Listeners,
    flows: &mut HashMap<SocketHandle, TcpFlow>,
    recv_buffer: &mut [u8],
    waker: &StackWaker,
    upload_bytes: &Arc<AtomicU64>,
    download_bytes: &Arc<AtomicU64>,
) {
    // A listener that accepted a connection becomes that flow's socket; a
    // fresh listener takes its place for the next connection.
    let accepted: Vec<_> = listeners
        .by_handle
        .keys()
        .copied()
        .filter(|handle| sockets.get::<tcp::Socket>(*handle).is_active())
        .collect();
    for handle in accepted {
        let Some((target_ip, target_port)) = listeners.remove_handle(handle) else {
            continue;
        };
        let (connect_tx, connect_rx) = mpsc::channel();
        let client = client.clone();
        // A fake address stands for a domain: connect by name so the gateway
        // resolves it. An address whose mapping is gone stays an IP string and
        // is refused by the route check below.
        let target = fake_pool
            .and_then(|pool| pool.domain_for(target_ip))
            .unwrap_or_else(|| target_ip.to_string());
        let connect_waker = waker.clone();
        thread::spawn(move || {
            let result = match client.route_tcp(&target, target_port) {
                RouteDecision::Managed(_) => TcpTunnel::connect(&client, &target, target_port)
                    .map(Arc::new)
                    .map_err(|e| AtrError::NetworkFailed(e.to_string())),
                RouteDecision::Direct => Err(AtrError::NotFound(format!(
                    "resource not managed for {target}:{target_port}"
                ))),
            };
            let _ = connect_tx.send(result);
            connect_waker.wake();
        });
        let (remote_tx, remote_write_rx) = mpsc::channel();
        flows.insert(
            handle,
            TcpFlow {
                remote: None,
                remote_rx: None,
                download_pending: None,
                remote_eof: false,
                fin_sent: false,
                remote_tx: Some(remote_tx),
                remote_write_rx: Some(remote_write_rx),
                connect_rx: Some(connect_rx),
                upload_pending: Arc::new(AtomicUsize::new(0)),
                closed: Arc::new(AtomicBool::new(false)),
            },
        );
        ensure_tcp_listener(sockets, listeners, target_ip, target_port);
    }

    for (&handle, flow) in flows.iter_mut() {
        if let Some(connect_rx) = &flow.connect_rx {
            match connect_rx.try_recv() {
                Ok(Ok(remote)) => {
                    start_tcp_flow_threads(flow, &remote, waker);
                    flow.remote = Some(remote);
                    flow.connect_rx = None;
                }
                Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                    sockets.get_mut::<tcp::Socket>(handle).abort();
                    flow.connect_rx = None;
                    flow.closed.store(true, Ordering::SeqCst);
                }
                Err(TryRecvError::Empty) => {}
            }
        }

        let socket = sockets.get_mut::<tcp::Socket>(handle);
        if flow.remote.is_some() {
            // The writer thread paces itself on the tunnel socket, so stop
            // draining the app-facing socket once too much upload data is
            // queued: the TCP window closes instead of buffering here.
            while flow.upload_pending.load(Ordering::Relaxed) < FLOW_CHANNEL_CAPACITY {
                let Some(tx) = &flow.remote_tx else { break };
                let n = match socket.recv_slice(recv_buffer) {
                    Ok(n) if n > 0 => n,
                    _ => break,
                };
                flow.upload_pending.fetch_add(1, Ordering::Relaxed);
                if tx.send(recv_buffer[..n].to_vec()).is_ok() {
                    upload_bytes.fetch_add(n as u64, Ordering::Relaxed);
                } else {
                    // The writer thread is gone; the upload direction is dead.
                    flow.upload_pending.fetch_sub(1, Ordering::Relaxed);
                    flow.remote_tx = None;
                    socket.abort();
                    flow.closed.store(true, Ordering::SeqCst);
                    break;
                }
            }

            deliver_download(flow, socket, download_bytes);
        }

        if socket.state() == tcp::State::Closed || (!socket.may_recv() && !socket.may_send()) {
            flow.closed.store(true, Ordering::SeqCst);
        }
    }

    let dead: Vec<_> = flows
        .iter()
        .filter(|(_, flow)| flow.closed.load(Ordering::SeqCst))
        .map(|(handle, _)| *handle)
        .collect();
    for handle in dead {
        if let Some(flow) = flows.remove(&handle) {
            close_in_background(flow.remote);
        }
        let _ = sockets.remove(handle);
    }
}

fn start_tcp_flow_threads(flow: &mut TcpFlow, remote: &Arc<TcpTunnel>, waker: &StackWaker) {
    let reader_remote = remote.clone();
    let reader_closed = flow.closed.clone();
    let reader_waker = waker.clone();
    let (incoming_tx, incoming_rx) = mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
    flow.remote_rx = Some(incoming_rx);
    thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        while !reader_closed.load(Ordering::SeqCst) {
            match reader_remote.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if incoming_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                    reader_waker.wake();
                }
            }
        }
        // Dropping the sender tells the stack loop the stream ended.
        drop(incoming_tx);
        reader_waker.wake();
    });

    if let Some(write_rx) = flow.remote_write_rx.take() {
        let writer_remote = remote.clone();
        let writer_closed = flow.closed.clone();
        let writer_pending = flow.upload_pending.clone();
        let writer_waker = waker.clone();
        thread::spawn(move || {
            while !writer_closed.load(Ordering::SeqCst) {
                match write_rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(data) => {
                        if writer_remote.write(&data).is_err() {
                            writer_closed.store(true, Ordering::SeqCst);
                            writer_waker.wake();
                            break;
                        }
                        writer_pending.fetch_sub(1, Ordering::Relaxed);
                        // Upload capacity freed up: resume draining the socket.
                        writer_waker.wake();
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });
    }
}

/// Moves tunnel data into the app-facing socket without losing bytes:
/// whatever does not fit stays pending until the app reads and the send
/// buffer drains. After the tunnel ends, the socket is closed with a FIN.
fn deliver_download(flow: &mut TcpFlow, socket: &mut tcp::Socket, download_bytes: &AtomicU64) {
    loop {
        if flow.download_pending.is_none() {
            let Some(remote_rx) = &flow.remote_rx else {
                return;
            };
            match remote_rx.try_recv() {
                Ok(data) => flow.download_pending = Some((data, 0)),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    flow.remote_eof = true;
                    break;
                }
            }
        }
        let Some((data, offset)) = flow.download_pending.as_mut() else {
            break;
        };
        if !socket.can_send() {
            break;
        }
        let written = socket.send_slice(&data[*offset..]).unwrap_or(0);
        download_bytes.fetch_add(written as u64, Ordering::Relaxed);
        *offset += written;
        if *offset < data.len() {
            break;
        }
        flow.download_pending = None;
    }

    if flow.remote_eof && flow.download_pending.is_none() && !flow.fin_sent {
        socket.close();
        flow.fin_sent = true;
    }
}

fn process_udp(
    client: &AtrClient,
    sockets: &mut SocketSet<'static>,
    listeners: &Listeners,
    flows: &mut HashMap<(SocketHandle, Ipv4Addr, u16), UdpFlow>,
    waker: &StackWaker,
    upload_bytes: &Arc<AtomicU64>,
    download_bytes: &Arc<AtomicU64>,
) {
    let now = now_millis();
    for (&(target, target_port), &handle) in listeners.by_target.iter() {
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
                let connect_waker = waker.clone();
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
                    connect_waker.wake();
                });
                flows.insert(
                    key,
                    UdpFlow {
                        local: source_ip,
                        local_port: source_port,
                        remote: None,
                        remote_rx: None,
                        upload_tx: None,
                        connect_rx: Some(connect_rx),
                        pending: VecDeque::new(),
                        last_activity: now,
                        closed: Arc::new(AtomicBool::new(false)),
                    },
                );
            }
            if let Some(flow) = flows.get_mut(&key) {
                flow.last_activity = now;
                if let Some(upload_tx) = &flow.upload_tx {
                    // UDP tolerates loss: drop rather than block when the
                    // tunnel cannot keep up.
                    let len = data.len();
                    if upload_tx.try_send(data).is_ok() {
                        upload_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    }
                } else if flow.pending.len() < UDP_PENDING_DATAGRAMS {
                    flow.pending.push_back(data);
                }
            }
        }

        for (_, flow) in flows
            .iter_mut()
            .filter(|((flow_handle, _, _), _)| *flow_handle == handle)
        {
            if let Some(connect_rx) = &flow.connect_rx {
                match connect_rx.try_recv() {
                    Ok(Ok(remote)) => {
                        start_udp_flow_threads(flow, &remote, waker);
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
            if let Some(upload_tx) = &flow.upload_tx {
                while let Some(data) = flow.pending.pop_front() {
                    let len = data.len();
                    if upload_tx.try_send(data).is_ok() {
                        upload_bytes.fetch_add(len as u64, Ordering::Relaxed);
                    }
                }
            }
            if let Some(remote_rx) = &flow.remote_rx {
                loop {
                    match remote_rx.try_recv() {
                        Ok(data) => {
                            flow.last_activity = now;
                            let endpoint = IpEndpoint::new(
                                IpAddress::v4(
                                    flow.local.octets()[0],
                                    flow.local.octets()[1],
                                    flow.local.octets()[2],
                                    flow.local.octets()[3],
                                ),
                                flow.local_port,
                            );
                            if socket.send_slice(&data, endpoint).is_ok() {
                                download_bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
                            }
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => {
                            flow.closed.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
            }
        }
    }
    // Reap closed and idle flows so the table stays below MAX_UDP_FLOWS and
    // memory does not accumulate for finished one-shot senders.
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
}

fn start_udp_flow_threads(flow: &mut UdpFlow, remote: &Arc<UdpTunnel>, waker: &StackWaker) {
    let reader_remote = remote.clone();
    let reader_closed = flow.closed.clone();
    let reader_waker = waker.clone();
    let (incoming_tx, incoming_rx) = mpsc::sync_channel(FLOW_CHANNEL_CAPACITY);
    flow.remote_rx = Some(incoming_rx);
    thread::spawn(move || {
        let mut buf = vec![0u8; 65_535];
        while !reader_closed.load(Ordering::SeqCst) {
            match reader_remote.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if incoming_tx.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                    reader_waker.wake();
                }
            }
        }
    });

    let writer_remote = remote.clone();
    let writer_closed = flow.closed.clone();
    let (upload_tx, upload_rx) = mpsc::sync_channel::<Vec<u8>>(UDP_PENDING_DATAGRAMS);
    flow.upload_tx = Some(upload_tx);
    thread::spawn(move || {
        while !writer_closed.load(Ordering::SeqCst) {
            match upload_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(data) => {
                    let _ = writer_remote.write(&data);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });
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
    use super::{TcpFlow, deliver_download};
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::socket::tcp;
    use smoltcp::time::Instant as SmoltcpInstant;
    use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
    use std::sync::mpsc;

    #[test]
    fn download_survives_partial_writes_and_ends_with_fin() {
        let mut device = Loopback::new(Medium::Ip);
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            SmoltcpInstant::from_millis(0),
        );
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8));
        });
        let mut sockets = SocketSet::new(vec![]);
        let small = || tcp::SocketBuffer::new(vec![0; 4096]);
        let server = sockets.add(tcp::Socket::new(small(), small()));
        let client = sockets.add(tcp::Socket::new(small(), small()));
        sockets.get_mut::<tcp::Socket>(server).listen(1234).unwrap();
        let mut clock = 0i64;
        let mut poll = |iface: &mut Interface, device: &mut Loopback, sockets: &mut SocketSet| {
            clock += 1;
            iface.poll(SmoltcpInstant::from_millis(clock), device, sockets);
        };
        sockets
            .get_mut::<tcp::Socket>(client)
            .connect(iface.context(), (IpAddress::v4(127, 0, 0, 1), 1234), 50000)
            .unwrap();
        for _ in 0..10 {
            poll(&mut iface, &mut device, &mut sockets);
        }
        assert!(sockets.get::<tcp::Socket>(server).may_send());

        // Tunnel data far larger than the 4 KiB socket buffers, in chunks
        // that never fit in one write.
        let expected: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (tx, rx) = mpsc::sync_channel(64);
        let chunks: Vec<Vec<u8>> = expected.chunks(10_000).map(<[u8]>::to_vec).collect();
        std::thread::spawn(move || {
            for chunk in chunks {
                tx.send(chunk).unwrap();
            }
        });
        let mut flow = TcpFlow {
            remote: None,
            remote_rx: Some(rx),
            download_pending: None,
            remote_eof: false,
            fin_sent: false,
            remote_tx: None,
            remote_write_rx: None,
            connect_rx: None,
            upload_pending: Arc::new(AtomicUsize::new(0)),
            closed: Arc::new(AtomicBool::new(false)),
        };
        let counter = AtomicU64::new(0);
        let mut received = Vec::new();
        for _ in 0..100_000 {
            deliver_download(&mut flow, sockets.get_mut::<tcp::Socket>(server), &counter);
            poll(&mut iface, &mut device, &mut sockets);
            let socket = sockets.get_mut::<tcp::Socket>(client);
            let mut buf = [0u8; 1500];
            while let Ok(n) = socket.recv_slice(&mut buf) {
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
            }
            if !socket.may_recv() {
                break;
            }
        }
        assert_eq!(received.len(), expected.len());
        assert!(received == expected, "stream corrupted");
        assert!(flow.fin_sent);
        assert!(
            !sockets.get::<tcp::Socket>(client).may_recv(),
            "FIN not delivered"
        );
        assert_eq!(
            counter.load(std::sync::atomic::Ordering::Relaxed),
            expected.len() as u64
        );
    }

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
