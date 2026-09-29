//! Fake-IP DNS for domain-based resources.
//!
//! Some resources are published as domain names rather than address ranges.
//! The TUN only ever sees IP packets, so it cannot tell which packets belong to
//! such a domain. This module closes the gap:
//!
//! * a small DNS server answers `A` queries for managed domains with an address
//!   from a private "fake" range and remembers which domain it handed out;
//! * the TUN stack looks a destination up in the [`FakeIpPool`] and, when it is
//!   a fake address, opens the tunnel connection by domain name so the gateway
//!   does the real name resolution.
//!
//! Queries the server cannot or should not fake are forwarded to the
//! configured upstream resolver unchanged.

use reatrust::{AtrClient, ProtocolKind};
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// First and last usable host address of the fake range `198.19.0.0/16`.
///
/// The range deliberately differs from `198.18.0.0/16`, which Clash and
/// similar tools use for their own fake IPs.
const FAKE_FIRST: u32 = u32::from_be_bytes([198, 19, 0, 2]);
const FAKE_LAST: u32 = u32::from_be_bytes([198, 19, 255, 254]);
const FAKE_POOL_SIZE: usize = (FAKE_LAST - FAKE_FIRST + 1) as usize;

/// CIDR of the fake range; it must be routed into the TUN.
pub const FAKE_IP_CIDR: &str = "198.19.0.0/16";

/// Short, so a re-allocated address is not kept in application caches.
const ANSWER_TTL_SECS: u32 = 60;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_INFLIGHT_FORWARDS: usize = 64;
const MAX_DNS_PACKET: usize = 4096;

const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

fn dns_log(message: &str) {
    if reatrust::verbose_logging_enabled() {
        reatrust::log_write(&format!("[NulConnect][FakeDNS] {message}"));
    }
}

/// Maps fake addresses to the domain they stand for.
///
/// Slots are handed out round-robin; once the whole range has been used the
/// oldest mapping is replaced. A mapping is only needed when a connection is
/// opened, so replacing an old one never affects an established connection.
#[derive(Debug)]
pub struct FakeIpPool {
    inner: Mutex<PoolInner>,
}

#[derive(Debug)]
struct PoolInner {
    slots: Vec<Option<String>>,
    by_domain: HashMap<String, usize>,
    next: usize,
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self {
            inner: Mutex::new(PoolInner {
                slots: vec![None; FAKE_POOL_SIZE],
                by_domain: HashMap::new(),
                next: 0,
            }),
        }
    }
}

impl FakeIpPool {
    pub fn contains(ip: Ipv4Addr) -> bool {
        (FAKE_FIRST..=FAKE_LAST).contains(&u32::from(ip))
    }

    /// The fake address for `domain`, allocating one if needed.
    pub fn allocate(&self, domain: &str) -> Ipv4Addr {
        let domain = normalize(domain);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(&slot) = inner.by_domain.get(&domain) {
            return slot_ip(slot);
        }
        let slot = inner.next;
        inner.next = (slot + 1) % FAKE_POOL_SIZE;
        if let Some(previous) = inner.slots[slot].take() {
            inner.by_domain.remove(&previous);
        }
        inner.slots[slot] = Some(domain.clone());
        inner.by_domain.insert(domain, slot);
        slot_ip(slot)
    }

    /// The domain a fake address was handed out for.
    pub fn domain_for(&self, ip: Ipv4Addr) -> Option<String> {
        if !Self::contains(ip) {
            return None;
        }
        let slot = (u32::from(ip) - FAKE_FIRST) as usize;
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .slots
            .get(slot)
            .cloned()
            .flatten()
    }
}

fn slot_ip(slot: usize) -> Ipv4Addr {
    Ipv4Addr::from(FAKE_FIRST + slot as u32)
}

fn normalize(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// What the DNS server needs to know about the resources.
pub trait DnsPolicy: Send + Sync {
    /// The name is a managed domain that carries TCP.
    fn is_managed_tcp_domain(&self, name: &str) -> bool;
    /// A server-provided address for the name that is already reachable by
    /// address routing, so no fake address is needed.
    fn routed_static_ip(&self, name: &str) -> Option<Ipv4Addr>;
}

impl DnsPolicy for AtrClient {
    fn is_managed_tcp_domain(&self, name: &str) -> bool {
        self.is_managed_domain(name, ProtocolKind::Tcp)
    }

    fn routed_static_ip(&self, name: &str) -> Option<Ipv4Addr> {
        self.static_dns_ip(name)
            .filter(|ip| self.is_managed_ip_for_tcp(*ip))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
    /// Offset just past the question section in the query packet.
    end: usize,
}

/// Parses a standard query with exactly one question and no name compression
/// (compression is not used in the question section of real queries).
fn parse_query(packet: &[u8]) -> Option<Question> {
    if packet.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    let is_response = flags & 0x8000 != 0;
    let opcode = (flags >> 11) & 0xf;
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if is_response || opcode != 0 || qdcount != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *packet.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None;
        }
        let label = packet.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += len;
    }
    let qtype = u16::from_be_bytes([*packet.get(pos)?, *packet.get(pos + 1)?]);
    let qclass = u16::from_be_bytes([*packet.get(pos + 2)?, *packet.get(pos + 3)?]);
    Some(Question {
        name: labels.join("."),
        qtype,
        qclass,
        end: pos + 4,
    })
}

/// Builds a response that echoes the question and carries `answers` as
/// `A` records; `rcode` 0 with no answers is a valid "no data" reply.
fn build_response(query: &[u8], question: &Question, rcode: u8, answers: &[Ipv4Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(question.end + answers.len() * 16);
    out.extend_from_slice(&query[0..2]);
    let opcode_and_rd = query[2] & 0x79; // opcode + RD
    out.push(0x80 | opcode_and_rd); // QR
    out.push(0x80 | (rcode & 0x0f)); // RA
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..question.end]);
    for ip in answers {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ANSWER_TTL_SECS.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    out
}

#[derive(Debug, PartialEq, Eq)]
enum Decision {
    Answer(Vec<Ipv4Addr>),
    /// The name exists but has no records of the requested type.
    NoData,
    Forward,
}

fn decide(policy: &dyn DnsPolicy, pool: &FakeIpPool, question: &Question) -> Decision {
    if question.qclass != CLASS_IN || !policy.is_managed_tcp_domain(&question.name) {
        return Decision::Forward;
    }
    if question.qtype == TYPE_A {
        let ip = policy
            .routed_static_ip(&question.name)
            .unwrap_or_else(|| pool.allocate(&question.name));
        return Decision::Answer(vec![ip]);
    }
    // The tunnel is IPv4-only. AAAA would give applications an address they
    // cannot use, and HTTPS/SVCB records can carry the real address hints,
    // bypassing the fake address.
    Decision::NoData
}

/// A DNS server on a local address answering for managed domains.
pub struct FakeDnsServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl FakeDnsServer {
    pub fn start(
        bind: SocketAddr,
        policy: Arc<dyn DnsPolicy>,
        pool: Arc<FakeIpPool>,
        upstream: Option<SocketAddr>,
    ) -> io::Result<Self> {
        let socket = UdpSocket::bind(bind)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        let addr = socket.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let thread = thread::Builder::new()
            .name("nulconnect-fake-dns".into())
            .spawn(move || serve(socket, policy, pool, upstream, worker_stop))?;
        dns_log(&format!("listening on {addr}, upstream={upstream:?}"));
        Ok(Self {
            addr,
            stop,
            thread: Mutex::new(Some(thread)),
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = thread.join();
        }
    }
}

impl Drop for FakeDnsServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve(
    socket: UdpSocket,
    policy: Arc<dyn DnsPolicy>,
    pool: Arc<FakeIpPool>,
    upstream: Option<SocketAddr>,
    stop: Arc<AtomicBool>,
) {
    let inflight = Arc::new(AtomicUsize::new(0));
    let mut buf = vec![0u8; MAX_DNS_PACKET];
    while !stop.load(Ordering::SeqCst) {
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(received) => received,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(err) => {
                dns_log(&format!("receive failed: {err}"));
                thread::sleep(Duration::from_millis(50));
                continue;
            }
        };
        let query = &buf[..len];
        let Some(question) = parse_query(query) else {
            continue;
        };
        match decide(policy.as_ref(), &pool, &question) {
            Decision::Answer(ips) => {
                dns_log(&format!("{} A -> {:?}", question.name, ips));
                let _ = socket.send_to(&build_response(query, &question, 0, &ips), peer);
            }
            Decision::NoData => {
                dns_log(&format!(
                    "{} type {} -> no data",
                    question.name, question.qtype
                ));
                let _ = socket.send_to(&build_response(query, &question, 0, &[]), peer);
            }
            Decision::Forward => {
                let Some(upstream) = upstream else {
                    let _ = socket.send_to(&build_response(query, &question, 2, &[]), peer);
                    continue;
                };
                if inflight.load(Ordering::SeqCst) >= MAX_INFLIGHT_FORWARDS {
                    let _ = socket.send_to(&build_response(query, &question, 2, &[]), peer);
                    continue;
                }
                let Ok(reply_socket) = socket.try_clone() else {
                    continue;
                };
                inflight.fetch_add(1, Ordering::SeqCst);
                let packet = query.to_vec();
                let inflight = inflight.clone();
                let name = question.name.clone();
                thread::spawn(move || {
                    match forward(&packet, upstream) {
                        Ok(response) => {
                            let _ = reply_socket.send_to(&response, peer);
                        }
                        Err(err) => dns_log(&format!("forward {name} failed: {err}")),
                    }
                    inflight.fetch_sub(1, Ordering::SeqCst);
                });
            }
        }
    }
}

fn forward(packet: &[u8], upstream: SocketAddr) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(UPSTREAM_TIMEOUT))?;
    socket.connect(upstream)?;
    socket.send(packet)?;
    let mut buf = vec![0u8; MAX_DNS_PACKET];
    let len = socket.recv(&mut buf)?;
    buf.truncate(len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubPolicy {
        managed: Vec<&'static str>,
        routed: Option<(&'static str, Ipv4Addr)>,
    }

    impl DnsPolicy for StubPolicy {
        fn is_managed_tcp_domain(&self, name: &str) -> bool {
            self.managed
                .iter()
                .any(|d| name == *d || name.ends_with(&format!(".{d}")))
        }

        fn routed_static_ip(&self, name: &str) -> Option<Ipv4Addr> {
            self.routed.filter(|(n, _)| *n == name).map(|(_, ip)| ip)
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        packet
    }

    #[test]
    fn pool_reuses_the_address_and_maps_back() {
        let pool = FakeIpPool::default();
        let a = pool.allocate("Example.com.");
        assert_eq!(pool.allocate("example.com"), a);
        assert!(FakeIpPool::contains(a));
        assert_eq!(pool.domain_for(a).as_deref(), Some("example.com"));
        let b = pool.allocate("other.com");
        assert_ne!(a, b);
        assert_eq!(pool.domain_for("10.0.0.1".parse().unwrap()), None);
        assert_eq!(pool.domain_for("198.19.200.200".parse().unwrap()), None);
    }

    #[test]
    fn pool_replaces_the_oldest_mapping_when_full() {
        let pool = FakeIpPool::default();
        let first = pool.allocate("first.example");
        for i in 0..FAKE_POOL_SIZE - 1 {
            pool.allocate(&format!("d{i}.example"));
        }
        assert_eq!(pool.domain_for(first).as_deref(), Some("first.example"));
        let wrapped = pool.allocate("new.example");
        assert_eq!(wrapped, first);
        assert_eq!(pool.domain_for(first).as_deref(), Some("new.example"));
        // The evicted domain gets a fresh address instead of a stale one.
        assert_ne!(pool.allocate("first.example"), wrapped);
    }

    #[test]
    fn pool_range_excludes_network_and_broadcast_addresses() {
        assert!(!FakeIpPool::contains("198.19.0.0".parse().unwrap()));
        assert!(!FakeIpPool::contains("198.19.0.1".parse().unwrap()));
        assert!(FakeIpPool::contains("198.19.0.2".parse().unwrap()));
        assert!(FakeIpPool::contains("198.19.255.254".parse().unwrap()));
        assert!(!FakeIpPool::contains("198.19.255.255".parse().unwrap()));
        assert!(!FakeIpPool::contains("198.18.0.5".parse().unwrap()));
    }

    #[test]
    fn parses_a_query_and_rejects_malformed_packets() {
        let q = parse_query(&query("WWW.Example.com", 28)).unwrap();
        assert_eq!(q.name, "www.example.com");
        assert_eq!(q.qtype, 28);
        assert_eq!(q.qclass, CLASS_IN);
        assert!(parse_query(&[0; 5]).is_none());
        let mut response = query("a.com", 1);
        response[2] |= 0x80;
        assert!(parse_query(&response).is_none());
        let truncated = &query("a.com", 1)[..14];
        assert!(parse_query(truncated).is_none());
    }

    #[test]
    fn builds_answers_that_echo_id_and_question() {
        let raw = query("a.example.com", 1);
        let q = parse_query(&raw).unwrap();
        let ip: Ipv4Addr = "198.19.0.2".parse().unwrap();
        let response = build_response(&raw, &q, 0, &[ip]);
        assert_eq!(&response[0..2], &[0x12, 0x34]);
        assert_eq!(response[2] & 0x80, 0x80, "QR");
        assert_eq!(response[2] & 0x01, 0x01, "RD echoed");
        assert_eq!(response[3] & 0x0f, 0, "NOERROR");
        assert_eq!(&response[6..8], &[0, 1], "one answer");
        assert_eq!(&response[12..q.end], &raw[12..q.end]);
        assert_eq!(&response[response.len() - 4..], &ip.octets());

        let empty = build_response(&raw, &q, 0, &[]);
        assert_eq!(&empty[6..8], &[0, 0]);
        assert_eq!(empty.len(), q.end);
    }

    #[test]
    fn decides_per_record_type_and_management() {
        let policy = StubPolicy {
            managed: vec!["example.com"],
            routed: Some(("routed.example.com", "10.1.1.1".parse().unwrap())),
        };
        let pool = FakeIpPool::default();
        let ask = |name: &str, qtype: u16| {
            decide(&policy, &pool, &parse_query(&query(name, qtype)).unwrap())
        };

        match ask("www.example.com", TYPE_A) {
            Decision::Answer(ips) => {
                assert!(FakeIpPool::contains(ips[0]));
                assert_eq!(pool.domain_for(ips[0]).as_deref(), Some("www.example.com"));
            }
            other => panic!("unexpected {other:?}"),
        }
        assert_eq!(
            ask("routed.example.com", TYPE_A),
            Decision::Answer(vec!["10.1.1.1".parse().unwrap()])
        );
        assert_eq!(ask("www.example.com", 28), Decision::NoData);
        assert_eq!(ask("www.example.com", 65), Decision::NoData);
        assert_eq!(ask("www.other.org", TYPE_A), Decision::Forward);
        assert_eq!(ask("www.other.org", 28), Decision::Forward);
    }

    fn ask_server(server: SocketAddr, packet: &[u8]) -> Vec<u8> {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket.send_to(packet, server).unwrap();
        let mut buf = vec![0u8; 512];
        let (len, _) = socket.recv_from(&mut buf).unwrap();
        buf.truncate(len);
        buf
    }

    #[test]
    fn server_answers_fakes_and_forwards_the_rest() {
        // A fake upstream resolver that answers every query with 9.9.9.9.
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        thread::spawn(move || {
            let mut buf = vec![0u8; 512];
            while let Ok((len, peer)) = upstream.recv_from(&mut buf) {
                let raw = buf[..len].to_vec();
                if let Some(q) = parse_query(&raw) {
                    let reply = build_response(&raw, &q, 0, &["9.9.9.9".parse().unwrap()]);
                    let _ = upstream.send_to(&reply, peer);
                }
            }
        });

        let pool = Arc::new(FakeIpPool::default());
        let server = FakeDnsServer::start(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(StubPolicy {
                managed: vec!["corp.example"],
                routed: None,
            }),
            pool.clone(),
            Some(upstream_addr),
        )
        .unwrap();
        let addr = server.local_addr();

        let fake = ask_server(addr, &query("app.corp.example", TYPE_A));
        let ip = Ipv4Addr::new(
            fake[fake.len() - 4],
            fake[fake.len() - 3],
            fake[fake.len() - 2],
            fake[fake.len() - 1],
        );
        assert_eq!(pool.domain_for(ip).as_deref(), Some("app.corp.example"));

        let nodata = ask_server(addr, &query("app.corp.example", 28));
        assert_eq!(&nodata[6..8], &[0, 0]);
        assert_eq!(nodata[3] & 0x0f, 0);

        let forwarded = ask_server(addr, &query("public.example.org", TYPE_A));
        assert_eq!(&forwarded[forwarded.len() - 4..], &[9, 9, 9, 9]);
        server.stop();
    }

    #[test]
    fn unmanaged_names_fail_without_an_upstream() {
        let server = FakeDnsServer::start(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(StubPolicy {
                managed: vec![],
                routed: None,
            }),
            Arc::new(FakeIpPool::default()),
            None,
        )
        .unwrap();
        let reply = ask_server(server.local_addr(), &query("a.example.org", TYPE_A));
        assert_eq!(reply[3] & 0x0f, 2, "SERVFAIL");
    }
}
