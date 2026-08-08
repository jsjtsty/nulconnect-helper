use crate::error::{AtrError, AtrResult};
use reatrust::{
    AtrClient, ClientConfig, CookieRecord, L3Tunnel, SessionMaterial, parse_resource_bytes,
};
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tun_rs::{DeviceBuilder, InterruptEvent, Layer, PACKET_INFORMATION_LENGTH};

#[derive(Debug, Clone)]
pub struct VpnCookieRecord {
    pub host: String,
    pub scheme: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct VpnSessionMaterial {
    pub username: String,
    pub sid: String,
    pub device_id: String,
    pub connection_id: String,
    pub sign_key_hex: String,
    pub cookies: Vec<VpnCookieRecord>,
}

#[derive(Debug, Clone)]
pub struct VpnEngineConfig {
    pub client: ClientConfig,
    pub session: VpnSessionMaterial,
    pub resource_bytes: Vec<u8>,
    pub service_host: String,
    pub tun_name: Option<String>,
    pub mtu: u16,
    pub packet_information: bool,
    pub exit_on_fatal_error: bool,
}

impl Default for VpnEngineConfig {
    fn default() -> Self {
        Self {
            client: ClientConfig::default(),
            session: VpnSessionMaterial {
                username: String::new(),
                sid: String::new(),
                device_id: String::new(),
                connection_id: String::new(),
                sign_key_hex: String::new(),
                cookies: Vec::new(),
            },
            resource_bytes: Vec::new(),
            service_host: String::new(),
            tun_name: None,
            mtu: 1400,
            packet_information: false,
            exit_on_fatal_error: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnEngineStatus {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VpnEngineTrafficStats {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub upload_packets: u64,
    pub download_packets: u64,
}

pub struct VpnEngine {
    inner: VpnEngineImpl,
}

struct VpnEngineImpl {
    close: Arc<AtomicBool>,
    interrupt: Arc<InterruptEvent>,
    tunnel: Arc<L3Tunnel>,
    result: Arc<Mutex<Option<AtrResult<usize>>>>,
    upload_bytes: Arc<AtomicU64>,
    download_bytes: Arc<AtomicU64>,
    upload_packets: Arc<AtomicU64>,
    download_packets: Arc<AtomicU64>,
    workers: Mutex<Vec<thread::JoinHandle<()>>>,
}

impl VpnEngine {
    pub fn start(config: VpnEngineConfig) -> AtrResult<Self> {
        start_l3_vpn_engine(config)
    }

    pub fn stop(&self) -> AtrResult<()> {
        self.cancel();
        join_workers(self);
        Ok(())
    }

    pub fn cancel(&self) {
        self.inner.close.store(true, Ordering::SeqCst);
        let _ = self.inner.interrupt.trigger();
        let _ = self.inner.tunnel.close();
    }

    pub fn status(&self) -> VpnEngineStatus {
        if self.inner.result.lock().unwrap().is_some() {
            VpnEngineStatus::Stopped
        } else {
            VpnEngineStatus::Running
        }
    }

    pub fn take_result(&self) -> Option<AtrResult<usize>> {
        let result = self.inner.result.lock().unwrap().take();
        if result.is_some() {
            self.cancel();
            join_workers(self);
        }
        result
    }

    pub fn traffic_stats(&self) -> VpnEngineTrafficStats {
        VpnEngineTrafficStats {
            upload_bytes: self.inner.upload_bytes.load(Ordering::Relaxed),
            download_bytes: self.inner.download_bytes.load(Ordering::Relaxed),
            upload_packets: self.inner.upload_packets.load(Ordering::Relaxed),
            download_packets: self.inner.download_packets.load(Ordering::Relaxed),
        }
    }
}

impl Drop for VpnEngine {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn start_l3_vpn_engine(config: VpnEngineConfig) -> AtrResult<VpnEngine> {
    helper_debug_log("start: requesting L3 virtual IP");
    let local_ip = request_l3_virtual_ip(&config)?;
    helper_debug_log(&format!("start: L3 virtual IP={local_ip}"));
    helper_debug_log("start: building TUN device");
    let device = Arc::new(build_tun_device(&config, local_ip)?);
    helper_debug_log("start: TUN device built");
    let interrupt = Arc::new(InterruptEvent::new()?);
    helper_debug_log("start: opening libreatrust L3 tunnel");
    let tunnel = build_l3_runtime(&config)?;
    let tunnel = Arc::new(tunnel);
    helper_debug_log("start: libreatrust L3 tunnel opened");
    let close = Arc::new(AtomicBool::new(false));
    let result = Arc::new(Mutex::new(None));
    let upload_bytes = Arc::new(AtomicU64::new(0));
    let download_bytes = Arc::new(AtomicU64::new(0));
    let upload_packets = Arc::new(AtomicU64::new(0));
    let download_packets = Arc::new(AtomicU64::new(0));

    helper_debug_log("start: spawning uplink worker");
    let tun_to_l3 = spawn_tun_to_l3(
        device.clone(),
        tunnel.clone(),
        close.clone(),
        result.clone(),
        interrupt.clone(),
        config.packet_information,
        config.exit_on_fatal_error,
        upload_bytes.clone(),
        upload_packets.clone(),
    )?;
    helper_debug_log("start: spawning downlink worker");
    let l3_to_tun = spawn_l3_to_tun(
        device,
        tunnel.clone(),
        close.clone(),
        result.clone(),
        config.packet_information,
        config.exit_on_fatal_error,
        download_bytes.clone(),
        download_packets.clone(),
    )?;
    helper_debug_log("start: workers spawned");

    Ok(VpnEngine {
        inner: VpnEngineImpl {
            close,
            interrupt,
            tunnel,
            result,
            upload_bytes,
            download_bytes,
            upload_packets,
            download_packets,
            workers: Mutex::new(vec![tun_to_l3, l3_to_tun]),
        },
    })
}

fn build_l3_runtime(config: &VpnEngineConfig) -> AtrResult<L3Tunnel> {
    helper_debug_log(&format!(
        "open_l3: client server={}:{} service_host={} resource_bytes={}",
        config.client.server_host,
        config.client.server_port,
        config.service_host,
        config.resource_bytes.len()
    ));
    let client = build_atr_client(config)?;
    helper_debug_log("open_l3: calling client.open_l3_tunnel");
    let tunnel = client.open_l3_tunnel().map_err(map_reatrust_error)?;
    Ok(tunnel)
}

fn build_atr_client(config: &VpnEngineConfig) -> AtrResult<AtrClient> {
    let mut client = AtrClient::new(config.client.clone()).map_err(map_reatrust_error)?;
    client.set_session(config.session.clone().into());
    let service_host = if config.service_host.is_empty() {
        config.client.server_host.as_str()
    } else {
        config.service_host.as_str()
    };
    let resource =
        parse_resource_bytes(&config.resource_bytes, service_host).map_err(map_reatrust_error)?;
    client.set_resource(resource);
    client.set_resource_bytes(config.resource_bytes.clone());
    Ok(client)
}

fn request_l3_virtual_ip(config: &VpnEngineConfig) -> AtrResult<Ipv4Addr> {
    let client = build_atr_client(config)?;
    let ips = client
        .request_l3_virtual_ips()
        .map_err(map_reatrust_error)?;
    ips.into_iter()
        .next()
        .ok_or_else(|| AtrError::NetworkFailed("server did not return L3 virtual IP".into()))
}

fn build_tun_device(config: &VpnEngineConfig, local_ip: Ipv4Addr) -> AtrResult<tun_rs::SyncDevice> {
    helper_debug_log(&format!(
        "tun: build requested name={} mtu={} local_ip={} packet_information={}",
        config.tun_name.as_deref().unwrap_or("auto"),
        config.mtu,
        local_ip,
        config.packet_information
    ));
    let mut builder = DeviceBuilder::new().layer(Layer::L3).mtu(config.mtu);

    if let Some(tun_name) = config.tun_name.as_ref().filter(|value| !value.is_empty()) {
        builder = builder.name(tun_name.clone());
    }

    builder = builder.ipv4(local_ip.to_string(), 32, Some("10.0.0.1".to_string()));

    #[cfg(target_os = "macos")]
    {
        builder = builder
            .packet_information(config.packet_information)
            .with(|platform| {
                platform.associate_route(false);
            });
    }

    #[cfg(not(target_os = "macos"))]
    {
        builder = builder.packet_information(config.packet_information);
    }

    let device = builder
        .build_sync()
        .map_err(|err| AtrError::NetworkFailed(format!("failed to create TUN device: {err}")))?;
    helper_debug_log("tun: build_sync succeeded");
    Ok(device)
}

fn spawn_tun_to_l3(
    device: Arc<tun_rs::SyncDevice>,
    tunnel: Arc<L3Tunnel>,
    close: Arc<AtomicBool>,
    result: Arc<Mutex<Option<AtrResult<usize>>>>,
    interrupt: Arc<InterruptEvent>,
    packet_information: bool,
    exit_on_fatal_error: bool,
    upload_bytes: Arc<AtomicU64>,
    upload_packets: Arc<AtomicU64>,
) -> AtrResult<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("nulconnect-l3-uplink".to_string())
        .spawn(move || {
            helper_debug_log("uplink: worker started");
            let mut read_packets = 0usize;
            let mut written_packets = 0usize;
            let mut samples = 0usize;
            let mut buf = vec![0u8; 65_535];
            while !close.load(Ordering::SeqCst) {
                match device.recv_intr(&mut buf, &interrupt) {
                    Ok(0) => continue,
                    Ok(n) => match strip_packet_information(&buf[..n], packet_information) {
                        Ok(packet) => {
                            read_packets += 1;
                            log_packet_sample(
                                "uplink-read",
                                read_packets,
                                &buf[..n],
                                packet,
                                &mut samples,
                                packet_information,
                            );
                            let start = Instant::now();
                            if read_packets <= 8 {
                                helper_debug_log(&format!(
                                    "uplink-write: begin packet #{read_packets} bytes={}",
                                    packet.len()
                                ));
                            }
                            match tunnel.write_packet(packet).map_err(map_reatrust_error) {
                                Ok(written) => {
                                    written_packets += 1;
                                    upload_bytes.fetch_add(written as u64, Ordering::Relaxed);
                                    upload_packets.fetch_add(1, Ordering::Relaxed);
                                    if read_packets <= 8 {
                                        helper_debug_log(&format!(
                                            "uplink-write: ready packet #{read_packets} elapsed_ms={}",
                                            start.elapsed().as_millis()
                                        ));
                                    }
                                }
                                Err(AtrError::NotFound(message)) => {
                                    helper_debug_log(&format!(
                                        "uplink packet route not found: {message}"
                                    ));
                                }
                                Err(err) if !exit_on_fatal_error => {
                                    helper_debug_log(&format!(
                                        "uplink packet dropped after {}ms: {err}",
                                        start.elapsed().as_millis()
                                    ));
                                }
                                Err(err) => {
                                    close.store(true, Ordering::SeqCst);
                                    let _ = tunnel.close();
                                    set_result(&result, Err(err));
                                    return;
                                }
                            }
                        }
                        Err(AtrError::NotFound(_)) => {}
                        Err(err) if !exit_on_fatal_error => {
                            helper_debug_log(&format!("uplink packet ignored: {err}"));
                        }
                        Err(err) => {
                            close.store(true, Ordering::SeqCst);
                            let _ = tunnel.close();
                            set_result(&result, Err(err));
                            return;
                        }
                    },
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => break,
                    Err(err) => {
                        close.store(true, Ordering::SeqCst);
                        let _ = tunnel.close();
                        set_result(&result, Err(AtrError::NetworkFailed(err.to_string())));
                        return;
                    }
                }
            }
            helper_debug_log(&format!(
                "uplink: worker stopped read_packets={read_packets} written_packets={written_packets}"
            ));
            set_result(&result, Ok(written_packets));
        })
        .map_err(|err| AtrError::Internal(format!("failed to start L3 uplink worker: {err}")))
}

fn spawn_l3_to_tun(
    device: Arc<tun_rs::SyncDevice>,
    tunnel: Arc<L3Tunnel>,
    close: Arc<AtomicBool>,
    result: Arc<Mutex<Option<AtrResult<usize>>>>,
    packet_information: bool,
    exit_on_fatal_error: bool,
    download_bytes: Arc<AtomicU64>,
    download_packets: Arc<AtomicU64>,
) -> AtrResult<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("nulconnect-l3-downlink".to_string())
        .spawn(move || {
            helper_debug_log("downlink: worker started");
            let mut packets = 0usize;
            let mut samples = 0usize;
            while !close.load(Ordering::SeqCst) {
                match tunnel.read_packet().map_err(map_reatrust_error) {
                    Ok(packet) => {
                        let tun_packet = add_packet_information(&packet, packet_information);
                        match device.send(&tun_packet) {
                            Ok(_) => {
                                packets += 1;
                                download_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                                download_packets.fetch_add(1, Ordering::Relaxed);
                                log_packet_sample(
                                    "downlink",
                                    packets,
                                    &tun_packet,
                                    &packet,
                                    &mut samples,
                                    packet_information,
                                );
                            }
                            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(2));
                            }
                            Err(err) if !exit_on_fatal_error => {
                                helper_debug_log(&format!("downlink packet dropped: {err}"));
                            }
                            Err(err) => {
                                close.store(true, Ordering::SeqCst);
                                let _ = tunnel.close();
                                set_result(&result, Err(AtrError::NetworkFailed(err.to_string())));
                                return;
                            }
                        }
                    }
                    Err(_err) if close.load(Ordering::SeqCst) => break,
                    Err(err) if !exit_on_fatal_error => {
                        helper_debug_log(&format!("downlink read failed: {err}"));
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => {
                        close.store(true, Ordering::SeqCst);
                        set_result(&result, Err(err));
                        return;
                    }
                }
            }
            helper_debug_log(&format!("downlink: worker stopped packets={packets}"));
            set_result(&result, Ok(packets));
        })
        .map_err(|err| AtrError::Internal(format!("failed to start L3 downlink worker: {err}")))
}

fn strip_packet_information(packet: &[u8], enabled: bool) -> AtrResult<&[u8]> {
    if !enabled {
        return Ok(packet);
    }
    if packet.len() <= PACKET_INFORMATION_LENGTH {
        return Err(AtrError::InvalidArgument(format!(
            "packet too short for packet information header: {} bytes",
            packet.len()
        )));
    }
    Ok(&packet[PACKET_INFORMATION_LENGTH..])
}

fn add_packet_information(packet: &[u8], enabled: bool) -> Vec<u8> {
    if !enabled {
        return packet.to_vec();
    }

    let mut result = Vec::with_capacity(PACKET_INFORMATION_LENGTH + packet.len());
    result.extend_from_slice(&packet_information_header(packet));
    result.extend_from_slice(packet);
    result
}

fn packet_information_header(packet: &[u8]) -> [u8; PACKET_INFORMATION_LENGTH] {
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
    ))]
    {
        let family = if packet.first().map(|byte| byte >> 4) == Some(6) {
            libc::AF_INET6
        } else {
            libc::AF_INET
        };
        (family as u32).to_be_bytes()
    }

    #[cfg(not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "openbsd",
        target_os = "freebsd",
        target_os = "netbsd",
    )))]
    {
        const ETH_P_IP: [u8; PACKET_INFORMATION_LENGTH] = (libc::ETH_P_IP as u32).to_be_bytes();
        const ETH_P_IPV6: [u8; PACKET_INFORMATION_LENGTH] = (libc::ETH_P_IPV6 as u32).to_be_bytes();
        if packet.first().map(|byte| byte >> 4) == Some(6) {
            ETH_P_IPV6
        } else {
            ETH_P_IP
        }
    }
}

fn log_packet_sample(
    direction: &str,
    packet_index: usize,
    tun_packet: &[u8],
    ip_packet: &[u8],
    samples: &mut usize,
    packet_information: bool,
) {
    if *samples >= 8 {
        return;
    }
    *samples += 1;

    let header = if packet_information && tun_packet.len() >= PACKET_INFORMATION_LENGTH {
        format!(
            "{:02x} {:02x} {:02x} {:02x}",
            tun_packet[0], tun_packet[1], tun_packet[2], tun_packet[3]
        )
    } else {
        "none".to_string()
    };
    helper_debug_log(&format!(
        "{direction}: sample #{packet_index} tun_len={} ip_len={} pi={} {}",
        tun_packet.len(),
        ip_packet.len(),
        header,
        describe_ip_packet(ip_packet)
    ));
}

fn describe_ip_packet(packet: &[u8]) -> String {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => format!(
            "ipv4 {}.{}.{}.{} -> {}.{}.{}.{} proto={}",
            packet[12],
            packet[13],
            packet[14],
            packet[15],
            packet[16],
            packet[17],
            packet[18],
            packet[19],
            packet[9]
        ),
        Some(6) if packet.len() >= 40 => "ipv6".to_string(),
        Some(version) => format!("ip_version={version} short_len={}", packet.len()),
        None => "empty".to_string(),
    }
}

fn join_workers(engine: &VpnEngine) {
    let workers = std::mem::take(&mut *engine.inner.workers.lock().unwrap());
    for worker in workers {
        let _ = worker.join();
    }
}

fn set_result(slot: &Arc<Mutex<Option<AtrResult<usize>>>>, value: AtrResult<usize>) {
    let mut guard = slot.lock().unwrap();
    if guard.is_none() {
        *guard = Some(value);
    }
}

fn map_reatrust_error(err: reatrust::AtrError) -> AtrError {
    match err {
        reatrust::AtrError::InvalidArgument(message) => AtrError::InvalidArgument(message),
        reatrust::AtrError::ParseFailed(message) => AtrError::ParseFailed(message),
        reatrust::AtrError::NetworkFailed(message) => AtrError::NetworkFailed(message),
        reatrust::AtrError::Unauthorized(message) => AtrError::Unauthorized(message),
        reatrust::AtrError::ChallengeRequired(message) => AtrError::ChallengeRequired(message),
        reatrust::AtrError::InvalidState(message) => AtrError::InvalidState(message),
        reatrust::AtrError::CryptoFailed(message) => AtrError::CryptoFailed(message),
        reatrust::AtrError::NotFound(message) => AtrError::NotFound(message),
        reatrust::AtrError::Unsupported(message) => AtrError::Unsupported(message),
        reatrust::AtrError::Internal(message) => AtrError::Internal(message),
    }
}

impl From<VpnSessionMaterial> for SessionMaterial {
    fn from(value: VpnSessionMaterial) -> Self {
        Self {
            username: value.username,
            sid: value.sid,
            device_id: value.device_id,
            connection_id: value.connection_id,
            sign_key_hex: value.sign_key_hex,
            cookies: value.cookies.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<VpnCookieRecord> for CookieRecord {
    fn from(value: VpnCookieRecord) -> Self {
        Self {
            host: value.host,
            scheme: value.scheme,
            name: value.name,
            value: value.value,
        }
    }
}

fn helper_debug_log(message: &str) {
    eprintln!("[NulConnect][L3] {message}");
}
