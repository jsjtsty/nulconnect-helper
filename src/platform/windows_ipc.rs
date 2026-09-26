//! Windows helper runtime and its Named Pipe IPC surface.
//!
//! Protocol: one UTF-8 JSON request per pipe connection, answered by one
//! JSON response (`{"id", "ok", "data" | "error"}`). The pipe runs in message
//! mode; requests larger than the pipe buffer arrive in several reads
//! (`ERROR_MORE_DATA`) and are reassembled.
//!
//! Commands: `version`, `status`, `start_tun`, `stop_tun`, `cleanup`, and
//! `shutdown` (console mode only).

use crate::platform::windows::{active_adapter_ip, active_adapter_luid, wide};
use crate::platform::windows_log::state_dir;
use crate::platform::windows_net::{self, RouteSpec};
use crate::{VpnCookieRecord, VpnEngine, VpnEngineConfig, VpnEngineStatus, VpnSessionMaterial};
use base64::Engine;
use reatrust::ClientConfig;
use reatrust::parse_resource_bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs;
use std::io;
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_MORE_DATA, ERROR_PIPE_CONNECTED, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, SetNamedPipeHandleState,
};

pub const PIPE_NAME: &str = r"\\.\pipe\NulConnectHelper";

const PIPE_ACCESS_DUPLEX: u32 = 3;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_TYPE_MESSAGE: u32 = 4;
const PIPE_READMODE_MESSAGE: u32 = 2;
const PIPE_WAIT: u32 = 0;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 8;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const BUFFER_SIZE: u32 = 64 * 1024;
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;
const SDDL_REVISION_1: u32 = 1;
/// SYSTEM and Administrators get full access; interactively logged-on users
/// may read/write so the unelevated desktop app can drive the helper.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const ADAPTER_NAME: &str = "NulConnect";
/// Synthetic address range used by the service for DNS-mapped resources.
const DEFAULT_MANAGED_CIDRS: &[&str] = &["198.18.0.0/15"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunStatus {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

impl TunStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Stopping => "stopping",
            Self::Failed => "failed",
        }
    }
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct PersistedNetworkState {
    routes: Vec<RouteSpec>,
    nrpt: bool,
}

struct TunState {
    status: TunStatus,
    message: Option<String>,
    engine: Option<Arc<VpnEngine>>,
    virtual_ip: Option<Ipv4Addr>,
    network: PersistedNetworkState,
    dns_namespaces: usize,
}

pub struct WindowsRuntime {
    state: Mutex<TunState>,
    /// Serializes start/stop so they never interleave.
    operation: Mutex<()>,
    /// Incremented by every stop so an in-flight start can notice it was
    /// cancelled and a stale monitor thread can retire.
    generation: AtomicU64,
    shutdown: AtomicBool,
}

impl Default for WindowsRuntime {
    fn default() -> Self {
        Self {
            state: Mutex::new(TunState {
                status: TunStatus::Stopped,
                message: None,
                engine: None,
                virtual_ip: None,
                network: PersistedNetworkState::default(),
                dns_namespaces: 0,
            }),
            operation: Mutex::new(()),
            generation: AtomicU64::new(0),
            shutdown: AtomicBool::new(false),
        }
    }
}

#[derive(Debug, Deserialize)]
struct WireConfig {
    client: WireClient,
    session: WireSession,
    resource_bytes: String,
    service_host: String,
    tun_name: Option<String>,
    #[serde(default = "default_mtu")]
    mtu: u16,
    #[serde(default = "default_exit_on_fatal_error")]
    exit_on_fatal_error: bool,
    #[serde(default)]
    setup_routes: bool,
    #[serde(default)]
    dns_addr: String,
    #[serde(default)]
    managed_route_cidrs: Vec<String>,
    #[serde(default)]
    managed_domains: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WireClient {
    server_host: String,
    server_port: u16,
    user_agent: String,
    connect_timeout_ms: u64,
    io_timeout_ms: u64,
    node_probe_timeout_ms: u64,
    allow_insecure_tls: bool,
}

#[derive(Debug, Deserialize)]
struct WireSession {
    username: String,
    sid: String,
    device_id: String,
    connection_id: String,
    sign_key_hex: String,
    #[serde(default)]
    cookies: Vec<WireCookie>,
}

#[derive(Debug, Deserialize)]
struct WireCookie {
    host: String,
    scheme: String,
    name: String,
    value: String,
}

fn default_mtu() -> u16 {
    1400
}

fn default_exit_on_fatal_error() -> bool {
    true
}

/// Everything that must be decided while the physical network is still the
/// only path: once managed routes exist, best-route lookups for addresses
/// inside them would point at the tunnel.
struct NetworkPlan {
    tunnel_routes: Vec<(Ipv4Addr, u8)>,
    bypass_routes: Vec<RouteSpec>,
    dns_server: Option<Ipv4Addr>,
    managed_domains: Vec<String>,
}

impl WindowsRuntime {
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Removes routes and NRPT rules recorded by a previous helper process
    /// that exited without cleaning up (crash, power loss, forced kill).
    pub fn cleanup_leftovers(&self) {
        let _operation = self.operation.lock().unwrap();
        cleanup_persisted_network_state();
    }

    fn status_json(&self) -> Value {
        let state = self.state.lock().unwrap();
        let stats = state
            .engine
            .as_ref()
            .map(|engine| engine.traffic_stats())
            .unwrap_or_default();
        json!({
            "version": env!("CARGO_PKG_VERSION"),
            "service": "running",
            "tun": {
                "status": state.status.as_str(),
                "message": state.message,
                "adapter": ADAPTER_NAME,
                "virtual_ip": state.virtual_ip.map(|ip| ip.to_string()),
                "routes": state.network.routes.len(),
                "dns_namespaces": state.dns_namespaces,
                "upload_bytes": stats.upload_bytes,
                "download_bytes": stats.download_bytes,
                "upload_packets": stats.upload_packets,
                "download_packets": stats.download_packets,
            }
        })
    }

    fn set_status(&self, status: TunStatus, message: Option<String>) {
        let mut state = self.state.lock().unwrap();
        state.status = status;
        state.message = message;
        crate::helper_log!(
            "[Tun] state={} message={}",
            status.as_str(),
            state.message.as_deref().unwrap_or("")
        );
    }

    fn begin_start(self: &Arc<Self>, config: WireConfig) -> Result<Value, String> {
        {
            let mut state = self.state.lock().unwrap();
            match state.status {
                TunStatus::Starting => return Err("VPN is already starting".into()),
                TunStatus::Running => return Err("VPN is already running".into()),
                TunStatus::Stopping => return Err("VPN is stopping".into()),
                TunStatus::Stopped | TunStatus::Failed => {}
            }
            state.status = TunStatus::Starting;
            state.message = None;
        }
        let generation = self.generation.load(Ordering::SeqCst);
        crate::helper_log!(
            "[Tun] start accepted: server={}:{} dns={} routes={} domains={} mtu={}",
            config.client.server_host,
            config.client.server_port,
            config.dns_addr,
            config.managed_route_cidrs.len(),
            config.managed_domains.len(),
            config.mtu
        );
        let runtime = Arc::clone(self);
        thread::Builder::new()
            .name("nulconnect-tun-start".into())
            .spawn(move || {
                let result = runtime.start_worker(config, generation);
                if let Err(message) = result {
                    crate::helper_log!("[Tun] start failed: {message}");
                    if runtime.generation.load(Ordering::SeqCst) == generation {
                        runtime.set_status(TunStatus::Failed, Some(message));
                    }
                }
            })
            .map_err(|error| format!("failed to spawn TUN start worker: {error}"))?;
        Ok(json!({ "status": "starting" }))
    }

    fn start_worker(self: &Arc<Self>, config: WireConfig, generation: u64) -> Result<(), String> {
        let _operation = self.operation.lock().unwrap();
        if self.generation.load(Ordering::SeqCst) != generation {
            return Ok(());
        }
        cleanup_persisted_network_state();

        let resource_bytes = base64::engine::general_purpose::STANDARD
            .decode(config.resource_bytes.as_bytes())
            .map_err(|error| format!("invalid resource_bytes: {error}"))?;
        let plan = if config.setup_routes {
            build_network_plan(&config, &resource_bytes)?
        } else {
            NetworkPlan {
                tunnel_routes: Vec::new(),
                bypass_routes: Vec::new(),
                dns_server: None,
                managed_domains: Vec::new(),
            }
        };

        let adapter_name = config
            .tun_name
            .clone()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| ADAPTER_NAME.to_string());
        let engine_config = VpnEngineConfig {
            client: ClientConfig {
                server_host: config.client.server_host,
                server_port: config.client.server_port,
                user_agent: config.client.user_agent,
                connect_timeout_ms: config.client.connect_timeout_ms,
                io_timeout_ms: config.client.io_timeout_ms,
                node_probe_timeout_ms: config.client.node_probe_timeout_ms,
                allow_insecure_tls: config.client.allow_insecure_tls,
                bind_interface: None,
                auto_detect_interface: true,
            },
            session: VpnSessionMaterial {
                username: config.session.username,
                sid: config.session.sid,
                device_id: config.session.device_id,
                connection_id: config.session.connection_id,
                sign_key_hex: config.session.sign_key_hex,
                cookies: config
                    .session
                    .cookies
                    .into_iter()
                    .map(|cookie| VpnCookieRecord {
                        host: cookie.host,
                        scheme: cookie.scheme,
                        name: cookie.name,
                        value: cookie.value,
                    })
                    .collect(),
            },
            resource_bytes,
            service_host: config.service_host,
            tun_name: Some(adapter_name),
            mtu: config.mtu,
            packet_information: false,
            exit_on_fatal_error: config.exit_on_fatal_error,
        };

        crate::helper_log!("[Tun] starting L3 engine");
        let engine = Arc::new(VpnEngine::start(engine_config).map_err(|error| error.to_string())?);
        let tunnel_luid =
            active_adapter_luid().ok_or_else(|| "Wintun adapter LUID is unavailable".to_string());
        let tunnel_luid = match tunnel_luid {
            Ok(luid) => luid,
            Err(error) => {
                let _ = engine.stop();
                return Err(error);
            }
        };

        let mut network = PersistedNetworkState::default();
        let install = install_network_plan(&plan, tunnel_luid, &mut network);
        // Persist before reporting errors so a crash mid-way still leaves a
        // record of what must be undone.
        save_persisted_network_state(&network);
        let dns_namespaces = match install {
            Ok(count) => count,
            Err(error) => {
                let _ = engine.stop();
                undo_network_state(&network);
                return Err(error);
            }
        };

        if self.generation.load(Ordering::SeqCst) != generation {
            crate::helper_log!("[Tun] start cancelled by stop request");
            let _ = engine.stop();
            undo_network_state(&network);
            return Ok(());
        }

        {
            let mut state = self.state.lock().unwrap();
            state.engine = Some(Arc::clone(&engine));
            state.network = network;
            state.dns_namespaces = dns_namespaces;
            state.virtual_ip = active_adapter_ip();
            state.status = TunStatus::Running;
            state.message = None;
        }
        crate::helper_log!("[Tun] running");
        self.spawn_monitor(engine, generation);
        Ok(())
    }

    fn spawn_monitor(self: &Arc<Self>, engine: Arc<VpnEngine>, generation: u64) {
        let runtime = Arc::clone(self);
        let _ = thread::Builder::new()
            .name("nulconnect-tun-monitor".into())
            .spawn(move || {
                loop {
                    thread::sleep(Duration::from_secs(1));
                    if runtime.generation.load(Ordering::SeqCst) != generation {
                        return;
                    }
                    if engine.status() != VpnEngineStatus::Stopped {
                        continue;
                    }
                    let _operation = runtime.operation.lock().unwrap();
                    if runtime.generation.load(Ordering::SeqCst) != generation {
                        return;
                    }
                    let result = engine.take_result();
                    let network = {
                        let mut state = runtime.state.lock().unwrap();
                        state.engine = None;
                        state.virtual_ip = None;
                        state.dns_namespaces = 0;
                        std::mem::take(&mut state.network)
                    };
                    let _ = engine.stop();
                    undo_network_state(&network);
                    clear_persisted_network_state();
                    match result {
                        Some(Err(error)) => {
                            runtime.set_status(TunStatus::Failed, Some(error.to_string()))
                        }
                        _ => runtime.set_status(TunStatus::Stopped, None),
                    }
                    return;
                }
            });
    }

    fn stop(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        {
            let mut state = self.state.lock().unwrap();
            if state.status == TunStatus::Running || state.status == TunStatus::Starting {
                state.status = TunStatus::Stopping;
            }
        }
        let _operation = self.operation.lock().unwrap();
        let (engine, network) = {
            let mut state = self.state.lock().unwrap();
            state.virtual_ip = None;
            state.dns_namespaces = 0;
            (state.engine.take(), std::mem::take(&mut state.network))
        };
        if let Some(engine) = engine {
            let _ = engine.stop();
        }
        undo_network_state(&network);
        clear_persisted_network_state();
        self.set_status(TunStatus::Stopped, None);
    }

    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.stop();
    }

    pub fn shutdown(&self) {
        self.request_shutdown();
    }
}

fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8), String> {
    let cidr = cidr.trim();
    let (address, prefix) = match cidr.split_once('/') {
        Some((address, prefix)) => (address, prefix),
        None => (cidr, "32"),
    };
    let address = address
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid route address: {cidr}"))?;
    let prefix = prefix
        .trim()
        .parse::<u8>()
        .map_err(|_| format!("invalid route prefix: {cidr}"))?;
    if prefix == 0 || prefix > 32 {
        return Err(format!("unsupported route prefix: {cidr}"));
    }
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok((Ipv4Addr::from(u32::from(address) & mask), prefix))
}

fn endpoint_host(endpoint: &str) -> Option<&str> {
    let endpoint = endpoint.trim();
    let host = match endpoint.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => endpoint,
    };
    let host = host.trim().trim_matches(['[', ']']);
    (!host.is_empty()).then_some(host)
}

fn resolve_ipv4s(host: &str) -> Vec<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return vec![ip];
    }
    (host, 0)
        .to_socket_addrs()
        .map(|addresses| {
            addresses
                .filter_map(|address| match address.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn build_network_plan(config: &WireConfig, resource_bytes: &[u8]) -> Result<NetworkPlan, String> {
    let service_host = if config.service_host.is_empty() {
        &config.client.server_host
    } else {
        &config.service_host
    };
    let resource = parse_resource_bytes(resource_bytes, service_host)
        .map_err(|error| format!("failed to parse resource for Windows routes: {error}"))?;

    let mut tunnel_routes = Vec::new();
    for cidr in DEFAULT_MANAGED_CIDRS
        .iter()
        .map(|cidr| cidr.to_string())
        .chain(config.managed_route_cidrs.iter().cloned())
    {
        match parse_cidr(&cidr) {
            Ok(route) => tunnel_routes.push(route),
            Err(error) => crate::helper_log!("[Tun] skipping route: {error}"),
        }
    }

    let gateway = windows_net::default_gateway();
    let dns_server = config.dns_addr.trim().parse::<Ipv4Addr>().ok();
    if let Some(dns) = dns_server {
        // A resolver that is the LAN gateway is a local resolver; routing it
        // into the tunnel would break ordinary name resolution.
        if Some(dns) == gateway {
            crate::helper_log!("[Tun] keeping DNS {dns} on the physical interface");
        } else {
            tunnel_routes.push((dns, 32));
        }
    }
    tunnel_routes.sort();
    tunnel_routes.dedup();

    // Keep the gateway nodes and the portal on the physical path even when a
    // managed prefix covers them, otherwise the tunnel would route itself.
    let mut bypass_hosts: Vec<&str> = resource
        .node_groups
        .values()
        .flatten()
        .filter_map(|endpoint| endpoint_host(endpoint))
        .collect();
    bypass_hosts.push(config.client.server_host.as_str());
    let mut bypass_routes = Vec::new();
    for host in bypass_hosts {
        for ip in resolve_ipv4s(host) {
            if ip.is_loopback() || ip.is_unspecified() {
                continue;
            }
            let covered = tunnel_routes.iter().any(|(network, prefix)| {
                let mask = u32::MAX << (32 - u32::from(*prefix));
                u32::from(ip) & mask == u32::from(*network)
            });
            if !covered {
                continue;
            }
            if let Some((interface_luid, next_hop)) = windows_net::best_route(ip) {
                bypass_routes.push(RouteSpec {
                    interface_luid,
                    destination: ip,
                    prefix: 32,
                    next_hop,
                });
            }
        }
    }
    bypass_routes.sort_by_key(|route| (u32::from(route.destination), route.interface_luid));
    bypass_routes.dedup();

    Ok(NetworkPlan {
        tunnel_routes,
        bypass_routes,
        dns_server,
        managed_domains: config.managed_domains.clone(),
    })
}

fn install_network_plan(
    plan: &NetworkPlan,
    tunnel_luid: u64,
    network: &mut PersistedNetworkState,
) -> Result<usize, String> {
    for route in &plan.bypass_routes {
        match windows_net::add_route(route) {
            Ok(true) => network.routes.push(*route),
            Ok(false) => {}
            Err(error) => crate::helper_log!("[Tun] warning: {error}"),
        }
    }
    for (destination, prefix) in &plan.tunnel_routes {
        let route = RouteSpec {
            interface_luid: tunnel_luid,
            destination: *destination,
            prefix: *prefix,
            next_hop: Ipv4Addr::UNSPECIFIED,
        };
        if windows_net::add_route(&route)? {
            network.routes.push(route);
        }
    }
    crate::helper_log!(
        "[Tun] routes installed: tunnel={} bypass={}",
        plan.tunnel_routes.len(),
        plan.bypass_routes.len()
    );
    let Some(dns_server) = plan.dns_server else {
        return Ok(0);
    };
    if plan.managed_domains.is_empty() {
        return Ok(0);
    }
    network.nrpt = true;
    windows_net::apply_nrpt(&plan.managed_domains, dns_server)
}

fn undo_network_state(network: &PersistedNetworkState) {
    for route in network.routes.iter().rev() {
        windows_net::delete_route(route);
    }
    if network.nrpt {
        windows_net::clear_nrpt();
    }
    windows_net::flush_dns_cache();
}

fn network_state_path() -> std::path::PathBuf {
    state_dir().join("network-state.json")
}

fn save_persisted_network_state(network: &PersistedNetworkState) {
    let _ = fs::create_dir_all(state_dir());
    if let Ok(data) = serde_json::to_vec_pretty(network) {
        let _ = fs::write(network_state_path(), data);
    }
}

fn clear_persisted_network_state() {
    let _ = fs::remove_file(network_state_path());
}

fn cleanup_persisted_network_state() {
    if let Ok(data) = fs::read(network_state_path())
        && let Ok(network) = serde_json::from_slice::<PersistedNetworkState>(&data)
    {
        crate::helper_log!(
            "[Tun] cleaning up {} leftover routes (nrpt={})",
            network.routes.len(),
            network.nrpt
        );
        undo_network_state(&network);
    }
    // The NRPT rule has a fixed name, so remove it even without a record.
    windows_net::clear_nrpt();
    clear_persisted_network_state();
}

struct PipeSecurity {
    descriptor: PSECURITY_DESCRIPTOR,
}

impl PipeSecurity {
    fn new() -> io::Result<Self> {
        let sddl = wide(PIPE_SDDL);
        let mut descriptor = ptr::null_mut();
        let mut size = 0u32;
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                &mut size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { descriptor })
    }
}

impl Drop for PipeSecurity {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe { LocalFree(self.descriptor) };
        }
    }
}

struct PipeHandle(HANDLE);

unsafe impl Send for PipeHandle {}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        unsafe {
            FlushFileBuffers(self.0);
            DisconnectNamedPipe(self.0);
            CloseHandle(self.0);
        }
    }
}

fn read_message(pipe: HANDLE) -> io::Result<Vec<u8>> {
    let mut message = Vec::new();
    let mut chunk = vec![0u8; BUFFER_SIZE as usize];
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                pipe,
                chunk.as_mut_ptr(),
                chunk.len() as u32,
                &mut read,
                ptr::null_mut(),
            )
        };
        message.extend_from_slice(&chunk[..read as usize]);
        if message.len() > MAX_REQUEST_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
        if ok != 0 {
            return Ok(message);
        }
        if unsafe { GetLastError() } != ERROR_MORE_DATA {
            return Err(io::Error::last_os_error());
        }
    }
}

fn write_message(pipe: HANDLE, data: &[u8]) -> io::Result<()> {
    let mut written = 0u32;
    let ok = unsafe {
        WriteFile(
            pipe,
            data.as_ptr(),
            data.len() as u32,
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn handle_request(runtime: &Arc<WindowsRuntime>, request: &[u8], allow_shutdown: bool) -> Value {
    let request: Value = match serde_json::from_slice(request) {
        Ok(value) => value,
        Err(error) => {
            return json!({ "id": null, "ok": false, "error": { "code": "invalid_request", "message": error.to_string() } });
        }
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let command = request.get("command").and_then(Value::as_str).unwrap_or("");
    let ok = |data: Value| json!({ "id": id, "ok": true, "data": data });
    let fail = |code: &str, message: String| json!({ "id": id, "ok": false, "error": { "code": code, "message": message } });
    match command {
        "version" => ok(json!({ "version": env!("CARGO_PKG_VERSION") })),
        "status" => ok(runtime.status_json()),
        "start_tun" => {
            let config = request
                .get("config")
                .cloned()
                .ok_or_else(|| "start_tun requires config".to_string())
                .and_then(|value| {
                    serde_json::from_value::<WireConfig>(value).map_err(|error| error.to_string())
                });
            match config.and_then(|config| runtime.begin_start(config)) {
                Ok(data) => ok(data),
                Err(message) => fail("tun_start_failed", message),
            }
        }
        "stop_tun" => {
            runtime.stop();
            ok(json!({ "status": "stopped" }))
        }
        "cleanup" => {
            runtime.stop();
            runtime.cleanup_leftovers();
            ok(json!({ "status": "clean" }))
        }
        "shutdown" if allow_shutdown => {
            runtime.request_shutdown();
            ok(json!({ "status": "stopping" }))
        }
        _ => fail("invalid_command", format!("unsupported command: {command}")),
    }
}

fn serve_client(runtime: Arc<WindowsRuntime>, pipe: PipeHandle, allow_shutdown: bool) {
    let request = match read_message(pipe.0) {
        Ok(request) => request,
        Err(error) => {
            crate::helper_log!("[IPC] read failed: {error}");
            return;
        }
    };
    let response = handle_request(&runtime, &request, allow_shutdown);
    match serde_json::to_vec(&response) {
        Ok(output) => {
            if let Err(error) = write_message(pipe.0, &output) {
                crate::helper_log!("[IPC] write failed: {error}");
            }
        }
        Err(error) => crate::helper_log!("[IPC] encode failed: {error}"),
    }
}

/// Accepts clients until `should_stop` returns true or a console-mode
/// `shutdown` request arrives. Each client is served on its own thread so a
/// long `stop_tun` never blocks `status` polling.
pub fn serve<F>(
    runtime: Arc<WindowsRuntime>,
    allow_shutdown: bool,
    should_stop: F,
) -> io::Result<()>
where
    F: Fn() -> bool,
{
    let name = wide(PIPE_NAME);
    let security = PipeSecurity::new()?;
    let mut first_instance = true;
    while !should_stop() && !runtime.shutdown_requested() {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.descriptor,
            bInheritHandle: 0,
        };
        let open_mode = if first_instance {
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            PIPE_ACCESS_DUPLEX
        };
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                &attributes,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        first_instance = false;
        let connected = unsafe { ConnectNamedPipe(pipe, ptr::null_mut()) };
        if connected == 0 && unsafe { GetLastError() } != ERROR_PIPE_CONNECTED {
            let error = io::Error::last_os_error();
            unsafe { CloseHandle(pipe) };
            crate::helper_log!("[IPC] ConnectNamedPipe failed: {error}");
            continue;
        }
        let pipe = PipeHandle(pipe);
        if should_stop() || runtime.shutdown_requested() {
            break;
        }
        let client_runtime = Arc::clone(&runtime);
        if let Err(error) = thread::Builder::new()
            .name("nulconnect-ipc-client".into())
            .spawn(move || serve_client(client_runtime, pipe, allow_shutdown))
        {
            crate::helper_log!("[IPC] failed to spawn client thread: {error}");
        }
    }
    Ok(())
}

/// Sends one request to a running helper and returns the parsed response.
pub fn call(request: &Value, timeout: Duration) -> io::Result<Value> {
    let name = wide(PIPE_NAME);
    let deadline = std::time::Instant::now() + timeout;
    let pipe = loop {
        let pipe = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if pipe != INVALID_HANDLE_VALUE {
            break pipe;
        }
        let error = io::Error::last_os_error();
        if std::time::Instant::now() >= deadline {
            return Err(error);
        }
        thread::sleep(Duration::from_millis(100));
    };
    struct Client(HANDLE);
    impl Drop for Client {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }
    let client = Client(pipe);
    let mode = PIPE_READMODE_MESSAGE;
    unsafe { SetNamedPipeHandleState(client.0, &mode, ptr::null_mut(), ptr::null_mut()) };
    let data = serde_json::to_vec(request)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    write_message(client.0, &data)?;
    let response = read_message(client.0)?;
    serde_json::from_slice(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Wakes a blocked `serve` loop so it can observe its stop condition.
pub fn wake_server() {
    let _ = call(
        &json!({ "id": "wake", "command": "version" }),
        Duration::from_millis(500),
    );
}
