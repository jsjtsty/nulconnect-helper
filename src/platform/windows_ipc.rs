use crate::{VpnCookieRecord, VpnEngine, VpnEngineConfig, VpnEngineStatus, VpnSessionMaterial};
use base64::Engine;
use reatrust::{ClientConfig, parse_resource_bytes};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io;
use std::net::Ipv4Addr;
use std::process::Command;
use std::ptr;
use std::sync::{Arc, Mutex};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING, ReadFile, WriteFile};
use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe};

const PIPE_ACCESS_DUPLEX: u32 = 3;
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;
const PIPE_TYPE_MESSAGE: u32 = 4;
const PIPE_READMODE_MESSAGE: u32 = 2;
const PIPE_WAIT: u32 = 0;
const PIPE_UNLIMITED_INSTANCES: u32 = 255;
const BUFFER_SIZE: u32 = 64 * 1024;
const SDDL_REVISION_1: u32 = 1;
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)";
const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;

#[derive(Debug, Clone)]
struct RouteEntry {
    network: Ipv4Addr,
    mask: Ipv4Addr,
}

pub struct WindowsRuntime {
    engine: Option<VpnEngine>,
    routes: Vec<RouteEntry>,
    shutdown_requested: bool,
}

impl Default for WindowsRuntime {
    fn default() -> Self {
        Self {
            engine: None,
            routes: Vec::new(),
            shutdown_requested: false,
        }
    }
}

impl WindowsRuntime {
    fn is_running(&self) -> bool {
        self.engine
            .as_ref()
            .is_some_and(|engine| engine.status() == VpnEngineStatus::Running)
    }

    fn start(&mut self, config: WireConfig) -> Result<(), String> {
        if self.is_running() {
            return Err("VPN engine is already running".into());
        }
        let resource_bytes = base64::engine::general_purpose::STANDARD
            .decode(config.resource_bytes.as_bytes())
            .map_err(|error| format!("invalid resource_bytes: {error}"))?;
        let route_plan = if config.setup_routes {
            build_route_plan(&config, &resource_bytes)?
        } else {
            Vec::new()
        };
        let adapter_name = config
            .tun_name
            .as_deref()
            .unwrap_or("NulConnect")
            .to_string();
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
            tun_name: Some(adapter_name.clone()),
            mtu: config.mtu,
            packet_information: false,
            exit_on_fatal_error: config.exit_on_fatal_error,
        };
        let engine = VpnEngine::start(engine_config).map_err(|error| error.to_string())?;
        if let Err(error) = install_routes(&route_plan, &adapter_name) {
            let _ = engine.stop();
            return Err(error);
        }
        self.routes = route_plan;
        self.engine = Some(engine);
        Ok(())
    }

    fn stop(&mut self) {
        remove_routes(&self.routes);
        self.routes.clear();
        if let Some(engine) = self.engine.take() {
            let _ = engine.stop();
        }
    }

    fn request_shutdown(&mut self) {
        self.shutdown_requested = true;
        self.stop();
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

fn build_route_plan(config: &WireConfig, resource_bytes: &[u8]) -> Result<Vec<RouteEntry>, String> {
    let service_host = if config.service_host.is_empty() {
        &config.client.server_host
    } else {
        &config.service_host
    };
    let _resource = parse_resource_bytes(resource_bytes, service_host)
        .map_err(|error| format!("failed to parse resource for Windows routes: {error}"))?;
    let mut cidrs = config.managed_route_cidrs.clone();
    if !config.dns_addr.trim().is_empty() {
        cidrs.push(format!("{}/32", config.dns_addr.trim()));
    }
    // Node endpoints are deliberately not installed on Wintun. The control
    // connection must remain on the physical interface while business CIDRs
    // are routed through the tunnel.
    cidrs.sort();
    cidrs.dedup();
    cidrs.into_iter().map(|cidr| parse_cidr(&cidr)).collect()
}

fn parse_cidr(cidr: &str) -> Result<RouteEntry, String> {
    let (address, prefix) = cidr
        .trim()
        .split_once('/')
        .ok_or_else(|| format!("invalid route CIDR: {cidr}"))?;
    let address = address
        .parse::<Ipv4Addr>()
        .map_err(|_| format!("invalid route address: {cidr}"))?;
    let prefix = prefix
        .parse::<u32>()
        .map_err(|_| format!("invalid route prefix: {cidr}"))?;
    if prefix == 0 || prefix > 32 {
        return Err(format!("unsupported route prefix: {cidr}"));
    }
    let mask = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(RouteEntry {
        network: Ipv4Addr::from(u32::from(address) & mask),
        mask: Ipv4Addr::from(mask),
    })
}

fn interface_index(adapter_name: &str) -> Result<String, String> {
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "show", "interfaces"])
        .output()
        .map_err(|error| format!("failed to inspect Windows interfaces: {error}"))?;
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let mut fields = line.split_whitespace();
        let Some(index) = fields.next() else { continue };
        let _ = fields.next();
        let _ = fields.next();
        let _ = fields.next();
        if fields.collect::<Vec<_>>().join(" ") == adapter_name && index.parse::<u32>().is_ok() {
            return Ok(index.to_string());
        }
    }
    Err(format!(
        "could not find Windows interface index for {adapter_name}"
    ))
}

fn install_routes(routes: &[RouteEntry], adapter_name: &str) -> Result<(), String> {
    if routes.is_empty() {
        return Ok(());
    }
    let index = interface_index(adapter_name)?;
    let mut installed = Vec::new();
    for route in routes {
        let output = Command::new("route")
            .args([
                "ADD",
                &route.network.to_string(),
                "MASK",
                &route.mask.to_string(),
                "0.0.0.0",
                "IF",
                &index,
                "METRIC",
                "1",
            ])
            .output()
            .map_err(|error| format!("failed to add Windows route: {error}"))?;
        if output.status.success() {
            installed.push(route.clone());
            continue;
        }
        let message = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !message
            .to_ascii_lowercase()
            .contains("object already exists")
        {
            remove_routes(&installed);
            return Err(format!(
                "failed to add route {}: {}",
                route.network,
                message.trim()
            ));
        }
    }
    Ok(())
}

fn remove_routes(routes: &[RouteEntry]) {
    for route in routes {
        let _ = Command::new("route")
            .args([
                "DELETE",
                &route.network.to_string(),
                "MASK",
                &route.mask.to_string(),
            ])
            .output();
    }
}

pub fn request_shutdown() -> io::Result<()> {
    let slash = char::from_u32(92).unwrap();
    let name = wide(&format!(
        "{slash}{slash}.{slash}pipe{slash}NulConnectHelper"
    ));
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
    if pipe == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let request = br#"{"id":"service-stop","command":"shutdown"}"#;
    let mut written = 0u32;
    let ok = unsafe {
        WriteFile(
            pipe,
            request.as_ptr(),
            request.len() as u32,
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        unsafe { CloseHandle(pipe) };
        return Err(io::Error::last_os_error());
    }
    let mut response = [0u8; 1024];
    let mut read = 0u32;
    let _ = unsafe {
        ReadFile(
            pipe,
            response.as_mut_ptr(),
            response.len() as u32,
            &mut read,
            ptr::null_mut(),
        )
    };
    unsafe { CloseHandle(pipe) };
    Ok(())
}

pub fn serve<F>(runtime: Arc<Mutex<WindowsRuntime>>, mut should_stop: F) -> io::Result<()>
where
    F: FnMut() -> bool,
{
    let slash = char::from_u32(92).unwrap();
    let name = wide(&format!(
        "{slash}{slash}.{slash}pipe{slash}NulConnectHelper"
    ));
    let security = PipeSecurity::new()?;
    while !should_stop() && !runtime.lock().unwrap().shutdown_requested {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: security.descriptor,
            bInheritHandle: 0,
        };
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
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
        let connected = unsafe { ConnectNamedPipe(pipe, ptr::null_mut()) };
        if connected == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                unsafe { CloseHandle(pipe) };
                return Err(error);
            }
        }
        let result = handle_client(pipe, &runtime);
        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
        result?;
    }
    runtime.lock().unwrap().stop();
    Ok(())
}

fn handle_client(pipe: HANDLE, runtime: &Arc<Mutex<WindowsRuntime>>) -> io::Result<()> {
    let mut input = vec![0u8; BUFFER_SIZE as usize];
    let mut read = 0u32;
    let ok = unsafe {
        ReadFile(
            pipe,
            input.as_mut_ptr(),
            input.len() as u32,
            &mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let request: Value = serde_json::from_slice(&input[..read as usize])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let response = match request.get("command").and_then(Value::as_str) {
        Some("version") => {
            json!({ "id": id, "ok": true, "data": { "version": env!("CARGO_PKG_VERSION") } })
        }
        Some("status") => {
            let state = runtime.lock().unwrap();
            let stats = state
                .engine
                .as_ref()
                .map(|engine| engine.traffic_stats())
                .unwrap_or_default();
            json!({ "id": id, "ok": true, "data": {
                "service": "running",
                "tun": if state.is_running() { "running" } else { "stopped" },
                "routes": state.routes.len(),
                "upload_bytes": stats.upload_bytes,
                "download_bytes": stats.download_bytes,
                "upload_packets": stats.upload_packets,
                "download_packets": stats.download_packets
            } })
        }
        Some("start_tun") => {
            let result = request
                .get("config")
                .cloned()
                .ok_or_else(|| "start_tun requires config".to_string())
                .and_then(|value| {
                    serde_json::from_value::<WireConfig>(value).map_err(|error| error.to_string())
                })
                .and_then(|config| runtime.lock().unwrap().start(config));
            match result {
                Ok(()) => {
                    json!({ "id": id, "ok": true, "data": { "tun": "running", "adapter": "NulConnect" } })
                }
                Err(message) => {
                    json!({ "id": id, "ok": false, "error": { "code": "tun_start_failed", "message": message } })
                }
            }
        }
        Some("stop_tun") => {
            runtime.lock().unwrap().stop();
            json!({ "id": id, "ok": true, "data": { "tun": "stopped" } })
        }
        Some("shutdown") => {
            runtime.lock().unwrap().request_shutdown();
            json!({ "id": id, "ok": true, "data": { "status": "stopping" } })
        }
        _ => {
            json!({ "id": id, "ok": false, "error": { "code": "invalid_command", "message": "unsupported command" } })
        }
    };
    let output = serde_json::to_vec(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut written = 0u32;
    let ok = unsafe {
        WriteFile(
            pipe,
            output.as_ptr(),
            output.len() as u32,
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
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
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
