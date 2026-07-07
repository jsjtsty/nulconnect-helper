use base64::Engine as _;
use nulconnect_tun::{
    AtrError, AtrResult, VpnCookieRecord, VpnEngine, VpnEngineConfig, VpnSessionMaterial,
};
use reatrust::{ClientConfig, parse_resource_bytes};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{Ipv4Addr, ToSocketAddrs};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const HELPER_VERSION: &str = env!("CARGO_PKG_VERSION");
const DEFAULT_SOCKET_PATH: &str = "/var/run/nulconnect-helper.sock";
const DEFAULT_STATE_DIR: &str = "/Library/Application Support/NulConnect";

macro_rules! helper_log {
    ($($arg:tt)*) => {
        eprintln!("[{}] {}", now_unix_secs(), format_args!($($arg)*));
    };
}

#[derive(Debug, Clone, Deserialize)]
struct HelperConfig {
    client: HelperClientConfig,
    session: HelperSessionMaterial,
    resource_bytes: String,
    service_host: String,
    tun_name: Option<String>,
    dns_addr: String,
    #[serde(default)]
    managed_route_cidrs: Vec<String>,
    #[serde(default)]
    managed_domains: Vec<String>,
    mtu: u16,
    setup_routes: bool,
    exit_on_fatal_error: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct HelperClientConfig {
    server_host: String,
    server_port: u16,
    user_agent: String,
    connect_timeout_ms: u64,
    io_timeout_ms: u64,
    node_probe_timeout_ms: u64,
    allow_insecure_tls: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct HelperSessionMaterial {
    username: String,
    sid: String,
    device_id: String,
    connection_id: String,
    sign_key_hex: String,
    #[serde(default)]
    cookies: Vec<HelperCookieRecord>,
}

#[derive(Debug, Clone, Deserialize)]
struct HelperCookieRecord {
    host: String,
    scheme: String,
    name: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct LegacyHelperState {
    pid: u32,
    status: String,
    message: Option<String>,
    updated_at_unix_secs: u64,
    sessions: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct HelperRequest {
    id: String,
    #[serde(flatten)]
    command: HelperCommand,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
enum HelperCommand {
    Version,
    Status,
    StartTun {
        config: HelperConfig,
    },
    StopTun,
    SetSystemProxy {
        endpoint: ProxyEndpoint,
        server_host: String,
    },
    RestoreSystemProxy,
    Cleanup,
    Shutdown,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct ProxyEndpoint {
    host: String,
    port: u16,
}

#[derive(Debug, Serialize)]
struct HelperResponse {
    id: String,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<HelperErrorResponse>,
}

#[derive(Debug, Serialize)]
struct HelperErrorResponse {
    code: String,
    message: String,
}

struct HelperRuntime {
    state_dir: PathBuf,
    tun_engine: Mutex<Option<VpnEngine>>,
    tun_starting: Mutex<bool>,
    tun_failure: Mutex<Option<String>>,
    shutting_down: Mutex<bool>,
}

#[derive(Debug, Serialize)]
struct TunState {
    pid: u32,
    status: String,
    message: Option<String>,
    updated_at_unix_secs: u64,
    sessions: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TunNetworkSnapshot {
    saved_at_unix_secs: u64,
    services: Vec<TunNetworkServiceSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TunNetworkServiceSnapshot {
    name: String,
    dns_servers: Vec<String>,
    search_domains: Vec<String>,
}

fn main() {
    ignore_sigpipe();
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn ignore_sigpipe() {
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

fn run() -> AtrResult<()> {
    raise_file_descriptor_limit();

    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| AtrError::InvalidArgument("missing command".into()))?;

    match command.as_str() {
        "run" => {
            let config_path = required_path(args.next(), "config path")?;
            let state_path = required_path(args.next(), "state path")?;
            let stop_path = required_path(args.next(), "stop path")?;
            run_legacy_engine(&config_path, &state_path, &stop_path)
        }
        "serve" => {
            let socket_path = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET_PATH));
            let state_dir = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STATE_DIR));
            serve(&socket_path, &state_dir)
        }
        "version" => {
            println!("{HELPER_VERSION}");
            Ok(())
        }
        _ => Err(AtrError::InvalidArgument(format!(
            "unsupported command: {command}"
        ))),
    }
}

fn serve(socket_path: &Path, state_dir: &Path) -> AtrResult<()> {
    helper_log!(
        "[NulConnect][Helper] serve: socket={} state_dir={}",
        socket_path.display(),
        state_dir.display()
    );
    fs::create_dir_all(state_dir)?;
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    listener.set_nonblocking(true)?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o777))?;
    helper_log!("[NulConnect][Helper] serve: listening");

    let runtime = Arc::new(HelperRuntime {
        state_dir: state_dir.to_path_buf(),
        tun_engine: Mutex::new(None),
        tun_starting: Mutex::new(false),
        tun_failure: Mutex::new(None),
        shutting_down: Mutex::new(false),
    });

    loop {
        if *runtime.shutting_down.lock().unwrap() {
            break;
        }
        match listener.accept() {
            Ok((stream, _addr)) => {
                helper_log!("[NulConnect][Helper] serve: accepted client");
                if let Err(err) = stream.set_nonblocking(false) {
                    helper_log!("[NulConnect][Helper] accepted client set blocking failed: {err}");
                    continue;
                }
                let worker_runtime = runtime.clone();
                thread::spawn(move || {
                    if let Err(err) = handle_client(stream, worker_runtime) {
                        helper_log!("[NulConnect][Helper] client handler failed: {err}");
                    }
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(AtrError::from(err)),
        }
    }

    let _ = stop_tun(&runtime);
    let _ = fs::remove_file(socket_path);
    Ok(())
}

fn handle_client(mut stream: UnixStream, runtime: Arc<HelperRuntime>) -> AtrResult<()> {
    let reader_stream = stream.try_clone()?;
    let reader = BufReader::new(reader_stream);
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                helper_log!("[NulConnect][Helper] client read would block, waiting");
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(err) => return Err(AtrError::from(err)),
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<HelperRequest>(&line) {
            Ok(request) => handle_request(request, &runtime),
            Err(err) => HelperResponse {
                id: String::new(),
                ok: false,
                data: None,
                error: Some(HelperErrorResponse {
                    code: "parse_failed".to_string(),
                    message: err.to_string(),
                }),
            },
        };
        if write_response(&mut stream, &response)? {
            break;
        }
    }
    Ok(())
}

fn write_response(stream: &mut UnixStream, response: &HelperResponse) -> AtrResult<bool> {
    let data = serde_json::to_vec(response)?;
    match stream
        .write_all(&data)
        .and_then(|_| stream.write_all(b"\n"))
    {
        Ok(()) => Ok(false),
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::BrokenPipe
                    | ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
            ) =>
        {
            helper_log!("[NulConnect][Helper] client disconnected before response was written");
            Ok(true)
        }
        Err(err) => Err(AtrError::from(err)),
    }
}

fn handle_request(request: HelperRequest, runtime: &Arc<HelperRuntime>) -> HelperResponse {
    let id = request.id;
    helper_log!("[NulConnect][Helper] request: id={id}");
    let result = match request.command {
        HelperCommand::Version => Ok(json!({
            "version": HELPER_VERSION,
            "pid": std::process::id(),
        })),
        HelperCommand::Status => helper_status(runtime),
        HelperCommand::StartTun { config } => start_tun(runtime.clone(), config),
        HelperCommand::StopTun => stop_tun(runtime).map(|_| json!({ "status": "stopped" })),
        HelperCommand::SetSystemProxy {
            endpoint,
            server_host,
        } => set_system_proxy(runtime, endpoint, &server_host),
        HelperCommand::RestoreSystemProxy => {
            restore_system_proxy(runtime).map(|_| json!({ "status": "restored" }))
        }
        HelperCommand::Cleanup => {
            let _ = stop_tun(runtime);
            restore_system_proxy(runtime).map(|_| json!({ "status": "cleaned" }))
        }
        HelperCommand::Shutdown => {
            let _ = stop_tun(runtime);
            *runtime.shutting_down.lock().unwrap() = true;
            Ok(json!({ "status": "shutting_down" }))
        }
    };

    match result {
        Ok(data) => HelperResponse {
            id,
            ok: true,
            data: Some(data),
            error: None,
        },
        Err(err) => HelperResponse {
            id,
            ok: false,
            data: None,
            error: Some(HelperErrorResponse {
                code: format!("{:?}", err.code()).to_lowercase(),
                message: err.to_string(),
            }),
        },
    }
}

fn helper_status(runtime: &HelperRuntime) -> AtrResult<Value> {
    let tun_status = {
        if *runtime.tun_starting.lock().unwrap() {
            json!({ "status": "starting" })
        } else if let Some(message) = runtime.tun_failure.lock().unwrap().clone() {
            json!({ "status": "failed", "message": message })
        } else {
            let mut guard = runtime.tun_engine.lock().unwrap();
            if let Some(engine) = guard.as_ref() {
                if let Some(result) = engine.take_result() {
                    *guard = None;
                    match result {
                        Ok(sessions) => {
                            write_tun_state(runtime, "stopped", None, Some(sessions))?;
                            json!({ "status": "stopped", "sessions": sessions })
                        }
                        Err(err) => {
                            let message = err.to_string();
                            write_tun_state(runtime, "failed", Some(&message), None)?;
                            json!({ "status": "failed", "message": message })
                        }
                    }
                } else {
                    json!({ "status": "running" })
                }
            } else {
                json!({ "status": "stopped" })
            }
        }
    };

    Ok(json!({
        "version": HELPER_VERSION,
        "pid": std::process::id(),
        "tun": tun_status,
        "system_proxy_snapshot_exists": system_proxy_snapshot_path(runtime).exists(),
    }))
}

fn start_tun(runtime: Arc<HelperRuntime>, config: HelperConfig) -> AtrResult<Value> {
    {
        let mut starting = runtime.tun_starting.lock().unwrap();
        if *starting {
            return Err(AtrError::InvalidState("tun is already starting".into()));
        }
        if runtime.tun_engine.lock().unwrap().is_some() {
            return Err(AtrError::InvalidState("tun is already running".into()));
        }
        *starting = true;
        *runtime.tun_failure.lock().unwrap() = None;
    }
    write_tun_state(&runtime, "starting", None, None)?;
    helper_log!(
        "[NulConnect][Helper][Tun] start accepted: server={}:{} dns={} routes={} domains={} mtu={}",
        config.client.server_host,
        config.client.server_port,
        config.dns_addr,
        config.managed_route_cidrs.len(),
        config.managed_domains.len(),
        config.mtu
    );

    thread::Builder::new()
        .name("nulconnect-l3-start".to_string())
        .spawn(move || {
            helper_log!("[NulConnect][Helper][Tun] start worker: begin");
            let result = start_tun_worker(&runtime, config);
            *runtime.tun_starting.lock().unwrap() = false;
            match result {
                Ok(()) => {
                    helper_log!("[NulConnect][Helper][Tun] start worker: running");
                }
                Err(err) => {
                    let message = err.to_string();
                    helper_log!("[NulConnect][Helper][Tun] start worker: failed: {message}");
                    *runtime.tun_failure.lock().unwrap() = Some(message.clone());
                    let _ = write_tun_state(&runtime, "failed", Some(&message), None);
                }
            }
        })
        .map_err(|err| AtrError::Internal(format!("failed to start TUN worker: {err}")))?;

    Ok(json!({ "status": "starting" }))
}

fn start_tun_worker(runtime: &HelperRuntime, config: HelperConfig) -> AtrResult<()> {
    if runtime.tun_engine.lock().unwrap().is_some() {
        return Err(AtrError::InvalidState("tun is already running".into()));
    }
    helper_log!("[NulConnect][Helper][Tun] worker: snapshot network state");
    log_tun_network_state("before start");
    snapshot_tun_network_state(&tun_network_snapshot_path(runtime))?;
    helper_log!(
        "[NulConnect][Helper][Tun] start: server={} dns={} setup_routes={} managed_routes={} managed_domains={}",
        config.client.server_host,
        config.dns_addr,
        config.setup_routes,
        config.managed_route_cidrs.len(),
        config.managed_domains.len()
    );
    helper_log!("[NulConnect][Helper][Tun] worker: creating L3 engine");
    let engine = match VpnEngine::start(config.clone().into_vpn_engine_config()?) {
        Ok(engine) => engine,
        Err(err) => {
            let message = err.to_string();
            let _ = restore_tun_network_state(&tun_network_snapshot_path(runtime));
            cleanup_tun_routes();
            write_tun_state(runtime, "failed", Some(&message), None)?;
            return Err(err);
        }
    };
    helper_log!("[NulConnect][Helper][Tun] worker: L3 engine created");
    if let Err(err) = setup_managed_tun_routes(&config) {
        helper_log!("[NulConnect][Helper][Tun] worker: route setup failed: {err}");
        restore_tun_network_after_stop(runtime);
        let _ = engine.stop();
        return Err(err);
    }
    helper_log!("[NulConnect][Helper][Tun] worker: route setup complete");
    if let Err(err) = wait_for_tun_setup(&config) {
        helper_log!("[NulConnect][Helper][Tun] worker: setup wait failed: {err}");
        restore_tun_network_after_stop(runtime);
        let _ = engine.stop();
        return Err(err);
    }
    helper_log!("[NulConnect][Helper][Tun] worker: setup wait complete");
    *runtime.tun_engine.lock().unwrap() = Some(engine);
    log_tun_network_state("after start");
    write_tun_state(runtime, "running", None, None)?;
    Ok(())
}

fn stop_tun(runtime: &HelperRuntime) -> AtrResult<()> {
    helper_log!("[NulConnect][Helper][Tun] stop: requested");
    log_tun_network_state("before stop");
    *runtime.tun_failure.lock().unwrap() = None;
    let mut guard = runtime.tun_engine.lock().unwrap();
    if let Some(engine) = guard.take() {
        engine.cancel();
    }
    drop(guard);
    restore_tun_network_after_stop(runtime);
    log_tun_network_state("after stop");
    write_tun_state(runtime, "stopped", None, None)?;
    Ok(())
}

fn restore_tun_network_after_stop(runtime: &HelperRuntime) {
    cleanup_tun_routes();
    cleanup_scoped_dns_resolvers();
    remove_global_dns_state();
    match restore_tun_network_state(&tun_network_snapshot_path(runtime)) {
        Ok(()) => {}
        Err(AtrError::NotFound(err)) => {
            helper_log!("[NulConnect][Helper][Tun] network snapshot already absent: {err}");
        }
        Err(err) => {
            helper_log!("[NulConnect][Helper][Tun] restore network snapshot failed: {err}");
            reset_dns_to_default();
        }
    }
    flush_dns_cache();
}

fn run_legacy_engine(config_path: &Path, state_path: &Path, stop_path: &Path) -> AtrResult<()> {
    let data = fs::read(config_path)?;
    let config: HelperConfig =
        serde_json::from_slice(&data).map_err(|err| AtrError::ParseFailed(err.to_string()))?;
    let snapshot_path = legacy_tun_network_snapshot_path(state_path);
    snapshot_tun_network_state(&snapshot_path)?;
    log_tun_network_state("legacy before start");
    helper_log!(
        "[NulConnect][Helper][Tun] legacy start: server={} dns={} setup_routes={} managed_routes={} managed_domains={}",
        config.client.server_host,
        config.dns_addr,
        config.setup_routes,
        config.managed_route_cidrs.len(),
        config.managed_domains.len()
    );
    let engine = match VpnEngine::start(config.clone().into_vpn_engine_config()?) {
        Ok(engine) => engine,
        Err(err) => {
            let _ = restore_tun_network_state(&snapshot_path);
            cleanup_tun_routes();
            return Err(err);
        }
    };
    if let Err(err) = setup_managed_tun_routes(&config) {
        engine.cancel();
        cleanup_tun_routes();
        cleanup_scoped_dns_resolvers();
        remove_global_dns_state();
        if let Err(restore_err) = restore_tun_network_state(&snapshot_path) {
            helper_log!(
                "[NulConnect][Helper][Tun] legacy restore network snapshot failed: {restore_err}"
            );
            reset_dns_to_default();
        }
        flush_dns_cache();
        return Err(err);
    }
    if let Err(err) = wait_for_tun_setup(&config) {
        engine.cancel();
        cleanup_tun_routes();
        cleanup_scoped_dns_resolvers();
        remove_global_dns_state();
        if let Err(restore_err) = restore_tun_network_state(&snapshot_path) {
            helper_log!(
                "[NulConnect][Helper][Tun] legacy restore network snapshot failed: {restore_err}"
            );
            reset_dns_to_default();
        }
        flush_dns_cache();
        return Err(err);
    }
    log_tun_network_state("legacy after start");
    write_legacy_state(state_path, "running", None, None)?;

    loop {
        if stop_path.exists() {
            break;
        }
        if let Some(result) = engine.take_result() {
            match result {
                Ok(sessions) => {
                    write_legacy_state(state_path, "stopped", None, Some(sessions))?;
                    return Ok(());
                }
                Err(err) => {
                    let message = err.to_string();
                    write_legacy_state(state_path, "failed", Some(&message), None)?;
                    return Err(err);
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }

    let stop_result = engine.stop();
    cleanup_tun_routes();
    cleanup_scoped_dns_resolvers();
    remove_global_dns_state();
    if let Err(err) = restore_tun_network_state(&snapshot_path) {
        helper_log!("[NulConnect][Helper][Tun] legacy restore network snapshot failed: {err}");
        reset_dns_to_default();
    }
    flush_dns_cache();
    log_tun_network_state("legacy after stop");
    stop_result?;
    write_legacy_state(state_path, "stopped", None, None)?;
    Ok(())
}

fn raise_file_descriptor_limit() {
    unsafe {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
            helper_log!(
                "[NulConnect][Helper] getrlimit(RLIMIT_NOFILE) failed: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        let desired = 4096;
        let target = std::cmp::min(limit.rlim_max, desired);
        if limit.rlim_cur >= target {
            return;
        }
        limit.rlim_cur = target;
        if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
            helper_log!(
                "[NulConnect][Helper] setrlimit(RLIMIT_NOFILE={target}) failed: {}",
                std::io::Error::last_os_error()
            );
        } else {
            helper_log!("[NulConnect][Helper] RLIMIT_NOFILE raised to {target}");
        }
    }
}

fn required_path(value: Option<String>, name: &str) -> AtrResult<PathBuf> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| AtrError::InvalidArgument(format!("missing {name}")))
}

fn write_legacy_state(
    path: &Path,
    status: &str,
    message: Option<&str>,
    sessions: Option<usize>,
) -> AtrResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let state = LegacyHelperState {
        pid: std::process::id(),
        status: status.to_string(),
        message: message.map(ToString::to_string),
        updated_at_unix_secs: now_unix_secs(),
        sessions,
    };
    let data =
        serde_json::to_vec_pretty(&state).map_err(|err| AtrError::Internal(err.to_string()))?;
    fs::write(path, data)?;
    Ok(())
}

fn write_tun_state(
    runtime: &HelperRuntime,
    status: &str,
    message: Option<&str>,
    sessions: Option<usize>,
) -> AtrResult<()> {
    fs::create_dir_all(&runtime.state_dir)?;
    let state = TunState {
        pid: std::process::id(),
        status: status.to_string(),
        message: message.map(ToString::to_string),
        updated_at_unix_secs: now_unix_secs(),
        sessions,
    };
    let data =
        serde_json::to_vec_pretty(&state).map_err(|err| AtrError::Internal(err.to_string()))?;
    fs::write(tun_state_path(runtime), data)?;
    helper_log!(
        "[NulConnect][Helper][Tun] state: status={} message={} sessions={}",
        status,
        message.unwrap_or(""),
        sessions.map(|value| value.to_string()).unwrap_or_default()
    );
    Ok(())
}

fn tun_state_path(runtime: &HelperRuntime) -> PathBuf {
    runtime.state_dir.join("tun-state.json")
}

fn tun_network_snapshot_path(runtime: &HelperRuntime) -> PathBuf {
    runtime.state_dir.join("tun-network-snapshot.json")
}

fn legacy_tun_network_snapshot_path(state_path: &Path) -> PathBuf {
    state_path
        .parent()
        .unwrap_or_else(|| Path::new("/tmp"))
        .join("tun-network-snapshot.json")
}

fn snapshot_tun_network_state(path: &Path) -> AtrResult<()> {
    if path.exists() {
        helper_log!(
            "[NulConnect][Helper][Tun] network snapshot already exists: {}",
            path.display()
        );
        return Ok(());
    }

    let services = list_network_services()?
        .iter()
        .map(|service| {
            Ok(TunNetworkServiceSnapshot {
                name: service.clone(),
                dns_servers: read_networksetup_list(&["-getdnsservers", service])?,
                search_domains: read_networksetup_list(&["-getsearchdomains", service])?,
            })
        })
        .collect::<AtrResult<Vec<_>>>()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let snapshot = TunNetworkSnapshot {
        saved_at_unix_secs: now_unix_secs(),
        services,
    };
    let data = serde_json::to_vec_pretty(&snapshot)?;
    fs::write(path, data)?;
    helper_log!(
        "[NulConnect][Helper][Tun] saved network snapshot: {} services={}",
        path.display(),
        snapshot.services.len()
    );
    Ok(())
}

fn restore_tun_network_state(path: &Path) -> AtrResult<()> {
    if !path.exists() {
        return Err(AtrError::NotFound(format!(
            "tun network snapshot not found: {}",
            path.display()
        )));
    }

    let data = fs::read(path)?;
    let snapshot: TunNetworkSnapshot = serde_json::from_slice(&data)?;
    let existing = list_network_services()?;
    for service in snapshot
        .services
        .iter()
        .filter(|service| existing.contains(&service.name))
    {
        let mut dns_args = vec!["-setdnsservers", service.name.as_str()];
        if service.dns_servers.is_empty() {
            dns_args.push("Empty");
        } else {
            dns_args.extend(service.dns_servers.iter().map(String::as_str));
        }
        run_networksetup(&dns_args)?;

        let mut search_args = vec!["-setsearchdomains", service.name.as_str()];
        if service.search_domains.is_empty() {
            search_args.push("Empty");
        } else {
            search_args.extend(service.search_domains.iter().map(String::as_str));
        }
        run_networksetup(&search_args)?;
    }
    fs::remove_file(path)?;
    helper_log!(
        "[NulConnect][Helper][Tun] restored network snapshot: services={}",
        snapshot.services.len()
    );
    Ok(())
}

fn reset_dns_to_default() {
    helper_log!("[NulConnect][Helper][Tun] fallback reset DNS/search domains to Empty");
    let Ok(services) = list_network_services() else {
        return;
    };
    for service in services {
        let _ = run_networksetup(&["-setdnsservers", &service, "Empty"]);
        let _ = run_networksetup(&["-setsearchdomains", &service, "Empty"]);
    }
}

fn cleanup_tun_routes() {
    helper_log!("[NulConnect][Helper][Tun] cleanup managed/fake-ip routes");
    let _ = Command::new("/sbin/route")
        .args(["-n", "delete", "-net", "198.18.0.0/15"])
        .output();
    let _ = Command::new("/sbin/route")
        .args(["-n", "delete", "-net", "198.18.0.0/16"])
        .output();
    let _ = Command::new("/sbin/route")
        .args(["-n", "delete", "-host", "198.18.0.1"])
        .output();
    let state_path = managed_routes_state_path();
    if let Ok(data) = fs::read_to_string(&state_path) {
        if let Ok(routes) = serde_json::from_str::<Vec<String>>(&data) {
            for cidr in routes {
                delete_route_cidr(&cidr);
            }
        }
    }
    let _ = fs::remove_file(state_path);
}

fn setup_managed_tun_routes(config: &HelperConfig) -> AtrResult<()> {
    if !config.setup_routes {
        helper_log!("[NulConnect][Helper][Tun] managed route setup skipped");
        return Ok(());
    }

    let tun_name = discover_tun_name()?;
    configure_scoped_dns_resolvers(&config.managed_domains, &config.dns_addr)?;

    let mut routes = config.managed_route_cidrs.clone();
    if !config.dns_addr.trim().is_empty() {
        routes.push(format!("{}/32", config.dns_addr.trim()));
    }
    routes.extend(config.managed_route_cidrs.iter().cloned());
    routes.sort();
    routes.dedup();
    let node_routes = node_route_cidrs(config)?;
    let default_gateway = if node_routes.is_empty() {
        None
    } else {
        Some(default_ipv4_gateway()?)
    };

    let mut installed: Vec<String> = Vec::new();
    for cidr in routes {
        if cidr.trim().is_empty() {
            continue;
        }
        if let Err(err) = add_route_cidr(&cidr, "10.0.0.1") {
            for route in installed {
                delete_route_cidr(&route);
            }
            return Err(err);
        }
        installed.push(cidr);
    }
    if let Some(gateway) = default_gateway {
        for cidr in node_routes {
            if let Err(err) = add_route_cidr(&cidr, &gateway) {
                helper_log!(
                    "[NulConnect][Helper][Tun] warning: failed to add direct node route {} via {}: {}",
                    cidr,
                    gateway,
                    err
                );
                continue;
            }
            installed.push(cidr);
        }
    }
    let data = serde_json::to_vec_pretty(&installed)?;
    fs::write(managed_routes_state_path(), data)?;
    flush_dns_cache();
    helper_log!(
        "[NulConnect][Helper][Tun] managed route setup ready: tun={} scoped_dns={} routes={} domains={}",
        tun_name,
        config.dns_addr,
        installed.len(),
        config.managed_domains.len()
    );
    Ok(())
}

fn node_route_cidrs(config: &HelperConfig) -> AtrResult<Vec<String>> {
    let resource_bytes = base64::engine::general_purpose::STANDARD
        .decode(config.resource_bytes.as_bytes())
        .map_err(|err| AtrError::InvalidArgument(format!("invalid resource bytes: {err}")))?;
    let resource = parse_resource_bytes(&resource_bytes, &config.service_host)
        .map_err(|err| AtrError::ParseFailed(err.to_string()))?;
    let mut routes = Vec::new();
    for endpoint in resource.node_groups.values().flatten() {
        let Some(host) = endpoint_host(endpoint) else {
            continue;
        };
        for ip in resolve_endpoint_ipv4s(host) {
            routes.push(format!("{ip}/32"));
        }
    }
    routes.sort();
    routes.dedup();
    helper_log!(
        "[NulConnect][Helper][Tun] direct node routes: {}",
        routes.join(",")
    );
    Ok(routes)
}

fn endpoint_host(endpoint: &str) -> Option<&str> {
    let endpoint = endpoint.trim();
    let (host, _port) = endpoint.rsplit_once(':')?;
    let host = host.trim().trim_matches(['[', ']']);
    if host.is_empty() { None } else { Some(host) }
}

fn resolve_endpoint_ipv4s(host: &str) -> Vec<Ipv4Addr> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return vec![ip];
    }
    (host, 0)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .filter_map(|addr| match addr.ip() {
                    std::net::IpAddr::V4(ip) => Some(ip),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn default_ipv4_gateway() -> AtrResult<String> {
    let text = command_text("/sbin/route", &["-n", "get", "default"])?;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(gateway) = trimmed.strip_prefix("gateway:") {
            let gateway = gateway.trim();
            if gateway.parse::<Ipv4Addr>().is_ok() {
                return Ok(gateway.to_string());
            }
        }
    }
    Err(AtrError::NetworkFailed(
        "unable to discover default IPv4 gateway".to_string(),
    ))
}

fn discover_tun_name() -> AtrResult<String> {
    let text = command_text("/usr/sbin/netstat", &["-rn", "-f", "inet"])?;
    for line in text.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() >= 4 && fields[0] == "10.0.0.1" {
            if let Some(iface) = fields.last().filter(|iface| iface.starts_with("utun")) {
                return Ok((*iface).to_string());
            }
        }
    }
    let text = command_text("/sbin/ifconfig", &[])?;
    for block in text.split('\n').collect::<Vec<_>>().windows(2) {
        let header = block[0];
        let body = block[1];
        if !header.starts_with("utun") || !body.contains("inet ") {
            continue;
        }
        if let Some((name, _)) = header.split_once(':') {
            return Ok(name.to_string());
        }
    }
    Err(AtrError::NetworkFailed(
        "unable to discover TUN interface after start".to_string(),
    ))
}

fn configure_scoped_dns_resolvers(domains: &[String], server: &str) -> AtrResult<()> {
    cleanup_scoped_dns_resolvers();
    let resolver_dir = Path::new("/etc/resolver");
    fs::create_dir_all(resolver_dir)?;

    let mut installed = Vec::new();
    for domain in normalized_resolver_domains(domains) {
        let path = resolver_dir.join(&domain);
        helper_log!(
            "[NulConnect][Helper][Tun] set scoped DNS resolver {} -> {}",
            path.display(),
            server
        );
        fs::write(&path, format!("nameserver {server}\n"))?;
        installed.push(domain);
    }

    fs::write(
        scoped_dns_state_path(),
        serde_json::to_vec_pretty(&installed)?,
    )?;
    flush_dns_cache();
    Ok(())
}

fn cleanup_scoped_dns_resolvers() {
    let state_path = scoped_dns_state_path();
    if let Ok(data) = fs::read_to_string(&state_path) {
        if let Ok(domains) = serde_json::from_str::<Vec<String>>(&data) {
            for domain in domains {
                if domain.contains('/') || domain == "." || domain == ".." {
                    continue;
                }
                let path = Path::new("/etc/resolver").join(domain);
                helper_log!(
                    "[NulConnect][Helper][Tun] remove scoped DNS resolver {}",
                    path.display()
                );
                let _ = fs::remove_file(path);
            }
        }
    }
    let _ = fs::remove_file(state_path);
}

fn scoped_dns_state_path() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_DIR).join("tun-scoped-dns.json")
}

fn normalized_resolver_domains(domains: &[String]) -> Vec<String> {
    let mut output = Vec::new();
    for domain in domains {
        let mut normalized = domain
            .trim_matches(|ch: char| ch == '.' || ch.is_whitespace())
            .to_ascii_lowercase();
        if let Some(stripped) = normalized.strip_prefix("*.") {
            normalized = stripped.to_string();
        }
        if normalized.is_empty()
            || normalized.contains('/')
            || normalized.contains(':')
            || normalized.contains('*')
            || normalized == "local"
        {
            continue;
        }
        output.push(normalized);
    }
    output.sort();
    output.dedup();
    output
}

fn add_route_cidr(cidr: &str, gateway: &str) -> AtrResult<()> {
    let normalized = normalize_route_cidr(cidr)?;
    helper_log!(
        "[NulConnect][Helper][Tun] route add {} {}",
        normalized.route_args.join(" "),
        gateway
    );
    let mut args = vec!["-n", "add"];
    args.extend(normalized.route_args.iter().map(String::as_str));
    args.push(gateway);
    match run_command_ok("/sbin/route", &args) {
        Ok(()) => Ok(()),
        Err(err) if err.to_string().contains("File exists") => Ok(()),
        Err(err) => Err(err),
    }
}

fn delete_route_cidr(cidr: &str) {
    let Ok(normalized) = normalize_route_cidr(cidr) else {
        return;
    };
    let mut args = vec!["-n", "delete"];
    args.extend(normalized.route_args.iter().map(String::as_str));
    let _ = Command::new("/sbin/route").args(args).output();
}

struct NormalizedRoute {
    route_args: Vec<String>,
}

fn normalize_route_cidr(cidr: &str) -> AtrResult<NormalizedRoute> {
    let trimmed = cidr.trim();
    let (addr, prefix) = trimmed
        .split_once('/')
        .ok_or_else(|| AtrError::InvalidArgument(format!("invalid CIDR route: {trimmed}")))?;
    if prefix == "32" {
        return Ok(NormalizedRoute {
            route_args: vec!["-host".to_string(), addr.to_string()],
        });
    }
    Ok(NormalizedRoute {
        route_args: vec!["-net".to_string(), trimmed.to_string()],
    })
}

fn run_command_ok(program: &str, args: &[&str]) -> AtrResult<()> {
    let output = Command::new(program).args(args).output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    });
    Err(AtrError::NetworkFailed(stderr.trim().to_string()))
}

fn managed_routes_state_path() -> PathBuf {
    PathBuf::from(DEFAULT_STATE_DIR).join("tun-managed-routes.json")
}

fn wait_for_tun_setup(config: &HelperConfig) -> AtrResult<()> {
    if !config.setup_routes {
        return Ok(());
    }

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        let route_ready = config
            .managed_route_cidrs
            .iter()
            .all(|cidr| tun_route_ready_for_cidr(cidr));
        let dns_ready = scoped_dns_ready(&config.managed_domains, &config.dns_addr);

        if route_ready && dns_ready {
            helper_log!("[NulConnect][Helper][Tun] setup ready: route=true dns=true");
            return Ok(());
        }

        thread::sleep(Duration::from_millis(250));
    }

    log_tun_network_state("setup timeout");
    Err(AtrError::NetworkFailed(
        "TUN setup did not install expected managed routes/DNS".to_string(),
    ))
}

fn tun_route_ready_for_cidr(cidr: &str) -> bool {
    let Ok(probe) = route_probe_address(cidr) else {
        return false;
    };
    command_text("/sbin/route", &["-n", "get", &probe])
        .map(|text| text.contains("gateway: 10.0.0.1") || text.contains("interface: utun"))
        .unwrap_or(false)
}

fn scoped_dns_ready(domains: &[String], server: &str) -> bool {
    let domains = normalized_resolver_domains(domains);
    if domains.is_empty() {
        return true;
    }
    let expected = format!("nameserver {}", server.trim());
    domains.iter().all(|domain| {
        let path = Path::new("/etc/resolver").join(domain);
        fs::read_to_string(path)
            .map(|text| text.lines().any(|line| line.trim() == expected))
            .unwrap_or(false)
    })
}

fn route_probe_address(cidr: &str) -> AtrResult<String> {
    let trimmed = cidr.trim();
    let (addr, prefix) = trimmed
        .split_once('/')
        .ok_or_else(|| AtrError::InvalidArgument(format!("invalid CIDR route: {trimmed}")))?;
    let octets = addr
        .split('.')
        .map(|part| part.parse::<u8>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AtrError::InvalidArgument(format!("invalid IPv4 route: {trimmed}")))?;
    if octets.len() != 4 {
        return Err(AtrError::InvalidArgument(format!(
            "invalid IPv4 route: {trimmed}"
        )));
    }
    let prefix = prefix
        .parse::<u32>()
        .map_err(|_| AtrError::InvalidArgument(format!("invalid CIDR prefix: {trimmed}")))?;
    if prefix > 32 {
        return Err(AtrError::InvalidArgument(format!(
            "invalid CIDR prefix: {trimmed}"
        )));
    }

    let address = ((octets[0] as u32) << 24)
        | ((octets[1] as u32) << 16)
        | ((octets[2] as u32) << 8)
        | (octets[3] as u32);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = address & mask;
    let broadcast = network | !mask;
    let probe = if prefix >= 31 {
        address
    } else {
        let candidate = network.saturating_add(1);
        if candidate < broadcast {
            candidate
        } else {
            network
        }
    };

    Ok(format!(
        "{}.{}.{}.{}",
        (probe >> 24) & 0xff,
        (probe >> 16) & 0xff,
        (probe >> 8) & 0xff,
        probe & 0xff
    ))
}

fn command_text(program: &str, args: &[&str]) -> AtrResult<String> {
    let output = Command::new(program).args(args).output()?;
    let mut text = String::from_utf8_lossy(&output.stdout).to_string();
    if !output.stderr.is_empty() {
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    Ok(text)
}

fn remove_global_dns_state() {
    helper_log!("[NulConnect][Helper][Tun] remove State:/Network/Global/DNS");
    let Ok(mut child) = Command::new("/usr/sbin/scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    else {
        helper_log!("[NulConnect][Helper][Tun] failed to spawn scutil");
        return;
    };
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = stdin.write_all(b"remove State:/Network/Global/DNS\nquit\n");
    }
    match child.wait_with_output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            helper_log!("[NulConnect][Helper][Tun] scutil remove Global/DNS failed: {stderr}");
        }
        Err(err) => {
            helper_log!("[NulConnect][Helper][Tun] scutil remove Global/DNS wait failed: {err}");
        }
    }
}

fn flush_dns_cache() {
    helper_log!("[NulConnect][Helper][Tun] flush DNS caches");
    let _ = Command::new("/usr/bin/dscacheutil")
        .arg("-flushcache")
        .output();
    let _ = Command::new("/usr/bin/killall")
        .args(["-HUP", "mDNSResponder"])
        .output();
}

fn log_tun_network_state(label: &str) {
    helper_log!("[NulConnect][Helper][Tun][Diag] {label}");
    log_command_output(
        "global_dns",
        Command::new("/usr/sbin/scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        Some(b"show State:/Network/Global/DNS\nquit\n"),
    );
    log_command_output(
        "route_198",
        Command::new("/usr/sbin/netstat")
            .args(["-rn", "-f", "inet"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        None,
    );
    log_command_output(
        "ifconfig_utun",
        Command::new("/sbin/ifconfig")
            .args(["-a"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        None,
    );
    log_command_output(
        "route_get_tibaiot",
        Command::new("/sbin/route")
            .args(["-n", "get", "10.160.22.90"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        None,
    );
    log_command_output(
        "route_get_hpc",
        Command::new("/sbin/route")
            .args(["-n", "get", "10.70.2.174"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        None,
    );
    log_command_output(
        "dns_summary",
        Command::new("/usr/sbin/scutil")
            .arg("--dns")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
        None,
    );
}

fn log_command_output(label: &str, command: &mut Command, stdin_data: Option<&[u8]>) {
    let output = if let Some(stdin_data) = stdin_data {
        match command.spawn() {
            Ok(mut child) => {
                if let Some(stdin) = child.stdin.as_mut() {
                    let _ = stdin.write_all(stdin_data);
                }
                child.wait_with_output()
            }
            Err(err) => {
                helper_log!("[NulConnect][Helper][Tun][Diag] {label}: spawn failed: {err}");
                return;
            }
        }
    } else {
        command.output()
    };

    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let text = if stdout.trim().is_empty() {
                stderr.trim()
            } else {
                stdout.trim()
            };
            let first_lines = text.lines().take(24).collect::<Vec<_>>().join(" | ");
            helper_log!("[NulConnect][Helper][Tun][Diag] {label}: {first_lines}");
        }
        Err(err) => {
            helper_log!("[NulConnect][Helper][Tun][Diag] {label}: failed: {err}");
        }
    }
}

fn read_networksetup_list(args: &[&str]) -> AtrResult<Vec<String>> {
    let output = run_networksetup(args)?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.to_ascii_lowercase().contains("there aren't any")
                && !line.to_ascii_lowercase().contains("aren't any")
                && !line.to_ascii_lowercase().contains("not configured")
        })
        .map(ToString::to_string)
        .collect())
}

impl HelperConfig {
    fn into_vpn_engine_config(self) -> AtrResult<VpnEngineConfig> {
        let resource_bytes = base64::engine::general_purpose::STANDARD
            .decode(self.resource_bytes.as_bytes())
            .map_err(|err| AtrError::ParseFailed(format!("invalid resource_bytes: {err}")))?;
        Ok(VpnEngineConfig {
            client: self.client.into(),
            session: self.session.into(),
            resource_bytes,
            service_host: self.service_host,
            tun_name: self.tun_name.filter(|value| !value.is_empty()),
            mtu: self.mtu,
            packet_information: false,
            exit_on_fatal_error: self.exit_on_fatal_error,
        })
    }
}

impl From<HelperClientConfig> for ClientConfig {
    fn from(value: HelperClientConfig) -> Self {
        Self {
            server_host: value.server_host,
            server_port: value.server_port,
            user_agent: value.user_agent,
            connect_timeout_ms: value.connect_timeout_ms,
            io_timeout_ms: value.io_timeout_ms,
            node_probe_timeout_ms: value.node_probe_timeout_ms,
            allow_insecure_tls: value.allow_insecure_tls,
        }
    }
}

impl From<HelperSessionMaterial> for VpnSessionMaterial {
    fn from(value: HelperSessionMaterial) -> Self {
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

impl From<HelperCookieRecord> for VpnCookieRecord {
    fn from(value: HelperCookieRecord) -> Self {
        Self {
            host: value.host,
            scheme: value.scheme,
            name: value.name,
            value: value.value,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemProxySnapshot {
    saved_at_unix_secs: u64,
    services: Vec<SystemProxyServiceSnapshot>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SystemProxyServiceSnapshot {
    name: String,
    web_proxy: ProxySetting,
    secure_web_proxy: ProxySetting,
    socks_proxy: ProxySetting,
    proxy_auto_discovery_enabled: bool,
    auto_proxy_url: AutoProxyUrl,
    bypass_domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProxySetting {
    enabled: bool,
    server: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AutoProxyUrl {
    enabled: bool,
    url: Option<String>,
}

fn set_system_proxy(
    runtime: &HelperRuntime,
    endpoint: ProxyEndpoint,
    server_host: &str,
) -> AtrResult<Value> {
    validate_proxy_endpoint(&endpoint)?;
    let services = list_network_services()?;
    if services.is_empty() {
        return Err(AtrError::NotFound("no network services found".into()));
    }
    let snapshot_path = system_proxy_snapshot_path(runtime);
    let snapshot = if snapshot_path.exists() {
        read_system_proxy_snapshot(&snapshot_path)?
    } else {
        let snapshot = SystemProxySnapshot {
            saved_at_unix_secs: now_unix_secs(),
            services: services
                .iter()
                .map(|service| make_service_snapshot(service))
                .collect::<AtrResult<Vec<_>>>()?,
        };
        write_system_proxy_snapshot(&snapshot_path, &snapshot)?;
        snapshot
    };
    let exceptions = merged_exceptions(server_host, &snapshot);
    for service in &snapshot.services {
        run_networksetup(&[
            "-setwebproxy",
            &service.name,
            &endpoint.host,
            &endpoint.port.to_string(),
            "off",
        ])?;
        run_networksetup(&["-setwebproxystate", &service.name, "on"])?;
        run_networksetup(&[
            "-setsecurewebproxy",
            &service.name,
            &endpoint.host,
            &endpoint.port.to_string(),
            "off",
        ])?;
        run_networksetup(&["-setsecurewebproxystate", &service.name, "on"])?;
        run_networksetup(&[
            "-setsocksfirewallproxy",
            &service.name,
            &endpoint.host,
            &endpoint.port.to_string(),
            "off",
        ])?;
        run_networksetup(&["-setsocksfirewallproxystate", &service.name, "on"])?;
        run_networksetup(&["-setproxyautodiscovery", &service.name, "off"])?;
        run_networksetup(&["-setautoproxystate", &service.name, "off"])?;
        let mut args = vec!["-setproxybypassdomains", service.name.as_str()];
        args.extend(exceptions.iter().map(String::as_str));
        run_networksetup(&args)?;
    }
    Ok(json!({ "services": snapshot.services.len() }))
}

fn restore_system_proxy(runtime: &HelperRuntime) -> AtrResult<()> {
    let snapshot_path = system_proxy_snapshot_path(runtime);
    if !snapshot_path.exists() {
        return Ok(());
    }
    let snapshot = read_system_proxy_snapshot(&snapshot_path)?;
    let existing = list_network_services()?;
    for service in snapshot
        .services
        .iter()
        .filter(|service| existing.contains(&service.name))
    {
        restore_proxy_setting(
            &service.name,
            "-setwebproxy",
            "-setwebproxystate",
            &service.web_proxy,
        )?;
        restore_proxy_setting(
            &service.name,
            "-setsecurewebproxy",
            "-setsecurewebproxystate",
            &service.secure_web_proxy,
        )?;
        restore_proxy_setting(
            &service.name,
            "-setsocksfirewallproxy",
            "-setsocksfirewallproxystate",
            &service.socks_proxy,
        )?;
        run_networksetup(&[
            "-setproxyautodiscovery",
            &service.name,
            if service.proxy_auto_discovery_enabled {
                "on"
            } else {
                "off"
            },
        ])?;
        if let Some(url) = service
            .auto_proxy_url
            .url
            .as_ref()
            .filter(|value| !value.is_empty())
        {
            run_networksetup(&["-setautoproxyurl", &service.name, url])?;
            run_networksetup(&[
                "-setautoproxystate",
                &service.name,
                if service.auto_proxy_url.enabled {
                    "on"
                } else {
                    "off"
                },
            ])?;
        } else {
            run_networksetup(&["-setautoproxystate", &service.name, "off"])?;
        }
        let mut args = vec!["-setproxybypassdomains", service.name.as_str()];
        if service.bypass_domains.is_empty() {
            args.push("Empty");
        } else {
            args.extend(service.bypass_domains.iter().map(String::as_str));
        }
        run_networksetup(&args)?;
    }
    fs::remove_file(snapshot_path)?;
    Ok(())
}

fn validate_proxy_endpoint(endpoint: &ProxyEndpoint) -> AtrResult<()> {
    if endpoint.host != "127.0.0.1" && endpoint.host != "::1" && endpoint.host != "localhost" {
        return Err(AtrError::InvalidArgument(
            "system proxy endpoint must be loopback".into(),
        ));
    }
    if endpoint.port == 0 {
        return Err(AtrError::InvalidArgument(
            "system proxy port must be non-zero".into(),
        ));
    }
    Ok(())
}

fn system_proxy_snapshot_path(runtime: &HelperRuntime) -> PathBuf {
    runtime.state_dir.join("system-proxy-snapshot.json")
}

fn read_system_proxy_snapshot(path: &Path) -> AtrResult<SystemProxySnapshot> {
    let data = fs::read(path)?;
    serde_json::from_slice(&data).map_err(AtrError::from)
}

fn write_system_proxy_snapshot(path: &Path, snapshot: &SystemProxySnapshot) -> AtrResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(snapshot)?;
    fs::write(path, data)?;
    Ok(())
}

fn make_service_snapshot(service: &str) -> AtrResult<SystemProxyServiceSnapshot> {
    Ok(SystemProxyServiceSnapshot {
        name: service.to_string(),
        web_proxy: read_proxy_setting(&["-getwebproxy", service])?,
        secure_web_proxy: read_proxy_setting(&["-getsecurewebproxy", service])?,
        socks_proxy: read_proxy_setting(&["-getsocksfirewallproxy", service])?,
        proxy_auto_discovery_enabled: read_bool(&["-getproxyautodiscovery", service]),
        auto_proxy_url: read_auto_proxy_url(&["-getautoproxyurl", service])?,
        bypass_domains: read_bypass_domains(&["-getproxybypassdomains", service])?,
    })
}

fn restore_proxy_setting(
    service: &str,
    set_proxy: &str,
    set_state: &str,
    setting: &ProxySetting,
) -> AtrResult<()> {
    if let (true, Some(server), Some(port)) = (setting.enabled, &setting.server, setting.port) {
        run_networksetup(&[set_proxy, service, server, &port.to_string(), "off"])?;
        run_networksetup(&[set_state, service, "on"])?;
    } else {
        run_networksetup(&[set_state, service, "off"])?;
    }
    Ok(())
}

fn merged_exceptions(server_host: &str, snapshot: &SystemProxySnapshot) -> Vec<String> {
    let mut exceptions = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
        "*.local".to_string(),
        "169.254/16".to_string(),
    ];
    let trimmed = server_host.trim();
    if !trimmed.is_empty() {
        exceptions.push(trimmed.to_string());
    }
    for service in &snapshot.services {
        for domain in &service.bypass_domains {
            let trimmed = domain.trim();
            if !trimmed.is_empty() {
                exceptions.push(trimmed.to_string());
            }
        }
    }
    exceptions.sort();
    exceptions.dedup();
    exceptions
}

fn list_network_services() -> AtrResult<Vec<String>> {
    let output = run_networksetup(&["-listallnetworkservices"])?;
    Ok(output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("An asterisk") {
                None
            } else if let Some(stripped) = trimmed.strip_prefix('*') {
                Some(stripped.trim().to_string())
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect())
}

fn read_proxy_setting(args: &[&str]) -> AtrResult<ProxySetting> {
    let values = parse_key_value_output(&run_networksetup(args)?);
    Ok(ProxySetting {
        enabled: bool_value(values.get("Enabled").map(String::as_str)),
        server: normalized_string(values.get("Server").map(String::as_str)),
        port: values
            .get("Port")
            .and_then(|value| value.parse::<u16>().ok()),
    })
}

fn read_bool(args: &[&str]) -> bool {
    let Ok(output) = run_networksetup(args) else {
        return false;
    };
    let values = parse_key_value_output(&output);
    values
        .values()
        .next()
        .map(|value| bool_value(Some(value)))
        .unwrap_or_else(|| output.to_ascii_lowercase().contains("yes"))
}

fn read_auto_proxy_url(args: &[&str]) -> AtrResult<AutoProxyUrl> {
    let values = parse_key_value_output(&run_networksetup(args)?);
    Ok(AutoProxyUrl {
        enabled: bool_value(values.get("Enabled").map(String::as_str)),
        url: normalized_string(values.get("URL").map(String::as_str)),
    })
}

fn read_bypass_domains(args: &[&str]) -> AtrResult<Vec<String>> {
    let output = run_networksetup(args)?;
    Ok(output
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty()
                && !line.to_ascii_lowercase().contains("there aren")
                && !line.to_ascii_lowercase().contains("bypass domain")
        })
        .map(ToString::to_string)
        .collect())
}

fn parse_key_value_output(output: &str) -> std::collections::BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn bool_value(value: Option<&str>) -> bool {
    matches!(
        value.map(|value| value.trim().to_ascii_lowercase()),
        Some(value) if value == "yes" || value == "on" || value == "1" || value == "true"
    )
}

fn normalized_string(value: Option<&str>) -> Option<String> {
    let trimmed = value?.trim();
    if trimmed.is_empty() || trimmed == "(null)" {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn run_networksetup(args: &[&str]) -> AtrResult<String> {
    let output = Command::new("/usr/sbin/networksetup").args(args).output()?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(AtrError::NetworkFailed(if stderr.is_empty() {
            "networksetup failed".to_string()
        } else {
            stderr
        }));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
