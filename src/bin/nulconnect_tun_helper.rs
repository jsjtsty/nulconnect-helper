use nulconnect_tun::{AtrError, AtrResult, TunDnsStrategy, TunLogLevel, TunProxyConfig, TunProxyEngine};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize)]
struct HelperConfig {
    proxy_url: String,
    tun_name: Option<String>,
    dns_strategy: String,
    dns_addr: String,
    virtual_dns_pool: String,
    bypass_cidrs: Vec<String>,
    mtu: u16,
    tcp_timeout_secs: u64,
    udp_timeout_secs: u64,
    max_sessions: usize,
    setup_routes: bool,
    ipv6_enabled: bool,
    packet_information: bool,
    exit_on_fatal_error: bool,
    verbosity: String,
}

#[derive(Debug, Serialize)]
struct HelperState {
    pid: u32,
    status: String,
    message: Option<String>,
    updated_at_unix_secs: u64,
    sessions: Option<usize>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> AtrResult<()> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or_else(|| AtrError::InvalidArgument("missing command".into()))?;

    match command.as_str() {
        "run" => {
            let config_path = required_path(args.next(), "config path")?;
            let state_path = required_path(args.next(), "state path")?;
            let stop_path = required_path(args.next(), "stop path")?;
            run_engine(&config_path, &state_path, &stop_path)
        }
        _ => Err(AtrError::InvalidArgument(format!(
            "unsupported command: {command}"
        ))),
    }
}

fn run_engine(config_path: &Path, state_path: &Path, stop_path: &Path) -> AtrResult<()> {
    let data = fs::read(config_path)?;
    let config: HelperConfig =
        serde_json::from_slice(&data).map_err(|err| AtrError::ParseFailed(err.to_string()))?;
    let engine = TunProxyEngine::start(config.into_tun_proxy_config()?)?;
    write_state(state_path, "running", None, None)?;

    loop {
        if stop_path.exists() {
            break;
        }
        if let Some(result) = engine.take_result() {
            match result {
                Ok(sessions) => {
                    write_state(state_path, "stopped", None, Some(sessions))?;
                    return Ok(());
                }
                Err(err) => {
                    let message = err.to_string();
                    write_state(state_path, "failed", Some(&message), None)?;
                    return Err(err);
                }
            }
        }
        thread::sleep(Duration::from_millis(500));
    }

    engine.stop()?;
    write_state(state_path, "stopped", None, None)?;
    Ok(())
}

fn required_path(value: Option<String>, name: &str) -> AtrResult<PathBuf> {
    value
        .map(PathBuf::from)
        .ok_or_else(|| AtrError::InvalidArgument(format!("missing {name}")))
}

fn write_state(
    path: &Path,
    status: &str,
    message: Option<&str>,
    sessions: Option<usize>,
) -> AtrResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let state = HelperState {
        pid: std::process::id(),
        status: status.to_string(),
        message: message.map(ToString::to_string),
        updated_at_unix_secs: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        sessions,
    };
    let data =
        serde_json::to_vec_pretty(&state).map_err(|err| AtrError::Internal(err.to_string()))?;
    fs::write(path, data)?;
    Ok(())
}

impl HelperConfig {
    fn into_tun_proxy_config(self) -> AtrResult<TunProxyConfig> {
        Ok(TunProxyConfig {
            proxy_url: self.proxy_url,
            tun_name: self.tun_name.filter(|value| !value.is_empty()),
            dns_strategy: parse_dns_strategy(&self.dns_strategy)?,
            dns_addr: self.dns_addr,
            virtual_dns_pool: self.virtual_dns_pool,
            bypass_cidrs: self.bypass_cidrs,
            mtu: self.mtu,
            tcp_timeout_secs: self.tcp_timeout_secs,
            udp_timeout_secs: self.udp_timeout_secs,
            max_sessions: self.max_sessions,
            setup_routes: self.setup_routes,
            ipv6_enabled: self.ipv6_enabled,
            packet_information: self.packet_information,
            exit_on_fatal_error: self.exit_on_fatal_error,
            verbosity: parse_log_level(&self.verbosity)?,
        })
    }
}

fn parse_dns_strategy(value: &str) -> AtrResult<TunDnsStrategy> {
    match value {
        "virtual" => Ok(TunDnsStrategy::Virtual),
        "over-tcp" => Ok(TunDnsStrategy::OverTcp),
        "direct" => Ok(TunDnsStrategy::Direct),
        _ => Err(AtrError::InvalidArgument(format!(
            "invalid dns strategy: {value}"
        ))),
    }
}

fn parse_log_level(value: &str) -> AtrResult<TunLogLevel> {
    match value {
        "off" => Ok(TunLogLevel::Off),
        "error" => Ok(TunLogLevel::Error),
        "warn" => Ok(TunLogLevel::Warn),
        "info" => Ok(TunLogLevel::Info),
        "debug" => Ok(TunLogLevel::Debug),
        "trace" => Ok(TunLogLevel::Trace),
        _ => Err(AtrError::InvalidArgument(format!(
            "invalid log level: {value}"
        ))),
    }
}
