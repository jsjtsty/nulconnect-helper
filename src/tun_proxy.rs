use crate::error::{AtrError, AtrResult};
#[cfg(feature = "tun2proxy")]
use std::sync::{Arc, Mutex, mpsc};
#[cfg(feature = "tun2proxy")]
use std::thread;

#[derive(Debug, Clone, Copy)]
pub enum TunDnsStrategy {
    Virtual,
    OverTcp,
    Direct,
}

#[derive(Debug, Clone, Copy)]
pub enum TunLogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone)]
pub struct TunProxyConfig {
    pub proxy_url: String,
    pub tun_name: Option<String>,
    pub dns_strategy: TunDnsStrategy,
    pub dns_addr: String,
    pub virtual_dns_pool: String,
    pub bypass_cidrs: Vec<String>,
    pub mtu: u16,
    pub tcp_timeout_secs: u64,
    pub udp_timeout_secs: u64,
    pub max_sessions: usize,
    pub setup_routes: bool,
    pub ipv6_enabled: bool,
    pub packet_information: bool,
    pub exit_on_fatal_error: bool,
    pub verbosity: TunLogLevel,
}

impl Default for TunProxyConfig {
    fn default() -> Self {
        Self {
            proxy_url: "socks5://127.0.0.1:1080".to_string(),
            tun_name: None,
            dns_strategy: TunDnsStrategy::Virtual,
            dns_addr: "8.8.8.8".to_string(),
            virtual_dns_pool: "198.18.0.0/15".to_string(),
            bypass_cidrs: Vec::new(),
            mtu: 1500,
            tcp_timeout_secs: 600,
            udp_timeout_secs: 30,
            max_sessions: 200,
            setup_routes: false,
            ipv6_enabled: false,
            packet_information: cfg!(any(target_os = "ios", target_os = "macos")),
            exit_on_fatal_error: false,
            verbosity: TunLogLevel::Warn,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunProxyStatus {
    Running,
    Stopped,
}

#[derive(Debug)]
pub struct TunProxyEngine {
    #[cfg(feature = "tun2proxy")]
    inner: TunProxyEngineImpl,
}

#[cfg(feature = "tun2proxy")]
#[derive(Debug)]
struct TunProxyEngineImpl {
    shutdown: tun2proxy::CancellationToken,
    result: Arc<Mutex<Option<AtrResult<usize>>>>,
    worker: Mutex<Option<thread::JoinHandle<()>>>,
}

impl TunProxyEngine {
    pub fn start(config: TunProxyConfig) -> AtrResult<Self> {
        start_tun_proxy_engine(config)
    }

    pub fn stop(&self) -> AtrResult<()> {
        stop_tun_proxy_engine(self)
    }

    pub fn cancel(&self) {
        cancel_tun_proxy_engine(self)
    }

    pub fn status(&self) -> TunProxyStatus {
        tun_proxy_engine_status(self)
    }

    pub fn take_result(&self) -> Option<AtrResult<usize>> {
        tun_proxy_engine_take_result(self)
    }
}

impl Drop for TunProxyEngine {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(feature = "tun2proxy")]
fn start_tun_proxy_engine(config: TunProxyConfig) -> AtrResult<TunProxyEngine> {
    let args = build_tun2proxy_args(&config)?;
    let shutdown = tun2proxy::CancellationToken::new();
    let result = Arc::new(Mutex::new(None));
    let thread_result = result.clone();
    let thread_shutdown = shutdown.clone();
    let mtu = config.mtu;
    let packet_information = config.packet_information;
    let (startup_tx, startup_rx) = mpsc::channel();

    let worker = thread::Builder::new()
        .name("nulconnect-tun2proxy".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("nulconnect-tun2proxy-rt")
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    let error =
                        AtrError::Internal(format!("failed to create tun2proxy runtime: {err}"));
                    let _ = startup_tx.send(Err(error.clone()));
                    *thread_result.lock().unwrap() = Some(Err(error));
                    return;
                }
            };
            let _ = startup_tx.send(Ok(()));
            let outcome = runtime.block_on(async move {
                tun2proxy::general_run_async(args, mtu, packet_information, thread_shutdown).await
            });
            let result = outcome.map_err(|err| AtrError::NetworkFailed(err.to_string()));
            *thread_result.lock().unwrap() = Some(result);
        })
        .map_err(|err| AtrError::Internal(format!("failed to start tun2proxy worker: {err}")))?;

    match startup_rx.recv() {
        Ok(Ok(())) => Ok(TunProxyEngine {
            inner: TunProxyEngineImpl {
                shutdown,
                result,
                worker: Mutex::new(Some(worker)),
            },
        }),
        Ok(Err(err)) => {
            let _ = worker.join();
            Err(err)
        }
        Err(err) => {
            let _ = worker.join();
            Err(AtrError::Internal(format!(
                "tun2proxy worker failed during startup: {err}"
            )))
        }
    }
}

#[cfg(not(feature = "tun2proxy"))]
fn start_tun_proxy_engine(_config: TunProxyConfig) -> AtrResult<TunProxyEngine> {
    Err(AtrError::Unsupported(
        "nulconnect-tun was built without tun2proxy support".into(),
    ))
}

#[cfg(feature = "tun2proxy")]
fn stop_tun_proxy_engine(engine: &TunProxyEngine) -> AtrResult<()> {
    engine.inner.shutdown.cancel();
    join_worker(engine);
    Ok(())
}

#[cfg(not(feature = "tun2proxy"))]
fn stop_tun_proxy_engine(_engine: &TunProxyEngine) -> AtrResult<()> {
    Ok(())
}

#[cfg(feature = "tun2proxy")]
fn cancel_tun_proxy_engine(engine: &TunProxyEngine) {
    engine.inner.shutdown.cancel();
}

#[cfg(not(feature = "tun2proxy"))]
fn cancel_tun_proxy_engine(_engine: &TunProxyEngine) {}

#[cfg(feature = "tun2proxy")]
fn tun_proxy_engine_status(engine: &TunProxyEngine) -> TunProxyStatus {
    if engine.inner.result.lock().unwrap().is_some() {
        TunProxyStatus::Stopped
    } else {
        TunProxyStatus::Running
    }
}

#[cfg(not(feature = "tun2proxy"))]
fn tun_proxy_engine_status(_engine: &TunProxyEngine) -> TunProxyStatus {
    TunProxyStatus::Stopped
}

#[cfg(feature = "tun2proxy")]
fn tun_proxy_engine_take_result(engine: &TunProxyEngine) -> Option<AtrResult<usize>> {
    let result = engine.inner.result.lock().unwrap().take();
    if result.is_some() {
        join_worker_if_finished(engine);
    }
    result
}

#[cfg(not(feature = "tun2proxy"))]
fn tun_proxy_engine_take_result(_engine: &TunProxyEngine) -> Option<AtrResult<usize>> {
    None
}

#[cfg(feature = "tun2proxy")]
fn join_worker_if_finished(engine: &TunProxyEngine) {
    if engine.inner.result.lock().unwrap().is_none() {
        return;
    }
    join_worker(engine);
}

#[cfg(feature = "tun2proxy")]
fn join_worker(engine: &TunProxyEngine) {
    if let Some(worker) = engine.inner.worker.lock().unwrap().take() {
        let _ = worker.join();
    }
}

#[cfg(feature = "tun2proxy")]
fn build_tun2proxy_args(config: &TunProxyConfig) -> AtrResult<tun2proxy::Args> {
    use clap::Parser;

    let mut argv = vec![
        "nulconnect-tun2proxy".to_string(),
        "--proxy".to_string(),
        config.proxy_url.clone(),
        "--dns".to_string(),
        dns_strategy_arg(config.dns_strategy).to_string(),
        "--dns-addr".to_string(),
        config.dns_addr.clone(),
        "--virtual-dns-pool".to_string(),
        config.virtual_dns_pool.clone(),
        "--tcp-timeout".to_string(),
        config.tcp_timeout_secs.to_string(),
        "--udp-timeout".to_string(),
        config.udp_timeout_secs.to_string(),
        "--max-sessions".to_string(),
        config.max_sessions.to_string(),
        "--verbosity".to_string(),
        log_level_arg(config.verbosity).to_string(),
    ];

    if let Some(tun_name) = config.tun_name.as_ref().filter(|value| !value.is_empty()) {
        argv.push("--tun".to_string());
        argv.push(tun_name.clone());
    }
    if config.setup_routes {
        argv.push("--setup".to_string());
    }
    if config.ipv6_enabled {
        argv.push("--ipv6-enabled".to_string());
    }
    if config.exit_on_fatal_error {
        argv.push("--exit-on-fatal-error".to_string());
    }
    for cidr in &config.bypass_cidrs {
        if cidr.is_empty() {
            continue;
        }
        argv.push("--bypass".to_string());
        argv.push(cidr.clone());
    }

    tun2proxy::Args::try_parse_from(argv).map_err(|err| AtrError::InvalidArgument(err.to_string()))
}

#[cfg(feature = "tun2proxy")]
fn dns_strategy_arg(strategy: TunDnsStrategy) -> &'static str {
    match strategy {
        TunDnsStrategy::Virtual => "virtual",
        TunDnsStrategy::OverTcp => "over-tcp",
        TunDnsStrategy::Direct => "direct",
    }
}

#[cfg(feature = "tun2proxy")]
fn log_level_arg(level: TunLogLevel) -> &'static str {
    match level {
        TunLogLevel::Off => "off",
        TunLogLevel::Error => "error",
        TunLogLevel::Warn => "warn",
        TunLogLevel::Info => "info",
        TunLogLevel::Debug => "debug",
        TunLogLevel::Trace => "trace",
    }
}
