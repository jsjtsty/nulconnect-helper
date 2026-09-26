//! Windows Service entry point, console mode and self-installation.
//!
//! `nulconnect-helper.exe` subcommands:
//!
//! * `service` — run under the Service Control Manager (the registered
//!   command line).
//! * `serve` — run the IPC server in the console for debugging (elevated).
//! * `install [--result <file>]` — copy the helper and `wintun.dll` into
//!   `%ProgramFiles%\NulConnect\Helper`, register/update and start the
//!   service. The desktop app runs this elevated through UAC; the optional
//!   result file receives a JSON outcome because an elevated child's output
//!   cannot be captured by the unelevated parent.
//! * `uninstall [--result <file>]` — stop and remove the service and files.
//! * `version` — print the helper version.

use crate::platform::windows::wintun_path;
use crate::platform::windows_ipc::{self, WindowsRuntime};
use serde_json::json;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

pub const SERVICE_NAME: &str = "NulConnectHelper";
const SERVICE_DISPLAY_NAME: &str = "NulConnect Helper";
const SERVICE_DESCRIPTION: &str =
    "Provides VPN tunnel, routing and DNS configuration for NulConnect.";
const HELPER_EXE_NAME: &str = "nulconnect-helper.exe";

pub fn cli_main() -> i32 {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let command = args
        .first()
        .and_then(|arg| arg.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let result_path = option_value(&args, "--result");
    match command.as_str() {
        "service" => run_dispatcher(),
        "serve" => run_console(),
        "version" | "--version" | "-v" => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            0
        }
        "install" => report(result_path, install()),
        "uninstall" => report(result_path, uninstall()),
        "" => {
            // Started by the SCM from an older registration without the
            // `service` argument, or double-clicked by a user.
            if service_dispatcher::start(SERVICE_NAME, ffi_service_main).is_ok() {
                0
            } else {
                print_usage();
                2
            }
        }
        _ => {
            print_usage();
            2
        }
    }
}

fn print_usage() {
    eprintln!(
        "nulconnect-helper {}\nusage: nulconnect-helper <service|serve|install|uninstall|version> [--result <file>]",
        env!("CARGO_PKG_VERSION")
    );
}

fn option_value(args: &[OsString], name: &str) -> Option<PathBuf> {
    let index = args.iter().position(|arg| arg == OsStr::new(name))?;
    args.get(index + 1).map(PathBuf::from)
}

fn report(result_path: Option<PathBuf>, result: Result<(), String>) -> i32 {
    let (code, body) = match &result {
        Ok(()) => (
            0,
            json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }),
        ),
        Err(message) => {
            eprintln!("{message}");
            (1, json!({ "ok": false, "message": message }))
        }
    };
    if let Some(path) = result_path {
        let _ = std::fs::write(path, body.to_string());
    }
    code
}

pub fn run_dispatcher() -> i32 {
    match service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("NulConnect service dispatcher failed: {error}");
            1
        }
    }
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        crate::helper_log!("[Service] failed: {error}");
    }
}

fn run_service() -> Result<(), windows_service::Error> {
    let (stop_sender, stop_receiver) = mpsc::channel();
    let stop_sender = Mutex::new(stop_sender);
    let handler = move |control_event| match control_event {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            let _ = stop_sender.lock().unwrap().send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
    let set_state = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| {
        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: wait,
            process_id: None,
        });
    };
    set_state(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(10),
    );
    crate::helper_log!("[Service] starting version {}", env!("CARGO_PKG_VERSION"));

    let runtime = Arc::new(WindowsRuntime::default());
    runtime.cleanup_leftovers();
    let stop = Arc::new(AtomicBool::new(false));
    let server = {
        let runtime = Arc::clone(&runtime);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            if let Err(error) = windows_ipc::serve(runtime, false, || stop.load(Ordering::SeqCst)) {
                crate::helper_log!("[Service] pipe server failed: {error}");
            }
        })
    };
    set_state(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        Duration::default(),
    );

    let _ = stop_receiver.recv();
    set_state(
        ServiceState::StopPending,
        ServiceControlAccept::empty(),
        Duration::from_secs(20),
    );
    crate::helper_log!("[Service] stopping");
    stop.store(true, Ordering::SeqCst);
    runtime.shutdown();
    windows_ipc::wake_server();
    let _ = server.join();
    set_state(
        ServiceState::Stopped,
        ServiceControlAccept::empty(),
        Duration::default(),
    );
    Ok(())
}

fn run_console() -> i32 {
    crate::helper_log!("[Console] serving version {}", env!("CARGO_PKG_VERSION"));
    let runtime = Arc::new(WindowsRuntime::default());
    runtime.cleanup_leftovers();
    match windows_ipc::serve(Arc::clone(&runtime), true, || false) {
        Ok(()) => {
            runtime.shutdown();
            0
        }
        Err(error) => {
            eprintln!("pipe server failed: {error}");
            runtime.shutdown();
            1
        }
    }
}

pub fn install_dir() -> PathBuf {
    let base = std::env::var_os("ProgramW6432")
        .or_else(|| std::env::var_os("ProgramFiles"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    base.join("NulConnect").join("Helper")
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn copy_with_retry(source: &Path, target: &Path) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match std::fs::copy(source, target) {
            Ok(_) => return Ok(()),
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(250));
            }
            Err(error) => {
                return Err(format!(
                    "failed to copy {} to {}: {error}",
                    source.display(),
                    target.display()
                ));
            }
        }
    }
}

fn wait_for_state(
    service: &windows_service::service::Service,
    state: ServiceState,
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match service.query_status() {
            Ok(status) if status.current_state == state => return true,
            Ok(_) => thread::sleep(Duration::from_millis(200)),
            Err(_) => return false,
        }
    }
    false
}

fn install() -> Result<(), String> {
    let source_exe = std::env::current_exe().map_err(|error| error.to_string())?;
    let source_wintun = wintun_path();
    if !source_wintun.exists() {
        return Err(format!("{} is missing", source_wintun.display()));
    }
    let target_dir = install_dir();
    let target_exe = target_dir.join(HELPER_EXE_NAME);

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|error| format!("cannot open the Service Control Manager: {error}"))?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG;
    let existing = manager.open_service(SERVICE_NAME, access).ok();
    if let Some(service) = &existing
        && let Ok(status) = service.query_status()
        && status.current_state != ServiceState::Stopped
    {
        let _ = service.stop();
        if !wait_for_state(service, ServiceState::Stopped, Duration::from_secs(30)) {
            return Err("the existing NulConnect Helper service did not stop".into());
        }
    }

    if !same_path(&source_exe, &target_exe) {
        std::fs::create_dir_all(&target_dir)
            .map_err(|error| format!("failed to create {}: {error}", target_dir.display()))?;
        copy_with_retry(&source_exe, &target_exe)?;
        copy_with_retry(&source_wintun, &target_dir.join("wintun.dll"))?;
    }

    let info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: target_exe.clone(),
        launch_arguments: vec![OsString::from("service")],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let service = match existing {
        Some(service) => {
            service
                .change_config(&info)
                .map_err(|error| format!("failed to update the service: {error}"))?;
            service
        }
        None => manager
            .create_service(&info, access)
            .map_err(|error| format!("failed to create the service: {error}"))?,
    };
    let _ = service.set_description(SERVICE_DESCRIPTION);
    let _ = service.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(2),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
        ]),
    });
    service
        .start::<&OsStr>(&[])
        .map_err(|error| format!("failed to start the service: {error}"))?;
    if !wait_for_state(&service, ServiceState::Running, Duration::from_secs(20)) {
        return Err("the NulConnect Helper service did not start in time".into());
    }
    windows_ipc::call(
        &json!({ "id": "install", "command": "version" }),
        Duration::from_secs(10),
    )
    .map_err(|error| format!("the service started but its pipe is unavailable: {error}"))?;
    Ok(())
}

fn uninstall() -> Result<(), String> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|error| format!("cannot open the Service Control Manager: {error}"))?;
    if let Ok(service) = manager.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        if let Ok(status) = service.query_status()
            && status.current_state != ServiceState::Stopped
        {
            let _ = service.stop();
            wait_for_state(&service, ServiceState::Stopped, Duration::from_secs(30));
        }
        service
            .delete()
            .map_err(|error| format!("failed to delete the service: {error}"))?;
    }
    let target_dir = install_dir();
    let current = std::env::current_exe().ok();
    let deadline = Instant::now() + Duration::from_secs(10);
    for name in [HELPER_EXE_NAME, "wintun.dll"] {
        let path = target_dir.join(name);
        if current
            .as_deref()
            .is_some_and(|current| same_path(current, &path))
        {
            continue;
        }
        while path.exists() && std::fs::remove_file(&path).is_err() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(250));
        }
    }
    let _ = std::fs::remove_dir_all(target_dir.join("state"));
    let _ = std::fs::remove_dir(&target_dir);
    if let Some(parent) = target_dir.parent() {
        let _ = std::fs::remove_dir(parent);
    }
    Ok(())
}
