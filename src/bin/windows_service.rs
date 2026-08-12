use nulconnect_helper::platform::windows_ipc::{self, WindowsRuntime};
use std::ffi::OsString;
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "NulConnectHelper";

fn main() {
    if let Err(error) = run() {
        eprintln!("NulConnect Windows Service dispatcher failed: {error}");
        std::process::exit(1);
    }
}

pub fn run() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

windows_service::define_windows_service!(ffi_service_main, service_main);

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = run_service() {
        eprintln!("NulConnect Windows Service failed: {error}");
    }
}

fn run_service() -> Result<(), windows_service::Error> {
    let (stop_sender, stop_receiver) = mpsc::channel();
    let handler = move |control_event| match control_event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_sender.send(());
            ServiceControlHandlerResult::NoError
        }
        _ => ServiceControlHandlerResult::NoError,
    };
    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    service_loop(stop_receiver);

    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;
    Ok(())
}

fn service_loop(stop_receiver: Receiver<()>) {
    let runtime = Arc::new(Mutex::new(WindowsRuntime::default()));
    let server_runtime = Arc::clone(&runtime);
    let server = thread::spawn(move || {
        if let Err(error) = windows_ipc::serve(server_runtime, || false) {
            eprintln!("NulConnect Named Pipe server failed: {error}");
        }
    });
    let _ = stop_receiver.recv();
    let _ = windows_ipc::request_shutdown();
    let _ = server.join();
}
