//! Service-only entry point kept for deployments that register the
//! dedicated service binary. `nulconnect-helper.exe service` is equivalent.

#[cfg(windows)]
fn main() {
    std::process::exit(nulconnect_helper::platform::windows_service_host::run_dispatcher());
}

#[cfg(not(windows))]
fn main() {
    eprintln!("nulconnect-helper-service is only available on Windows");
    std::process::exit(1);
}
