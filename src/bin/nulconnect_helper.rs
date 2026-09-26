#[cfg(windows)]
fn main() {
    std::process::exit(nulconnect_helper::platform::windows_service_host::cli_main());
}

#[cfg(target_os = "macos")]
#[path = "../platform/macos/helper_main.rs"]
mod macos_helper;

#[cfg(target_os = "macos")]
fn main() {
    macos_helper::main();
}

#[cfg(all(not(windows), not(target_os = "macos")))]
fn main() {
    eprintln!("nulconnect-helper currently supports Windows and macOS only");
    std::process::exit(1);
}
