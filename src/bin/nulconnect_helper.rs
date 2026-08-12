#[cfg(windows)]
mod windows_service;

#[cfg(windows)]
fn main() {
    if let Err(error) = windows_service::run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
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
