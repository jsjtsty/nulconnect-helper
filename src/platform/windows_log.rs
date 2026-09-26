//! File logging and on-disk locations for the Windows helper.
//!
//! Everything lives next to the installed executable (under Program Files),
//! which only administrators can write. `%ProgramData%` is deliberately not
//! used: standard users can create files there, which would let them plant
//! links that a SYSTEM process later writes through.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

static LOG_LOCK: Mutex<()> = Mutex::new(());

pub fn executable_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn state_dir() -> PathBuf {
    executable_dir().join("state")
}

pub fn log_dir() -> PathBuf {
    executable_dir().join("logs")
}

pub fn log(message: &str) {
    let _guard = LOG_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    let line = format!("{} {message}\r\n", timestamp());
    eprint!("{line}");
    let dir = log_dir();
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    let path = dir.join("helper.log");
    if fs::metadata(&path).is_ok_and(|metadata| metadata.len() > MAX_LOG_BYTES) {
        let _ = fs::rename(&path, dir.join("helper.old.log"));
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = file.write_all(line.as_bytes());
    }
}

fn timestamp() -> String {
    let mut now = SYSTEMTIME::default();
    unsafe { GetLocalTime(&mut now) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond, now.wMilliseconds
    )
}

#[macro_export]
macro_rules! helper_log {
    ($($arg:tt)*) => {
        $crate::platform::windows_log::log(&format!($($arg)*))
    };
}
