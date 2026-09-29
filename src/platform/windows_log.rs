//! File logging and on-disk locations for the Windows helper.
//!
//! Logs and state live in `%ProgramData%\NulConnect`. The helper runs as
//! SYSTEM, and standard users may create files under ProgramData, so the
//! directories are created here with an ACL that only lets administrators and
//! SYSTEM write (users can read), and are never used if they turn out to be
//! owned by someone else or to be links.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, LocalFree, SYSTEMTIME};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{CreateDirectoryW, FILE_ATTRIBUTE_REPARSE_POINT};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;
/// SYSTEM and Administrators: full control; Users: read and traverse.
const DIRECTORY_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";

static LOG_LOCK: Mutex<()> = Mutex::new(());
static DATA_DIR: OnceLock<Option<PathBuf>> = OnceLock::new();

pub fn executable_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn program_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("NulConnect")
}

/// `%ProgramData%\NulConnect`, created and locked down on first use; `None`
/// when it cannot be made safe.
fn data_dir() -> Option<&'static Path> {
    DATA_DIR
        .get_or_init(|| {
            let root = program_data_dir();
            let ok = secure_directory(&root)
                && secure_directory(&root.join("Logs"))
                && secure_directory(&root.join("State"));
            ok.then_some(root)
        })
        .as_deref()
}

pub fn state_dir() -> PathBuf {
    // Falls back to the install directory, which only administrators can write.
    data_dir()
        .map(|dir| dir.join("State"))
        .unwrap_or_else(|| executable_dir().join("state"))
}

pub fn log_dir() -> PathBuf {
    data_dir()
        .map(|dir| dir.join("Logs"))
        .unwrap_or_else(|| executable_dir().join("logs"))
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn secure_directory(path: &Path) -> bool {
    if trusted_existing(path) == Some(false) {
        // Something we did not create is in the way; move it aside.
        let mut aside = path.as_os_str().to_owned();
        aside.push(format!(".untrusted-{}", std::process::id()));
        if fs::rename(path, PathBuf::from(aside)).is_err() {
            return false;
        }
    }
    if fs::symlink_metadata(path).is_err() && !create_protected(path) {
        return false;
    }
    trusted_existing(path) == Some(true)
}

fn create_protected(path: &Path) -> bool {
    let sddl: Vec<u16> = DIRECTORY_SDDL.encode_utf16().chain(Some(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let converted = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if converted == 0 {
        return false;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let created = unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } != 0
        || unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    unsafe { LocalFree(descriptor) };
    created
}

/// `None` when the path does not exist, otherwise whether it is a real
/// directory owned by SYSTEM or Administrators.
fn trusted_existing(path: &Path) -> Option<bool> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Some(false);
    }
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Some(false);
    }
    let trusted = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid) != 0
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
    };
    unsafe { LocalFree(descriptor) };
    Some(trusted)
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
