#[cfg(windows)]
#[macro_use]
pub mod windows_log;

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub mod windows_ipc;

#[cfg(windows)]
pub mod windows_net;

#[cfg(windows)]
pub mod windows_service_host;
