//! Windows Wintun platform binding.
//!
//! Wintun is deliberately loaded at runtime. The signed `wintun.dll` is an
//! application deployment artifact, while this module owns the ABI boundary
//! and adapter/session lifetimes.

use libloading::Library;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

type AdapterHandle = *mut c_void;
type SessionHandle = *mut c_void;

type CreateAdapter =
    unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> AdapterHandle;
type OpenAdapter = unsafe extern "system" fn(*const u16) -> AdapterHandle;
type CloseAdapter = unsafe extern "system" fn(AdapterHandle);
type StartSession = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
type EndSession = unsafe extern "system" fn(SessionHandle);
type GetReadWaitEvent = unsafe extern "system" fn(SessionHandle) -> isize;
type ReceivePacket = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(SessionHandle, *mut u8);
type AllocateSendPacket = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(SessionHandle, *mut u8);

pub struct WintunApi {
    _library: Library,
    pub path: PathBuf,
    create_adapter: CreateAdapter,
    open_adapter: OpenAdapter,
    close_adapter: CloseAdapter,
    start_session: StartSession,
    end_session: EndSession,
    get_read_wait_event: GetReadWaitEvent,
    receive_packet: ReceivePacket,
    release_receive_packet: ReleaseReceivePacket,
    allocate_send_packet: AllocateSendPacket,
    send_packet: SendPacket,
}

unsafe impl Send for WintunApi {}
unsafe impl Sync for WintunApi {}

impl WintunApi {
    pub fn load(path: Option<&Path>) -> Result<Arc<Self>, String> {
        let path = path
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("wintun.dll"));
        let library = unsafe { Library::new(&path) }
            .map_err(|error| format!("failed to load Wintun from {}: {error}", path.display()))?;

        unsafe fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
            unsafe { library.get::<T>(name) }
                .map(|value| *value)
                .map_err(|error| {
                    format!(
                        "Wintun entry point {} is missing: {error}",
                        String::from_utf8_lossy(name)
                    )
                })
        }

        let api = Self {
            create_adapter: unsafe { symbol(&library, b"WintunCreateAdapter\0")? },
            open_adapter: unsafe { symbol(&library, b"WintunOpenAdapter\0")? },
            close_adapter: unsafe { symbol(&library, b"WintunCloseAdapter\0")? },
            start_session: unsafe { symbol(&library, b"WintunStartSession\0")? },
            end_session: unsafe { symbol(&library, b"WintunEndSession\0")? },
            get_read_wait_event: unsafe { symbol(&library, b"WintunGetReadWaitEvent\0")? },
            receive_packet: unsafe { symbol(&library, b"WintunReceivePacket\0")? },
            release_receive_packet: unsafe { symbol(&library, b"WintunReleaseReceivePacket\0")? },
            allocate_send_packet: unsafe { symbol(&library, b"WintunAllocateSendPacket\0")? },
            send_packet: unsafe { symbol(&library, b"WintunSendPacket\0")? },
            _library: library,
            path,
        };
        Ok(Arc::new(api))
    }

    pub fn create_adapter(self: &Arc<Self>, name: &str) -> Result<WintunAdapter, String> {
        let name = wide(name);
        let kind = wide("NulConnect");
        let handle =
            unsafe { (self.create_adapter)(name.as_ptr(), kind.as_ptr(), std::ptr::null()) };
        if handle.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(183) {
                let handle = unsafe { (self.open_adapter)(name.as_ptr()) };
                if !handle.is_null() {
                    return Ok(WintunAdapter {
                        api: Arc::clone(self),
                        handle,
                    });
                }
                return Err(format!(
                    "WintunOpenAdapter failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            return Err(format!("WintunCreateAdapter failed: {error}"));
        }
        Ok(WintunAdapter {
            api: Arc::clone(self),
            handle,
        })
    }

    pub fn open_adapter(self: &Arc<Self>, name: &str) -> Result<WintunAdapter, String> {
        let name = wide(name);
        let handle = unsafe { (self.open_adapter)(name.as_ptr()) };
        if handle.is_null() {
            return Err(format!(
                "WintunOpenAdapter failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(WintunAdapter {
            api: Arc::clone(self),
            handle,
        })
    }
}

pub struct WintunAdapter {
    api: Arc<WintunApi>,
    handle: AdapterHandle,
}

unsafe impl Send for WintunAdapter {}

impl WintunAdapter {
    pub fn start_session(self: &Arc<Self>, capacity: u32) -> Result<WintunSession, String> {
        let handle = unsafe { (self.api.start_session)(self.handle, capacity) };
        if handle.is_null() {
            return Err(format!(
                "WintunStartSession failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(WintunSession {
            adapter: Arc::clone(self),
            handle,
        })
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.api.close_adapter)(self.handle) };
        }
    }
}

pub struct WintunSession {
    adapter: Arc<WintunAdapter>,
    handle: SessionHandle,
}

unsafe impl Send for WintunSession {}
unsafe impl Sync for WintunSession {}

impl WintunSession {
    pub fn read_wait_event(&self) -> isize {
        unsafe { (self.adapter.api.get_read_wait_event)(self.handle) }
    }

    pub fn receive(&self) -> Result<Option<Vec<u8>>, String> {
        let mut size = 0u32;
        let packet = unsafe { (self.adapter.api.receive_packet)(self.handle, &mut size) };
        if packet.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(259) {
                return Ok(None);
            }
            return Err(format!("WintunReceivePacket failed: {error}"));
        }
        let data = unsafe { std::slice::from_raw_parts(packet, size as usize).to_vec() };
        unsafe { (self.adapter.api.release_receive_packet)(self.handle, packet) };
        Ok(Some(data))
    }

    pub fn send(&self, packet: &[u8]) -> Result<(), String> {
        let buffer =
            unsafe { (self.adapter.api.allocate_send_packet)(self.handle, packet.len() as u32) };
        if buffer.is_null() {
            return Err(format!(
                "WintunAllocateSendPacket failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe { std::ptr::copy_nonoverlapping(packet.as_ptr(), buffer, packet.len()) };
        unsafe { (self.adapter.api.send_packet)(self.handle, buffer) };
        Ok(())
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.adapter.api.end_session)(self.handle) };
        }
    }
}

pub struct WintunTunDevice {
    session: WintunSession,
    adapter_name: String,
    local_ip: Ipv4Addr,
}

impl WintunTunDevice {
    pub fn open(
        dll_path: Option<&Path>,
        adapter_name: &str,
        local_ip: Ipv4Addr,
    ) -> Result<Self, String> {
        let api = WintunApi::load(dll_path)?;
        let adapter = Arc::new(api.create_adapter(adapter_name)?);
        let session = adapter.start_session(0x400000)?;
        configure_adapter_ipv4(adapter_name, local_ip)?;
        Ok(Self {
            session,
            adapter_name: adapter_name.to_string(),
            local_ip,
        })
    }

    pub fn receive(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self.session.receive() {
            Ok(Some(packet)) => {
                if packet.len() > buffer.len() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Wintun packet exceeds buffer",
                    ));
                }
                buffer[..packet.len()].copy_from_slice(&packet);
                Ok(packet.len())
            }
            Ok(None) => Err(std::io::ErrorKind::WouldBlock.into()),
            Err(error) => Err(std::io::Error::other(error)),
        }
    }

    pub fn send_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        self.session.send(packet).map_err(std::io::Error::other)
    }
}

impl Drop for WintunTunDevice {
    fn drop(&mut self) {
        let _ = remove_adapter_ipv4(&self.adapter_name, self.local_ip);
    }
}

fn configure_adapter_ipv4(adapter_name: &str, local_ip: Ipv4Addr) -> Result<(), String> {
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "set", "address"])
        .arg(format!("name={adapter_name}"))
        .args([
            "static",
            &local_ip.to_string(),
            "255.255.255.255",
            "none",
            "store=active",
        ])
        .output()
        .map_err(|error| format!("failed to run netsh for Wintun address: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "netsh failed to configure Wintun address: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

fn remove_adapter_ipv4(adapter_name: &str, local_ip: Ipv4Addr) -> Result<(), String> {
    let output = Command::new("netsh")
        .args(["interface", "ipv4", "delete", "address"])
        .arg(format!("name={adapter_name}"))
        .arg(format!("addr={local_ip}"))
        .output()
        .map_err(|error| format!("failed to remove Wintun address: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "netsh failed to remove Wintun address: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(())
}

#[derive(Default)]
pub struct WintunRuntime {
    adapter: Option<Arc<WintunAdapter>>,
    session: Option<WintunSession>,
    adapter_name: Option<String>,
}

impl WintunRuntime {
    pub fn start(&mut self, dll_path: Option<&Path>, adapter_name: &str) -> Result<(), String> {
        if self.session.is_some() {
            return Err("Wintun session is already running".into());
        }
        let api = WintunApi::load(dll_path)?;
        let adapter = Arc::new(api.create_adapter(adapter_name)?);
        let session = adapter.start_session(0x400000)?;
        self.adapter = Some(adapter);
        self.session = Some(session);
        self.adapter_name = Some(adapter_name.to_string());
        Ok(())
    }

    pub fn stop(&mut self) {
        self.session = None;
        self.adapter = None;
        self.adapter_name = None;
    }

    pub fn is_running(&self) -> bool {
        self.session.is_some()
    }

    pub fn adapter_name(&self) -> Option<&str> {
        self.adapter_name.as_deref()
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
