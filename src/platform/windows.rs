//! Windows Wintun platform binding.
//!
//! Wintun is deliberately loaded at runtime. The signed `wintun.dll` is an
//! application deployment artifact that must sit next to the helper
//! executable; this module owns the ABI boundary and adapter/session
//! lifetimes.

use crate::platform::windows_log::executable_dir;
use crate::platform::windows_net;
use libloading::Library;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::core::GUID;

type AdapterHandle = *mut c_void;
type SessionHandle = *mut c_void;

type CreateAdapter =
    unsafe extern "system" fn(*const u16, *const u16, *const GUID) -> AdapterHandle;
type OpenAdapter = unsafe extern "system" fn(*const u16) -> AdapterHandle;
type CloseAdapter = unsafe extern "system" fn(AdapterHandle);
type GetAdapterLuid = unsafe extern "system" fn(AdapterHandle, *mut u64);
type StartSession = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
type EndSession = unsafe extern "system" fn(SessionHandle);
type GetReadWaitEvent = unsafe extern "system" fn(SessionHandle) -> *mut c_void;
type ReceivePacket = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
type ReleaseReceivePacket = unsafe extern "system" fn(SessionHandle, *mut u8);
type AllocateSendPacket = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(SessionHandle, *mut u8);

/// A stable adapter GUID keeps Windows from creating a new network profile
/// ("NulConnect 2", "NulConnect 3", ...) every time the tunnel starts.
const ADAPTER_GUID: GUID = GUID {
    data1: 0x6e75_6c43,
    data2: 0x6f6e,
    data3: 0x4e43,
    data4: [0x9a, 0x51, 0x4e, 0x75, 0x6c, 0x54, 0x75, 0x6e],
};

const ERROR_NO_MORE_ITEMS: i32 = 259;
const RING_CAPACITY: u32 = 0x40_0000;
const READ_WAIT_MS: u32 = 100;

/// LUID of the adapter owned by the running engine, or 0. The IPC runtime
/// reads it after the engine has started to install routes on the tunnel.
static ACTIVE_ADAPTER_LUID: AtomicU64 = AtomicU64::new(0);

pub fn active_adapter_luid() -> Option<u64> {
    match ACTIVE_ADAPTER_LUID.load(Ordering::SeqCst) {
        0 => None,
        luid => Some(luid),
    }
}

static ACTIVE_ADAPTER_IP: AtomicU32 = AtomicU32::new(0);

pub fn active_adapter_ip() -> Option<Ipv4Addr> {
    match ACTIVE_ADAPTER_IP.load(Ordering::SeqCst) {
        0 => None,
        ip => Some(Ipv4Addr::from(ip)),
    }
}

pub fn wintun_path() -> PathBuf {
    executable_dir().join("wintun.dll")
}

pub struct WintunApi {
    _library: Library,
    create_adapter: CreateAdapter,
    open_adapter: OpenAdapter,
    close_adapter: CloseAdapter,
    get_adapter_luid: GetAdapterLuid,
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
    pub fn load() -> Result<Arc<Self>, String> {
        // Load by absolute path so the DLL search order can never pick up a
        // planted wintun.dll from the working directory or PATH.
        let path = wintun_path();
        let library = unsafe { Library::new(&path) }
            .map_err(|error| format!("failed to load Wintun from {}: {error}", path.display()))?;

        unsafe fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, String> {
            unsafe { library.get::<T>(name) }
                .map(|value| *value)
                .map_err(|error| {
                    format!(
                        "Wintun entry point {} is missing: {error}",
                        String::from_utf8_lossy(&name[..name.len() - 1])
                    )
                })
        }

        let api = Self {
            create_adapter: unsafe { symbol(&library, b"WintunCreateAdapter\0")? },
            open_adapter: unsafe { symbol(&library, b"WintunOpenAdapter\0")? },
            close_adapter: unsafe { symbol(&library, b"WintunCloseAdapter\0")? },
            get_adapter_luid: unsafe { symbol(&library, b"WintunGetAdapterLUID\0")? },
            start_session: unsafe { symbol(&library, b"WintunStartSession\0")? },
            end_session: unsafe { symbol(&library, b"WintunEndSession\0")? },
            get_read_wait_event: unsafe { symbol(&library, b"WintunGetReadWaitEvent\0")? },
            receive_packet: unsafe { symbol(&library, b"WintunReceivePacket\0")? },
            release_receive_packet: unsafe { symbol(&library, b"WintunReleaseReceivePacket\0")? },
            allocate_send_packet: unsafe { symbol(&library, b"WintunAllocateSendPacket\0")? },
            send_packet: unsafe { symbol(&library, b"WintunSendPacket\0")? },
            _library: library,
        };
        Ok(Arc::new(api))
    }

    /// Reuses an adapter left behind by a crashed run, otherwise creates one.
    pub fn open_or_create_adapter(self: &Arc<Self>, name: &str) -> Result<WintunAdapter, String> {
        let wide_name = wide(name);
        let handle = unsafe { (self.open_adapter)(wide_name.as_ptr()) };
        if !handle.is_null() {
            crate::helper_log!("[Wintun] reusing existing adapter {name}");
            return Ok(WintunAdapter {
                api: Arc::clone(self),
                handle,
            });
        }
        let kind = wide("NulConnect");
        let handle =
            unsafe { (self.create_adapter)(wide_name.as_ptr(), kind.as_ptr(), &ADAPTER_GUID) };
        if handle.is_null() {
            return Err(format!(
                "WintunCreateAdapter failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        crate::helper_log!("[Wintun] created adapter {name}");
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
unsafe impl Sync for WintunAdapter {}

impl WintunAdapter {
    pub fn luid(&self) -> u64 {
        let mut luid = 0u64;
        unsafe { (self.api.get_adapter_luid)(self.handle, &mut luid) };
        luid
    }

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
    fn read_wait_event(&self) -> *mut c_void {
        unsafe { (self.adapter.api.get_read_wait_event)(self.handle) }
    }

    /// Copies the next packet into `buffer`. `Ok(None)` means the ring is
    /// currently empty.
    fn receive_into(&self, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
        let mut size = 0u32;
        let packet = unsafe { (self.adapter.api.receive_packet)(self.handle, &mut size) };
        if packet.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_ITEMS) {
                return Ok(None);
            }
            return Err(std::io::Error::other(format!(
                "WintunReceivePacket failed: {error}"
            )));
        }
        let size = size as usize;
        let result = if size > buffer.len() {
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Wintun packet exceeds buffer",
            ))
        } else {
            unsafe { std::ptr::copy_nonoverlapping(packet, buffer.as_mut_ptr(), size) };
            Ok(Some(size))
        };
        unsafe { (self.adapter.api.release_receive_packet)(self.handle, packet) };
        result
    }

    fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        let buffer =
            unsafe { (self.adapter.api.allocate_send_packet)(self.handle, packet.len() as u32) };
        if buffer.is_null() {
            return Err(std::io::Error::other(format!(
                "WintunAllocateSendPacket failed: {}",
                std::io::Error::last_os_error()
            )));
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
    // Field order matters: the session must end before the adapter closes.
    session: WintunSession,
    adapter: Arc<WintunAdapter>,
    read_event: usize,
    luid: u64,
    local_ip: Ipv4Addr,
}

impl WintunTunDevice {
    pub fn open(adapter_name: &str, local_ip: Ipv4Addr, mtu: u16) -> Result<Self, String> {
        let api = WintunApi::load()?;
        let adapter = Arc::new(api.open_or_create_adapter(adapter_name)?);
        let luid = adapter.luid();
        windows_net::configure_tunnel_interface(luid, local_ip, mtu)?;
        let session = adapter.start_session(RING_CAPACITY)?;
        let read_event = session.read_wait_event() as usize;
        ACTIVE_ADAPTER_LUID.store(luid, Ordering::SeqCst);
        ACTIVE_ADAPTER_IP.store(u32::from(local_ip), Ordering::SeqCst);
        crate::helper_log!("[Wintun] session started luid={luid:#x} local_ip={local_ip} mtu={mtu}");
        Ok(Self {
            session,
            adapter,
            read_event,
            luid,
            local_ip,
        })
    }

    /// Returns `Ok(0)` when nothing arrived within the wait window so the
    /// caller can re-check its shutdown flag without spinning.
    pub fn receive(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if let Some(size) = self.session.receive_into(buffer)? {
            return Ok(size);
        }
        match unsafe { WaitForSingleObject(self.read_event as *mut c_void, READ_WAIT_MS) } {
            WAIT_OBJECT_0 | WAIT_TIMEOUT => {}
            _ => return Err(std::io::Error::last_os_error()),
        }
        Ok(self.session.receive_into(buffer)?.unwrap_or(0))
    }

    pub fn send_packet(&self, packet: &[u8]) -> std::io::Result<()> {
        self.session.send(packet)
    }
}

impl Drop for WintunTunDevice {
    fn drop(&mut self) {
        let _ =
            ACTIVE_ADAPTER_LUID.compare_exchange(self.luid, 0, Ordering::SeqCst, Ordering::SeqCst);
        let _ = ACTIVE_ADAPTER_IP.compare_exchange(
            u32::from(self.local_ip),
            0,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
        // A reused adapter survives CloseAdapter, so drop its address
        // explicitly; a freshly created adapter is removed entirely.
        windows_net::remove_interface_address(self.luid, self.local_ip);
        let _ = &self.adapter;
        crate::helper_log!("[Wintun] session closed luid={:#x}", self.luid);
    }
}

pub(crate) fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
