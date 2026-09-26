//! Windows network configuration through the IP Helper API and the Name
//! Resolution Policy Table (NRPT).
//!
//! Earlier revisions shelled out to `netsh` and `route` and parsed their
//! output, which breaks on localized Windows installations (column layout
//! and error text differ per language). The IP Helper API is locale-neutral
//! and available on every supported Windows release.

use crate::platform::windows::wide;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::ptr;
use windows_sys::Win32::Foundation::{ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
    DeleteUnicastIpAddressEntry, FreeMibTable, GetBestRoute2, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeIpForwardEntry, InitializeIpInterfaceEntry,
    InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
};
use windows_sys::Win32::System::GroupPolicy::{RP_FORCE, RefreshPolicyEx};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_MULTI_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegOpenKeyExW,
    RegSetValueExW,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_PARAMCHANGE, SERVICE_PAUSE_CONTINUE, SERVICE_STATUS,
};

/// Interface metric for the tunnel. Low enough that managed prefixes always
/// win over a physical interface's equally specific route.
const TUNNEL_INTERFACE_METRIC: u32 = 5;

const NRPT_LOCAL_KEY: &str =
    r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
const NRPT_POLICY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
const NRPT_RULE_NAME: &str = "NulConnect";
/// NRPT `ConfigOptions` flag: the rule carries generic DNS servers.
const NRPT_CONFIG_GENERIC_DNS: u32 = 0x8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RouteSpec {
    pub interface_luid: u64,
    pub destination: Ipv4Addr,
    pub prefix: u8,
    pub next_hop: Ipv4Addr,
}

impl std::fmt::Display for RouteSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}/{} via {} (luid {:#x})",
            self.destination, self.prefix, self.next_hop, self.interface_luid
        )
    }
}

fn sockaddr_v4(ip: Ipv4Addr) -> SOCKADDR_INET {
    let mut address = SOCKADDR_INET::default();
    address.Ipv4.sin_family = AF_INET;
    address.Ipv4.sin_addr.S_un.S_addr = u32::from(ip).to_be();
    address
}

fn ipv4_of(address: &SOCKADDR_INET) -> Option<Ipv4Addr> {
    unsafe {
        if address.si_family == AF_INET {
            Some(Ipv4Addr::from(u32::from_be(
                address.Ipv4.sin_addr.S_un.S_addr,
            )))
        } else {
            None
        }
    }
}

fn luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

fn win32_error(context: &str, code: u32) -> String {
    format!(
        "{context}: {}",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

/// Assigns the /32 tunnel address, disables automatic metrics and applies
/// the MTU. Stale IPv4 addresses from a previous crashed run are removed.
pub fn configure_tunnel_interface(
    interface: u64,
    local_ip: Ipv4Addr,
    mtu: u16,
) -> Result<(), String> {
    remove_all_ipv4_addresses(interface, Some(local_ip));

    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.Address = sockaddr_v4(local_ip);
    row.InterfaceLuid = luid(interface);
    row.OnLinkPrefixLength = 32;
    // Wintun has no link partner, so duplicate address detection would only
    // delay the address becoming usable.
    row.DadState = IpDadStatePreferred;
    let result = unsafe { CreateUnicastIpAddressEntry(&row) };
    if result != NO_ERROR && result != ERROR_OBJECT_ALREADY_EXISTS {
        return Err(win32_error("failed to assign tunnel address", result));
    }

    let mut interface_row = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut interface_row) };
    interface_row.Family = AF_INET;
    interface_row.InterfaceLuid = luid(interface);
    let result = unsafe { GetIpInterfaceEntry(&mut interface_row) };
    if result != NO_ERROR {
        return Err(win32_error("failed to read tunnel interface", result));
    }
    interface_row.UseAutomaticMetric = false;
    interface_row.Metric = TUNNEL_INTERFACE_METRIC;
    interface_row.NlMtu = u32::from(mtu);
    // SetIpInterfaceEntry rejects IPv4 rows with a non-zero site prefix.
    interface_row.SitePrefixLength = 0;
    let result = unsafe { SetIpInterfaceEntry(&mut interface_row) };
    if result != NO_ERROR {
        return Err(win32_error("failed to configure tunnel interface", result));
    }
    Ok(())
}

pub fn remove_interface_address(interface: u64, local_ip: Ipv4Addr) {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.Address = sockaddr_v4(local_ip);
    row.InterfaceLuid = luid(interface);
    let _ = unsafe { DeleteUnicastIpAddressEntry(&row) };
}

fn remove_all_ipv4_addresses(interface: u64, keep: Option<Ipv4Addr>) {
    let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
    if unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) } != NO_ERROR || table.is_null() {
        return;
    }
    unsafe {
        let rows =
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
        for row in rows {
            if row.InterfaceLuid.Value != interface {
                continue;
            }
            if keep.is_some() && ipv4_of(&row.Address) == keep {
                continue;
            }
            let _ = DeleteUnicastIpAddressEntry(row);
        }
        FreeMibTable(table as *const c_void);
    }
}

fn route_row(spec: &RouteSpec) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(spec.interface_luid);
    row.DestinationPrefix.Prefix = sockaddr_v4(spec.destination);
    row.DestinationPrefix.PrefixLength = spec.prefix;
    row.NextHop = sockaddr_v4(spec.next_hop);
    row.Metric = 0;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Adds a route. Returns `Ok(false)` when an identical route already existed,
/// in which case it is not ours to remove later.
pub fn add_route(spec: &RouteSpec) -> Result<bool, String> {
    let row = route_row(spec);
    match unsafe { CreateIpForwardEntry2(&row) } {
        NO_ERROR => Ok(true),
        ERROR_OBJECT_ALREADY_EXISTS => Ok(false),
        error => Err(win32_error(&format!("failed to add route {spec}"), error)),
    }
}

pub fn delete_route(spec: &RouteSpec) {
    let row = route_row(spec);
    match unsafe { DeleteIpForwardEntry2(&row) } {
        NO_ERROR | ERROR_NOT_FOUND => {}
        error => crate::helper_log!(
            "{}",
            win32_error(&format!("failed to delete route {spec}"), error)
        ),
    }
}

/// The route Windows currently uses for `destination`: `(interface LUID,
/// next hop)`. The next hop is `0.0.0.0` for on-link destinations.
pub fn best_route(destination: Ipv4Addr) -> Option<(u64, Ipv4Addr)> {
    let destination = sockaddr_v4(destination);
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let result = unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &destination,
            0,
            &mut row,
            &mut source,
        )
    };
    if result != NO_ERROR {
        return None;
    }
    Some((unsafe { row.InterfaceLuid.Value }, ipv4_of(&row.NextHop)?))
}

/// The IPv4 default gateway on the currently preferred interface.
pub fn default_gateway() -> Option<Ipv4Addr> {
    best_route(Ipv4Addr::new(8, 8, 8, 8))
        .map(|(_, next_hop)| next_hop)
        .filter(|gateway| !gateway.is_unspecified())
}

struct RegKey(HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn open_key(path: &str) -> Option<RegKey> {
    let path = wide(path);
    let mut key: HKEY = ptr::null_mut();
    let result = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    (result == NO_ERROR).then_some(RegKey(key))
}

fn create_key(path: &str) -> Result<RegKey, String> {
    let wide_path = wide(path);
    let mut key: HKEY = ptr::null_mut();
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wide_path.as_ptr(),
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE | KEY_WOW64_64KEY,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if result != NO_ERROR {
        return Err(win32_error(
            &format!("failed to create registry key {path}"),
            result,
        ));
    }
    Ok(RegKey(key))
}

fn set_value(key: &RegKey, name: &str, kind: u32, data: &[u8]) -> Result<(), String> {
    let name_wide = wide(name);
    let result = unsafe {
        RegSetValueExW(
            key.0,
            name_wide.as_ptr(),
            0,
            kind,
            data.as_ptr(),
            data.len() as u32,
        )
    };
    if result != NO_ERROR {
        return Err(win32_error(
            &format!("failed to write registry value {name}"),
            result,
        ));
    }
    Ok(())
}

fn utf16_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn multi_sz(values: &[String]) -> Vec<u8> {
    let mut units = Vec::new();
    for value in values {
        units.extend(value.encode_utf16());
        units.push(0);
    }
    units.push(0);
    utf16_bytes(&units)
}

/// NRPT namespaces for the managed domains. `corp.example` needs both the
/// exact entry and the `.corp.example` suffix entry to cover the apex and
/// every subdomain, which matches the macOS `/etc/resolver` behaviour.
pub fn nrpt_namespaces(domains: &[String]) -> Vec<String> {
    let mut names = Vec::new();
    for domain in domains {
        let domain = domain
            .trim()
            .trim_start_matches("*.")
            .trim_matches(|c: char| c == '.' || c.is_whitespace())
            .to_ascii_lowercase();
        if domain.is_empty() || domain.parse::<Ipv4Addr>().is_ok() || domain.contains(':') {
            continue;
        }
        if domain.contains(|c: char| c.is_whitespace() || c == '/' || c == '\\') {
            continue;
        }
        names.push(domain.clone());
        names.push(format!(".{domain}"));
    }
    names.sort();
    names.dedup();
    names
}

fn policy_nrpt_active() -> bool {
    open_key(NRPT_POLICY_KEY).is_some()
}

/// Sends managed domains to the service DNS server. When Group Policy
/// already defines NRPT rules, the local rule table is ignored by Windows, so
/// the rule is written to the policy location instead.
pub fn apply_nrpt(domains: &[String], dns_server: Ipv4Addr) -> Result<usize, String> {
    clear_nrpt();
    let names = nrpt_namespaces(domains);
    if names.is_empty() {
        return Ok(0);
    }
    let use_policy = policy_nrpt_active();
    let base = if use_policy {
        NRPT_POLICY_KEY
    } else {
        NRPT_LOCAL_KEY
    };
    let key = create_key(&format!(r"{base}\{NRPT_RULE_NAME}"))?;
    set_value(&key, "Version", REG_DWORD, &2u32.to_le_bytes())?;
    set_value(&key, "Name", REG_MULTI_SZ, &multi_sz(&names))?;
    let server: Vec<u16> = dns_server.to_string().encode_utf16().chain([0]).collect();
    set_value(&key, "GenericDNSServers", REG_SZ, &utf16_bytes(&server))?;
    set_value(
        &key,
        "ConfigOptions",
        REG_DWORD,
        &NRPT_CONFIG_GENERIC_DNS.to_le_bytes(),
    )?;
    set_value(&key, "IPSECCARestriction", REG_SZ, &utf16_bytes(&[0]))?;
    drop(key);
    reload_dns_policy(use_policy);
    crate::helper_log!(
        "[Net] NRPT rule installed: namespaces={} server={dns_server} policy={use_policy}",
        names.len()
    );
    Ok(names.len())
}

pub fn clear_nrpt() {
    let mut removed = false;
    for base in [NRPT_LOCAL_KEY, NRPT_POLICY_KEY] {
        let path = wide(&format!(r"{base}\{NRPT_RULE_NAME}"));
        if unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, path.as_ptr()) } == NO_ERROR {
            removed = true;
        }
    }
    if removed {
        reload_dns_policy(policy_nrpt_active());
        crate::helper_log!("[Net] NRPT rule removed");
    }
}

fn reload_dns_policy(refresh_group_policy: bool) {
    if refresh_group_policy {
        unsafe { RefreshPolicyEx(1, RP_FORCE) };
    }
    unsafe {
        let manager = OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT);
        if !manager.is_null() {
            let name = wide("Dnscache");
            let service = OpenServiceW(manager, name.as_ptr(), SERVICE_PAUSE_CONTINUE);
            if !service.is_null() {
                let mut status = SERVICE_STATUS::default();
                if ControlService(service, SERVICE_CONTROL_PARAMCHANGE, &mut status) == 0 {
                    crate::helper_log!(
                        "[Net] Dnscache PARAMCHANGE failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
                CloseServiceHandle(service);
            }
            CloseServiceHandle(manager);
        }
    }
    flush_dns_cache();
}

pub fn flush_dns_cache() {
    // DnsFlushResolverCache is exported by dnsapi.dll but absent from the
    // SDK import libraries, so it is resolved at runtime.
    type Flush = unsafe extern "system" fn() -> i32;
    unsafe {
        if let Ok(library) = libloading::Library::new("dnsapi.dll")
            && let Ok(flush) = library.get::<Flush>(b"DnsFlushResolverCache\0")
        {
            flush();
        }
    }
}
