mod error;
mod fake_dns;
mod tun_stack;
mod vpn_engine;

#[cfg(windows)]
pub mod platform;

pub use error::{AtrError, AtrResult, ErrorCode};
pub use fake_dns::FAKE_IP_CIDR;
pub use vpn_engine::{
    FakeIpConfig, VpnCookieRecord, VpnEngine, VpnEngineConfig, VpnEngineStatus,
    VpnEngineTrafficStats, VpnSessionMaterial,
};
