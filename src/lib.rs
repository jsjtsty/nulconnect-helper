mod error;
mod vpn_engine;

#[cfg(windows)]
pub mod platform;

pub use error::{AtrError, AtrResult, ErrorCode};
pub use vpn_engine::{
    VpnCookieRecord, VpnEngine, VpnEngineConfig, VpnEngineStatus, VpnEngineTrafficStats,
    VpnSessionMaterial,
};
