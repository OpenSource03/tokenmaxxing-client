//! Tokenmaxxing client core.
//!
//! Everything the desktop app does that is not UI: locate provider credentials where the
//! official tools keep them, scan local usage logs, execute server-issued proof specs over
//! MPC-TLS (via `tmx-attest`), and submit device-signed reports to the Tokenmaxxing API.
//!
//! Trust model reminder: this code runs on the user's machine and is assumed hostile by the
//! server. Nothing here is a security boundary; the API judges every submission.

pub mod account;
pub mod api;
pub mod burn;
pub mod claude_homes;
pub mod credentials;
pub mod identity;
pub mod logs;
pub mod paths;
pub mod provider;
pub mod state;
pub mod sync;

pub use account::Account;
pub use provider::Provider;

/// Client version reported to the API.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Platform label reported at pairing.
pub fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// Human-readable machine name for the device list.
pub fn device_name() -> String {
    std::env::var("TMX_DEVICE_NAME")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .arg("-s")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| format!("{} device", platform()))
}
