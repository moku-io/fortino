//! Daemon configuration (administrator-owned TOML file).

use std::path::{Path, PathBuf};
use std::time::Duration;

use ofc_core::worker::FakeWorkerConfig;
use serde::Deserialize;

/// Default configuration file.
pub const DEFAULT_CONFIG: &str = "/Library/Application Support/Fortino/ofcd.toml";

/// Daemon settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DaemonConfig {
    /// Control socket path.
    pub socket_path: PathBuf,
    /// Directory for the profile database and network journal (root-owned, 0700).
    pub state_dir: PathBuf,
    /// Group that may connect to the socket. Members must also be in `allowed_uids`.
    pub socket_group: Option<String>,
    /// UIDs allowed to use the VPN. Root is always allowed.
    pub allowed_uids: Vec<u32>,
    /// UIDs that may see and stop any user's attempt. Root is always an administrator.
    pub admin_uids: Vec<u32>,
    /// Seconds to establish the transport.
    pub transport_timeout_secs: u64,
    /// Seconds to answer one challenge.
    pub challenge_timeout_secs: u64,
    /// Seconds for a graceful worker shutdown. Keep above the process supervisor's own
    /// 5 s grace plus kill time, so a hung worker is reaped before the slot is released.
    pub shutdown_timeout_secs: u64,
    /// Use the fake worker and fake network (development and tests only).
    pub fake: Option<FakeWorkerConfig>,
    /// External tunnel worker (the openfortivpn adapter).
    pub worker: Option<WorkerSection>,
    /// Apply network changes to an in-memory fake instead of the host. Implied by `[fake]`.
    /// Use the in-memory fake network instead of the platform controller (development).
    pub fake_network: bool,
}

/// External worker settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSection {
    /// Fixed executable path. Must be root-owned and not group/world-writable.
    pub path: PathBuf,
    /// Directory of administrator-provisioned CA bundles, `<trust-id>.pem`.
    pub ca_dir: PathBuf,
    /// Skip the ownership check (development only).
    #[serde(default)]
    pub allow_unowned: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(ofc_core::client::DEFAULT_SOCKET),
            state_dir: PathBuf::from("/Library/Application Support/Fortino/state"),
            socket_group: None,
            allowed_uids: Vec::new(),
            admin_uids: Vec::new(),
            transport_timeout_secs: 30,
            challenge_timeout_secs: 120,
            shutdown_timeout_secs: 10,
            fake: None,
            worker: None,
            fake_network: false,
        }
    }
}

impl DaemonConfig {
    /// Loads a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Deadlines.
    pub fn timeouts(&self) -> Timeouts {
        Timeouts {
            transport: Duration::from_secs(self.transport_timeout_secs),
            challenge: Duration::from_secs(self.challenge_timeout_secs),
            shutdown: Duration::from_secs(self.shutdown_timeout_secs),
        }
    }
}

/// Daemon-owned deadlines.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// Transport establishment.
    pub transport: Duration,
    /// Per challenge.
    pub challenge: Duration,
    /// Graceful worker shutdown.
    pub shutdown: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        DaemonConfig::default().timeouts()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toml() {
        let c: DaemonConfig = toml::from_str(
            r#"
            socket_path = "/tmp/x.sock"
            allowed_uids = [501]
            [fake]
            otp = "654321"
            step_delay_ms = 5
            "#,
        )
        .unwrap();
        assert_eq!(c.allowed_uids, vec![501]);
        assert_eq!(c.fake.unwrap().otp.as_deref(), Some("654321"));
        assert_eq!(c.challenge_timeout_secs, 120);
        assert!(toml::from_str::<DaemonConfig>("bogus = 1").is_err());
    }

    #[test]
    fn dev_fixture_parses() {
        let text = include_str!("../../../fixtures/dev/ofcd-fake.toml");
        let c: DaemonConfig = toml::from_str(text).unwrap();
        assert!(c.fake.is_some());
        assert_eq!(c.socket_group, None);
    }
}
