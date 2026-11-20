//! Daemon configuration (administrator-owned TOML file).

use std::path::{Path, PathBuf};
use std::time::Duration;

use fortino_core::worker::FakeWorkerConfig;
use serde::Deserialize;

/// Default configuration file.
pub const DEFAULT_CONFIG: &str = "/Library/Application Support/Fortino/fortinod.toml";

/// Administrator-provisioned CA bundles (`<trust-id>.pem`) when `[worker]` is not set.
pub const DEFAULT_CA_DIR: &str = "/Library/Application Support/Fortino/ca";

/// Root-owned copy of the daemon used as the worker when `[worker]` is not set.
pub const DEFAULT_WORKER_DIR: &str = "/Library/Application Support/Fortino/libexec";

/// Group allowed by default: every local user on macOS.
pub const DEFAULT_ALLOWED_GROUP: &str = "staff";

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
    /// Groups whose members may use the VPN, checked on every connection (so `dseditgroup`
    /// changes apply without a restart). Unset means `["staff"]` (every local user on macOS),
    /// unless `allowed_uids` lists users; then only those users. `[]` disables groups.
    pub allowed_groups: Option<Vec<String>>,
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
    /// Tunnel worker. Unset: the daemon runs itself as the worker (`fortinod --worker`) with
    /// CA bundles in [`DEFAULT_CA_DIR`].
    pub worker: Option<WorkerSection>,
    /// Apply network changes to an in-memory fake instead of the host. Implied by `[fake]`.
    /// Use the in-memory fake network instead of the platform controller (development).
    pub fake_network: bool,
    /// EMS servers the daemon may talk to.
    pub ems: EmsSection,
}

/// EMS settings. A profile's EMS server is contacted only if it is listed here with a trust
/// setting, and registered with only if `register = true`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct EmsSection {
    /// Registration store; default `<state_dir>/ems`.
    pub state_dir: Option<PathBuf>,
    /// Endpoint UID override (32 hex digits); default is the platform UUID.
    pub uid: Option<String>,
    /// Servers by `host:port`.
    pub servers: std::collections::HashMap<String, EmsServerSection>,
    /// Seconds to wait after the tunnel is up before the first keepalive.
    pub settle_secs: Option<u64>,
    /// Defer to an installed FortiClient whose EMS agent manages this device on the same EMS
    /// (default true).
    pub defer_to_forticlient: Option<bool>,
}

/// One EMS server.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmsServerSection {
    /// SHA-256 pin of the server's certificate (`sha256:…`).
    pub pin: Option<String>,
    /// CA bundle that verifies the server.
    pub ca_file: Option<PathBuf>,
    /// File holding the connection key (root-owned, 0600).
    pub key_file: Option<PathBuf>,
    /// Allow creating a registration (a device record on the EMS) on first connect.
    #[serde(default)]
    pub register: bool,
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
            socket_path: PathBuf::from(fortino_core::client::DEFAULT_SOCKET),
            state_dir: PathBuf::from("/Library/Application Support/Fortino/state"),
            socket_group: None,
            allowed_uids: Vec::new(),
            allowed_groups: None,
            admin_uids: Vec::new(),
            transport_timeout_secs: 30,
            challenge_timeout_secs: 120,
            shutdown_timeout_secs: 10,
            fake: None,
            worker: None,
            fake_network: false,
            ems: EmsSection::default(),
        }
    }
}

impl DaemonConfig {
    /// Loads `path`, or without one the default file if it exists, otherwise the built-in
    /// defaults (the installed app needs no configuration file).
    pub fn load_or_default(path: Option<&Path>) -> Result<Self, String> {
        match path {
            Some(p) => Self::load(p),
            None if Path::new(DEFAULT_CONFIG).exists() => Self::load(Path::new(DEFAULT_CONFIG)),
            None => Ok(Self::builtin()),
        }
    }

    /// Built-in defaults: every local user (group `staff`) may connect, the daemon is its own
    /// worker, and gateways are checked against the system CA bundle.
    pub fn builtin() -> Self {
        let staff = nix::unistd::Group::from_name(DEFAULT_ALLOWED_GROUP)
            .ok()
            .flatten()
            .is_some();
        Self {
            socket_group: staff.then(|| DEFAULT_ALLOWED_GROUP.to_owned()),
            ..Self::default()
        }
    }

    /// Loads a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Groups allowed to use the VPN, with the default applied.
    pub fn effective_allowed_groups(&self) -> Vec<String> {
        match &self.allowed_groups {
            Some(g) => g.clone(),
            None if self.allowed_uids.is_empty() => vec![DEFAULT_ALLOWED_GROUP.to_owned()],
            None => Vec::new(),
        }
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
    fn builtin_defaults_need_no_file() {
        let c = DaemonConfig::builtin();
        assert!(c.worker.is_none() && c.fake.is_none());
        assert_eq!(c.effective_allowed_groups(), vec!["staff".to_owned()]);
        #[cfg(target_os = "macos")]
        assert_eq!(c.socket_group.as_deref(), Some("staff"));
        let c = DaemonConfig::load_or_default(Some(Path::new("/nonexistent/fortinod.toml")));
        assert!(c.is_err(), "an explicit --config must exist");
    }

    #[test]
    fn allowed_groups_default() {
        let c: DaemonConfig = toml::from_str("").unwrap();
        assert_eq!(c.effective_allowed_groups(), vec!["staff".to_owned()]);
        let c: DaemonConfig = toml::from_str("allowed_uids = [501]").unwrap();
        assert!(c.effective_allowed_groups().is_empty());
        let c: DaemonConfig =
            toml::from_str("allowed_uids = [501]\nallowed_groups = [\"vpn\"]").unwrap();
        assert_eq!(c.effective_allowed_groups(), vec!["vpn".to_owned()]);
        let c: DaemonConfig = toml::from_str("allowed_groups = []").unwrap();
        assert!(c.effective_allowed_groups().is_empty());
    }

    #[test]
    fn parses_ems_servers() {
        let c: DaemonConfig = toml::from_str(
            r#"
            [ems.servers."ems.example.org:8013"]
            pin = "sha256:00"
            register = true
            "#,
        )
        .unwrap();
        let s = &c.ems.servers["ems.example.org:8013"];
        assert!(s.register && s.key_file.is_none());
        assert!(toml::from_str::<DaemonConfig>("[ems.servers.x]\nbogus = 1").is_err());
    }

    #[test]
    fn dev_fixture_parses() {
        let text = include_str!("../../../fixtures/dev/fortinod-fake.toml");
        let c: DaemonConfig = toml::from_str(text).unwrap();
        assert!(c.fake.is_some());
        assert_eq!(c.socket_group, None);
    }
}
