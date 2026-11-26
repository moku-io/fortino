//! `fortinod`: the Fortino daemon.
//!
//! Owns the profile store, the single machine-wide session slot, the tunnel worker and all
//! network changes. Clients (`fortino`, the desktop app) talk to it over a Unix socket.

pub mod auth;
pub mod config;
pub mod logctl;
pub mod netctl;
pub mod procworker;
pub mod server;
pub mod session;

use std::path::Path;
use std::sync::{Arc, Mutex};

use fortino_config::ProfileStore;
use fortino_core::worker::FakeWorker;
use fortino_platform::fake::{FakeNet, FakeState};
use fortino_platform::journal::Journaled;
use tokio::net::UnixListener;

use crate::auth::Authorizer;
use crate::config::DaemonConfig;
use crate::netctl::JournaledController;
use crate::session::Session;

/// Build identifier stamped by `apps/macos/scripts/bundle.sh` (`FORTINO_BUILD_ID`): the commit,
/// plus a timestamp for a tree with local changes. The app compares it with its own to notice
/// a daemon left running from before an update. Unstamped (development) builds have none.
pub const BUILD_ID: Option<&str> = option_env!("FORTINO_BUILD_ID");

/// Binds the control socket, replacing a stale one, and restricts its permissions.
///
/// With a group the socket is `0660 root:<group>`; without one it is `0600`.
pub fn bind_socket(path: &Path, group: Option<&str>) -> Result<UnixListener, String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("{}: {e}", path.display())),
    }
    let l = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mode = if let Some(name) = group {
        let g = nix::unistd::Group::from_name(name)
            .map_err(|e| format!("group {name}: {e}"))?
            .ok_or_else(|| format!("group {name} does not exist"))?;
        nix::unistd::chown(path, None, Some(g.gid))
            .map_err(|e| format!("chown {}: {e}", path.display()))?;
        0o660
    } else {
        0o600
    };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    Ok(l)
}

/// Builds the session manager from configuration.
pub fn build_session(cfg: &DaemonConfig) -> Result<Arc<Session>, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&cfg.state_dir)
        .map_err(|e| format!("{}: {e}", cfg.state_dir.display()))?;
    let _ = std::fs::set_permissions(&cfg.state_dir, std::fs::Permissions::from_mode(0o700));
    let store = ProfileStore::open(&cfg.state_dir.join("profiles.db"))
        .map_err(|e| format!("profile store: {e}"))?;
    let workers: Box<dyn fortino_core::worker::WorkerFactory> = match (&cfg.fake, &cfg.worker) {
        (Some(_), Some(_)) => return Err("configure either [fake] or [worker], not both".into()),
        (Some(fake), None) => {
            tracing::warn!("using the FAKE worker; no real tunnel will be created");
            Box::new(FakeWorker {
                config: fake.clone(),
            })
        }
        (None, Some(w)) => {
            if !w.allow_unowned {
                crate::procworker::check_executable(&w.path)?;
            }
            Box::new(crate::procworker::ProcessWorker {
                path: w.path.clone(),
                args: Vec::new(),
                ca_dir: w.ca_dir.clone(),
                gateway_pins: None,
                env: Vec::new(),
            })
        }
        (None, None) => {
            // The daemon runs itself as the worker, from a root-owned copy (see `stage_worker`).
            let path = crate::procworker::stage_worker(
                std::path::Path::new(crate::config::DEFAULT_WORKER_DIR),
                option_env!("FORTINO_TEAM_ID"),
            )?;
            Box::new(crate::procworker::ProcessWorker {
                path,
                args: vec!["--worker".into()],
                ca_dir: crate::config::DEFAULT_CA_DIR.into(),
                gateway_pins: Some(crate::procworker::GatewayPins {
                    dir: crate::procworker::GATEWAY_PIN_DIR.into(),
                    owner: 0,
                }),
                env: Vec::new(),
            })
        }
    };
    let ems = fortino_ems::service::EmsWorkers::new(
        std::sync::Arc::from(workers),
        ems_settings(cfg)?,
        fortino_ems::service::system_facts(),
    )
    .with_forticlient(fortino_ems::forticlient::source(
        (cfg.ems.defer_to_forticlient != Some(false) && cfg!(target_os = "macos"))
            .then(|| fortino_ems::forticlient::MACOS_ROOT.into()),
    ));
    let journal_path = cfg.state_dir.join("net-journal.json");
    let net: Box<dyn crate::netctl::NetController> = if cfg.fake.is_some() || cfg.fake_network {
        tracing::warn!("using the FAKE network; routes and DNS on this host are not changed");
        let net = FakeNet::new(Arc::new(Mutex::new(FakeState::typical_host())));
        Box::new(JournaledController::new(
            Journaled::open(net, journal_path).map_err(|e| format!("network journal: {e}"))?,
        ))
    } else {
        real_network(journal_path)?
    };
    Ok(Session::with_ems(
        store,
        Box::new(ems.clone()),
        net,
        cfg.timeouts(),
        Some(ems),
    ))
}

#[cfg(target_os = "macos")]
fn real_network(
    journal: std::path::PathBuf,
) -> Result<Box<dyn crate::netctl::NetController>, String> {
    tracing::info!("using the macOS network controller (route, scutil, pfctl)");
    let j = Journaled::open(fortino_platform::macos::MacNet::system(), journal)
        .map_err(|e| format!("network journal: {e}"))?;
    Ok(Box::new(JournaledController::new(j)))
}

#[cfg(not(target_os = "macos"))]
fn real_network(
    _journal: std::path::PathBuf,
) -> Result<Box<dyn crate::netctl::NetController>, String> {
    Err("no network controller for this platform yet; set fake_network = true".into())
}

/// EMS agent settings from the `[ems]` section. Every listed server needs a pin or a CA file.
pub fn ems_settings(cfg: &DaemonConfig) -> Result<fortino_ems::service::Settings, String> {
    use fortino_ems::service::{ServerSettings, Settings};
    let mut servers = std::collections::HashMap::new();
    for (name, s) in &cfg.ems.servers {
        let server: fortino_config::EmsServer = name
            .parse()
            .map_err(|e| format!("[ems.servers.\"{name}\"]: {e}"))?;
        let trust = match (&s.pin, &s.ca_file) {
            (Some(p), None) => fortino_tls::Trust::Pinned(vec![
                fortino_tls::parse_pin(p.trim_start_matches("sha256:"))
                    .ok_or_else(|| format!("[ems.servers.\"{name}\"]: invalid pin"))?,
            ]),
            (None, Some(ca)) => fortino_tls::Trust::CaFile(ca.clone()),
            _ => {
                return Err(format!(
                    "[ems.servers.\"{name}\"]: set exactly one of pin or ca_file"
                ));
            }
        };
        servers.insert(
            fortino_ems::store::server_key(&server),
            ServerSettings {
                trust,
                key_file: s.key_file.clone(),
                register: s.register,
            },
        );
    }
    if let Some(u) = &cfg.ems.uid {
        fortino_proto_ems::ids::Uid::parse(u).map_err(|_| "[ems] uid: not a UUID".to_owned())?;
    }
    Ok(Settings {
        package_approvals: cfg.ems.builtin_package_enrollment.then(|| {
            fortino_ems::service::PackageApprovals {
                directory: "/private/var/db/fortino-ems-approvals".into(),
                ca_file: crate::procworker::SYSTEM_CA_BUNDLE.into(),
            }
        }),
        state_dir: cfg
            .ems
            .state_dir
            .clone()
            .unwrap_or_else(|| cfg.state_dir.join("ems")),
        uid: cfg.ems.uid.clone(),
        compat: fortino_ems::report::Compat::default(),
        servers,
        settle: std::time::Duration::from_secs(cfg.ems.settle_secs.unwrap_or(2)),
        min_ka_interval: std::time::Duration::from_secs(10),
        retry: std::time::Duration::from_secs(60),
    })
}

/// Builds the authorizer from configuration.
pub fn build_authorizer(cfg: &DaemonConfig) -> Result<Arc<Authorizer>, String> {
    let mut a = Authorizer::new(
        cfg.allowed_uids.clone(),
        cfg.admin_uids.clone(),
        cfg.socket_group.as_deref(),
    )?;
    a.allowed_groups = auth::resolve_groups(&cfg.effective_allowed_groups());
    if a.allowed.is_empty() && a.allowed_groups.is_empty() {
        tracing::warn!("no allowed_uids or allowed_groups: only root can use the VPN");
    }
    Ok(Arc::new(a))
}
