//! `ofcd`: the Fortino daemon.
//!
//! Owns the profile store, the single machine-wide session slot, the tunnel worker and all
//! network changes. Clients (`ofctl`, the desktop app) talk to it over a Unix socket; see
//! the design notes.

pub mod auth;
pub mod config;
pub mod netctl;
pub mod procworker;
pub mod server;
pub mod session;

use std::path::Path;
use std::sync::{Arc, Mutex};

use ofc_config::ProfileStore;
use ofc_core::worker::FakeWorker;
use ofc_platform::fake::{FakeNet, FakeState};
use ofc_platform::journal::Journaled;
use tokio::net::UnixListener;

use crate::auth::Authorizer;
use crate::config::DaemonConfig;
use crate::netctl::JournaledController;
use crate::session::Session;

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
    let workers: Box<dyn ofc_core::worker::WorkerFactory> = match (&cfg.fake, &cfg.worker) {
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
                ca_dir: w.ca_dir.clone(),
                env: Vec::new(),
            })
        }
        (None, None) => {
            return Err("no tunnel backend: configure [worker] (or [fake] for development)".into());
        }
    };
    if cfg.fake.is_none() && !cfg.fake_network {
        return Err(
            "the macOS network controller is not implemented yet; set fake_network = true for \
             development"
                .into(),
        );
    }
    tracing::warn!("using the FAKE network; routes and DNS on this host are not changed");
    let net = FakeNet::new(Arc::new(Mutex::new(FakeState::typical_host())));
    let journal = Journaled::open(net, cfg.state_dir.join("net-journal.json"))
        .map_err(|e| format!("network journal: {e}"))?;
    Ok(Session::new(
        store,
        workers,
        Box::new(JournaledController::new(journal)),
        cfg.timeouts(),
    ))
}

/// Builds the authorizer from configuration.
pub fn build_authorizer(cfg: &DaemonConfig) -> Result<Arc<Authorizer>, String> {
    Authorizer::new(
        cfg.allowed_uids.clone(),
        cfg.admin_uids.clone(),
        cfg.socket_group.as_deref(),
    )
    .map(Arc::new)
}
