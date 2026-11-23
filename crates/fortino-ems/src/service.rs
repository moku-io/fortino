//! EMS in the connect flow: a [`WorkerFactory`] that wraps the tunnel worker.
//!
//! For a profile whose endpoint names an EMS server, before the worker starts it:
//!
//! 1. uses the registration stored for that server, or creates one if the administrator allowed
//!    it for that server (registering creates a device record on the EMS);
//! 2. hands the worker that registration's serial and tenant, which the worker presents only if
//!    the gateway asks for them.
//!
//! Once the tunnel is up it sends a full keepalive. That keepalive's `NWIFS` includes the
//! tunnel interface and its address, which is how EMS, and the FortiGates it feeds, can tie the
//! tunnel address to this device and its tags. It then reports host-verification results and
//! keeps the registration alive until the tunnel ends. EMS failures after the tunnel is up are
//! logged and never take the tunnel down.
//!
//! Registrations are per server and never moved: switching to a profile with another EMS uses
//! that EMS's registration.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fortino_config::EmsServer;
use fortino_core::ErrorCode;
use fortino_core::worker::{
    EmsIdentity, Termination, WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory,
    WorkerHandle, WorkerStage,
};
use fortino_platform::facts::Facts;
use fortino_proto_ems::ids::Uid;
use fortino_tls::Trust;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::forticlient::{FortiClientSource, FortiClientState};
use crate::report::Compat;
use crate::store::{Store, server_key};
use crate::{Agent, Connection, Error, Keepalive};

/// Administrator settings for one EMS server.
#[derive(Debug, Clone)]
pub struct ServerSettings {
    /// How to verify the server. Without it the server is not contacted.
    pub trust: Trust,
    /// File holding the connection key, if the server requires one.
    pub key_file: Option<PathBuf>,
    /// May the daemon create a registration (a device record) on first use?
    pub register: bool,
}

/// Built-in daemon policy for destinations approved by a local administrator.
#[derive(Debug, Clone)]
pub struct PackageApprovals {
    /// Protected directory of root-created approval markers named by the SHA-256 of the normalized server.
    pub directory: PathBuf,
    /// System CA bundle. Package-provided certificates are never trust anchors.
    pub ca_file: PathBuf,
}

impl PackageApprovals {
    /// The trust for an approved server, or `None` when it is not approved. An empty marker
    /// trusts the system CA bundle; a marker holding a SHA-256 pin trusts exactly that leaf
    /// certificate, which the administrator accepted after a warning (for an EMS reached by an
    /// address its certificate doesn't name). Any other content is refused.
    fn trust_for(&self, server: &EmsServer) -> Option<Trust> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::MetadataExt;
        let protected = |meta: &std::fs::Metadata| meta.uid() == 0 && meta.mode() & 0o022 == 0;
        if !std::fs::symlink_metadata(&self.directory).is_ok_and(|m| m.is_dir() && protected(&m)) {
            return None;
        }
        let marker = self
            .directory
            .join(hex::encode(Sha256::digest(server_key(server))));
        if !std::fs::symlink_metadata(&marker)
            .is_ok_and(|m| m.is_file() && protected(&m) && m.len() <= 256)
        {
            return None;
        }
        let content = std::fs::read_to_string(&marker).ok()?;
        marker_trust(&content, &self.ca_file)
    }
}

/// Parses an approval marker's content (see [`PackageApprovals::trust_for`]).
fn marker_trust(content: &str, ca_file: &std::path::Path) -> Option<Trust> {
    let pin = content.trim();
    if pin.is_empty() {
        return Some(Trust::CaFile(ca_file.to_path_buf()));
    }
    match fortino_tls::parse_pin(pin) {
        Some(p) => Some(Trust::Pinned(vec![p])),
        None => {
            tracing::warn!(
                "EMS approval marker holds neither nothing nor a SHA-256 pin; ignoring it"
            );
            None
        }
    }
}

/// Agent settings.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Local administrator approval mechanism, when enabled by the daemon.
    pub package_approvals: Option<PackageApprovals>,
    /// Registration store directory (root-owned).
    pub state_dir: PathBuf,
    /// Endpoint UID override; default is the platform UUID.
    pub uid: Option<String>,
    /// Compatibility profile.
    pub compat: Compat,
    /// Servers by `host:port` (lower-case).
    pub servers: HashMap<String, ServerSettings>,
    /// Wait this long after the tunnel is up before the first keepalive, so the daemon has
    /// applied routes and DNS.
    pub settle: Duration,
    /// Shortest keepalive interval honoured, whatever the server asks (10 s in production).
    pub min_ka_interval: Duration,
}

/// Reads host facts. Replaceable for tests.
pub type FactsSource = Arc<dyn Fn() -> Option<Facts> + Send + Sync>;

/// The default facts source: the platform collector.
pub fn system_facts() -> FactsSource {
    Arc::new(|| match fortino_platform::facts::collect() {
        Ok(f) => Some(f),
        Err(e) => {
            tracing::warn!(error = %e, "could not read host facts for EMS");
            None
        }
    })
}

/// Wraps a worker factory with the EMS steps.
#[derive(Clone)]
pub struct EmsWorkers {
    registration_lock: Arc<tokio::sync::Mutex<()>>,
    inner: Arc<dyn WorkerFactory>,
    settings: Arc<Settings>,
    facts: FactsSource,
    forticlient: FortiClientSource,
    /// This device's UID, for gateways that ask for it (`/remote/info` `0x80`) whether or not
    /// the profile names an EMS, as FortiClient does.
    device_uid: Option<String>,
    /// Connect EMS exchanges here instead of resolving (tests).
    pub connect_override: Option<std::net::SocketAddr>,
}

impl std::fmt::Debug for EmsWorkers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmsWorkers")
            .field("inner", &self.inner)
            .field("servers", &self.settings.servers.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl EmsWorkers {
    /// Wraps `inner`.
    /// Reads the device UID once, here: it does not change while the daemon runs.
    pub fn new(inner: Arc<dyn WorkerFactory>, settings: Settings, facts: FactsSource) -> Self {
        let device_uid = settings
            .uid
            .clone()
            .or_else(|| facts().and_then(|f| f.platform_uuid))
            .and_then(|u| Uid::parse(&u).ok())
            .map(|u| u.to_string());
        if device_uid.is_none() {
            tracing::warn!("no device UID; gateways that ask for one will not get it");
        }
        Self {
            registration_lock: Arc::default(),
            inner,
            settings: Arc::new(settings),
            facts,
            forticlient: crate::forticlient::source(None),
            device_uid,
            connect_override: None,
        }
    }

    fn context(
        &self,
        server: EmsServer,
        server_settings: ServerSettings,
        overrides: std::collections::BTreeMap<String, String>,
    ) -> Ctx {
        Ctx {
            registration_lock: self.registration_lock.clone(),
            settings: self.settings.clone(),
            facts: self.facts.clone(),
            forticlient: self.forticlient.clone(),
            server,
            server_settings,
            connect_override: self.connect_override,
            overrides,
        }
    }

    /// Settings for `server`: from the daemon configuration, or from a local administrator's
    /// approval of that address. An approved server registers on connect with or without a
    /// deployment package: a device the EMS already knows (enrolled earlier, by FortiClient
    /// or by Fortino) is matched by its hardware identity, so the package is only needed for
    /// devices the EMS has never seen. Without an approval nothing is sent to the EMS.
    fn server_settings(&self, server: &EmsServer) -> Option<ServerSettings> {
        if let Some(settings) = self.settings.servers.get(&server_key(server)) {
            return Some(settings.clone());
        }
        let approvals = self.settings.package_approvals.as_ref()?;
        approvals.trust_for(server).map(|trust| ServerSettings {
            trust,
            key_file: None,
            register: true,
        })
    }

    /// Explicit first enrollment without a VPN tunnel. Uses the same registration as connect.
    pub async fn enroll_package(
        &self,
        server: EmsServer,
        install_uid: &str,
    ) -> Result<(&'static str, bool), Error> {
        if install_uid.is_empty()
            || install_uid.len() > 256
            || !install_uid
                .bytes()
                .all(|b| b.is_ascii_graphic() && b != b'|')
        {
            return Err(Error::Protocol("invalid package installer ID".into()));
        }
        let settings = match self.server_settings(&server) {
            Some(settings) if settings.register => settings,
            None if self.settings.package_approvals.is_some() => {
                return Ok(("approval-required", false));
            }
            _ => return Err(Error::RegistrationDisabled),
        };
        // Explicit package enrollment carries no per-profile debug overrides.
        let ctx = self.context(server, settings, std::collections::BTreeMap::new());
        match ctx.prepare(Some(install_uid)).await?.0 {
            Prepared::Deferred(_) => Ok(("managed-by-forticlient", false)),
            Prepared::Agent(Some(_)) => {
                let record = Store::open(&ctx.settings.state_dir)?
                    .load(&server_key(&ctx.server))?
                    .ok_or(Error::NotRegistered)?;
                let status = if record.install_uid.as_deref() == Some(install_uid) {
                    "registered"
                } else {
                    "existing-registration"
                };
                Ok((status, record.host_rules.content.is_some()))
            }
            Prepared::Agent(None) => Err(Error::NotRegistered),
        }
    }

    /// This device's registration state with `server`, from local records only: no network
    /// exchange, nothing created. Reveals no serial, UID or keys.
    pub fn status(&self, server: &EmsServer) -> Result<EmsStatusInfo, Error> {
        if self.server_settings(server).is_none() {
            return Ok(EmsStatusInfo::bare(EmsState::Unconfigured));
        }
        if (self.forticlient)()
            .is_some_and(|fc| fc.running && fc.serial.is_some() && fc.uses_address(server))
        {
            return Ok(EmsStatusInfo::bare(EmsState::ManagedByForticlient));
        }
        let Some(r) = Store::open(&self.settings.state_dir)?.load(&server_key(server))? else {
            return Ok(EmsStatusInfo::bare(EmsState::NotRegistered));
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        Ok(EmsStatusInfo {
            state: registration_state(&r, now),
            registered_at: Some(r.registered_at),
            last_keepalive: r.last_keepalive,
            rules: Some(r.host_rules.content.is_some()),
        })
    }

    /// Defers to an installed FortiClient's EMS agent where it manages the same device on the
    /// same EMS (see [`crate::forticlient`]).
    pub fn with_forticlient(mut self, source: FortiClientSource) -> Self {
        self.forticlient = source;
        self
    }
}

/// Registration state reported by [`EmsWorkers::status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmsState {
    /// The daemon has no settings for this server.
    Unconfigured,
    /// FortiClient's own agent manages this device on this EMS.
    ManagedByForticlient,
    /// No registration with this EMS.
    NotRegistered,
    /// Registered, with a recent keepalive.
    Registered,
    /// Registered, but no keepalive within three full-keepalive intervals.
    Stale,
    /// The server quarantined this device.
    Quarantined,
}

impl EmsState {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unconfigured => "unconfigured",
            Self::ManagedByForticlient => "managed-by-forticlient",
            Self::NotRegistered => "not-registered",
            Self::Registered => "registered",
            Self::Stale => "stale",
            Self::Quarantined => "quarantined",
        }
    }
}

/// One EMS registration's state and times.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmsStatusInfo {
    /// State.
    pub state: EmsState,
    /// Unix time of registration.
    pub registered_at: Option<u64>,
    /// Unix time of the last accepted keepalive.
    pub last_keepalive: Option<u64>,
    /// Whether the EMS has sent host-verification rules for this device. An EMS that knows
    /// the device and assigns it a policy sends them; none after a keepalive usually means
    /// the EMS doesn't recognize this Mac or its policy doesn't cover it.
    pub rules: Option<bool>,
}

impl EmsStatusInfo {
    fn bare(state: EmsState) -> Self {
        Self {
            state,
            registered_at: None,
            last_keepalive: None,
            rules: None,
        }
    }
}

/// Keepalives only run while a tunnel is up, so "stale" means "not checked in recently", not an
/// error.
fn registration_state(r: &crate::store::Registration, now: u64) -> EmsState {
    if r.quarantined {
        return EmsState::Quarantined;
    }
    let window = u64::from(r.full_ka_interval.max(r.ka_interval).max(60)).saturating_mul(3);
    match r.last_keepalive {
        Some(t) if now.saturating_sub(t) <= window => EmsState::Registered,
        _ => EmsState::Stale,
    }
}

/// What the EMS step decided for one attempt.
enum Prepared {
    /// Fortino is the agent for this EMS; `None` when it has no registration.
    Agent(Option<EmsIdentity>),
    /// FortiClient's agent manages this device on this EMS.
    Deferred(EmsIdentity),
}

/// One attempt's EMS context.
struct Ctx {
    registration_lock: Arc<tokio::sync::Mutex<()>>,
    settings: Arc<Settings>,
    facts: FactsSource,
    forticlient: FortiClientSource,
    server: EmsServer,
    server_settings: ServerSettings,
    connect_override: Option<std::net::SocketAddr>,
    /// Debug only: per-profile SYSINFO overrides for this attempt. Empty in normal use.
    overrides: std::collections::BTreeMap<String, String>,
}

impl Ctx {
    async fn facts(&self) -> Option<Facts> {
        let f = self.facts.clone();
        tokio::task::spawn_blocking(move || f())
            .await
            .ok()
            .flatten()
    }

    fn connection(&self) -> Result<Connection, Error> {
        let c = Connection::new(self.server.clone(), &self.server_settings.trust)?;
        Ok(match self.connect_override {
            Some(a) => c.connect_to(a),
            None => c,
        })
    }

    async fn agent(&self) -> Result<Agent, Error> {
        let facts = self
            .facts()
            .await
            .ok_or_else(|| Error::Store("host facts unavailable".into()))?;
        let uid_text = self
            .settings
            .uid
            .clone()
            .or_else(|| facts.platform_uuid.clone())
            .ok_or_else(|| Error::Store("no endpoint UID".into()))?;
        let uid = Uid::parse(&uid_text).map_err(|_| Error::Store("invalid endpoint UID".into()))?;
        Ok(Agent {
            compat: self.settings.compat.clone(),
            facts,
            uid,
            store: Store::open(&self.settings.state_dir)?,
            overrides: self.overrides.clone(),
        })
    }

    fn key(&self) -> Result<Option<zeroize::Zeroizing<String>>, Error> {
        let Some(p) = &self.server_settings.key_file else {
            return Ok(None);
        };
        let text =
            std::fs::read_to_string(p).map_err(|e| Error::Store(format!("EMS key file: {e}")))?;
        Ok(Some(zeroize::Zeroizing::new(text.trim().to_owned())))
    }

    /// The identity to give the worker. `Err` ends the attempt.
    async fn forticlient_state(&self) -> Option<FortiClientState> {
        let f = self.forticlient.clone();
        tokio::task::spawn_blocking(move || f())
            .await
            .ok()
            .flatten()
    }

    /// Whether FortiClient's agent is the active agent for this device on this EMS. Matches by
    /// address, by the serial of Fortino's own registration, or, failing both, by a PROBE
    /// (which registers nothing).
    async fn forticlient_manages(
        &self,
        agent: &Agent,
        conn: &Connection,
        fc: &FortiClientState,
    ) -> Result<bool, Error> {
        let Some(fc_serial) = fc.serial.as_ref().filter(|_| fc.active_with(&agent.uid)) else {
            return Ok(false);
        };
        if fc.uses_address(&self.server) {
            return Ok(true);
        }
        if let Some(r) = agent.registration(conn)? {
            return Ok(r.serial == fc_serial.as_str());
        }
        Ok(agent.probe(conn).await?.serial == *fc_serial)
    }

    /// The identity to give the worker, and this device's UID for the gateway. `Err` ends the
    /// attempt.
    async fn prepare(&self, install_uid: Option<&str>) -> Result<(Prepared, Uid), Error> {
        let _guard = self.registration_lock.lock().await;
        let mut agent = self.agent().await?;
        agent.compat.install_uid = install_uid.map(str::to_owned);
        let conn = self.connection()?;
        if let Some(fc) = self.forticlient_state().await {
            if self.forticlient_manages(&agent, &conn, &fc).await? {
                if let Some(serial) = &fc.serial {
                    tracing::info!(
                        ems = %self.server,
                        "FortiClient's EMS agent manages this device on this EMS; Fortino defers to it"
                    );
                    return Ok((
                        Prepared::Deferred(EmsIdentity {
                            serial: serial.to_string(),
                            tenant: fc
                                .tenant
                                .clone()
                                .unwrap_or_else(fortino_proto_ems::ids::Tenant::on_premises)
                                .as_str()
                                .to_owned(),
                        }),
                        agent.uid.clone(),
                    ));
                }
            }
        }
        if agent.registration(&conn)?.is_none() {
            if !self.server_settings.register {
                tracing::warn!(
                    ems = %self.server,
                    "not registered to this EMS and registration is not enabled for it; connecting without EMS identity"
                );
                return Ok((Prepared::Agent(None), agent.uid.clone()));
            }
            tracing::info!(ems = %self.server, "registering with EMS");
            let key = self.key()?;
            agent
                .register(&conn, key.as_deref().map(String::as_str))
                .await?;
        }
        Ok((
            Prepared::Agent(
                agent
                    .gateway_identity(&conn)?
                    .map(|(serial, tenant)| EmsIdentity {
                        serial: serial.to_string(),
                        tenant: tenant.as_str().to_owned(),
                    }),
            ),
            agent.uid.clone(),
        ))
    }

    /// Keepalives and host checks while the tunnel is up.
    async fn keep_alive(self: Arc<Self>) {
        tokio::time::sleep(self.settings.settle).await;
        let mut since_full = Duration::ZERO;
        let mut full = true;
        loop {
            let interval = match self.round(full).await {
                Ok(Some(i)) => i,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(ems = %self.server, error = %e, "EMS keepalive failed");
                    Duration::from_secs(60)
                }
            };
            tokio::time::sleep(interval).await;
            since_full += interval;
            full = false;
            if let Ok(agent) = self.agent().await {
                if let Ok(Some(r)) = self.connection().and_then(|c| agent.registration(&c)) {
                    if since_full >= Duration::from_secs(u64::from(r.full_ka_interval)) {
                        full = true;
                        since_full = Duration::ZERO;
                    }
                }
            }
        }
    }

    /// One keepalive (with fresh facts), then a host check after a full one. Returns the next
    /// interval, or `None` when the registration is gone.
    async fn round(&self, full: bool) -> Result<Option<Duration>, Error> {
        let agent = self.agent().await?;
        let conn = self.connection()?;
        // FortiClient may register to this EMS while the tunnel is up: then it takes over.
        if let (Some(fc), Some(r)) = (self.forticlient_state().await, agent.registration(&conn)?) {
            if fc.active_with(&agent.uid)
                && fc.serial.as_ref().is_some_and(|s| s.as_str() == r.serial)
            {
                tracing::info!(ems = %self.server, "FortiClient's EMS agent took over this EMS; Fortino stops its keepalives");
                return Ok(None);
            }
        }
        match agent.keepalive(&conn, full).await? {
            Keepalive::Dropped => {
                tracing::warn!(ems = %self.server, "the EMS dropped this device; its registration was removed");
                return Ok(None);
            }
            Keepalive::Kept { tags, renew } => {
                tracing::info!(ems = %self.server, full, tags = %tags, "EMS keepalive");
                if renew {
                    tracing::warn!(ems = %self.server, "the EMS asked for a new registration; not acted on yet");
                }
            }
        }
        if full {
            if let Some(tags) = agent.check_host(&conn).await? {
                tracing::info!(ems = %self.server, tags = %tags, "host verification reported");
            }
        }
        let secs = agent.registration(&conn)?.map_or(60, |r| r.ka_interval);
        Ok(Some(Duration::from_secs(u64::from(secs)).clamp(
            self.settings.min_ka_interval,
            Duration::from_secs(3600),
        )))
    }
}

fn termination(e: &Error) -> Termination {
    let code = match e {
        Error::Trust(_) => ErrorCode::TrustFailure,
        Error::Transport(_) => ErrorCode::TransportFailure,
        Error::RegistrationDisabled | Error::Refused(_) => ErrorCode::UnsupportedPolicy,
        Error::Protocol(_) | Error::NotRegistered | Error::Store(_) => ErrorCode::BackendFailure,
    };
    Termination {
        code: Some(code),
        message: format!("EMS: {e}").chars().take(200).collect(),
    }
}

impl WorkerFactory for EmsWorkers {
    fn spawn(&self, mut cfg: WorkerConfig) -> WorkerHandle {
        if cfg.fct_uid.is_none() {
            cfg.fct_uid = self.device_uid.clone();
        }
        let Some(server) = cfg.endpoint.ems.clone() else {
            return self.inner.spawn(cfg);
        };
        let Some(server_settings) = self.server_settings(&server) else {
            tracing::warn!(ems = %server, "profile names an EMS that is neither configured nor approved on this Mac; connecting without EMS");
            return self.inner.spawn(cfg);
        };
        let ctx = Arc::new(self.context(server, server_settings, cfg.debug_ems_sysinfo.clone()));
        let inner = self.inner.clone();
        let (ev_tx, ev_rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = ev_tx.send(WorkerEvent::Stage(WorkerStage::Transport)).await;
            let prepared = tokio::select! {
                r = ctx.prepare(None) => r,
                c = cmd_rx.recv() => {
                    if matches!(c, Some(WorkerCommand::Stop) | None) {
                        let _ = ev_tx.send(WorkerEvent::Terminated(Termination {
                            code: None,
                            message: "cancelled".into(),
                        })).await;
                        return;
                    }
                    // No challenge is outstanding yet; nothing else can arrive.
                    ctx.prepare(None).await
                }
            };
            let mut keep_alive = true;
            match prepared {
                Ok((Prepared::Agent(identity), uid)) => {
                    cfg.ems = identity;
                    cfg.fct_uid = Some(uid.to_string());
                }
                Ok((Prepared::Deferred(identity), uid)) => {
                    cfg.ems = Some(identity);
                    cfg.fct_uid = Some(uid.to_string());
                    keep_alive = false;
                }
                Err(e) => {
                    tracing::warn!(ems = %ctx.server, error = %e, "EMS step failed");
                    let _ = ev_tx.send(WorkerEvent::Terminated(termination(&e))).await;
                    return;
                }
            }
            let mut h = inner.spawn(cfg);
            let mut ka: Option<JoinHandle<()>> = None;
            loop {
                tokio::select! {
                    ev = h.events.recv() => {
                        let Some(ev) = ev else { break };
                        let up = matches!(ev, WorkerEvent::Up(_));
                        let last = matches!(ev, WorkerEvent::Terminated(_));
                        if last {
                            if let Some(t) = ka.take() {
                                t.abort();
                            }
                        }
                        if ev_tx.send(ev).await.is_err() {
                            break;
                        }
                        if up && keep_alive && ka.is_none() {
                            ka = Some(tokio::spawn(ctx.clone().keep_alive()));
                        }
                        if last {
                            break;
                        }
                    }
                    c = cmd_rx.recv() => {
                        let c = c.unwrap_or(WorkerCommand::Stop);
                        if h.commands.send(c).await.is_err() {
                            // The worker ended; its Terminated event is still queued.
                        }
                    }
                }
            }
            if let Some(t) = ka.take() {
                t.abort();
            }
        });
        WorkerHandle {
            events: ev_rx,
            commands: cmd_tx,
        }
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;

    #[test]
    fn marker_content_selects_trust() {
        let ca = std::path::Path::new("/etc/ssl/cert.pem");
        assert!(matches!(marker_trust("", ca), Some(Trust::CaFile(_))));
        assert!(matches!(marker_trust("\n", ca), Some(Trust::CaFile(_))));
        let pin = "ab".repeat(32);
        match marker_trust(&format!("{pin}\n"), ca) {
            Some(Trust::Pinned(p)) => assert_eq!(p, vec![[0xab; 32]]),
            other => panic!("expected a pin, got {other:?}"),
        }
        assert!(marker_trust("not a pin", ca).is_none());
        assert!(marker_trust(&"ab".repeat(31), ca).is_none());
    }
}

#[cfg(test)]
mod status_tests {
    use super::*;
    use crate::store::{Received, Registration};

    fn reg() -> Registration {
        Registration {
            server: "ems.test:8013".into(),
            install_uid: None,
            uid: "0A1B2C3D4E5F60718293A4B5C6D7E8F9".into(),
            serial: "FCTEMS0000000001".into(),
            host: "ems.test".into(),
            tenant: None,
            vdom: "default".into(),
            ka_interval: 60,
            full_ka_interval: 600,
            tags: String::new(),
            rules_sent: String::new(),
            quarantined: false,
            conf: Received::default(),
            host_rules: Received::default(),
            server_list: Received::default(),
            on_net: Received::default(),
            off_net: Received::default(),
            registered_at: 1,
            last_keepalive: None,
        }
    }

    #[test]
    fn states_from_record() {
        let mut r = reg();
        assert_eq!(registration_state(&r, 10_000), EmsState::Stale);
        r.last_keepalive = Some(9_000);
        assert_eq!(registration_state(&r, 10_000), EmsState::Registered);
        assert_eq!(registration_state(&r, 9_000 + 1_801), EmsState::Stale);
        r.quarantined = true;
        assert_eq!(registration_state(&r, 10_000), EmsState::Quarantined);
    }
}
