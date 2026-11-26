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
    EMS_REGISTRATION_REQUIRED, EmsIdentity, Termination, WorkerCommand, WorkerConfig, WorkerEvent,
    WorkerFactory, WorkerHandle, WorkerStage,
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
        let (_, content) =
            fortino_tls::markers::read_protected(&self.directory, &server_key(server), 0)?;
        marker_trust(&content, &self.ca_file)
    }

    /// Withdraws the approval of `server`. Returns whether there was one.
    fn withdraw(&self, server: &EmsServer) -> Result<bool, Error> {
        let path = self
            .directory
            .join(fortino_tls::markers::marker_name(&server_key(server)));
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Store(format!("remove EMS approval: {e}"))),
        }
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
    /// Wait after a keepalive round that failed before trying again (60 s in production).
    pub retry: Duration,
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
    refusals: Refusals,
    inner: Arc<dyn WorkerFactory>,
    settings: Arc<Settings>,
    facts: FactsSource,
    forticlient: FortiClientSource,
    /// This device's UID, for gateways that ask for it (`/remote/info` `0x80`) whether or not
    /// the profile names an EMS: the gateway asks for the endpoint, not for an EMS identity.
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
            refusals: Refusals::default(),
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
            refusals: self.refusals.clone(),
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

    /// Explicit enrollment without a VPN tunnel, with a deployment package's installer ID or
    /// without one (**Register Now**). Uses the same registration as connect.
    pub async fn enroll(
        &self,
        server: EmsServer,
        install_uid: Option<&str>,
    ) -> Result<(&'static str, bool), Error> {
        if install_uid.is_some_and(|id| {
            id.is_empty()
                || id.len() > 256
                || !id.bytes().all(|b| b.is_ascii_graphic() && b != b'|')
        }) {
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
        match ctx.prepare(install_uid).await?.0 {
            Prepared::Deferred(_) => Ok(("managed-by-forticlient", false)),
            Prepared::HeldByForticlient => Ok(("held-by-forticlient", false)),
            Prepared::Agent(Some(_)) => {
                let record = Store::open(&ctx.settings.state_dir)?
                    .load(&server_key(&ctx.server))?
                    .ok_or(Error::NotRegistered)?;
                let status = match install_uid {
                    Some(id) if record.install_uid.as_deref() != Some(id) => {
                        "existing-registration"
                    }
                    _ => "registered",
                };
                Ok((status, record.host_rules.content.is_some()))
            }
            Prepared::Agent(None) => Err(Error::NotRegistered),
        }
    }

    /// This device's registration state with `server`, from local records only: no network
    /// exchange, nothing created. Reveals no serial, UID or keys.
    pub fn status(&self, server: &EmsServer) -> Result<EmsStatusInfo, Error> {
        let Some(settings) = self.server_settings(server) else {
            return Ok(EmsStatusInfo::bare(EmsState::Unconfigured));
        };
        let mut info = self.registration_status(server)?;
        info.key = settings.key_file.is_some()
            || Store::open(&self.settings.state_dir)?
                .load_key(&server_key(server))?
                .is_some();
        if info.state == EmsState::NotRegistered {
            info.refusal = self.refusals.get(server);
        }
        Ok(info)
    }

    fn registration_status(&self, server: &EmsServer) -> Result<EmsStatusInfo, Error> {
        // The same rules as a connect: FortiClient's registration is used only when it has
        // this device's UID; under another UID it still holds this Mac's place on the EMS.
        let uid = self.device_uid.as_deref().and_then(|u| Uid::parse(u).ok());
        // As in a connect: FortiClient is on this EMS if it uses this address, or if its serial
        // is the one Fortino's own registration with this server holds (the EMS reached by
        // another name or address). Local records only: no PROBE here.
        let record = self.own_registration(&Store::open(&self.settings.state_dir)?, server)?;
        if let Some(fc) = (self.forticlient)().filter(|fc| {
            fc.running
                && fc.serial.as_ref().is_some_and(|s| {
                    fc.uses_address(server)
                        || record.as_ref().is_some_and(|r| r.serial == s.as_str())
                })
        }) {
            return Ok(EmsStatusInfo::bare(
                if uid.as_ref().is_some_and(|u| fc.active_with(u)) {
                    EmsState::ManagedByForticlient
                } else {
                    EmsState::HeldByForticlient
                },
            ));
        }
        let Some(r) = record else {
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
            key: false,
            refusal: None,
        })
    }

    /// This device's record for `server`, as a connect sees it: a record another device made (a
    /// copied state directory, or one made under another `[ems] uid`) is not this Mac's.
    fn own_registration(
        &self,
        store: &Store,
        server: &EmsServer,
    ) -> Result<Option<crate::store::Registration>, Error> {
        Ok(store
            .load(&server_key(server))?
            .filter(|r| r.device_uid.is_none() || r.device_uid == self.device_uid))
    }

    /// Saves the connection key the user gave for `server` (`Some`), or removes it (`None`).
    /// The next registration sends it. A key in the daemon configuration takes precedence, and
    /// saving needs the server to be configured or approved on this Mac. Returns the outcome:
    /// `saved`, `removed`, `none` (nothing to remove), `configured` (the configuration's key
    /// is used; nothing changed) or `approval-required`. Never returns the key.
    pub fn set_key(&self, server: &EmsServer, key: Option<&str>) -> Result<&'static str, Error> {
        let store = Store::open(&self.settings.state_dir)?;
        let name = server_key(server);
        let Some(key) = key else {
            let removed = store.remove_key(&name)?;
            return Ok(if removed { "removed" } else { "none" });
        };
        check_key(key).map_err(|e| Error::Protocol(e.into()))?;
        match self.server_settings(server) {
            None => return Ok("approval-required"),
            Some(s) if s.key_file.is_some() => return Ok("configured"),
            Some(_) => {}
        }
        store.save_key(&name, key)?;
        // The refusal was for the previous key (or none).
        self.refusals.clear(server);
        tracing::info!(ems = %server, "connection key saved");
        Ok("saved")
    }

    /// Removes the saved connection keys of servers no profile names any more (`in_use` holds
    /// server keys, as [`server_key`] gives them). A key only serves registrations for profiles
    /// that use its server. Returns how many were removed.
    pub fn forget_unused_keys(
        &self,
        in_use: &std::collections::HashSet<String>,
    ) -> Result<usize, Error> {
        let store = Store::open(&self.settings.state_dir)?;
        let mut n = 0;
        for server in store.key_servers()? {
            if !in_use.contains(&server) && store.remove_key(&server)? {
                tracing::info!(ems = %server, "no profile uses this EMS any more; its connection key was removed");
                n += 1;
            }
        }
        Ok(n)
    }

    /// Leaves `server`: asks the EMS to remove this device's record (Fortino's own
    /// registration only, never one FortiClient's agent uses), then forgets the local
    /// registration, the saved connection key and this Mac's approval of the server. Local
    /// state goes even when the EMS can't be reached or keeps the record. A server listed in
    /// the daemon configuration stays configured.
    pub async fn leave(&self, server: &EmsServer) -> Result<Left, Error> {
        let _guard = self.registration_lock.lock().await;
        let name = server_key(server);
        let store = Store::open(&self.settings.state_dir)?;
        let mut left = Left::default();
        if self.own_registration(&store, server)?.is_some() {
            match self.server_settings(server) {
                Some(settings) => {
                    let ctx = self.context(server.clone(), settings, Default::default());
                    match ctx.deregister().await {
                        Ok(()) => left.deregistered = true,
                        Err(e) => {
                            tracing::warn!(ems = %server, error = %e, "the EMS kept this device's record");
                            left.kept = Some(e.to_string());
                        }
                    }
                }
                None => left.kept = Some("the server isn't approved on this Mac".into()),
            }
        }
        // Also a record another device made: it goes from this Mac, and its EMS record stays
        // untouched (this Mac can't speak for that device).
        store.remove(&name)?;
        store.remove_key(&name)?;
        self.refusals.clear(server);
        if let Some(a) = &self.settings.package_approvals {
            left.approval_withdrawn = a.withdraw(server)?;
        }
        tracing::info!(ems = %server, deregistered = left.deregistered, "left EMS");
        Ok(left)
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
    /// FortiClient's agent is registered with this EMS under another device UID. The EMS
    /// keeps one registration per Mac, so Fortino neither registers nor uses FortiClient's.
    HeldByForticlient,
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
            Self::HeldByForticlient => "held-by-forticlient",
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
    /// Whether a connection key is set for this server (in the configuration or by the user).
    pub key: bool,
    /// Why the EMS refused this device's last registration, while it is not registered.
    pub refusal: Option<Refusal>,
}

impl EmsStatusInfo {
    fn bare(state: EmsState) -> Self {
        Self {
            state,
            registered_at: None,
            last_keepalive: None,
            rules: None,
            key: false,
            refusal: None,
        }
    }
}

/// What [`EmsWorkers::leave`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Left {
    /// The EMS removed this device's record.
    pub deregistered: bool,
    /// Why a registration's record stayed on the EMS.
    pub kept: Option<String>,
    /// This Mac's approval of the server was withdrawn.
    pub approval_withdrawn: bool,
}

/// A registration the EMS refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The reason, with the EMS's own message when it gave one.
    pub reason: String,
    /// The EMS wants a connection key, or a different one.
    pub key: bool,
}

/// The last refusal per server, kept in memory until a registration succeeds or the key changes.
#[derive(Debug, Clone, Default)]
struct Refusals(Arc<std::sync::Mutex<HashMap<String, Refusal>>>);

impl Refusals {
    fn map(&self) -> std::sync::MutexGuard<'_, HashMap<String, Refusal>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn get(&self, server: &EmsServer) -> Option<Refusal> {
        self.map().get(&server_key(server)).cloned()
    }

    fn clear(&self, server: &EmsServer) {
        self.map().remove(&server_key(server));
    }

    /// Records the outcome of one registration.
    fn record<T>(&self, server: &EmsServer, r: &Result<T, Error>) {
        let refusal = match r {
            Ok(_) => None,
            Err(Error::KeyRefused(m)) => Some(Refusal {
                reason: m.clone(),
                key: true,
            }),
            Err(Error::Refused(m)) => Some(Refusal {
                reason: m.clone(),
                key: false,
            }),
            // Not an answer from the EMS: keep what it said last.
            Err(_) => return,
        };
        let mut map = self.map();
        match refusal {
            Some(f) => map.insert(server_key(server), f),
            None => map.remove(&server_key(server)),
        };
    }
}

/// Longest connection key accepted.
pub const MAX_KEY_LEN: usize = 256;

/// Checks a connection key before it is saved. It travels as one SYSINFO value, so it can't
/// hold the field separator.
pub fn check_key(key: &str) -> Result<(), &'static str> {
    if key.is_empty() {
        return Err("the connection key is empty");
    }
    if key.len() > MAX_KEY_LEN {
        return Err("the connection key is too long");
    }
    if key.trim() != key {
        return Err("the connection key starts or ends with a space");
    }
    if key.chars().any(|c| c.is_control() || c == '|') {
        return Err("the connection key contains a control character or '|'");
    }
    Ok(())
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
    /// FortiClient's agent is registered with this EMS under another UID: no identity, and
    /// nothing sent to the EMS.
    HeldByForticlient,
}

/// One attempt's EMS context.
struct Ctx {
    registration_lock: Arc<tokio::sync::Mutex<()>>,
    refusals: Refusals,
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

    /// The connection key: the configuration's key file, else the key the user saved.
    fn key(&self) -> Result<Option<zeroize::Zeroizing<String>>, Error> {
        let Some(p) = &self.server_settings.key_file else {
            return Store::open(&self.settings.state_dir)?.load_key(&server_key(&self.server));
        };
        let text = zeroize::Zeroizing::new(
            std::fs::read_to_string(p).map_err(|e| Error::Store(format!("EMS key file: {e}")))?,
        );
        Ok(Some(zeroize::Zeroizing::new(text.trim().to_owned())))
    }

    /// REGISTER with the connection key, remembering a refusal for EMS Setup.
    async fn register(&self, agent: &Agent, conn: &Connection) -> Result<(), Error> {
        let key = self.key()?;
        let r = agent
            .register(conn, key.as_deref().map(String::as_str))
            .await;
        self.refusals.record(&self.server, &r);
        r.map(|_| ())
    }

    /// The identity to give the worker. `Err` ends the attempt.
    async fn forticlient_state(&self) -> Option<FortiClientState> {
        let f = self.forticlient.clone();
        tokio::task::spawn_blocking(move || f())
            .await
            .ok()
            .flatten()
    }

    /// Why an attempt goes without an EMS serial, in words for the user.
    fn no_identity_hint(&self) -> &'static str {
        if self.server_settings.register {
            "Fortino has no registration with this EMS; open EMS Setup to register this Mac."
        } else {
            "Fortino isn't registered with this EMS, and registering with it isn't enabled on this Mac; ask your IT administrator."
        }
    }

    /// Whether FortiClient's agent is running and registered with this EMS, under any UID.
    /// Matches by address, by the serial of Fortino's own registration, or, failing both, by a
    /// PROBE (which registers nothing).
    async fn forticlient_on_this_ems(
        &self,
        agent: &Agent,
        conn: &Connection,
        fc: &FortiClientState,
    ) -> Result<bool, Error> {
        let Some(fc_serial) = fc.serial.as_ref().filter(|_| fc.running) else {
            return Ok(false);
        };
        if fc.uses_address(&self.server) {
            return Ok(true);
        }
        if let Some(r) = agent.registration(conn)? {
            return Ok(r.serial == fc_serial.as_str());
        }
        match agent.probe(conn).await {
            Ok(p) => Ok(p.serial == *fc_serial),
            // Without permission to register nothing can push FortiClient out, so an EMS that
            // doesn't answer is no reason to end the attempt: it goes on without an identity,
            // as it would without FortiClient.
            Err(e) if !self.server_settings.register => {
                tracing::info!(ems = %self.server, error = %e, "EMS probe failed; connecting without EMS identity");
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// The identity to give the worker, and this device's UID for the gateway. `Err` ends the
    /// attempt.
    async fn prepare(&self, install_uid: Option<&str>) -> Result<(Prepared, Uid), Error> {
        let _guard = self.registration_lock.lock().await;
        let mut agent = self.agent().await?;
        agent.compat.install_uid = install_uid.map(str::to_owned);
        let conn = self.connection()?;
        if let Some(fc) = self.forticlient_state().await {
            if self.forticlient_on_this_ems(&agent, &conn, &fc).await? {
                // The EMS keeps one registration per Mac: a registration under another UID
                // ends FortiClient's (observed: its next keepalive is discontinued and it
                // registers again, ending ours). Leave this EMS to FortiClient.
                if fc.uid.as_ref() != Some(&agent.uid) {
                    tracing::warn!(
                        ems = %self.server,
                        "FortiClient's EMS agent is registered with this EMS under another device UID; Fortino neither registers nor uses its registration"
                    );
                    return Ok((Prepared::HeldByForticlient, agent.uid.clone()));
                }
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
            self.register(&agent, &conn).await?;
        }
        // The gateway gets the UID the EMS knows this device by: the registration's, which
        // the EMS may have assigned (NEW_GUID), so tags and the tunnel address line up.
        let gateway_uid = agent
            .registration(&conn)?
            .and_then(|r| Uid::parse(&r.uid).ok())
            .unwrap_or_else(|| agent.uid.clone());
        Ok((
            Prepared::Agent(
                agent
                    .gateway_identity(&conn)?
                    .map(|(serial, tenant)| EmsIdentity {
                        serial: serial.to_string(),
                        tenant: tenant.as_str().to_owned(),
                    }),
            ),
            gateway_uid,
        ))
    }

    /// Deregisters Fortino's own registration. Refused when FortiClient's agent uses the same
    /// device record (same UID on this EMS): removing it would remove FortiClient's too.
    async fn deregister(&self) -> Result<(), Error> {
        let agent = self.agent().await?;
        let conn = self.connection()?;
        if let Some(fc) = self.forticlient_state().await {
            if fc.active_with(&agent.uid)
                && self.forticlient_on_this_ems(&agent, &conn, &fc).await?
            {
                return Err(Error::Refused(
                    "FortiClient's EMS agent uses the same device record".into(),
                ));
            }
        }
        agent.deregister(&conn).await
    }

    /// Keepalives and host checks while the tunnel is up.
    async fn keep_alive(self: Arc<Self>) {
        tokio::time::sleep(self.settings.settle).await;
        let mut since_full = Duration::ZERO;
        let mut full = true;
        let mut registered_again: Option<tokio::time::Instant> = None;
        loop {
            let interval = match self.round(full).await {
                Ok(Round::Next(i)) => {
                    if full {
                        // The EMS has the tunnel address and the host check; the next full
                        // keepalive is a full interval away.
                        full = false;
                        since_full = Duration::ZERO;
                    }
                    i
                }
                Ok(Round::Stop) => return,
                Ok(Round::Dropped) => {
                    // Dropped again soon after registering again: something else keeps taking
                    // this Mac's registration (or the EMS refuses it). Don't loop.
                    if registered_again.is_some_and(|t| t.elapsed() < REREGISTER_WINDOW) {
                        tracing::warn!(ems = %self.server, "the EMS dropped this device again; Fortino stops its keepalives");
                        return;
                    }
                    match self.register_again().await {
                        Ok(true) => {
                            registered_again = Some(tokio::time::Instant::now());
                            // A full keepalive right away, so the EMS learns the tunnel
                            // address of the new registration.
                            full = true;
                            since_full = Duration::ZERO;
                            continue;
                        }
                        Ok(false) => return,
                        Err(e) => {
                            tracing::warn!(ems = %self.server, error = %e, "registering again with the EMS failed; Fortino stops its keepalives");
                            return;
                        }
                    }
                }
                // Retried as it was: a full keepalive that didn't get through still has to tell
                // the EMS the tunnel address, which gateways that admit by tag depend on.
                Err(e) => {
                    tracing::warn!(ems = %self.server, error = %e, "EMS keepalive failed");
                    self.settings.retry
                }
            };
            tokio::time::sleep(interval).await;
            since_full += interval;
            if full {
                continue;
            }
            if let Ok(agent) = self.agent().await {
                if let Ok(Some(r)) = self.connection().and_then(|c| agent.registration(&c)) {
                    if since_full >= Duration::from_secs(u64::from(r.full_ka_interval)) {
                        full = true;
                    }
                }
            }
        }
    }

    /// After the EMS dropped this device during a session: registers again, unless
    /// registration isn't allowed for this server or FortiClient's agent is on this EMS (the
    /// EMS keeps one registration per Mac, so registering would push FortiClient out).
    /// Returns whether keepalives should go on.
    async fn register_again(&self) -> Result<bool, Error> {
        if !self.server_settings.register {
            tracing::warn!(ems = %self.server, "the EMS dropped this device and registering isn't enabled for it; Fortino stops its keepalives");
            return Ok(false);
        }
        let _guard = self.registration_lock.lock().await;
        let agent = self.agent().await?;
        let conn = self.connection()?;
        if let Some(fc) = self.forticlient_state().await {
            if self.forticlient_on_this_ems(&agent, &conn, &fc).await? {
                tracing::info!(ems = %self.server, "the EMS dropped this device and FortiClient's agent is on this EMS; Fortino leaves it to FortiClient");
                return Ok(false);
            }
        }
        if agent.registration(&conn)?.is_none() {
            self.register(&agent, &conn).await?;
        }
        tracing::info!(ems = %self.server, "the EMS dropped this device; Fortino registered it again");
        Ok(true)
    }

    /// One keepalive (with fresh facts), then a host check after a full one.
    async fn round(&self, full: bool) -> Result<Round, Error> {
        let agent = self.agent().await?;
        let conn = self.connection()?;
        // FortiClient may register to this EMS while the tunnel is up: then it takes over.
        if let (Some(fc), Some(r)) = (self.forticlient_state().await, agent.registration(&conn)?) {
            if fc.active_with(&agent.uid)
                && fc.serial.as_ref().is_some_and(|s| s.as_str() == r.serial)
            {
                tracing::info!(ems = %self.server, "FortiClient's EMS agent took over this EMS; Fortino stops its keepalives");
                return Ok(Round::Stop);
            }
        }
        match agent.keepalive(&conn, full).await? {
            Keepalive::Dropped => {
                tracing::warn!(ems = %self.server, "the EMS dropped this device; its registration was removed");
                return Ok(Round::Dropped);
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
        Ok(Round::Next(Duration::from_secs(u64::from(secs)).clamp(
            self.settings.min_ka_interval,
            Duration::from_secs(3600),
        )))
    }
}

/// What one keepalive round decided.
enum Round {
    /// Keep going after this interval.
    Next(Duration),
    /// The EMS dropped this device (its local registration is already removed).
    Dropped,
    /// Stop the keepalives.
    Stop,
}

/// A second drop within this time of registering again stops the keepalives.
const REREGISTER_WINDOW: Duration = Duration::from_secs(600);

/// Added to the worker's message when the gateway wanted an EMS serial and the profile's EMS
/// server is neither configured nor approved on this Mac.
const UNAPPROVED_HINT: &str = "Fortino can't register with this profile's EMS server until it is approved on this Mac: approve it on the profile's EMS row, then connect again.";

/// Added when FortiClient's agent holds this Mac's registration with the profile's EMS.
const FORTICLIENT_HOLDS_HINT: &str = "FortiClient on this Mac is registered with this EMS, and the EMS keeps one registration per Mac. Open EMS Setup to choose: disconnect FortiClient from the EMS, remove FortiClient, or use FortiClient for this VPN.";

/// Appends `hint` to a termination caused by a missing EMS serial.
fn annotate(ev: &mut WorkerEvent, hint: Option<&str>) {
    if let (WorkerEvent::Terminated(t), Some(hint)) = (ev, hint) {
        if t.code == Some(ErrorCode::UnsupportedPolicy)
            && t.message.contains(EMS_REGISTRATION_REQUIRED)
        {
            t.message = format!("{}. {hint}", t.message);
        }
    }
}

/// Relays `inner`, annotating its termination with `hint`.
fn with_hint(mut inner: WorkerHandle, hint: String) -> WorkerHandle {
    let (ev_tx, ev_rx) = mpsc::channel(16);
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<WorkerCommand>(4);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                ev = inner.events.recv() => {
                    let Some(mut ev) = ev else { break };
                    annotate(&mut ev, Some(&hint));
                    let last = matches!(ev, WorkerEvent::Terminated(_));
                    if ev_tx.send(ev).await.is_err() || last {
                        break;
                    }
                }
                c = cmd_rx.recv() => {
                    let c = c.unwrap_or(WorkerCommand::Stop);
                    // A send error means the worker ended; its Terminated event is still queued.
                    let _ = inner.commands.send(c).await;
                }
            }
        }
    });
    WorkerHandle {
        events: ev_rx,
        commands: cmd_tx,
    }
}

fn termination(e: &Error) -> Termination {
    let code = match e {
        Error::Trust(_) => ErrorCode::TrustFailure,
        Error::Transport(_) => ErrorCode::TransportFailure,
        Error::RegistrationDisabled | Error::Refused(_) | Error::KeyRefused(_) => {
            ErrorCode::UnsupportedPolicy
        }
        Error::Protocol(_) | Error::NotRegistered | Error::Store(_) => ErrorCode::BackendFailure,
    };
    let mut message: String = format!("EMS: {e}").chars().take(200).collect();
    if matches!(e, Error::KeyRefused(_)) {
        message.push_str(". ");
        message.push_str(KEY_HINT);
    }
    Termination {
        code: Some(code),
        message,
    }
}

/// Added when the EMS refused the registration for its connection key.
const KEY_HINT: &str = "Enter the connection key from your IT administrator in EMS Setup.";

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
            return with_hint(self.inner.spawn(cfg), UNAPPROVED_HINT.to_owned());
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
            let mut hint = None;
            match prepared {
                Ok((Prepared::Agent(identity), uid)) => {
                    if identity.is_none() {
                        hint = Some(ctx.no_identity_hint().to_owned());
                        // No registration, so nothing to keep alive.
                        keep_alive = false;
                    }
                    cfg.ems = identity;
                    cfg.fct_uid = Some(uid.to_string());
                }
                Ok((Prepared::Deferred(identity), uid)) => {
                    cfg.ems = Some(identity);
                    cfg.fct_uid = Some(uid.to_string());
                    keep_alive = false;
                }
                Ok((Prepared::HeldByForticlient, uid)) => {
                    cfg.ems = None;
                    cfg.fct_uid = Some(uid.to_string());
                    keep_alive = false;
                    hint = Some(FORTICLIENT_HOLDS_HINT.to_owned());
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
                        let Some(mut ev) = ev else { break };
                        annotate(&mut ev, hint.as_deref());
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

    #[test]
    fn withdrawing_removes_the_servers_marker_only() {
        let d = tempfile::tempdir().unwrap();
        let approvals = PackageApprovals {
            directory: d.path().into(),
            ca_file: "/etc/ssl/cert.pem".into(),
        };
        let a: EmsServer = "EMS-A.test:8013".parse().unwrap();
        let b: EmsServer = "ems-b.test:8013".parse().unwrap();
        let marker = |s: &EmsServer| {
            d.path()
                .join(fortino_tls::markers::marker_name(&server_key(s)))
        };
        std::fs::write(marker(&a), "").unwrap();
        std::fs::write(marker(&b), "").unwrap();
        assert!(approvals.withdraw(&a).unwrap());
        assert!(!approvals.withdraw(&a).unwrap());
        assert!(!marker(&a).exists());
        assert!(marker(&b).exists());
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn keys_are_checked() {
        assert!(check_key("k3y-With.Symbols!").is_ok());
        assert!(check_key("chiave è").is_ok());
        assert!(check_key("").is_err());
        assert!(check_key(" k3y").is_err());
        assert!(check_key("k3y\n").is_err());
        assert!(check_key("a|b").is_err());
        assert!(check_key(&"x".repeat(MAX_KEY_LEN)).is_ok());
        assert!(check_key(&"x".repeat(MAX_KEY_LEN + 1)).is_err());
    }

    #[test]
    fn refusals_follow_registrations() {
        let r = Refusals::default();
        let a: EmsServer = "ems-a.test:8013".parse().unwrap();
        let b: EmsServer = "ems-b.test:8013".parse().unwrap();
        r.record::<()>(&a, &Err(Error::KeyRefused("no key".into())));
        r.record::<()>(&b, &Err(Error::Refused("blocked".into())));
        assert_eq!(r.get(&a).map(|f| f.key), Some(true));
        assert_eq!(r.get(&b).map(|f| f.key), Some(false));
        // A network failure says nothing new about the EMS's answer.
        r.record::<()>(&a, &Err(Error::Transport("down".into())));
        assert!(r.get(&a).is_some());
        r.record(&a, &Ok(()));
        assert!(r.get(&a).is_none());
        r.clear(&b);
        assert!(r.get(&b).is_none());
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
            device_uid: None,
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
