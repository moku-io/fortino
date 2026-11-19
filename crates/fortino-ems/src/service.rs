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

/// Agent settings.
#[derive(Debug, Clone)]
pub struct Settings {
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
pub struct EmsWorkers {
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
            inner,
            settings: Arc::new(settings),
            facts,
            forticlient: crate::forticlient::source(None),
            device_uid,
            connect_override: None,
        }
    }

    /// Defers to an installed FortiClient's EMS agent where it manages the same device on the
    /// same EMS (see [`crate::forticlient`]).
    pub fn with_forticlient(mut self, source: FortiClientSource) -> Self {
        self.forticlient = source;
        self
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
    settings: Arc<Settings>,
    facts: FactsSource,
    forticlient: FortiClientSource,
    server: EmsServer,
    server_settings: ServerSettings,
    connect_override: Option<std::net::SocketAddr>,
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
    async fn prepare(&self) -> Result<(Prepared, Uid), Error> {
        let agent = self.agent().await?;
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
        Error::Refused(_) => ErrorCode::UnsupportedPolicy,
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
        let Some(server_settings) = self.settings.servers.get(&server_key(&server)).cloned() else {
            tracing::warn!(ems = %server, "profile names an EMS with no trust configured; connecting without EMS");
            return self.inner.spawn(cfg);
        };
        let ctx = Arc::new(Ctx {
            settings: self.settings.clone(),
            facts: self.facts.clone(),
            forticlient: self.forticlient.clone(),
            server,
            server_settings,
            connect_override: self.connect_override,
        });
        let inner = self.inner.clone();
        let (ev_tx, ev_rx) = mpsc::channel(16);
        let (cmd_tx, mut cmd_rx) = mpsc::channel(4);
        tokio::spawn(async move {
            let _ = ev_tx.send(WorkerEvent::Stage(WorkerStage::Transport)).await;
            let prepared = tokio::select! {
                r = ctx.prepare() => r,
                c = cmd_rx.recv() => {
                    if matches!(c, Some(WorkerCommand::Stop) | None) {
                        let _ = ev_tx.send(WorkerEvent::Terminated(Termination {
                            code: None,
                            message: "cancelled".into(),
                        })).await;
                        return;
                    }
                    // No challenge is outstanding yet; nothing else can arrive.
                    ctx.prepare().await
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
