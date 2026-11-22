//! The single machine-wide session slot, its state machine and challenges.
//!
//! All state lives in one [`Inner`] behind a mutex, so slot acquisition, challenge answers and
//! stop requests serialize. Every change bumps `seq` and is broadcast as a [`Snapshot`]; each
//! subscriber sees it filtered through [`Snapshot::view`] for its own UID.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::{Notify, broadcast, mpsc};
use tokio::time::Instant;

use fortino_config::{IpPolicy, Profile, ProfileId, ProfileStore, StoreError};
use fortino_core::proto::{
    Challenge, ChallengeKind, ConnectParams, ConnectResult, LastResult, State, Status,
};
use fortino_core::worker::{
    Termination, WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory, WorkerStage,
};
use fortino_core::{ErrorCode, ProtoError};
use fortino_secret::Secret;

use crate::auth::Peer;
use crate::config::Timeouts;
use crate::netctl::{NetController, NetError};

/// Broadcast capacity; a subscriber that falls further behind gets resync-required.
pub const EVENT_CAPACITY: usize = 64;
/// Maximum remembered connect request keys.
const MAX_REQUEST_KEYS: usize = 1024;
/// Maximum length of a username, request key or ID in a request.
pub const MAX_TOKEN_LEN: usize = 256;

#[derive(Debug, Clone)]
struct PendingChallenge {
    id: String,
    kind: ChallengeKind,
    prompt: String,
    deadline: Instant,
}

#[derive(Debug, Clone)]
struct StopCause {
    code: Option<ErrorCode>,
    message: String,
}

#[derive(Debug)]
struct Active {
    attempt_id: String,
    owner: u32,
    profile: Profile,
    cmd: mpsc::Sender<WorkerCommand>,
    wake: Arc<Notify>,
    challenge: Option<PendingChallenge>,
    assigned_ip: Option<String>,
    interface: Option<String>,
    connected_since: Option<u64>,
    stop: Option<StopCause>,
    stop_deadline: Option<Instant>,
    /// Deadline for the worker's next step while no challenge is outstanding.
    progress_deadline: Option<Instant>,
    network_applied: bool,
    /// Sequence number when the attempt started (what other users see).
    start_seq: u64,
}

#[derive(Debug, Clone)]
struct Finished {
    owner: u32,
    attempt_id: String,
    profile_id: ProfileId,
    profile_name: String,
    gateway: String,
    ip_policy: IpPolicy,
    result: LastResult,
}

/// Snapshot of an active attempt for viewing.
#[derive(Debug, Clone)]
struct ActiveView {
    start_seq: u64,
    attempt_id: String,
    owner: u32,
    profile_id: ProfileId,
    profile_name: String,
    gateway: String,
    ip_policy: IpPolicy,
    assigned_ip: Option<String>,
    interface: Option<String>,
    connected_since: Option<u64>,
    challenge: Option<PendingChallenge>,
}

/// Daemon-wide state at one sequence number.
#[derive(Debug, Clone)]
pub struct Snapshot {
    instance: String,
    seq: u64,
    state: State,
    active: Option<ActiveView>,
    last: Option<Finished>,
}

impl Snapshot {
    /// Sequence number.
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// The status as `peer` may see it. Other users only learn that the VPN is in use.
    pub fn view(&self, peer: Peer) -> Status {
        let mut st = Status::bare(&self.instance, self.seq, self.state);
        let allowed = |owner: u32| peer.admin || owner == peer.uid;
        if let Some(a) = &self.active {
            if !allowed(a.owner) {
                // Only reveal that the VPN is in use, not how the attempt progresses.
                st.state = State::InUse;
                st.seq = a.start_seq;
                return st;
            }
            st.attempt_id = Some(a.attempt_id.clone());
            st.profile_id = Some(a.profile_id.clone());
            st.profile_name = Some(a.profile_name.clone());
            st.gateway = Some(a.gateway.clone());
            st.ip_policy = Some(a.ip_policy);
            st.assigned_ip.clone_from(&a.assigned_ip);
            st.interface.clone_from(&a.interface);
            st.connected_since = a.connected_since;
            // Only the owner can answer, so only the owner sees the challenge.
            if a.owner == peer.uid
                && let Some(c) = &a.challenge
            {
                st.challenge = Some(Challenge {
                    id: c.id.clone(),
                    kind: c.kind,
                    prompt: c.prompt.clone(),
                    expires_in_secs: c
                        .deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs(),
                });
            }
        } else if let Some(f) = &self.last
            && allowed(f.owner)
        {
            st.attempt_id = Some(f.attempt_id.clone());
            st.profile_id = Some(f.profile_id.clone());
            st.profile_name = Some(f.profile_name.clone());
            st.gateway = Some(f.gateway.clone());
            st.ip_policy = Some(f.ip_policy);
            st.last_result = Some(f.result.clone());
        }
        st
    }
}

#[derive(Debug)]
struct Inner {
    instance: String,
    seq: u64,
    state: State,
    active: Option<Active>,
    last: Option<Finished>,
    keys: HashMap<(u32, String), (ConnectParams, ConnectResult)>,
}

/// Shared daemon state.
pub struct Session {
    pub(crate) ems: Option<fortino_ems::service::EmsWorkers>,
    inner: Mutex<Inner>,
    events: broadcast::Sender<Arc<Snapshot>>,
    workers: Box<dyn WorkerFactory>,
    net: Mutex<Box<dyn NetController>>,
    store: Mutex<ProfileStore>,
    timeouts: Timeouts,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn gateway_of(p: &Profile) -> String {
    format!("{}:{}", p.spec.endpoint.host, p.spec.endpoint.port)
}

/// Maps a store error to a protocol error.
pub fn store_err(e: StoreError) -> ProtoError {
    match e {
        StoreError::NotFound => ProtoError::new(ErrorCode::NotFound, "profile not found"),
        StoreError::StaleRevision { current } => {
            let mut p = ProtoError::new(
                ErrorCode::StaleRevision,
                "the profile changed; reload and retry",
            );
            p.current_revision = Some(current);
            p
        }
        StoreError::NameTaken => ProtoError::new(
            ErrorCode::Conflict,
            "a profile with this name already exists",
        )
        .with_field("name"),
        StoreError::Invalid(fe) => {
            ProtoError::new(ErrorCode::InvalidProfile, format!("invalid {}", fe.code))
                .with_field(fe.field)
        }
        StoreError::ImportConflict(m) => ProtoError::new(ErrorCode::Conflict, m),
        StoreError::Limit => ProtoError::new(ErrorCode::InvalidRequest, "profile limit reached"),
        StoreError::Schema(_) | StoreError::Sqlite(_) | StoreError::Corrupt(_) => {
            tracing::error!(error = %e, "profile store failure");
            ProtoError::new(ErrorCode::Internal, "profile store failure")
        }
    }
}

impl Session {
    /// Creates the session manager, reconciling leftover network state first.
    pub fn new(
        store: ProfileStore,
        workers: Box<dyn WorkerFactory>,
        net: Box<dyn NetController>,
        timeouts: Timeouts,
    ) -> Arc<Self> {
        Self::with_ems(store, workers, net, timeouts, None)
    }

    pub(crate) fn with_ems(
        store: ProfileStore,
        workers: Box<dyn WorkerFactory>,
        mut net: Box<dyn NetController>,
        timeouts: Timeouts,
        ems: Option<fortino_ems::service::EmsWorkers>,
    ) -> Arc<Self> {
        let state = match net.recover() {
            Ok(n) => {
                if n > 0 {
                    tracing::warn!(entries = n, "restored network state left by a previous run");
                }
                State::Idle
            }
            Err(e) => {
                tracing::error!(error = %e, "network recovery failed");
                State::RecoveryRequired
            }
        };
        let (events, _) = broadcast::channel(EVENT_CAPACITY);
        Arc::new(Self {
            ems,
            inner: Mutex::new(Inner {
                instance: uuid_like(),
                seq: 1,
                state,
                active: None,
                last: None,
                keys: HashMap::new(),
            }),
            events,
            workers,
            net: Mutex::new(net),
            store: Mutex::new(store),
            timeouts,
        })
    }

    /// Daemon instance ID.
    pub fn instance(&self) -> String {
        lock(&self.inner).instance.clone()
    }

    /// Runs `f` on the profile store.
    pub fn with_store<R>(&self, f: impl FnOnce(&mut ProfileStore) -> R) -> R {
        f(&mut lock(&self.store))
    }

    /// Runs a profile mutation unless `id` is pinned by the active attempt.
    pub fn mutate_profile<R>(
        &self,
        id: &ProfileId,
        f: impl FnOnce(&mut ProfileStore) -> Result<R, ProtoError>,
    ) -> Result<R, ProtoError> {
        let g = lock(&self.inner);
        if g.active.as_ref().is_some_and(|a| &a.profile.id == id) {
            return Err(ProtoError::new(
                ErrorCode::ProfileInUse,
                "disconnect before changing this profile",
            ));
        }
        let r = f(&mut lock(&self.store));
        drop(g);
        r
    }

    /// Imports a batch unless it names the profile pinned by the active attempt. The check and
    /// the write happen under one lock, so a concurrent connect cannot slip in between.
    pub fn import(
        &self,
        owner: u32,
        store_revision: u64,
        entries: Vec<fortino_config::ProfileSpec>,
        replace: &[String],
    ) -> Result<Vec<fortino_config::ImportResult>, ProtoError> {
        let g = lock(&self.inner);
        if let Some(a) = &g.active
            && a.owner == owner
        {
            let key = fortino_config::name_key(&a.profile.spec.name);
            let hit = entries.iter().any(|e| {
                let n = &e.name;
                fortino_config::normalize_name(n).is_ok_and(|n| fortino_config::name_key(&n) == key)
            });
            if hit {
                return Err(ProtoError::new(
                    ErrorCode::ProfileInUse,
                    "disconnect before replacing the active profile",
                ));
            }
        }
        let r = lock(&self.store)
            .import(owner, store_revision, entries, replace)
            .map_err(store_err);
        drop(g);
        r
    }

    fn snapshot(g: &Inner) -> Snapshot {
        Snapshot {
            instance: g.instance.clone(),
            seq: g.seq,
            state: g.state,
            active: g.active.as_ref().map(|a| ActiveView {
                start_seq: a.start_seq,
                attempt_id: a.attempt_id.clone(),
                owner: a.owner,
                profile_id: a.profile.id.clone(),
                profile_name: a.profile.spec.name.clone(),
                gateway: gateway_of(&a.profile),
                ip_policy: a.profile.spec.ip_policy,
                assigned_ip: a.assigned_ip.clone(),
                interface: a.interface.clone(),
                connected_since: a.connected_since,
                challenge: a.challenge.clone(),
            }),
            last: g.last.clone(),
        }
    }

    fn publish(&self, g: &mut Inner) {
        g.seq += 1;
        let _ = self.events.send(Arc::new(Self::snapshot(g)));
    }

    /// Status for `peer`.
    pub fn status(&self, peer: Peer) -> Status {
        Self::snapshot(&lock(&self.inner)).view(peer)
    }

    /// Atomic snapshot plus a receiver for every later change.
    pub fn subscribe(&self, peer: Peer) -> (Status, broadcast::Receiver<Arc<Snapshot>>) {
        let g = lock(&self.inner);
        let rx = self.events.subscribe();
        (Self::snapshot(&g).view(peer), rx)
    }

    /// Starts an attempt.
    pub fn connect(
        self: &Arc<Self>,
        peer: Peer,
        p: ConnectParams,
    ) -> Result<ConnectResult, ProtoError> {
        if p.request_key.is_empty() || p.request_key.len() > MAX_TOKEN_LEN {
            return Err(ProtoError::new(
                ErrorCode::InvalidRequest,
                "invalid request key",
            ));
        }
        let username = match p.username.as_deref().map(str::trim) {
            Some(u) if u.is_empty() || u.len() > MAX_TOKEN_LEN || u.contains(char::is_control) => {
                return Err(
                    ProtoError::new(ErrorCode::InvalidRequest, "invalid username")
                        .with_field("username"),
                );
            }
            other => other.map(str::to_owned),
        };
        let mut g = lock(&self.inner);
        let key = (peer.uid, p.request_key.clone());
        if let Some((prev, res)) = g.keys.get(&key) {
            return if *prev == p {
                Ok(res.clone())
            } else {
                Err(ProtoError::new(
                    ErrorCode::Conflict,
                    "request key reused with different parameters",
                ))
            };
        }
        if g.state == State::RecoveryRequired {
            // Retry reconciliation before refusing.
            match lock(&self.net).recover() {
                Ok(_) => {
                    g.state = State::Idle;
                    self.publish(&mut g);
                }
                Err(_) => {
                    return Err(ProtoError::new(
                        ErrorCode::RecoveryRequired,
                        "network cleanup from an earlier session failed; see the daemon log",
                    ));
                }
            }
        }
        if g.active.is_some() {
            return Err(ProtoError::new(ErrorCode::Busy, "VPN in use"));
        }
        let profile = lock(&self.store)
            .get(peer.uid, &p.profile_id)
            .map_err(store_err)?;
        if profile.revision != p.revision {
            return Err(store_err(StoreError::StaleRevision {
                current: profile.revision,
            }));
        }
        let attempt_id = format!("a-{}", uuid::Uuid::new_v4().simple());
        let username = username.or_else(|| profile.spec.username_hint.clone());
        let handle = self.workers.spawn(WorkerConfig {
            attempt_id: attempt_id.clone(),
            endpoint: profile.spec.endpoint.clone(),
            username,
            trust_id: profile.spec.trust_id.clone(),
            ip_policy: profile.spec.ip_policy,
            ems: None,
            // Filled by the EMS workers once the device UID is known for this EMS.
            fct_uid: None,
        });
        let wake = Arc::new(Notify::new());
        g.active = Some(Active {
            attempt_id: attempt_id.clone(),
            owner: peer.uid,
            profile,
            cmd: handle.commands,
            wake: wake.clone(),
            challenge: None,
            assigned_ip: None,
            interface: None,
            connected_since: None,
            stop: None,
            stop_deadline: None,
            progress_deadline: Some(Instant::now() + self.timeouts.transport),
            network_applied: false,
            start_seq: g.seq + 1,
        });
        g.last = None;
        g.state = State::Starting;
        self.publish(&mut g);
        let res = ConnectResult {
            attempt_id: attempt_id.clone(),
            state: State::Starting,
            seq: g.seq,
        };
        if g.keys.len() >= MAX_REQUEST_KEYS {
            g.keys.clear();
        }
        g.keys.insert(key, (p, res.clone()));
        drop(g);
        tracing::info!(attempt = %attempt_id, uid = peer.uid, "connection attempt started");
        let me = self.clone();
        tokio::spawn(async move { me.drive(attempt_id, handle.events, wake).await });
        Ok(res)
    }

    /// Answers the outstanding challenge. Exactly one answer wins.
    pub fn respond(
        &self,
        peer: Peer,
        attempt_id: &str,
        challenge_id: &str,
        value: Secret,
    ) -> Result<(), ProtoError> {
        let stale = || ProtoError::new(ErrorCode::StaleChallenge, "no such pending challenge");
        let mut g = lock(&self.inner);
        let a = g.active.as_mut().ok_or_else(stale)?;
        // Another user's attempt looks exactly like an unknown one.
        if a.attempt_id != attempt_id || a.owner != peer.uid {
            return Err(stale());
        }
        if a.challenge.as_ref().is_none_or(|c| c.id != challenge_id) {
            return Err(stale());
        }
        if value.expose().len() > MAX_TOKEN_LEN {
            return Err(ProtoError::new(
                ErrorCode::InvalidRequest,
                "answer too long",
            ));
        }
        let sent = a.cmd.try_send(WorkerCommand::Respond {
            challenge_id: challenge_id.to_owned(),
            value,
        });
        if sent.is_err() {
            self.request_stop(
                &mut g,
                StopCause {
                    code: Some(ErrorCode::BackendFailure),
                    message: "tunnel worker stopped accepting input".into(),
                },
            );
            return Err(ProtoError::new(
                ErrorCode::BackendFailure,
                "tunnel worker stopped accepting input",
            ));
        }
        a.challenge = None;
        // The gateway must answer within the progress deadline.
        a.progress_deadline = Some(Instant::now() + self.timeouts.transport);
        a.wake.notify_one();
        g.state = State::Authenticating;
        self.publish(&mut g);
        Ok(())
    }

    /// Requests that an attempt stop. Stopping an unknown or finished attempt is a no-op.
    pub fn disconnect(&self, peer: Peer, attempt_id: &str) -> Result<(), ProtoError> {
        let mut g = lock(&self.inner);
        let Some(a) = g.active.as_ref() else {
            return Ok(());
        };
        if a.attempt_id != attempt_id {
            return Ok(());
        }
        if a.owner != peer.uid && !peer.admin {
            // Same answer as for an unknown attempt, so IDs cannot be probed.
            return Ok(());
        }
        let cause = if g.state == State::Connected {
            StopCause {
                code: None,
                message: "disconnected".into(),
            }
        } else {
            StopCause {
                code: Some(ErrorCode::Cancelled),
                message: "cancelled by user".into(),
            }
        };
        self.request_stop(&mut g, cause);
        Ok(())
    }

    /// Records the first stop cause, enters `stopping` and tells the worker to stop.
    fn request_stop(&self, g: &mut Inner, cause: StopCause) {
        let Some(a) = g.active.as_mut() else { return };
        if a.stop.is_some() {
            return;
        }
        tracing::info!(attempt = %a.attempt_id, code = ?cause.code, "stopping attempt");
        a.stop = Some(cause);
        a.challenge = None;
        a.stop_deadline = Some(Instant::now() + self.timeouts.shutdown);
        let _ = a.cmd.try_send(WorkerCommand::Stop);
        a.wake.notify_one();
        g.state = State::Stopping;
        self.publish(g);
    }

    /// Follows one attempt's worker until it ends, enforcing deadlines.
    ///
    /// Deadlines live in [`Active`] and are re-read under the lock when the timer fires, so an
    /// answer or event that arrived meanwhile always wins over a stale timer.
    async fn drive(
        self: Arc<Self>,
        attempt_id: String,
        mut events: mpsc::Receiver<WorkerEvent>,
        wake: Arc<Notify>,
    ) {
        loop {
            let deadline = {
                let g = lock(&self.inner);
                match g.active.as_ref().filter(|a| a.attempt_id == attempt_id) {
                    Some(a) => Self::next_deadline(a),
                    None => return,
                }
            };
            let sleep = async {
                match deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                ev = events.recv() => {
                    let ev = ev.unwrap_or_else(|| WorkerEvent::Terminated(Termination {
                        code: Some(ErrorCode::BackendFailure),
                        message: "worker exited unexpectedly".into(),
                    }));
                    if let WorkerEvent::Terminated(t) = ev {
                        self.finish(&attempt_id, t);
                        return;
                    }
                    self.on_event(ev);
                }
                () = wake.notified() => {}
                () = sleep => {
                    if self.on_deadline(&attempt_id) {
                        tracing::error!(attempt = %attempt_id, "worker did not stop in time");
                        // The process supervisor kills and reaps a real worker on its own
                        // shorter grace period (see procworker), before this deadline.
                        self.finish(&attempt_id, Termination {
                            code: Some(ErrorCode::BackendFailure),
                            message: "worker did not stop in time".into(),
                        });
                        return;
                    }
                }
            }
        }
    }

    fn next_deadline(a: &Active) -> Option<Instant> {
        if a.stop.is_some() {
            return a.stop_deadline;
        }
        match &a.challenge {
            Some(c) => Some(c.deadline),
            None => a.progress_deadline,
        }
    }

    /// Handles an expired timer using current state. Returns true when the worker failed to
    /// stop in time and the attempt must be finished without it.
    fn on_deadline(&self, attempt_id: &str) -> bool {
        let mut g = lock(&self.inner);
        let state = g.state;
        let Some(a) = g.active.as_mut().filter(|a| a.attempt_id == attempt_id) else {
            return false;
        };
        let now = Instant::now();
        if a.stop.is_some() {
            return a.stop_deadline.is_some_and(|d| d <= now);
        }
        let cause = match &a.challenge {
            Some(c) if c.deadline <= now => StopCause {
                code: Some(ErrorCode::AuthTimeout),
                message: "authentication prompt timed out".into(),
            },
            Some(_) => return false,
            None if a.progress_deadline.is_some_and(|d| d <= now) => StopCause {
                code: Some(ErrorCode::TransportFailure),
                message: if state == State::Starting {
                    "timed out connecting to the gateway".into()
                } else {
                    "the gateway stopped responding".into()
                },
            },
            None => return false,
        };
        self.request_stop(&mut g, cause);
        false
    }

    /// Applies a worker event if it fits the current state; otherwise stops the attempt.
    fn on_event(&self, ev: WorkerEvent) {
        let mut g = lock(&self.inner);
        let state = g.state;
        let Some(a) = g.active.as_mut() else { return };
        if a.stop.is_some() {
            // Ignore progress after a stop request; wait for termination.
            return;
        }
        let pre_connect = matches!(
            state,
            State::Starting | State::Authenticating | State::AwaitingInput | State::Configuring
        );
        let fits = match &ev {
            WorkerEvent::Stage(WorkerStage::Transport) => state == State::Starting,
            WorkerEvent::Stage(_) => pre_connect && a.challenge.is_none(),
            WorkerEvent::Challenge { .. } => pre_connect && a.challenge.is_none(),
            WorkerEvent::Up(_) => pre_connect && a.challenge.is_none() && !a.network_applied,
            WorkerEvent::Terminated(_) => true,
        };
        if !fits {
            tracing::warn!(?state, "worker event out of order");
            self.request_stop(
                &mut g,
                StopCause {
                    code: Some(ErrorCode::BackendFailure),
                    message: "tunnel worker sent an unexpected event".into(),
                },
            );
            return;
        }
        let progress = Some(Instant::now() + self.timeouts.transport);
        match ev {
            WorkerEvent::Stage(s) => {
                a.progress_deadline = progress;
                g.state = match s {
                    WorkerStage::Transport => State::Starting,
                    WorkerStage::Authenticating => State::Authenticating,
                    WorkerStage::Negotiating => State::Configuring,
                };
                self.publish(&mut g);
            }
            WorkerEvent::Challenge { id, kind, prompt } => {
                let id = id.chars().take(64).collect();
                let prompt = sanitize_prompt(&prompt);
                a.progress_deadline = None;
                a.challenge = Some(PendingChallenge {
                    id,
                    kind,
                    prompt,
                    deadline: Instant::now() + self.timeouts.challenge,
                });
                g.state = State::AwaitingInput;
                self.publish(&mut g);
            }
            WorkerEvent::Up(tc) => {
                a.progress_deadline = None;
                let policy = a.profile.spec.ip_policy;
                g.state = State::Configuring;
                self.publish(&mut g);
                let res = lock(&self.net).apply(&tc, policy);
                let Some(a) = g.active.as_mut() else { return };
                match res {
                    Ok(()) => {
                        a.network_applied = true;
                        a.assigned_ip = Some(tc.assigned_ip.to_string());
                        a.interface = Some(tc.interface.clone());
                        a.connected_since = Some(now_unix());
                        tracing::info!(attempt = %a.attempt_id, "connected");
                        g.state = State::Connected;
                        self.publish(&mut g);
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "tunnel settings not applied");
                        if matches!(e, NetError::Cleanup(_)) {
                            a.network_applied = true;
                        }
                        let code = match e {
                            NetError::Unsupported(_) => ErrorCode::UnsupportedPolicy,
                            _ => ErrorCode::NetworkConfigFailure,
                        };
                        self.request_stop(
                            &mut g,
                            StopCause {
                                code: Some(code),
                                message: e.to_string(),
                            },
                        );
                    }
                }
            }
            WorkerEvent::Terminated(_) => {}
        }
    }

    fn finish(&self, attempt_id: &str, t: Termination) {
        let applied = {
            let mut g = lock(&self.inner);
            let Some(a) = g.active.as_mut().filter(|a| a.attempt_id == attempt_id) else {
                return;
            };
            a.challenge = None;
            // Keep the real cause if a disconnect arrives during cleanup.
            if a.stop.is_none() {
                a.stop = Some(match t.code {
                    Some(code) => StopCause {
                        code: Some(code),
                        message: t.message.clone(),
                    },
                    None => StopCause {
                        code: Some(ErrorCode::BackendFailure),
                        message: "tunnel ended unexpectedly".into(),
                    },
                });
            }
            let applied = a.network_applied;
            if g.state != State::Stopping {
                g.state = State::Stopping;
                self.publish(&mut g);
            }
            applied
        };
        let cleanup = if applied {
            lock(&self.net).rollback()
        } else {
            Ok(())
        };
        let mut g = lock(&self.inner);
        let Some(a) = g.active.take() else { return };
        let cause = a.stop.unwrap_or(match t.code {
            Some(code) => StopCause {
                code: Some(code),
                message: t.message,
            },
            None => StopCause {
                code: Some(ErrorCode::BackendFailure),
                message: "tunnel ended unexpectedly".into(),
            },
        });
        let mut result = LastResult {
            attempt_id: a.attempt_id.clone(),
            code: cause.code,
            message: cause.message,
        };
        g.state = match cleanup {
            Ok(()) => State::Idle,
            Err(e) => {
                tracing::error!(error = %e, "network cleanup failed");
                result.code = Some(ErrorCode::RecoveryRequired);
                result.message = "network cleanup failed; new connections are blocked".into();
                State::RecoveryRequired
            }
        };
        tracing::info!(attempt = %a.attempt_id, code = ?result.code, "attempt finished");
        g.last = Some(Finished {
            owner: a.owner,
            attempt_id: a.attempt_id,
            profile_id: a.profile.id.clone(),
            profile_name: a.profile.spec.name.clone(),
            gateway: gateway_of(&a.profile),
            ip_policy: a.profile.spec.ip_policy,
            result,
        });
        self.publish(&mut g);
    }
}

fn sanitize_prompt(p: &str) -> String {
    p.chars().filter(|c| !c.is_control()).take(128).collect()
}

fn uuid_like() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}
