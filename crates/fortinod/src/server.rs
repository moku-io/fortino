//! Control socket server: framing, authentication and method dispatch.

use std::sync::Arc;

use serde::Serialize;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc, oneshot};

use fortino_core::framing::{MAX_CONTROL_FRAME, read_frame, write_frame};
use fortino_core::proto::*;
use fortino_core::{ErrorCode, ProtoError};
use fortino_secret::Secret;

use crate::auth::{Authorizer, Peer};
use crate::session::{Session, store_err};

/// Maximum profiles in one import batch.
pub const MAX_IMPORT_ENTRIES: usize = 256;
/// Outgoing frames buffered per connection before a slow subscriber is dropped.
const OUT_QUEUE: usize = 128;
/// Open connections allowed per UID.
pub const MAX_CONNECTIONS_PER_UID: usize = 32;
/// Time allowed for the first request (`hello`, or the rejected peer's request).
const FIRST_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

type ConnCounts = Arc<std::sync::Mutex<std::collections::HashMap<u32, usize>>>;

/// Counts one open connection for a UID; released on drop.
struct ConnSlot {
    counts: ConnCounts,
    uid: u32,
}

impl ConnSlot {
    fn acquire(counts: &ConnCounts, uid: u32) -> Option<Self> {
        let mut m = counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = m.entry(uid).or_default();
        if *n >= MAX_CONNECTIONS_PER_UID {
            return None;
        }
        *n += 1;
        Some(Self {
            counts: counts.clone(),
            uid,
        })
    }
}

impl Drop for ConnSlot {
    fn drop(&mut self) {
        let mut m = self
            .counts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(n) = m.get_mut(&self.uid) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.uid);
            }
        }
    }
}

/// Accepts connections until the listener fails.
pub async fn serve(listener: UnixListener, session: Arc<Session>, auth: Arc<Authorizer>) {
    let counts: ConnCounts = Arc::default();
    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let uid = match stream.peer_cred() {
                    Ok(c) => c.uid(),
                    Err(e) => {
                        tracing::warn!(error = %e, "no peer credentials");
                        continue;
                    }
                };
                let Some(slot) = ConnSlot::acquire(&counts, uid) else {
                    tracing::warn!(uid, "too many connections; closing");
                    continue;
                };
                let s = session.clone();
                let a = auth.clone();
                tokio::spawn(async move {
                    handle(stream, uid, s, a).await;
                    drop(slot);
                });
            }
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

fn encode<T: Serialize>(v: &T) -> Option<Vec<u8>> {
    serde_json::to_vec(v).ok()
}

fn response(id: &str, r: Result<serde_json::Value, ProtoError>) -> Response {
    match r {
        Ok(v) => Response {
            v: PROTOCOL_VERSION,
            id: id.into(),
            result: Some(v),
            error: None,
        },
        Err(e) => Response {
            v: PROTOCOL_VERSION,
            id: id.into(),
            result: None,
            error: Some(e),
        },
    }
}

fn to_value<T: Serialize>(v: T) -> Result<serde_json::Value, ProtoError> {
    serde_json::to_value(v).map_err(|_| ProtoError::new(ErrorCode::Internal, "encode failed"))
}

struct Conn {
    peer: Peer,
    session: Arc<Session>,
    out: mpsc::Sender<Vec<u8>>,
    hello: bool,
    subscribed: bool,
    /// Releases the event forwarder once the subscribe response is queued.
    start_events: Option<oneshot::Sender<()>>,
    /// The event forwarder, stopped when the client goes: it holds a sender of the outgoing
    /// queue and would otherwise keep the connection, and its per-user slot, until the next
    /// state change.
    forwarder: Option<tokio::task::JoinHandle<()>>,
}

async fn handle(stream: UnixStream, uid: u32, session: Arc<Session>, auth: Arc<Authorizer>) {
    let (mut rd, mut wr) = stream.into_split();
    let (out, mut out_rx) = mpsc::channel::<Vec<u8>>(OUT_QUEUE);
    let writer = tokio::spawn(async move {
        while let Some(f) = out_rx.recv().await {
            if write_frame(&mut wr, &f, MAX_CONTROL_FRAME).await.is_err() {
                break;
            }
        }
    });

    let Some(peer) = auth.authorize(uid) else {
        tracing::info!(uid, "rejected unauthorized peer");
        // Answer the first request so the client can report a clear error.
        if let Ok(Ok(Some(frame))) = tokio::time::timeout(
            FIRST_REQUEST_TIMEOUT,
            read_frame(&mut rd, MAX_CONTROL_FRAME),
        )
        .await
        {
            let id = serde_json::from_slice::<RequestRef<'_>>(&frame)
                .map(|r| r.id)
                .unwrap_or_default();
            let e = ProtoError::new(
                ErrorCode::PermissionDenied,
                "this user is not allowed to use the VPN service",
            );
            if let Some(b) = encode(&response(&id, Err(e))) {
                let _ = out.send(b).await;
            }
        }
        drop(out);
        let _ = writer.await;
        return;
    };

    let mut conn = Conn {
        peer,
        session,
        out,
        hello: false,
        subscribed: false,
        start_events: None,
        forwarder: None,
    };
    loop {
        let read = read_frame(&mut rd, MAX_CONTROL_FRAME);
        let next = if conn.hello {
            read.await
        } else {
            match tokio::time::timeout(FIRST_REQUEST_TIMEOUT, read).await {
                Ok(r) => r,
                Err(_) => break,
            }
        };
        let frame = match next {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(_) => {
                let e = ProtoError::new(ErrorCode::TooLarge, "malformed or oversized frame");
                if let Some(b) = encode(&response("", Err(e))) {
                    let _ = conn.out.send(b).await;
                }
                break;
            }
        };
        let req: RequestRef<'_> = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(_) => {
                let e = ProtoError::new(ErrorCode::InvalidRequest, "malformed request");
                if let Some(b) = encode(&response("", Err(e))) {
                    let _ = conn.out.send(b).await;
                }
                break;
            }
        };
        let id = req.id.clone();
        let result = conn.dispatch(req).await;
        drop(frame);
        let fatal = matches!(&result, Err(e) if e.code == ErrorCode::UnsupportedVersion);
        let Some(mut bytes) = encode(&response(&id, result)) else {
            break;
        };
        // An answer the frame limit can't carry would make the writer drop the connection,
        // which the client would report as a lost service. Say what happened instead.
        if bytes.len() > MAX_CONTROL_FRAME {
            let e = ProtoError::new(ErrorCode::TooLarge, "the answer is too large to send");
            let Some(b) = encode(&response(&id, Err(e))) else {
                break;
            };
            bytes = b;
        }
        if conn.out.send(bytes).await.is_err() || fatal {
            break;
        }
        if let Some(go) = conn.start_events.take() {
            let _ = go.send(());
        }
    }
    if let Some(f) = conn.forwarder.take() {
        f.abort();
    }
    drop(conn);
    let _ = writer.await;
}

impl Conn {
    async fn dispatch(&mut self, req: RequestRef<'_>) -> Result<serde_json::Value, ProtoError> {
        if req.v != PROTOCOL_VERSION {
            return Err(ProtoError::new(
                ErrorCode::UnsupportedVersion,
                "unsupported protocol version",
            ));
        }
        if req.id.len() > crate::session::MAX_TOKEN_LEN {
            return Err(ProtoError::new(
                ErrorCode::InvalidRequest,
                "request ID too long",
            ));
        }
        let params = req.params;
        let uid = self.peer.uid;
        if !self.hello && req.method != method::HELLO {
            return Err(ProtoError::new(ErrorCode::InvalidRequest, "hello required"));
        }
        let s = &self.session;
        match req.method.as_str() {
            method::HELLO => {
                let p: HelloParams = parse_params(params)?;
                if !p.versions.contains(&PROTOCOL_VERSION) {
                    return Err(ProtoError::new(
                        ErrorCode::UnsupportedVersion,
                        "no common protocol version",
                    ));
                }
                self.hello = true;
                to_value(HelloResult {
                    version: PROTOCOL_VERSION,
                    daemon_instance: s.instance(),
                    uid,
                    build: s.build(),
                })
            }
            method::STATUS => {
                let _: Empty = parse_params(params)?;
                to_value(s.status(self.peer))
            }
            method::SUBSCRIBE => {
                let _: Empty = parse_params(params)?;
                if self.subscribed {
                    return Err(ProtoError::new(
                        ErrorCode::InvalidRequest,
                        "already subscribed",
                    ));
                }
                self.subscribed = true;
                let (st, rx) = s.subscribe(self.peer);
                // The forwarder waits until the response is queued, so the snapshot always
                // precedes the first event.
                let (go, started) = oneshot::channel();
                self.start_events = Some(go);
                self.forwarder = Some(tokio::spawn(forward_events(
                    rx,
                    self.out.clone(),
                    self.peer,
                    st.seq,
                    started,
                )));
                to_value(st)
            }
            method::EMS_ENROLL => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Enrollment {
                    server: String,
                    /// Absent for **Register Now** (no deployment package).
                    #[serde(default)]
                    install_uid: Option<String>,
                }
                let p: Enrollment = parse_params(params)?;
                let server = p.server.parse().map_err(|_| {
                    ProtoError::new(ErrorCode::InvalidRequest, "Invalid EMS address")
                })?;
                let ems = s.ems.as_ref().ok_or_else(|| {
                    ProtoError::new(ErrorCode::UnsupportedPolicy, "EMS enrollment unavailable")
                })?;
                let (status, rules) = ems
                    .enroll(server, p.install_uid.as_deref())
                    .await
                    .map_err(enrollment_error)?;
                Ok(serde_json::json!({"status":status,"rules":rules}))
            }
            method::EMS_STATUS => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Query {
                    server: String,
                }
                let p: Query = parse_params(params)?;
                let server = p.server.parse().map_err(|_| {
                    ProtoError::new(ErrorCode::InvalidRequest, "Invalid EMS address")
                })?;
                let Some(ems) = s.ems.as_ref() else {
                    return Ok(serde_json::json!({"state":"unconfigured"}));
                };
                let info = ems.status(&server).map_err(enrollment_error)?;
                let mut v = serde_json::json!({"state": info.state.as_str()});
                if let Some(t) = info.registered_at {
                    v["registeredAt"] = t.into();
                }
                if let Some(t) = info.last_keepalive {
                    v["lastKeepalive"] = t.into();
                }
                if let Some(r) = info.rules {
                    v["rules"] = r.into();
                }
                Ok(v)
            }
            method::PROFILE_LIST => {
                let _: Empty = parse_params(params)?;
                let (store_revision, profiles) = s
                    .with_store(|st| {
                        Ok::<_, fortino_config::StoreError>((
                            st.store_revision(uid)?,
                            st.list(uid)?,
                        ))
                    })
                    .map_err(store_err)?;
                to_value(ProfileListResult {
                    store_revision,
                    profiles,
                })
            }
            method::PROFILE_GET => {
                let p: ProfileGetParams = parse_params(params)?;
                to_value(
                    s.with_store(|st| st.find(uid, &p.id_or_name))
                        .map_err(store_err)?,
                )
            }
            method::PROFILE_CREATE => {
                let p: ProfileCreateParams = parse_params(params)?;
                to_value(
                    s.with_store(|st| st.create(uid, p.spec))
                        .map_err(store_err)?,
                )
            }
            method::PROFILE_UPDATE => {
                let p: ProfileUpdateParams = parse_params(params)?;
                let id = p.id.clone();
                to_value(s.mutate_profile(&id, |st| {
                    st.update(uid, &p.id, p.revision, p.spec).map_err(store_err)
                })?)
            }
            method::PROFILE_DELETE => {
                let p: ProfileDeleteParams = parse_params(params)?;
                s.mutate_profile(&p.id, |st| {
                    st.delete(uid, &p.id, p.revision).map_err(store_err)
                })?;
                to_value(serde_json::json!({}))
            }
            method::PROFILE_IMPORT => {
                let p: ProfileImportParams = parse_params(params)?;
                if p.entries.len() > MAX_IMPORT_ENTRIES {
                    return Err(ProtoError::new(ErrorCode::TooLarge, "too many entries"));
                }
                let results = s.import(uid, p.store_revision, p.entries, &p.replace)?;
                to_value(ProfileImportResult { results })
            }
            method::CONNECT => {
                let p: ConnectParams = parse_params(params)?;
                to_value(s.connect(self.peer, p)?)
            }
            method::RESPOND => {
                let mut p: RespondParams = parse_params(params)?;
                let value = Secret::new(std::mem::take(&mut p.value));
                s.respond(self.peer, &p.attempt_id, &p.challenge_id, value)?;
                to_value(serde_json::json!({}))
            }
            method::DISCONNECT => {
                let p: DisconnectParams = parse_params(params)?;
                s.disconnect(self.peer, &p.attempt_id)?;
                to_value(serde_json::json!({}))
            }
            method::LOG_GET_LEVEL => {
                let _: Empty = parse_params(params)?;
                to_value(LogLevelResult {
                    level: crate::logctl::current(),
                })
            }
            method::LOG_SET_LEVEL => {
                let p: LogSetLevelParams = parse_params(params)?;
                crate::logctl::set(p.level)
                    .map_err(|e| ProtoError::new(ErrorCode::InvalidRequest, e))?;
                to_value(LogLevelResult {
                    level: Some(p.level),
                })
            }
            method::DAEMON_RESTART => {
                let p: DaemonRestartParams = parse_params(params)?;
                if p.build.len() > MAX_BUILD_ID_LEN {
                    return Err(ProtoError::new(
                        ErrorCode::InvalidRequest,
                        "build ID too long",
                    ));
                }
                // Only a client from a different build has a reason to restart the daemon.
                if s.build().is_none_or(|b| b == p.build) {
                    return Err(ProtoError::new(
                        ErrorCode::InvalidRequest,
                        "the VPN service already runs this build",
                    ));
                }
                tracing::info!(uid, "restart requested by a client from another build");
                to_value(DaemonRestartResult {
                    when: s.request_restart(),
                })
            }
            _ => Err(ProtoError::new(ErrorCode::InvalidRequest, "unknown method")),
        }
    }
}

async fn forward_events(
    mut rx: broadcast::Receiver<Arc<crate::session::Snapshot>>,
    out: mpsc::Sender<Vec<u8>>,
    peer: Peer,
    first_seq: u64,
    started: oneshot::Receiver<()>,
) {
    if started.await.is_err() {
        return;
    }
    let mut last_in_use = false;
    loop {
        let event = match rx.recv().await {
            Ok(snap) => {
                if snap.seq() <= first_seq {
                    continue;
                }
                let st = snap.view(peer);
                // Other users' progress is not observable beyond "in use".
                let in_use = st.state == State::InUse;
                if in_use && last_in_use {
                    continue;
                }
                last_in_use = in_use;
                Event::Status {
                    status: Box::new(st),
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => Event::ResyncRequired,
            Err(broadcast::error::RecvError::Closed) => break,
        };
        let Some(bytes) = encode(&EventMsg {
            v: PROTOCOL_VERSION,
            event,
        }) else {
            break;
        };
        match out.try_send(bytes) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                // The client fell behind: drop this event and tell it to refresh.
                let Some(b) = encode(&EventMsg {
                    v: PROTOCOL_VERSION,
                    event: Event::ResyncRequired,
                }) else {
                    break;
                };
                if out.send(b).await.is_err() {
                    break;
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => break,
        }
    }
}

fn enrollment_error(e: fortino_ems::Error) -> ProtoError {
    use fortino_ems::Error;
    let (code, message) = match e {
        Error::RegistrationDisabled => (
            ErrorCode::PermissionDenied,
            "Enable registration and configure TLS trust for this EMS in fortinod.toml.",
        ),
        Error::Trust(_) => (
            ErrorCode::TrustFailure,
            "Could not verify EMS using the configured TLS trust.",
        ),
        Error::Transport(_) => (
            ErrorCode::TransportFailure,
            "Could not establish a verified TLS connection to EMS.",
        ),
        Error::Refused(reason) => {
            // The EMS's own reason (connection key, invitation, quarantine) tells the user
            // what IT has to provide.
            let message: String = format!("The EMS refused the registration: {reason}")
                .chars()
                .take(300)
                .collect();
            return ProtoError::new(ErrorCode::UnsupportedPolicy, &message);
        }
        Error::Protocol(_) => (
            ErrorCode::InvalidRequest,
            "Invalid enrollment data or unsupported EMS reply.",
        ),
        Error::Store(_) | Error::NotRegistered => (
            ErrorCode::BackendFailure,
            "Could not read or save this Mac's EMS registration.",
        ),
    };
    ProtoError::new(code, message)
}
