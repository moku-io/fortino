//! Async control-protocol client used by `ofctl` and the desktop app.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::net::UnixStream;
use tokio::net::unix::OwnedWriteHalf;
use tokio::sync::{Mutex, mpsc, oneshot};

use ofc_config::{Profile, ProfileId, ProfileSpec};

use crate::error::{ErrorCode, ProtoError};
use crate::framing::{MAX_CONTROL_FRAME, read_frame, write_frame};
use crate::proto::{self, *};

type Pending = Arc<std::sync::Mutex<HashMap<String, oneshot::Sender<Response>>>>;

/// Default control socket path.
pub const DEFAULT_SOCKET: &str = "/var/run/openforticlient/ofcd.sock";

/// A connection to the daemon.
#[derive(Debug)]
pub struct Client {
    writer: Mutex<OwnedWriteHalf>,
    pending: Pending,
    events: Option<mpsc::UnboundedReceiver<Event>>,
    next_id: AtomicU64,
    /// The daemon's hello answer.
    pub hello: HelloResult,
}

fn unavailable(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::ServiceUnavailable, msg)
}

impl Client {
    /// Connects to the daemon socket and performs `hello`.
    pub async fn connect(path: &Path, client_name: &str) -> Result<Self, ProtoError> {
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::PermissionDenied => ProtoError::new(
                    ErrorCode::PermissionDenied,
                    "not allowed to use the VPN service",
                ),
                _ => unavailable("VPN service is not running"),
            })?;
        Self::from_stream(stream, client_name).await
    }

    /// Wraps a connected stream and performs `hello`.
    pub async fn from_stream(stream: UnixStream, client_name: &str) -> Result<Self, ProtoError> {
        let (mut rd, wr) = stream.into_split();
        let pending: Pending = Arc::default();
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        let p = pending.clone();
        tokio::spawn(async move {
            loop {
                let frame = match read_frame(&mut rd, MAX_CONTROL_FRAME).await {
                    Ok(Some(f)) => f,
                    Ok(None) | Err(_) => break,
                };
                match serde_json::from_slice::<ServerMessage>(&frame) {
                    Ok(ServerMessage::Response(r)) => {
                        let tx = p.lock().ok().and_then(|mut m| m.remove(&r.id));
                        if let Some(tx) = tx {
                            let _ = tx.send(r);
                        }
                    }
                    Ok(ServerMessage::Event(e)) => {
                        let _ = ev_tx.send(e.event);
                    }
                    Err(_) => break,
                }
            }
            // Fail every outstanding call.
            if let Ok(mut m) = p.lock() {
                m.clear();
            }
        });
        let mut c = Self {
            writer: Mutex::new(wr),
            pending,
            events: Some(ev_rx),
            next_id: AtomicU64::new(1),
            hello: HelloResult {
                version: 0,
                daemon_instance: String::new(),
                uid: 0,
            },
        };
        c.hello = c
            .call(
                method::HELLO,
                &HelloParams {
                    versions: vec![PROTOCOL_VERSION],
                    client: client_name.into(),
                },
            )
            .await?;
        Ok(c)
    }

    /// Calls a method.
    pub async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        params: &P,
    ) -> Result<R, ProtoError> {
        let id = format!("r{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let bytes = encode_request(&id, method, params)
            .map_err(|_| ProtoError::new(ErrorCode::InvalidRequest, "unserializable request"))?;
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| unavailable("client state poisoned"))?
            .insert(id, tx);
        write_frame(&mut *self.writer.lock().await, &bytes, MAX_CONTROL_FRAME)
            .await
            .map_err(|_| unavailable("lost connection to the VPN service"))?;
        let resp = rx
            .await
            .map_err(|_| unavailable("lost connection to the VPN service"))?;
        if let Some(e) = resp.error {
            return Err(e);
        }
        serde_json::from_value(resp.result.unwrap_or(serde_json::Value::Null))
            .map_err(|_| ProtoError::new(ErrorCode::Internal, "unexpected response"))
    }

    /// Subscribes. Returns the initial snapshot and the event stream (once per client).
    pub async fn subscribe(
        &mut self,
    ) -> Result<(Status, mpsc::UnboundedReceiver<Event>), ProtoError> {
        let rx = self
            .events
            .take()
            .ok_or_else(|| ProtoError::new(ErrorCode::InvalidRequest, "already subscribed"))?;
        let st: Status = self.call(method::SUBSCRIBE, &Empty {}).await?;
        Ok((st, rx))
    }

    /// Status snapshot.
    pub async fn status(&self) -> Result<Status, ProtoError> {
        self.call(method::STATUS, &Empty {}).await
    }

    /// Lists the caller's profiles.
    pub async fn profile_list(&self) -> Result<ProfileListResult, ProtoError> {
        self.call(method::PROFILE_LIST, &Empty {}).await
    }

    /// Fetches a profile by ID or name.
    pub async fn profile_get(&self, id_or_name: &str) -> Result<Profile, ProtoError> {
        self.call(
            method::PROFILE_GET,
            &ProfileGetParams {
                id_or_name: id_or_name.into(),
            },
        )
        .await
    }

    /// Creates a profile.
    pub async fn profile_create(&self, spec: ProfileSpec) -> Result<Profile, ProtoError> {
        self.call(method::PROFILE_CREATE, &ProfileCreateParams { spec })
            .await
    }

    /// Updates a profile.
    pub async fn profile_update(
        &self,
        id: ProfileId,
        revision: u64,
        spec: ProfileSpec,
    ) -> Result<Profile, ProtoError> {
        self.call(
            method::PROFILE_UPDATE,
            &ProfileUpdateParams { id, revision, spec },
        )
        .await
    }

    /// Deletes a profile.
    pub async fn profile_delete(&self, id: ProfileId, revision: u64) -> Result<(), ProtoError> {
        let _: serde_json::Value = self
            .call(
                method::PROFILE_DELETE,
                &ProfileDeleteParams { id, revision },
            )
            .await?;
        Ok(())
    }

    /// Commits an import batch.
    pub async fn profile_import(
        &self,
        params: &ProfileImportParams,
    ) -> Result<ProfileImportResult, ProtoError> {
        self.call(method::PROFILE_IMPORT, params).await
    }

    /// Starts an attempt.
    pub async fn connect_profile(&self, p: &ConnectParams) -> Result<ConnectResult, ProtoError> {
        self.call(method::CONNECT, p).await
    }

    /// Answers a challenge.
    pub async fn respond(
        &self,
        attempt_id: &str,
        challenge_id: &str,
        value: String,
    ) -> Result<(), ProtoError> {
        let p = RespondParams {
            attempt_id: attempt_id.into(),
            challenge_id: challenge_id.into(),
            value,
        };
        let _: serde_json::Value = self.call(method::RESPOND, &p).await?;
        Ok(())
    }

    /// Stops an attempt.
    pub async fn disconnect(&self, attempt_id: &str) -> Result<(), ProtoError> {
        let _: serde_json::Value = self
            .call(
                proto::method::DISCONNECT,
                &DisconnectParams {
                    attempt_id: attempt_id.into(),
                },
            )
            .await?;
        Ok(())
    }
}
