//! Control protocol messages (version 1).
//!
//! UTF-8 JSON in [`crate::framing`] frames. A request is
//! `{"v":1,"id":"r7","method":"connect","params":{...}}`; the daemon answers with exactly one
//! [`Response`] carrying the same `id`, and sends [`EventMsg`]s on subscribed connections.
//! Unknown fields, duplicate keys and unknown methods are rejected.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use fortino_config::{ImportResult, IpPolicy, Profile, ProfileId, ProfileSpec};

use crate::error::{ErrorCode, ProtoError};

/// The protocol major version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Method names.
pub mod method {
    /// Version negotiation.
    pub const HELLO: &str = "hello";
    /// Status snapshot.
    pub const STATUS: &str = "status";
    /// Snapshot followed by events on this connection.
    pub const SUBSCRIBE: &str = "subscribe";
    /// Enroll this machine using deployment metadata for a trusted EMS.
    pub const EMS_ENROLL: &str = "ems.enroll";
    /// This machine's registration state with one EMS, from local records.
    pub const EMS_STATUS: &str = "ems.status";
    /// List the caller's profiles.
    pub const PROFILE_LIST: &str = "profile.list";
    /// Fetch one profile by ID or name.
    pub const PROFILE_GET: &str = "profile.get";
    /// Create a profile.
    pub const PROFILE_CREATE: &str = "profile.create";
    /// Update a profile.
    pub const PROFILE_UPDATE: &str = "profile.update";
    /// Delete a profile.
    pub const PROFILE_DELETE: &str = "profile.delete";
    /// Commit an import batch.
    pub const PROFILE_IMPORT: &str = "profile.import";
    /// Start a connection attempt.
    pub const CONNECT: &str = "connect";
    /// Answer a challenge.
    pub const RESPOND: &str = "respond";
    /// Stop an attempt.
    pub const DISCONNECT: &str = "disconnect";
    /// Read the daemon's log level.
    pub const LOG_GET_LEVEL: &str = "log.getLevel";
    /// Change the daemon's log level at runtime.
    pub const LOG_SET_LEVEL: &str = "log.setLevel";
    /// Ask the daemon to exit so launchd starts the build installed on disk.
    pub const DAEMON_RESTART: &str = "daemon.restart";
}

/// Longest build identifier accepted from a client.
pub const MAX_BUILD_ID_LEN: usize = 128;

/// A client request.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Protocol major version.
    pub v: u32,
    /// Opaque request ID, echoed in the response.
    pub id: String,
    /// Method name.
    pub method: String,
    /// Method parameters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Box<RawValue>>,
}

/// A received request whose parameters borrow from the (zeroizing) frame buffer, so secrets in
/// `params` are not copied.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestRef<'a> {
    /// Protocol major version.
    pub v: u32,
    /// Opaque request ID.
    pub id: String,
    /// Method name.
    pub method: String,
    /// Method parameters, unparsed.
    #[serde(borrow, default)]
    pub params: Option<&'a RawValue>,
}

/// Serializes a request into a zeroizing buffer without intermediate copies of `params`.
pub fn encode_request<P: Serialize>(
    id: &str,
    method: &str,
    params: &P,
) -> serde_json::Result<zeroize::Zeroizing<Vec<u8>>> {
    #[derive(Serialize)]
    struct Out<'a, P> {
        v: u32,
        id: &'a str,
        method: &'a str,
        params: &'a P,
    }
    // Pre-size so small requests (the ones carrying secrets) never reallocate.
    let mut buf = zeroize::Zeroizing::new(Vec::with_capacity(4096));
    serde_json::to_writer(
        &mut *buf,
        &Out {
            v: PROTOCOL_VERSION,
            id,
            method,
            params,
        },
    )?;
    Ok(buf)
}

/// A daemon response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Protocol major version.
    pub v: u32,
    /// The request ID.
    pub id: String,
    /// Result on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error on failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProtoError>,
}

/// An asynchronous event on a subscribed connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventMsg {
    /// Protocol major version.
    pub v: u32,
    /// The event.
    pub event: Event,
}

/// Events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Event {
    /// The status changed. Carries the full status as seen by this subscriber.
    Status {
        /// New status.
        status: Box<Status>,
    },
    /// Events were dropped; the client must refresh with `status`.
    ResyncRequired,
}

/// Anything the daemon sends.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ServerMessage {
    /// A response.
    Response(Response),
    /// An event.
    Event(EventMsg),
}

/// Session states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// No attempt.
    Idle,
    /// Worker starting, transport being established.
    Starting,
    /// Authenticating with the gateway.
    Authenticating,
    /// Waiting for the user to answer a challenge.
    AwaitingInput,
    /// Tunnel up, applying routes and DNS.
    Configuring,
    /// Routes and DNS verified.
    Connected,
    /// Shutting down and restoring networking.
    Stopping,
    /// Cleanup failed; new connections are refused.
    RecoveryRequired,
    /// Another user's attempt is active (details withheld).
    InUse,
}

impl State {
    /// True for states holding the session slot.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            State::Starting
                | State::Authenticating
                | State::AwaitingInput
                | State::Configuring
                | State::Connected
                | State::Stopping
        )
    }

    /// Display text.
    pub fn as_str(self) -> &'static str {
        match self {
            State::Idle => "idle",
            State::Starting => "starting",
            State::Authenticating => "authenticating",
            State::AwaitingInput => "awaiting-input",
            State::Configuring => "configuring",
            State::Connected => "connected",
            State::Stopping => "stopping",
            State::RecoveryRequired => "recovery-required",
            State::InUse => "in-use",
        }
    }
}

/// What a challenge asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ChallengeKind {
    /// Account name (not secret).
    Username,
    /// Password (secret).
    Password,
    /// One-time code (secret).
    Otp,
}

impl ChallengeKind {
    /// True when the answer must be read with echo disabled.
    pub fn is_secret(self) -> bool {
        !matches!(self, ChallengeKind::Username)
    }
}

/// An outstanding challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Challenge {
    /// Opaque challenge ID.
    pub id: String,
    /// What is asked for.
    pub kind: ChallengeKind,
    /// Sanitized prompt text.
    pub prompt: String,
    /// A one-time code prompt where an empty answer asks the gateway for a push notification
    /// (FortiToken Mobile) instead of a typed code. Left out when false.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub push: bool,
    /// Seconds until expiry, at the time of the snapshot.
    pub expires_in_secs: u64,
}

/// Terminal result of the last attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LastResult {
    /// The attempt.
    pub attempt_id: String,
    /// Error code, absent on a clean user disconnect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<ErrorCode>,
    /// Sanitized description.
    pub message: String,
}

/// Status as seen by one user.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    /// Changes when the daemon restarts.
    pub daemon_instance: String,
    /// Monotonic event sequence number.
    pub seq: u64,
    /// Current state.
    pub state: State,
    /// Active or last attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    /// Profile of that attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<ProfileId>,
    /// Profile name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_name: Option<String>,
    /// `host:port` of the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    /// IP scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_policy: Option<IpPolicy>,
    /// Address assigned by the gateway.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ip: Option<String>,
    /// Tunnel interface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// Unix time (seconds) the tunnel became connected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_since: Option<u64>,
    /// Outstanding challenge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<Challenge>,
    /// Result of the last finished attempt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_result: Option<LastResult>,
}

impl Status {
    /// A bare status with only instance, seq and state.
    pub fn bare(daemon_instance: impl Into<String>, seq: u64, state: State) -> Self {
        Self {
            daemon_instance: daemon_instance.into(),
            seq,
            state,
            attempt_id: None,
            profile_id: None,
            profile_name: None,
            gateway: None,
            ip_policy: None,
            assigned_ip: None,
            interface: None,
            connected_since: None,
            challenge: None,
            last_result: None,
        }
    }
}

/// Parameters with no fields.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

/// `hello` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HelloParams {
    /// Supported major versions.
    pub versions: Vec<u32>,
    /// Client name, for diagnostics.
    pub client: String,
}

/// `hello` result.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HelloResult {
    /// Selected version.
    pub version: u32,
    /// Daemon instance ID.
    pub daemon_instance: String,
    /// The caller's UID as seen by the daemon.
    pub uid: u32,
    /// Build identifier of the running daemon, stamped at packaging time. Absent from daemons
    /// built without one and from daemons that predate this field. A client whose own build
    /// differs is newer or older than the daemon (see `daemon.restart`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
}

/// `daemon.restart` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonRestartParams {
    /// The caller's build. The daemon refuses when it already runs this build, so a client
    /// can't restart it for nothing.
    pub build: String,
}

/// When a requested restart happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RestartWhen {
    /// No attempt is active; the daemon exits right after answering.
    Now,
    /// An attempt is active; the daemon exits once it has ended and its network state has
    /// been rolled back. The tunnel is never cut for an update.
    AfterDisconnect,
}

/// `daemon.restart` result.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DaemonRestartResult {
    /// When the daemon will exit.
    pub when: RestartWhen,
}

/// `profile.list` result.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileListResult {
    /// Owner store revision, for imports.
    pub store_revision: u64,
    /// Profiles.
    pub profiles: Vec<Profile>,
}

/// `profile.get` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileGetParams {
    /// Exact ID or name.
    pub id_or_name: String,
}

/// `profile.create` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileCreateParams {
    /// The new profile.
    pub spec: ProfileSpec,
}

/// `profile.update` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileUpdateParams {
    /// Profile ID.
    pub id: ProfileId,
    /// Expected current revision.
    pub revision: u64,
    /// Replacement fields.
    pub spec: ProfileSpec,
}

/// `profile.delete` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileDeleteParams {
    /// Profile ID.
    pub id: ProfileId,
    /// Expected current revision.
    pub revision: u64,
}

/// `profile.import` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileImportParams {
    /// Expected owner store revision.
    pub store_revision: u64,
    /// Canonical entries.
    pub entries: Vec<ProfileSpec>,
    /// Names the user explicitly chose to replace.
    #[serde(default)]
    pub replace: Vec<String>,
}

/// `profile.import` result.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileImportResult {
    /// One result per entry.
    pub results: Vec<ImportResult>,
}

/// `connect` parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectParams {
    /// Profile ID.
    pub profile_id: ProfileId,
    /// Profile revision the user selected.
    pub revision: u64,
    /// Idempotency key.
    pub request_key: String,
    /// Username override (otherwise the profile's hint, otherwise a challenge).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// `connect` result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConnectResult {
    /// New attempt ID.
    pub attempt_id: String,
    /// State right after acquiring the slot.
    pub state: State,
    /// Event sequence at that point.
    pub seq: u64,
}

/// `respond` parameters. `value` is a secret for password/OTP challenges.
///
/// The received frame and this struct are zeroized. Limitation: if the value contains
/// characters JSON must escape (`"`, `\`, control characters), serde_json unescapes it through
/// an internal scratch buffer that is not zeroized.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RespondParams {
    /// Attempt ID.
    pub attempt_id: String,
    /// Challenge ID.
    pub challenge_id: String,
    /// The answer.
    pub value: String,
}

impl std::fmt::Debug for RespondParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RespondParams")
            .field("attempt_id", &self.attempt_id)
            .field("challenge_id", &self.challenge_id)
            .field("value", &fortino_secret::REDACTED)
            .finish()
    }
}

impl Drop for RespondParams {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.value.zeroize();
    }
}

/// `disconnect` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisconnectParams {
    /// The attempt to stop.
    pub attempt_id: String,
}

/// Daemon log verbosity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Errors only.
    Error,
    /// Warnings and errors.
    Warn,
    /// The default.
    Info,
    /// Protocol exchanges: status codes, cookie names and paths, never values.
    Debug,
    /// Debug plus small masked bodies.
    Trace,
}

impl LogLevel {
    /// The filter directive for this level.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Parses a plain level name.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Self::Error),
            "warn" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }
}

/// `log.setLevel` parameters.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogSetLevelParams {
    /// The new level.
    pub level: LogLevel,
}

/// `log.getLevel` / `log.setLevel` result.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LogLevelResult {
    /// The current level, absent when `RUST_LOG` set a per-target filter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,
}

/// Parses `params` into `T`, mapping failures to `invalid_request`.
pub fn parse_params<T: serde::de::DeserializeOwned>(
    params: Option<&RawValue>,
) -> Result<T, ProtoError> {
    let raw = params.map_or("{}", RawValue::get);
    serde_json::from_str(raw)
        .map_err(|_| ProtoError::new(ErrorCode::InvalidRequest, "invalid parameters"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_rejects_duplicates_and_unknown() {
        let ok = r#"{"v":1,"id":"r7","method":"connect","params":{"profileId":"p1","revision":2,"requestKey":"k7"}}"#;
        let r: Request = serde_json::from_str(ok).unwrap();
        let p: ConnectParams = parse_params(r.params.as_deref()).unwrap();
        assert_eq!(p.revision, 2);

        let enc = encode_request("r7", "connect", &p).unwrap();
        let back: RequestRef<'_> = serde_json::from_slice(&enc).unwrap();
        assert_eq!(back.method, "connect");
        let p2: ConnectParams = parse_params(back.params).unwrap();
        assert_eq!(p2, p);

        let dup = r#"{"v":1,"id":"a","id":"b","method":"status"}"#;
        assert!(serde_json::from_str::<Request>(dup).is_err());
        let unk = r#"{"v":1,"id":"a","method":"status","x":1}"#;
        assert!(serde_json::from_str::<Request>(unk).is_err());
        let dup_param = r#"{"profileId":"p1","profileId":"p2","revision":2,"requestKey":"k"}"#;
        assert!(serde_json::from_str::<ConnectParams>(dup_param).is_err());
    }

    #[test]
    fn log_level_params() {
        let p: LogSetLevelParams = serde_json::from_str(r#"{"level":"debug"}"#).unwrap();
        assert_eq!(p.level, LogLevel::Debug);
        assert!(serde_json::from_str::<LogSetLevelParams>(r#"{"level":"loud"}"#).is_err());
        assert_eq!(LogLevel::parse(" TRACE"), Some(LogLevel::Trace));
        assert_eq!(LogLevel::parse("fortino=debug"), None);
    }

    #[test]
    fn server_message_untagged() {
        let s = serde_json::to_string(&EventMsg {
            v: 1,
            event: Event::Status {
                status: Box::new(Status::bare("i", 3, State::Idle)),
            },
        })
        .unwrap();
        assert!(matches!(
            serde_json::from_str::<ServerMessage>(&s).unwrap(),
            ServerMessage::Event(_)
        ));
        let s = r#"{"v":1,"id":"r1","result":{}}"#;
        assert!(matches!(
            serde_json::from_str::<ServerMessage>(s).unwrap(),
            ServerMessage::Response(_)
        ));
    }

    #[test]
    fn respond_debug_redacts() {
        let p = RespondParams {
            attempt_id: "a".into(),
            challenge_id: "c".into(),
            value: "hunter2".into(),
        };
        assert!(!format!("{p:?}").contains("hunter2"));
    }
}
