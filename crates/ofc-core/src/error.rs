//! Stable error codes shared by the daemon, CLI and desktop app, and their CLI exit codes.

use std::fmt;

use serde::{Deserialize, Serialize};

/// A stable, machine-readable error code. Serialized as a snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed envelope, unknown method, bad parameters.
    InvalidRequest,
    /// Unsupported protocol major version.
    UnsupportedVersion,
    /// A profile field failed validation.
    InvalidProfile,
    /// No such profile (or not visible to this user).
    NotFound,
    /// The VPN is in use by another attempt.
    Busy,
    /// The supplied revision is stale.
    StaleRevision,
    /// Name collision or conflicting import / request key.
    Conflict,
    /// The profile is pinned by the active attempt.
    ProfileInUse,
    /// The gateway rejected the credentials.
    AuthDenied,
    /// A challenge was not answered in time.
    AuthTimeout,
    /// A required secret has no source (non-interactive use).
    InteractionRequired,
    /// The challenge was already answered, cancelled or expired.
    StaleChallenge,
    /// The gateway certificate failed verification.
    TrustFailure,
    /// The gateway was unreachable or the transport failed.
    TransportFailure,
    /// Local route/DNS configuration failed.
    NetworkConfigFailure,
    /// The backend failed for an unclassified reason.
    BackendFailure,
    /// Cleanup failed; the daemon refuses new connections until reconciled.
    RecoveryRequired,
    /// The daemon is unreachable.
    ServiceUnavailable,
    /// The caller is not allowed to do this.
    PermissionDenied,
    /// The gateway requires a policy this client cannot enforce.
    UnsupportedPolicy,
    /// The attempt was cancelled.
    Cancelled,
    /// A message exceeded the size limit.
    TooLarge,
    /// Internal daemon error.
    Internal,
}

impl ErrorCode {
    /// The `ofctl` exit status for this code.
    pub fn exit_code(self) -> i32 {
        use ErrorCode::*;
        match self {
            InvalidRequest | UnsupportedVersion | InvalidProfile | NotFound | TooLarge => 2,
            Busy | StaleRevision | Conflict | ProfileInUse => 3,
            AuthDenied | AuthTimeout | InteractionRequired | StaleChallenge => 4,
            TrustFailure => 5,
            TransportFailure | NetworkConfigFailure | BackendFailure | RecoveryRequired
            | Internal => 6,
            ServiceUnavailable | PermissionDenied => 7,
            UnsupportedPolicy => 8,
            Cancelled => 9,
        }
    }

    /// The snake_case name.
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            InvalidRequest => "invalid_request",
            UnsupportedVersion => "unsupported_version",
            InvalidProfile => "invalid_profile",
            NotFound => "not_found",
            Busy => "busy",
            StaleRevision => "stale_revision",
            Conflict => "conflict",
            ProfileInUse => "profile_in_use",
            AuthDenied => "auth_denied",
            AuthTimeout => "auth_timeout",
            InteractionRequired => "interaction_required",
            StaleChallenge => "stale_challenge",
            TrustFailure => "trust_failure",
            TransportFailure => "transport_failure",
            NetworkConfigFailure => "network_config_failure",
            BackendFailure => "backend_failure",
            RecoveryRequired => "recovery_required",
            ServiceUnavailable => "service_unavailable",
            PermissionDenied => "permission_denied",
            UnsupportedPolicy => "unsupported_policy",
            Cancelled => "cancelled",
            TooLarge => "too_large",
            Internal => "internal",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An error returned over the control protocol. `message` is sanitized human text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{message} ({code})")]
#[serde(deny_unknown_fields)]
pub struct ProtoError {
    /// Stable code.
    pub code: ErrorCode,
    /// Sanitized message.
    pub message: String,
    /// Optional field name for validation errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Optional current revision for stale-revision errors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_revision: Option<u64>,
}

impl ProtoError {
    /// Builds an error.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            field: None,
            current_revision: None,
        }
    }

    /// Attaches a field name.
    pub fn with_field(mut self, field: impl Into<String>) -> Self {
        self.field = Some(field.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_serde() {
        for c in [
            ErrorCode::InvalidRequest,
            ErrorCode::AuthDenied,
            ErrorCode::AuthTimeout,
            ErrorCode::NetworkConfigFailure,
            ErrorCode::Cancelled,
        ] {
            assert_eq!(
                serde_json::to_string(&c).unwrap(),
                format!("\"{}\"", c.as_str())
            );
        }
        assert_ne!(
            ErrorCode::AuthDenied.as_str(),
            ErrorCode::AuthTimeout.as_str()
        );
        assert_eq!(ErrorCode::Cancelled.exit_code(), 9);
        assert_eq!(ErrorCode::Busy.exit_code(), 3);
    }
}
