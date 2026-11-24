//! Private daemon ↔ worker channel, protocol version 1.
//!
//! One socket pair per attempt; the worker receives its end as standard input. Frames are
//! [`crate::framing`] frames of at most [`MAX_WORKER_FRAME`] bytes carrying one JSON object.
//! Every frame names the attempt; worker frames also carry a strictly increasing `seq`. The
//! daemon treats everything from the worker as untrusted: [`WorkerMsg::into_event`] bounds and
//! validates it before the session sees it.
//!
//! Daemon → worker: `start` (once, first), `respond`, `stop`.
//! Worker → daemon: `stage`, `challenge`, `up`, `terminated` (last).
//! Daemon-side EOF cancels the attempt; worker-side EOF triggers reconciliation.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use fortino_platform::IpNet;

use crate::error::ErrorCode;
use crate::proto::ChallengeKind;
use crate::worker::{SplitDnsRule, Termination, TunnelConfig, WorkerEvent, WorkerStage};

/// Worker channel protocol version.
pub const WORKER_PROTOCOL_VERSION: u32 = 1;
/// Maximum worker frame (64 KiB).
pub const MAX_WORKER_FRAME: usize = 64 * 1024;
/// Maximum routes accepted from a worker.
pub const MAX_ROUTES: usize = 1024;
/// Maximum DNS servers accepted from a worker.
pub const MAX_DNS: usize = 8;
/// Maximum DNS match domains accepted from a worker.
pub const MAX_DOMAINS: usize = 64;
/// Maximum length of short strings (IDs, prompts, interface names).
pub const MAX_SHORT: usize = 128;
/// Most split-DNS rules in an `up` frame.
pub const MAX_SPLIT_RULES: usize = 32;

/// Messages from the daemon.
#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum DaemonMsg {
    /// Start the attempt. Sent once, first.
    Start {
        /// Protocol version.
        v: u32,
        /// Attempt ID.
        attempt: String,
        /// Gateway host (DNS name kept for certificate verification).
        host: String,
        /// Gateway port.
        port: u16,
        /// Realm.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        realm: Option<String>,
        /// Username, if known; otherwise the worker sends a username challenge.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        username: Option<String>,
        /// Administrator-provisioned CA bundle path for this profile's trust ID.
        ca_file: String,
        /// EMS server serial, when this client is registered to the profile's EMS. Sent to the
        /// gateway only if it asks for it (`/remote/info` flag `0x100`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ems_serial: Option<String>,
        /// EMS tenant, with `ems_serial`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ems_tenant: Option<String>,
        /// This device's `FCTUID`, sent to the gateway only if it asks (`0x80`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fct_uid: Option<String>,
    },
    /// Answer to a challenge. `value` is secret.
    Respond {
        /// Protocol version.
        v: u32,
        /// Attempt ID.
        attempt: String,
        /// Challenge ID.
        challenge: String,
        /// The answer.
        value: String,
    },
    /// Stop gracefully.
    Stop {
        /// Protocol version.
        v: u32,
        /// Attempt ID.
        attempt: String,
    },
}

impl std::fmt::Debug for DaemonMsg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonMsg::Start {
                attempt,
                host,
                port,
                ..
            } => f
                .debug_struct("Start")
                .field("attempt", attempt)
                .field("host", host)
                .field("port", port)
                .finish_non_exhaustive(),
            DaemonMsg::Respond {
                attempt, challenge, ..
            } => f
                .debug_struct("Respond")
                .field("attempt", attempt)
                .field("challenge", challenge)
                .field("value", &fortino_secret::REDACTED)
                .finish(),
            DaemonMsg::Stop { attempt, .. } => {
                f.debug_struct("Stop").field("attempt", attempt).finish()
            }
        }
    }
}

impl Drop for DaemonMsg {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let DaemonMsg::Respond { value, .. } = self {
            value.zeroize();
        }
    }
}

/// Bounded reasons a worker reports for terminating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WireReason {
    /// Stopped on request.
    Stopped,
    /// Credentials rejected.
    AuthDenied,
    /// Gateway unreachable or TLS/transport failure.
    Transport,
    /// Certificate or hostname verification failed.
    InvalidCertificate,
    /// The gateway requires something unsupported (posture, certificate login, …).
    Unsupported,
    /// Local network configuration failed inside the worker.
    LocalNetwork,
    /// User cancellation observed by the worker.
    Cancelled,
    /// Anything else.
    Backend,
}

impl WireReason {
    fn to_termination(self) -> Termination {
        let (code, message) = match self {
            WireReason::Stopped => (None, "stopped"),
            WireReason::AuthDenied => (Some(ErrorCode::AuthDenied), "credentials rejected"),
            WireReason::Transport => (
                Some(ErrorCode::TransportFailure),
                "could not reach the gateway",
            ),
            WireReason::InvalidCertificate => (
                Some(ErrorCode::TrustFailure),
                "gateway certificate not trusted",
            ),
            WireReason::Unsupported => (
                Some(ErrorCode::UnsupportedPolicy),
                "gateway requires an unsupported policy",
            ),
            WireReason::LocalNetwork => (
                Some(ErrorCode::NetworkConfigFailure),
                "local network configuration failed",
            ),
            WireReason::Cancelled => (Some(ErrorCode::Cancelled), "cancelled"),
            WireReason::Backend => (Some(ErrorCode::BackendFailure), "tunnel backend failed"),
        };
        Termination {
            code,
            message: message.into(),
        }
    }
}

/// Messages from the worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WorkerMsg {
    /// Entered a stage.
    Stage {
        /// Protocol version.
        v: u32,
        /// Attempt ID.
        attempt: String,
        /// Sequence number.
        seq: u64,
        /// Stage.
        stage: WorkerStage,
    },
    /// Needs input.
    Challenge {
        /// Protocol version.
        v: u32,
        /// Attempt ID.
        attempt: String,
        /// Sequence number.
        seq: u64,
        /// Challenge ID.
        id: String,
        /// What is asked for.
        kind: ChallengeKind,
        /// Prompt text from the gateway.
        prompt: String,
    },
    /// PPP interface is up with these settings.
    #[serde(rename_all = "camelCase")]
    Up {
        /// Protocol version.
        v: u32,
        /// Attempt ID.
        attempt: String,
        /// Sequence number.
        seq: u64,
        /// PPP interface.
        interface: String,
        /// Address assigned by IPCP.
        assigned_ip: Ipv4Addr,
        /// Gateway address on the physical uplink.
        gateway_ip: Ipv4Addr,
        /// Split routes as CIDR strings.
        #[serde(default)]
        routes: Vec<String>,
        /// DNS servers.
        #[serde(default)]
        dns: Vec<Ipv4Addr>,
        /// DNS match domains resolved by `dns`.
        #[serde(default)]
        dns_domains: Vec<String>,
        /// Per-domain rules with their own resolvers.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        split_dns: Vec<SplitDnsRule>,
        /// Gateway requires blocking IPv6.
        #[serde(default)]
        block_ipv6: bool,
    },
    /// The worker is exiting.
    Terminated {
        /// Protocol version.
        v: u32,
        /// Attempt ID.
        attempt: String,
        /// Sequence number.
        seq: u64,
        /// Bounded reason.
        reason: WireReason,
        /// Stage at which it failed, if known.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stage: Option<WorkerStage>,
        /// The worker's own short description of the failure (e.g. "tunnel settings: HTTP
        /// 500"), so the user and log see the cause and not only the category. The daemon
        /// bounds and sanitizes it (see [`failure_detail`]). Never holds credentials or
        /// cookies: the worker's failure messages carry statuses, paths and stage names only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

/// Longest failure detail the daemon keeps.
pub const MAX_DETAIL: usize = 160;

/// Bounds a worker's failure detail: no control characters, no query strings (which could
/// carry tokens), at most [`MAX_DETAIL`] bytes on a character boundary. Empty becomes `None`.
pub fn failure_detail(s: &str) -> Option<String> {
    let s = s.split('?').next().unwrap_or_default();
    let mut out = String::new();
    for c in s.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > MAX_DETAIL {
            break;
        }
        out.push(c);
    }
    let out = out.trim().to_owned();
    (!out.is_empty()).then_some(out)
}

/// A protocol violation by the worker. The daemon terminates the attempt.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("worker protocol violation: {0}")]
pub struct Violation(pub &'static str);

fn short(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_SHORT && !s.chars().any(char::is_control)
}

impl WorkerMsg {
    fn header(&self) -> (u32, &str, u64) {
        match self {
            WorkerMsg::Stage {
                v, attempt, seq, ..
            }
            | WorkerMsg::Challenge {
                v, attempt, seq, ..
            }
            | WorkerMsg::Up {
                v, attempt, seq, ..
            }
            | WorkerMsg::Terminated {
                v, attempt, seq, ..
            } => (*v, attempt, *seq),
        }
    }

    /// Validates the message against the expected attempt and the last sequence number and
    /// converts it into a session event.
    pub fn into_event(self, attempt: &str, last_seq: &mut u64) -> Result<WorkerEvent, Violation> {
        let (v, att, seq) = self.header();
        if v != WORKER_PROTOCOL_VERSION {
            return Err(Violation("unknown version"));
        }
        if att != attempt {
            return Err(Violation("frame for another attempt"));
        }
        if seq <= *last_seq {
            return Err(Violation("sequence did not increase"));
        }
        *last_seq = seq;
        Ok(match self {
            WorkerMsg::Stage { stage, .. } => WorkerEvent::Stage(stage),
            WorkerMsg::Challenge {
                id, kind, prompt, ..
            } => {
                if !short(&id) {
                    return Err(Violation("challenge id"));
                }
                let prompt: String = prompt
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(MAX_SHORT)
                    .collect();
                WorkerEvent::Challenge { id, kind, prompt }
            }
            WorkerMsg::Up {
                interface,
                assigned_ip,
                gateway_ip,
                routes,
                dns,
                dns_domains,
                split_dns,
                block_ipv6,
                ..
            } => {
                if !short(&interface) {
                    return Err(Violation("interface name"));
                }
                if routes.len() > MAX_ROUTES
                    || dns.len() > MAX_DNS
                    || dns_domains.len() > MAX_DOMAINS
                {
                    return Err(Violation("too many network entries"));
                }
                if dns_domains.iter().any(|d| !short(d)) {
                    return Err(Violation("dns domain"));
                }
                let rule_domains: usize = split_dns.iter().map(|r| r.domains.len()).sum();
                if split_dns.len() > MAX_SPLIT_RULES
                    || dns_domains.len() + rule_domains > MAX_DOMAINS
                    || split_dns.iter().any(|r| {
                        r.domains.is_empty()
                            || r.servers.is_empty()
                            || r.servers.len() > MAX_DNS
                            || r.domains.iter().any(|d| !short(d))
                    })
                {
                    return Err(Violation("split dns"));
                }
                let routes = routes
                    .iter()
                    .map(|r| r.parse::<IpNet>())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| Violation("route"))?;
                WorkerEvent::Up(TunnelConfig {
                    interface,
                    assigned_ip,
                    routes,
                    dns_servers: dns,
                    dns_domains,
                    split_dns,
                    gateway_ip,
                    block_ipv6,
                })
            }
            WorkerMsg::Terminated { reason, detail, .. } => {
                let mut t = reason.to_termination();
                if !matches!(reason, WireReason::Stopped | WireReason::Cancelled) {
                    if let Some(d) = detail.as_deref().and_then(failure_detail) {
                        // An unsupported-policy detail already names what the gateway requires
                        // ("gateway requires EMS registration: …"); the generic words would
                        // only repeat it.
                        t.message = if reason == WireReason::Unsupported {
                            d
                        } else {
                            format!("{}: {d}", t.message)
                        };
                    }
                }
                WorkerEvent::Terminated(t)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage(seq: u64, attempt: &str) -> WorkerMsg {
        WorkerMsg::Stage {
            v: 1,
            attempt: attempt.into(),
            seq,
            stage: WorkerStage::Transport,
        }
    }

    #[test]
    fn sequence_attempt_and_version() {
        let mut last = 0;
        assert!(stage(1, "a").into_event("a", &mut last).is_ok());
        assert_eq!(
            stage(1, "a").into_event("a", &mut last),
            Err(Violation("sequence did not increase"))
        );
        assert_eq!(
            stage(5, "b").into_event("a", &mut last),
            Err(Violation("frame for another attempt"))
        );
        let m = WorkerMsg::Stage {
            v: 2,
            attempt: "a".into(),
            seq: 9,
            stage: WorkerStage::Transport,
        };
        assert!(m.into_event("a", &mut last).is_err());
    }

    #[test]
    fn bounds_and_json_shape() {
        let j = r#"{"type":"up","v":1,"attempt":"a","seq":3,"interface":"ppp0","assignedIp":"10.1.2.3","gatewayIp":"203.0.113.1","routes":["10.0.0.0/8"],"dns":["10.0.0.53"],"dnsDomains":["corp.example"],"blockIpv6":true}"#;
        let m: WorkerMsg = serde_json::from_str(j).unwrap();
        let mut last = 0;
        let WorkerEvent::Up(tc) = m.into_event("a", &mut last).unwrap() else {
            panic!("not up")
        };
        assert_eq!(tc.routes.len(), 1);
        assert!(tc.block_ipv6);

        let unknown = r#"{"type":"stage","v":1,"attempt":"a","seq":1,"stage":"transport","x":1}"#;
        assert!(serde_json::from_str::<WorkerMsg>(unknown).is_err());

        let many = WorkerMsg::Up {
            v: 1,
            attempt: "a".into(),
            seq: 10,
            interface: "ppp0".into(),
            assigned_ip: Ipv4Addr::new(10, 0, 0, 1),
            gateway_ip: Ipv4Addr::new(203, 0, 113, 1),
            routes: vec!["10.0.0.0/8".into(); MAX_ROUTES + 1],
            dns: vec![],
            dns_domains: vec![],
            split_dns: vec![],
            block_ipv6: false,
        };
        assert!(many.into_event("a", &mut last).is_err());
    }

    #[test]
    fn failure_detail_is_bounded_and_sanitized() {
        assert_eq!(
            failure_detail("tunnel settings: HTTP 500").as_deref(),
            Some("tunnel settings: HTTP 500")
        );
        assert_eq!(
            failure_detail("redirect to /remote/x?token=abc").as_deref(),
            Some("redirect to /remote/x")
        );
        assert_eq!(failure_detail("a\nb\u{7}c").as_deref(), Some("abc"));
        assert_eq!(failure_detail("  "), None);
        let long = "é".repeat(200);
        let d = failure_detail(&long).unwrap();
        assert!(d.len() <= MAX_DETAIL && d.chars().all(|c| c == 'é'));
    }

    #[test]
    fn termination_carries_detail_except_for_stops() {
        let msg = |reason, detail: &str| WorkerMsg::Terminated {
            v: WORKER_PROTOCOL_VERSION,
            attempt: "a".into(),
            seq: 1,
            reason,
            stage: None,
            detail: Some(detail.into()),
        };
        let mut seq = 0;
        match msg(WireReason::Backend, "tunnel settings: HTTP 500").into_event("a", &mut seq) {
            Ok(WorkerEvent::Terminated(t)) => {
                assert_eq!(
                    t.message,
                    "tunnel backend failed: tunnel settings: HTTP 500"
                );
            }
            other => panic!("{other:?}"),
        }
        let mut seq = 0;
        let ems = "gateway requires EMS registration: it refused the login without this Mac's EMS serial (HTTP 503)";
        match msg(WireReason::Unsupported, ems).into_event("a", &mut seq) {
            Ok(WorkerEvent::Terminated(t)) => {
                assert_eq!(t.code, Some(ErrorCode::UnsupportedPolicy));
                assert_eq!(t.message, ems);
            }
            other => panic!("{other:?}"),
        }
        let mut seq = 0;
        match msg(WireReason::Stopped, "ignored").into_event("a", &mut seq) {
            Ok(WorkerEvent::Terminated(t)) => assert_eq!(t.message, "stopped"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn reasons_stay_distinct() {
        let t = |r: WireReason| r.to_termination().code;
        assert_eq!(t(WireReason::Stopped), None);
        assert_ne!(t(WireReason::AuthDenied), t(WireReason::Transport));
        assert_eq!(
            t(WireReason::InvalidCertificate),
            Some(ErrorCode::TrustFailure)
        );
    }

    #[test]
    fn respond_debug_redacts() {
        let m = DaemonMsg::Respond {
            v: 1,
            attempt: "a".into(),
            challenge: "c".into(),
            value: "s3cret".into(),
        };
        assert!(!format!("{m:?}").contains("s3cret"));
    }
}
