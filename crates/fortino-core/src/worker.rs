//! The daemon's view of a tunnel worker, and a deterministic fake worker.
//!
//! One worker runs per connection attempt. The daemon sends [`WorkerCommand`]s and receives
//! [`WorkerEvent`]s. The production adapter (openfortivpn in private adapter mode) will
//! implement the same interface over the private socket pair
//! ([`crate::worker_wire`]). The [`FakeWorker`] drives the daemon deterministically in tests and
//! in the development daemon.

use std::net::Ipv4Addr;
use std::time::Duration;

use fortino_config::{Endpoint, IpPolicy};
use fortino_platform::IpNet;
use fortino_secret::Secret;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::error::ErrorCode;
use crate::proto::ChallengeKind;

/// The EMS registration a gateway may ask for (`FSV_EMS_SN` and the tenant header). Present
/// only when this client is registered to the EMS named by the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmsIdentity {
    /// EMS server serial (`FCTEMS…`).
    pub serial: String,
    /// Tenant (32 digits; all zero on premises).
    pub tenant: String,
}

/// Settings for one attempt, pinned at connect time.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Attempt ID.
    pub attempt_id: String,
    /// Gateway endpoint.
    pub endpoint: Endpoint,
    /// Username if known; otherwise the worker asks for it.
    pub username: Option<String>,
    /// Trust configuration ID.
    pub trust_id: String,
    /// IP policy.
    pub ip_policy: IpPolicy,
    /// EMS registration for this profile's EMS, if any.
    pub ems: Option<EmsIdentity>,
    /// This device's `FCTUID` (platform UUID without dashes, upper-case). Sent on the tunnel
    /// request only when `/remote/info` asks for it (`f` bit `0x80`), the same value the EMS
    /// knows for this device.
    pub fct_uid: Option<String>,
    /// Debug only: per-profile SYSINFO overrides the EMS agent injects into its register and
    /// keepalive reports. Empty in normal use; see `fortino_ems::debug_override`.
    pub debug_ems_sysinfo: std::collections::BTreeMap<String, String>,
}

/// Worker progress stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkerStage {
    /// Opening TLS to the gateway.
    Transport,
    /// Exchanging credentials.
    Authenticating,
    /// PPP negotiation and tunnel settings.
    Negotiating,
}

/// One per-domain DNS rule from the gateway: these domains resolve through these servers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitDnsRule {
    /// Match domains.
    pub domains: Vec<String>,
    /// Resolvers for them.
    pub servers: Vec<Ipv4Addr>,
}

/// Network settings negotiated with the gateway. Untrusted input: the daemon validates them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelConfig {
    /// PPP/tun interface name.
    pub interface: String,
    /// Address assigned to this end.
    pub assigned_ip: Ipv4Addr,
    /// Split routes (empty for a full tunnel).
    pub routes: Vec<IpNet>,
    /// DNS servers.
    pub dns_servers: Vec<Ipv4Addr>,
    /// DNS match domains resolved by `dns_servers`, if supplied by explicit policy.
    pub dns_domains: Vec<String>,
    /// Per-domain rules with their own resolvers (gateways with several server sets).
    pub split_dns: Vec<SplitDnsRule>,
    /// Resolved gateway address (kept on the physical uplink).
    pub gateway_ip: Ipv4Addr,
    /// The gateway requires IPv6 to be blocked while connected.
    pub block_ipv6: bool,
}

/// How a worker's termination message starts when the gateway asked for an EMS serial the
/// attempt did not have. The EMS layer recognizes it and appends why there was none.
pub const EMS_REGISTRATION_REQUIRED: &str = "gateway requires EMS registration";

/// How a worker run ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Termination {
    /// `None` for a clean stop requested by the daemon.
    pub code: Option<ErrorCode>,
    /// Sanitized description.
    pub message: String,
}

/// Events from a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerEvent {
    /// Entered a stage.
    Stage(WorkerStage),
    /// Needs input.
    Challenge {
        /// Challenge ID, unique within the attempt.
        id: String,
        /// What is asked for.
        kind: ChallengeKind,
        /// Sanitized prompt.
        prompt: String,
        /// A one-time code prompt where an empty answer asks for a push notification instead
        /// (FortiToken Mobile).
        push: bool,
    },
    /// Tunnel interface is up with these settings. The daemon applies and verifies them.
    Up(TunnelConfig),
    /// The worker has exited.
    Terminated(Termination),
}

/// Commands to a worker.
#[derive(Debug)]
pub enum WorkerCommand {
    /// Answer a challenge.
    Respond {
        /// Challenge ID.
        challenge_id: String,
        /// The answer.
        value: Secret,
    },
    /// Shut down gracefully.
    Stop,
}

/// A running worker's channels. Dropping `commands` cancels the attempt.
#[derive(Debug)]
pub struct WorkerHandle {
    /// Events from the worker; closes after [`WorkerEvent::Terminated`].
    pub events: mpsc::Receiver<WorkerEvent>,
    /// Commands to the worker.
    pub commands: mpsc::Sender<WorkerCommand>,
}

/// Starts workers.
pub trait WorkerFactory: Send + Sync + std::fmt::Debug {
    /// Starts a worker for one attempt.
    fn spawn(&self, cfg: WorkerConfig) -> WorkerHandle;
}

/// A scripted failure for the fake worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FakeFailure {
    /// Gateway unreachable.
    Transport,
    /// Certificate rejected (before any credential is sent).
    Trust,
    /// Gateway requires an unsupported policy.
    UnsupportedPolicy,
    /// Tunnel drops right after coming up.
    DropAfterUp,
}

/// Fake worker behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields, default)]
pub struct FakeWorkerConfig {
    /// Accepted password. `None` accepts any non-empty password.
    pub password: Option<String>,
    /// Required OTP. `None` means the gateway does not ask for one.
    pub otp: Option<String>,
    /// Address to assign.
    pub assigned_ip: Ipv4Addr,
    /// Interface name to report.
    pub interface: String,
    /// Split routes to push.
    pub routes: Vec<IpNet>,
    /// DNS servers to push.
    pub dns_servers: Vec<Ipv4Addr>,
    /// DNS match domains to push.
    pub dns_domains: Vec<String>,
    /// Gateway address to report.
    pub gateway_ip: Ipv4Addr,
    /// Whether the gateway requires blocking IPv6.
    pub block_ipv6: bool,
    /// Delay between steps.
    pub step_delay_ms: u64,
    /// Scripted failure.
    pub fail: Option<FakeFailure>,
}

impl Default for FakeWorkerConfig {
    fn default() -> Self {
        Self {
            password: None,
            otp: Some("123456".into()),
            assigned_ip: Ipv4Addr::new(10, 212, 134, 200),
            interface: "ppp0".into(),
            routes: vec![IpNet {
                addr: Ipv4Addr::new(10, 0, 0, 0).into(),
                prefix: 8,
            }],
            dns_servers: vec![Ipv4Addr::new(10, 0, 0, 53)],
            dns_domains: vec!["corp.example".into()],
            gateway_ip: Ipv4Addr::new(203, 0, 113, 10),
            block_ipv6: true,
            step_delay_ms: 50,
            fail: None,
        }
    }
}

/// The fake worker factory.
#[derive(Debug, Clone, Default)]
pub struct FakeWorker {
    /// Behavior.
    pub config: FakeWorkerConfig,
}

impl WorkerFactory for FakeWorker {
    fn spawn(&self, cfg: WorkerConfig) -> WorkerHandle {
        let (ev_tx, ev_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let script = self.config.clone();
        tokio::spawn(async move {
            let mut run = FakeRun {
                ev: ev_tx,
                cmd: cmd_rx,
                delay: Duration::from_millis(script.step_delay_ms),
                next_challenge: 0,
            };
            let t = run.run(&script, cfg).await;
            let _ = run.ev.send(WorkerEvent::Terminated(t)).await;
        });
        WorkerHandle {
            events: ev_rx,
            commands: cmd_tx,
        }
    }
}

struct FakeRun {
    ev: mpsc::Sender<WorkerEvent>,
    cmd: mpsc::Receiver<WorkerCommand>,
    delay: Duration,
    next_challenge: u32,
}

/// Why a step was interrupted.
enum Stop {
    Requested,
    Failed(Termination),
}

fn fail(code: ErrorCode, msg: &str) -> Stop {
    Stop::Failed(Termination {
        code: Some(code),
        message: msg.into(),
    })
}

impl FakeRun {
    async fn emit(&mut self, e: WorkerEvent) -> Result<(), Stop> {
        // The daemon dropped its receiver: treat as cancellation.
        self.ev.send(e).await.map_err(|_| Stop::Requested)
    }

    /// Sleeps one step, honoring a stop request.
    async fn step(&mut self) -> Result<(), Stop> {
        tokio::select! {
            () = tokio::time::sleep(self.delay) => Ok(()),
            c = self.cmd.recv() => match c {
                Some(WorkerCommand::Stop) | None => Err(Stop::Requested),
                Some(WorkerCommand::Respond { .. }) => Ok(()),
            },
        }
    }

    async fn ask(&mut self, kind: ChallengeKind, prompt: &str) -> Result<Secret, Stop> {
        self.next_challenge += 1;
        let id = format!("c{}", self.next_challenge);
        self.emit(WorkerEvent::Challenge {
            id: id.clone(),
            kind,
            prompt: prompt.into(),
            push: false,
        })
        .await?;
        loop {
            match self.cmd.recv().await {
                Some(WorkerCommand::Respond {
                    challenge_id,
                    value,
                }) if challenge_id == id => return Ok(value),
                Some(WorkerCommand::Respond { .. }) => {}
                Some(WorkerCommand::Stop) | None => return Err(Stop::Requested),
            }
        }
    }

    async fn run(&mut self, s: &FakeWorkerConfig, cfg: WorkerConfig) -> Termination {
        match self.run_inner(s, cfg).await {
            Ok(()) | Err(Stop::Requested) => Termination {
                code: None,
                message: "stopped".into(),
            },
            Err(Stop::Failed(t)) => t,
        }
    }

    async fn run_inner(&mut self, s: &FakeWorkerConfig, cfg: WorkerConfig) -> Result<(), Stop> {
        self.emit(WorkerEvent::Stage(WorkerStage::Transport))
            .await?;
        self.step().await?;
        match s.fail {
            Some(FakeFailure::Transport) => {
                return Err(fail(ErrorCode::TransportFailure, "gateway unreachable"));
            }
            Some(FakeFailure::Trust) => {
                return Err(fail(
                    ErrorCode::TrustFailure,
                    "gateway certificate not trusted",
                ));
            }
            _ => {}
        }
        self.emit(WorkerEvent::Stage(WorkerStage::Authenticating))
            .await?;
        if cfg.username.is_none() {
            let u = self.ask(ChallengeKind::Username, "Username").await?;
            if u.is_empty() {
                return Err(fail(ErrorCode::AuthDenied, "username required"));
            }
        }
        let pw = self.ask(ChallengeKind::Password, "Password").await?;
        self.step().await?;
        let ok = match &s.password {
            Some(p) => pw.expose() == p,
            None => !pw.is_empty(),
        };
        drop(pw);
        if !ok {
            return Err(fail(ErrorCode::AuthDenied, "credentials rejected"));
        }
        if let Some(expected) = &s.otp {
            let otp = self.ask(ChallengeKind::Otp, "Token code").await?;
            self.step().await?;
            if otp.expose() != expected {
                return Err(fail(ErrorCode::AuthDenied, "token code rejected"));
            }
        }
        if s.fail == Some(FakeFailure::UnsupportedPolicy) {
            return Err(fail(
                ErrorCode::UnsupportedPolicy,
                "gateway requires an unsupported policy",
            ));
        }
        self.emit(WorkerEvent::Stage(WorkerStage::Negotiating))
            .await?;
        self.step().await?;
        let routes = match cfg.ip_policy {
            IpPolicy::SplitIpv4 => s.routes.clone(),
            IpPolicy::FullIpv4 => Vec::new(),
        };
        self.emit(WorkerEvent::Up(TunnelConfig {
            interface: s.interface.clone(),
            assigned_ip: s.assigned_ip,
            routes,
            dns_servers: s.dns_servers.clone(),
            dns_domains: s.dns_domains.clone(),
            split_dns: Vec::new(),
            gateway_ip: s.gateway_ip,
            block_ipv6: s.block_ipv6,
        }))
        .await?;
        if s.fail == Some(FakeFailure::DropAfterUp) {
            self.step().await?;
            self.step().await?;
            return Err(fail(
                ErrorCode::TransportFailure,
                "tunnel closed by gateway",
            ));
        }
        loop {
            match self.cmd.recv().await {
                Some(WorkerCommand::Stop) | None => return Err(Stop::Requested),
                Some(WorkerCommand::Respond { .. }) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(username: Option<&str>) -> WorkerConfig {
        WorkerConfig {
            attempt_id: "a1".into(),
            endpoint: Endpoint {
                host: "vpn.example.org".parse().unwrap(),
                port: 443,
                realm: None,
                ems: None,
            },
            username: username.map(Into::into),
            trust_id: "system".into(),
            ip_policy: IpPolicy::SplitIpv4,
            ems: None,
            fct_uid: None,
            debug_ems_sysinfo: Default::default(),
        }
    }

    async fn answer(h: &mut WorkerHandle, kind: ChallengeKind, v: &str) {
        loop {
            match h.events.recv().await.unwrap() {
                WorkerEvent::Challenge { id, kind: k, .. } => {
                    assert_eq!(k, kind);
                    h.commands
                        .send(WorkerCommand::Respond {
                            challenge_id: id,
                            value: v.into(),
                        })
                        .await
                        .unwrap();
                    return;
                }
                WorkerEvent::Terminated(t) => panic!("terminated: {t:?}"),
                _ => {}
            }
        }
    }

    async fn until_end(h: &mut WorkerHandle) -> (bool, Termination) {
        let mut up = false;
        loop {
            match h.events.recv().await.unwrap() {
                WorkerEvent::Up(_) => {
                    up = true;
                    h.commands.send(WorkerCommand::Stop).await.unwrap();
                }
                WorkerEvent::Terminated(t) => return (up, t),
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn happy_path_with_otp() {
        let w = FakeWorker {
            config: FakeWorkerConfig {
                step_delay_ms: 1,
                ..Default::default()
            },
        };
        let mut h = w.spawn(cfg(None));
        answer(&mut h, ChallengeKind::Username, "alice").await;
        answer(&mut h, ChallengeKind::Password, "pw").await;
        answer(&mut h, ChallengeKind::Otp, "123456").await;
        let (up, t) = until_end(&mut h).await;
        assert!(up);
        assert_eq!(t.code, None);
    }

    #[tokio::test]
    async fn wrong_otp_is_auth_denied() {
        let w = FakeWorker {
            config: FakeWorkerConfig {
                step_delay_ms: 1,
                ..Default::default()
            },
        };
        let mut h = w.spawn(cfg(Some("alice")));
        answer(&mut h, ChallengeKind::Password, "pw").await;
        answer(&mut h, ChallengeKind::Otp, "000000").await;
        let (up, t) = until_end(&mut h).await;
        assert!(!up);
        assert_eq!(t.code, Some(ErrorCode::AuthDenied));
    }

    #[tokio::test]
    async fn trust_failure_before_credentials() {
        let w = FakeWorker {
            config: FakeWorkerConfig {
                step_delay_ms: 1,
                fail: Some(FakeFailure::Trust),
                ..Default::default()
            },
        };
        let mut h = w.spawn(cfg(Some("alice")));
        loop {
            match h.events.recv().await.unwrap() {
                WorkerEvent::Challenge { .. } => panic!("asked for credentials"),
                WorkerEvent::Terminated(t) => {
                    assert_eq!(t.code, Some(ErrorCode::TrustFailure));
                    break;
                }
                _ => {}
            }
        }
    }
}
