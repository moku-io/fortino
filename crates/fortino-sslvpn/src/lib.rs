//! Native FortiGate SSL VPN worker. It replaces openfortivpn as the production backend.
//!
//! One attempt: TLS to the gateway → `/remote/info` → login with challenges answered through
//! the daemon → tunnel settings → `/remote/sslvpn-tunnel` with in-process PPP → a tun device
//! carrying IPv4 → `Up` to the daemon, which applies routes, DNS and the IPv6 block.
//!
//! It implements [`WorkerFactory`], so it runs in-process in tests and behind the private worker
//! channel in production (`fortino-sslvpn-worker`).

pub mod device;
mod session;
pub mod transport;
mod tunnel;
#[cfg(target_os = "macos")]
pub mod utun;
pub mod worker_main;

use std::net::SocketAddr;
use std::sync::Arc;

use fortino_core::ErrorCode;
use fortino_core::worker::{WorkerConfig, WorkerFactory, WorkerHandle};
use fortino_proto_sslvpn::identity::ClientIdentity;
use tokio::sync::mpsc;

pub use device::{DeviceFactory, LinkParams};
pub use transport::Trust;

/// Why an attempt ended. Messages are sanitized and never carry secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Certificate or trust configuration.
    Trust(String),
    /// Network, TLS or the gateway closing on us.
    Transport(String),
    /// Credentials refused.
    AuthDenied(String),
    /// A challenge went unanswered.
    AuthTimeout,
    /// The gateway requires something this client does not do.
    Unsupported(String),
    /// Creating or configuring the tun device failed.
    LocalNetwork(String),
    /// Stopped by the daemon.
    Cancelled,
    /// Anything else.
    Backend(String),
}

impl From<fortino_tls::Failure> for Failure {
    fn from(e: fortino_tls::Failure) -> Self {
        match e {
            fortino_tls::Failure::Trust(m) => Self::Trust(m),
            fortino_tls::Failure::Transport(m) => Self::Transport(m),
            fortino_tls::Failure::Backend(m) => Self::Backend(m),
            fortino_tls::Failure::Unsupported(m) => Self::Unsupported(m),
        }
    }
}

impl Failure {
    /// The daemon-facing error code.
    pub fn code(&self) -> ErrorCode {
        match self {
            Failure::Trust(_) => ErrorCode::TrustFailure,
            Failure::Transport(_) => ErrorCode::TransportFailure,
            Failure::AuthDenied(_) => ErrorCode::AuthDenied,
            Failure::AuthTimeout => ErrorCode::AuthTimeout,
            Failure::Unsupported(_) => ErrorCode::UnsupportedPolicy,
            Failure::LocalNetwork(_) => ErrorCode::NetworkConfigFailure,
            Failure::Cancelled => ErrorCode::Cancelled,
            Failure::Backend(_) => ErrorCode::BackendFailure,
        }
    }

    /// A short message for the user.
    pub fn message(&self) -> String {
        match self {
            Failure::Trust(m)
            | Failure::Transport(m)
            | Failure::AuthDenied(m)
            | Failure::Unsupported(m)
            | Failure::LocalNetwork(m)
            | Failure::Backend(m) => m.clone(),
            Failure::AuthTimeout => "sign-in timed out".into(),
            Failure::Cancelled => "cancelled".into(),
        }
    }
}

/// The native worker.
#[derive(Debug, Clone)]
pub struct NativeWorker {
    /// Gateway trust.
    pub trust: Trust,
    /// Wire identity (header profile, hostname, EMS facts).
    pub identity: ClientIdentity,
    /// Creates the tun device once PPP is up.
    pub devices: Arc<dyn DeviceFactory>,
    /// Connect here instead of resolving the gateway (tests).
    pub connect_override: Option<SocketAddr>,
}

impl WorkerFactory for NativeWorker {
    fn spawn(&self, cfg: WorkerConfig) -> WorkerHandle {
        let (ev_tx, ev_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let me = self.clone();
        tokio::spawn(async move {
            session::run(me, cfg, ev_tx, cmd_rx).await;
        });
        WorkerHandle {
            events: ev_rx,
            commands: cmd_tx,
        }
    }
}
