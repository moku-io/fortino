//! EMS agent (M3): keeps one registration per EMS server and talks to the server that owns the
//! gateway being connected.
//!
//! - [`transport`]: TLS, one connection per exchange.
//! - [`store`]: registrations side by side, keyed by server.
//! - [`report`]: SYSINFO from real host facts; nothing claimed that Fortino does not have.
//! - [`hostcheck`]: host-verification rules evaluated truthfully into `RULES`.
//! - [`agent`]: probe, register, keepalive, tag report, deregister.

pub mod agent;
pub mod hostcheck;
pub mod report;
pub mod store;
pub mod transport;

pub use agent::{Agent, Keepalive};
pub use store::{Registration, Store};
pub use transport::Connection;

/// Agent errors.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Certificate or trust configuration.
    #[error("trust: {0}")]
    Trust(String),
    /// Network or TLS.
    #[error("transport: {0}")]
    Transport(String),
    /// The server's reply did not make sense.
    #[error("protocol: {0}")]
    Protocol(String),
    /// The server refused, with its message.
    #[error("refused by EMS: {0}")]
    Refused(String),
    /// No registration for this server.
    #[error("not registered to this EMS")]
    NotRegistered,
    /// Local registration storage.
    #[error("store: {0}")]
    Store(String),
}

impl From<fortino_proto_ems::reply::ReplyError> for Error {
    fn from(e: fortino_proto_ems::reply::ReplyError) -> Self {
        Self::Protocol(e.to_string())
    }
}

impl From<fortino_proto_ems::message::BuildError> for Error {
    fn from(e: fortino_proto_ems::message::BuildError) -> Self {
        Self::Protocol(e.to_string())
    }
}

impl From<fortino_proto_ems::sysinfo::SysInfoError> for Error {
    fn from(e: fortino_proto_ems::sysinfo::SysInfoError) -> Self {
        Self::Protocol(e.to_string())
    }
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
