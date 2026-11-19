//! Platform abstraction for the network changes the daemon makes.
//!
//! - [`NetPlatform`] creates the tun device and applies/reverts [`NetChange`]s.
//! - [`journal::Journaled`] wraps a platform so every change is written to a journal on disk
//!   **before** it is applied, and can be undone after a crash.
//! - [`fake::FakeNet`] is an in-memory implementation for tests.

pub mod fake;
pub mod journal;
pub mod macos;
mod types;

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;

pub use types::*;

/// Errors from platform operations.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// An OS call failed.
    #[error("{op}: {source}")]
    Io {
        /// What we were doing.
        op: String,
        /// The OS error.
        #[source]
        source: io::Error,
    },
    /// The platform can't do this.
    #[error("unsupported on this platform: {0}")]
    Unsupported(String),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

impl PlatformError {
    /// Wraps an I/O error with context.
    pub fn io(op: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            op: op.into(),
            source,
        }
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, PlatformError>;

/// Boxed future used by [`PacketIo`].
pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Packet I/O on a tun device: one IP packet per call, no link header.
pub trait PacketIo: Send {
    /// Reads one packet from the OS (traffic to send into the tunnel).
    fn recv(&mut self) -> BoxFut<'_, io::Result<Vec<u8>>>;
    /// Writes one packet to the OS (traffic that came out of the tunnel).
    fn send<'a>(&'a mut self, pkt: &'a [u8]) -> BoxFut<'a, io::Result<()>>;
}

/// A tun device. The OS removes it when this value (its file descriptor) is dropped, so it
/// needs no journal entry.
pub struct TunDevice {
    /// Interface name (e.g. `utun5`, `ofc0`).
    pub name: String,
    /// Packet I/O.
    pub io: Box<dyn PacketIo>,
}

impl std::fmt::Debug for TunDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunDevice")
            .field("name", &self.name)
            .finish()
    }
}

/// Operations on the host network. Implementations: macOS, Linux, [`fake::FakeNet`].
///
/// Changes go through [`journal::Journaled`], which calls [`NetPlatform::prepare`] to capture
/// the [`Undo`], persists it, then calls [`NetPlatform::apply`].
pub trait NetPlatform: Send {
    /// Creates a non-persistent tun device.
    fn create_tun(&mut self) -> Result<TunDevice>;

    /// Captures what is needed to reverse `change` without modifying anything.
    fn prepare(&mut self, change: &NetChange) -> Result<Undo>;

    /// Applies `change`.
    fn apply(&mut self, change: &NetChange) -> Result<()>;

    /// Reverses a change. Must succeed (or be a no-op) when the change was never applied,
    /// was partly applied, or was already reverted.
    fn revert(&mut self, undo: &Undo) -> Result<()>;

    /// The route the OS would currently use to reach `dst` (used to pin the VPN server
    /// outside a full tunnel).
    fn route_to(&mut self, dst: IpAddr) -> Result<Option<RouteVia>>;
}
