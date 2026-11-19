//! The tun device the worker creates once PPP is up, and an in-memory one for tests.

use std::io;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use fortino_platform::{BoxFut, PacketIo, TunDevice};
use tokio::sync::mpsc;

/// Addresses and MTU for the tunnel interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkParams {
    /// Our address.
    pub local: Ipv4Addr,
    /// The gateway's PPP address (point-to-point peer).
    pub peer: Ipv4Addr,
    /// Interface MTU.
    pub mtu: u16,
}

/// Creates the tunnel interface. The interface is the worker's own; it disappears when the
/// device is dropped, so it needs no journal entry. Routes and DNS stay with the daemon.
pub trait DeviceFactory: Send + Sync + std::fmt::Debug {
    /// Creates and addresses the interface.
    fn create(&self, link: &LinkParams) -> io::Result<TunDevice>;
}

/// The far end of a [`MemoryDevices`] interface: what the "OS" sees.
#[derive(Debug)]
pub struct MemoryPeer {
    /// Packets the tunnel delivered to the OS.
    pub from_tunnel: mpsc::Receiver<Vec<u8>>,
    /// Inject packets as if an application sent them.
    pub to_tunnel: mpsc::Sender<Vec<u8>>,
    /// The parameters the device was created with.
    pub link: LinkParams,
}

/// In-memory tun devices for tests. Each created device's far end lands in `peers`.
#[derive(Debug, Clone, Default)]
pub struct MemoryDevices {
    /// Far ends, in creation order.
    pub peers: Arc<Mutex<Vec<MemoryPeer>>>,
}

struct MemoryIo {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl PacketIo for MemoryIo {
    fn recv(&mut self) -> BoxFut<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            self.rx
                .recv()
                .await
                .ok_or_else(|| io::Error::from(io::ErrorKind::BrokenPipe))
        })
    }

    fn send<'a>(&'a mut self, pkt: &'a [u8]) -> BoxFut<'a, io::Result<()>> {
        Box::pin(async move {
            self.tx
                .send(pkt.to_vec())
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
        })
    }
}

impl DeviceFactory for MemoryDevices {
    fn create(&self, link: &LinkParams) -> io::Result<TunDevice> {
        let (to_os, from_tunnel) = mpsc::channel(64);
        let (to_tunnel, from_os) = mpsc::channel(64);
        let mut peers = self
            .peers
            .lock()
            .map_err(|_| io::Error::other("poisoned"))?;
        let name = format!("faketun{}", peers.len());
        peers.push(MemoryPeer {
            from_tunnel,
            to_tunnel,
            link: *link,
        });
        Ok(TunDevice {
            name,
            io: Box::new(MemoryIo {
                rx: from_os,
                tx: to_os,
            }),
        })
    }
}
