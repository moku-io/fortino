//! macOS `utun` device for the tunnel (via `tun-rs`). The worker addresses its own
//! point-to-point interface; routes, DNS and the IPv6 block stay with the daemon, so automatic
//! route association is turned off.

use std::io;
use std::sync::Arc;

use ofc_platform::{BoxFut, PacketIo, TunDevice};
use tun_rs::{AsyncDevice, DeviceBuilder};

use crate::device::{DeviceFactory, LinkParams};

/// Creates `utunN` interfaces. Needs root.
#[derive(Debug, Clone, Copy, Default)]
pub struct UtunDevices;

struct UtunIo {
    dev: Arc<AsyncDevice>,
    mtu: usize,
}

impl PacketIo for UtunIo {
    fn recv(&mut self) -> BoxFut<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            let mut buf = vec![0u8; self.mtu + 64];
            let n = self.dev.recv(&mut buf).await?;
            buf.truncate(n);
            Ok(buf)
        })
    }

    fn send<'a>(&'a mut self, pkt: &'a [u8]) -> BoxFut<'a, io::Result<()>> {
        Box::pin(async move {
            self.dev.send(pkt).await?;
            Ok(())
        })
    }
}

impl DeviceFactory for UtunDevices {
    fn create(&self, link: &LinkParams) -> io::Result<TunDevice> {
        let dev = DeviceBuilder::new()
            .ipv4(link.local, 32u8, Some(link.peer))
            .mtu(link.mtu)
            .associate_route(false)
            .build_async()?;
        let name = dev.name()?;
        Ok(TunDevice {
            name,
            io: Box::new(UtunIo {
                dev: Arc::new(dev),
                mtu: usize::from(link.mtu),
            }),
        })
    }
}
