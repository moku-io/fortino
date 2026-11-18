//! In-memory [`NetPlatform`] for tests.
//!
//! State is shared through an `Arc<Mutex<_>>` so a test can inspect it, and can simulate a
//! daemon restart by building a second `FakeNet` on the same state.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::sync::mpsc;

use crate::{
    BoxFut, DnsConfig, IpNet, NetChange, NetPlatform, PacketIo, PlatformError, Result, Route,
    RouteVia, TunDevice, Undo,
};

/// Host network state as the fake sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FakeState {
    /// Existing interfaces and their MTU.
    pub links: BTreeMap<String, u32>,
    /// Interfaces that are up.
    pub up: BTreeSet<String>,
    /// Addresses per interface.
    pub addrs: BTreeSet<(String, IpNet)>,
    /// Routing table.
    pub routes: BTreeSet<RouteKey>,
    /// Global resolver settings and the interface that owns them.
    pub dns: Option<(String, DnsConfig)>,
    /// Split-DNS resolvers per domain.
    pub split_dns: BTreeMap<String, Vec<IpAddr>>,
    /// IPv6 blocked.
    pub ipv6_blocked: bool,
    /// Number of `apply` calls so far.
    pub applies: usize,
    /// Make the apply call with this (0-based) index fail.
    pub fail_apply_at: Option<usize>,
}

/// Route stored in a sortable form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RouteKey(pub String);

impl From<&Route> for RouteKey {
    fn from(r: &Route) -> Self {
        let via = match &r.via {
            RouteVia::Interface(i) => format!("dev {i}"),
            RouteVia::Gateway { gateway, ifname } => match ifname {
                Some(i) => format!("via {gateway} dev {i}"),
                None => format!("via {gateway}"),
            },
        };
        Self(format!("{} {via}", r.dest))
    }
}

impl FakeState {
    /// A host with `en0` (MTU 1500), a default route via 192.0.2.1 and one resolver.
    pub fn typical_host() -> Self {
        let mut s = Self::default();
        s.links.insert("en0".into(), 1500);
        s.up.insert("en0".into());
        s.routes
            .insert(RouteKey("0.0.0.0/0 via 192.0.2.1 dev en0".into()));
        s.dns = Some((
            "en0".into(),
            DnsConfig {
                servers: vec![IpAddr::from([192, 0, 2, 53])],
                search_domains: vec!["home.example".into()],
            },
        ));
        s
    }

    /// True when the routing table has this route.
    pub fn has_route(&self, r: &Route) -> bool {
        self.routes.contains(&RouteKey::from(r))
    }

    /// Network state without the bookkeeping counters (for before/after comparisons).
    pub fn net_only(&self) -> Self {
        Self {
            applies: 0,
            fail_apply_at: None,
            ..self.clone()
        }
    }
}

/// Test side of a fake tun device.
#[derive(Debug)]
pub struct FakeTunPeer {
    /// Packets the "OS" injects into the tunnel (what the client must send to the server).
    pub to_tunnel: mpsc::Sender<Vec<u8>>,
    /// Packets the client wrote to the "OS".
    pub from_tunnel: mpsc::Receiver<Vec<u8>>,
}

struct FakeTunIo {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl PacketIo for FakeTunIo {
    fn recv(&mut self) -> BoxFut<'_, io::Result<Vec<u8>>> {
        Box::pin(async move {
            self.rx
                .recv()
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "fake tun closed"))
        })
    }

    fn send<'a>(&'a mut self, pkt: &'a [u8]) -> BoxFut<'a, io::Result<()>> {
        Box::pin(async move {
            self.tx
                .send(pkt.to_vec())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "fake tun closed"))
        })
    }
}

/// In-memory platform.
#[derive(Debug, Clone)]
pub struct FakeNet {
    state: Arc<Mutex<FakeState>>,
    tun_peers: Arc<Mutex<Vec<FakeTunPeer>>>,
    next_tun: Arc<Mutex<u32>>,
}

impl FakeNet {
    /// New fake on the given shared state.
    pub fn new(state: Arc<Mutex<FakeState>>) -> Self {
        Self {
            state,
            tun_peers: Arc::default(),
            next_tun: Arc::default(),
        }
    }

    /// Shared state handle.
    pub fn state(&self) -> Arc<Mutex<FakeState>> {
        self.state.clone()
    }

    /// Snapshot of the state.
    pub fn snapshot(&self) -> FakeState {
        self.lock().clone()
    }

    /// Takes the test side of the oldest tun device not yet taken.
    pub fn take_tun_peer(&self) -> Option<FakeTunPeer> {
        let mut p = self.tun_peers.lock().unwrap_or_else(|e| e.into_inner());
        (!p.is_empty()).then(|| p.remove(0))
    }

    fn lock(&self) -> MutexGuard<'_, FakeState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn dns_snapshot(dns: &Option<(String, DnsConfig)>) -> String {
    serde_json::to_string(dns).unwrap_or_default()
}

impl NetPlatform for FakeNet {
    fn create_tun(&mut self) -> Result<TunDevice> {
        let n = {
            let mut g = self.next_tun.lock().unwrap_or_else(|e| e.into_inner());
            let n = *g;
            *g += 1;
            n
        };
        let name = format!("faketun{n}");
        self.lock().links.insert(name.clone(), 1500);
        let (to_tunnel, rx) = mpsc::channel(256);
        let (tx, from_tunnel) = mpsc::channel(256);
        self.tun_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(FakeTunPeer {
                to_tunnel,
                from_tunnel,
            });
        Ok(TunDevice {
            name,
            io: Box::new(FakeTunIo { rx, tx }),
        })
    }

    fn prepare(&mut self, change: &NetChange) -> Result<Undo> {
        let s = self.lock();
        Ok(match change {
            NetChange::AddAddress { ifname, addr, .. } => Undo::DelAddress {
                ifname: ifname.clone(),
                addr: *addr,
            },
            NetChange::SetMtu { ifname, .. } => Undo::RestoreMtu {
                ifname: ifname.clone(),
                mtu: s.links.get(ifname).copied().unwrap_or(1500),
            },
            NetChange::LinkUp { .. } => Undo::Nothing,
            NetChange::AddRoute(r) => Undo::DelRoute(r.clone()),
            NetChange::SetDns { ifname, .. } => Undo::RestoreDns {
                ifname: ifname.clone(),
                previous: dns_snapshot(&s.dns),
            },
            NetChange::AddSplitDns { domain, .. } => Undo::DelSplitDns {
                domain: domain.clone(),
                previous: s
                    .split_dns
                    .get(domain)
                    .map(|v| serde_json::to_string(v).unwrap_or_default()),
            },
            NetChange::BlockIpv6 => Undo::UnblockIpv6,
        })
    }

    fn apply(&mut self, change: &NetChange) -> Result<()> {
        let mut s = self.lock();
        let idx = s.applies;
        s.applies += 1;
        if s.fail_apply_at == Some(idx) {
            return Err(PlatformError::Other(format!(
                "injected failure at apply #{idx}"
            )));
        }
        let need_link = |s: &FakeState, i: &str| {
            if s.links.contains_key(i) {
                Ok(())
            } else {
                Err(PlatformError::Other(format!("no such interface {i}")))
            }
        };
        match change {
            NetChange::AddAddress { ifname, addr, .. } => {
                need_link(&s, ifname)?;
                s.addrs.insert((ifname.clone(), *addr));
            }
            NetChange::SetMtu { ifname, mtu } => {
                need_link(&s, ifname)?;
                s.links.insert(ifname.clone(), *mtu);
            }
            NetChange::LinkUp { ifname } => {
                need_link(&s, ifname)?;
                s.up.insert(ifname.clone());
            }
            NetChange::AddRoute(r) => {
                s.routes.insert(r.into());
            }
            NetChange::SetDns { ifname, dns } => {
                s.dns = Some((ifname.clone(), dns.clone()));
            }
            NetChange::AddSplitDns { domain, servers } => {
                s.split_dns.insert(domain.clone(), servers.clone());
            }
            NetChange::BlockIpv6 => s.ipv6_blocked = true,
        }
        Ok(())
    }

    fn revert(&mut self, undo: &Undo) -> Result<()> {
        let mut s = self.lock();
        match undo {
            Undo::Nothing => {}
            Undo::DelAddress { ifname, addr } => {
                s.addrs.remove(&(ifname.clone(), *addr));
            }
            Undo::RestoreMtu { ifname, mtu } => {
                if let Some(m) = s.links.get_mut(ifname) {
                    *m = *mtu;
                }
            }
            Undo::DelRoute(r) => {
                s.routes.remove(&RouteKey::from(r));
            }
            Undo::RestoreDns { previous, .. } => {
                s.dns = serde_json::from_str(previous)
                    .map_err(|e| PlatformError::Other(format!("bad dns snapshot: {e}")))?;
            }
            Undo::DelSplitDns { domain, previous } => match previous {
                Some(p) => {
                    let v = serde_json::from_str(p)
                        .map_err(|e| PlatformError::Other(format!("bad split dns: {e}")))?;
                    s.split_dns.insert(domain.clone(), v);
                }
                None => {
                    s.split_dns.remove(domain);
                }
            },
            Undo::UnblockIpv6 => s.ipv6_blocked = false,
        }
        Ok(())
    }

    fn route_to(&mut self, dst: IpAddr) -> Result<Option<RouteVia>> {
        // Longest prefix match over the textual routes.
        let s = self.lock();
        let mut best: Option<(u8, RouteVia)> = None;
        for RouteKey(r) in &s.routes {
            let mut parts = r.split_whitespace();
            let (Some(net), Some(kind), Some(arg)) = (parts.next(), parts.next(), parts.next())
            else {
                continue;
            };
            let Ok(net) = net.parse::<IpNet>() else {
                continue;
            };
            if !net.contains(dst) || best.as_ref().is_some_and(|(p, _)| *p >= net.prefix) {
                continue;
            }
            let via = match kind {
                "dev" => RouteVia::Interface(arg.into()),
                _ => {
                    let Ok(gateway) = arg.parse() else { continue };
                    let ifname = match (parts.next(), parts.next()) {
                        (Some("dev"), Some(i)) => Some(i.to_owned()),
                        _ => None,
                    };
                    RouteVia::Gateway { gateway, ifname }
                }
            };
            best = Some((net.prefix, via));
        }
        Ok(best.map(|(_, v)| v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_and_revert_round_trip() {
        let st = Arc::new(Mutex::new(FakeState::typical_host()));
        let mut net = FakeNet::new(st.clone());
        let before = net.snapshot().net_only();
        let tun = net.create_tun().unwrap();
        let changes = vec![
            NetChange::AddAddress {
                ifname: tun.name.clone(),
                addr: "10.212.134.5/32".parse().unwrap(),
                peer: None,
            },
            NetChange::SetMtu {
                ifname: tun.name.clone(),
                mtu: 1300,
            },
            NetChange::AddRoute(Route {
                dest: "10.0.0.0/8".parse().unwrap(),
                via: RouteVia::Interface(tun.name.clone()),
            }),
            NetChange::SetDns {
                ifname: tun.name.clone(),
                dns: DnsConfig {
                    servers: vec!["10.0.0.53".parse().unwrap()],
                    search_domains: vec![],
                },
            },
            NetChange::AddSplitDns {
                domain: "corp.example".into(),
                servers: vec!["10.0.0.53".parse().unwrap()],
            },
            NetChange::BlockIpv6,
        ];
        let mut undos = vec![];
        for c in &changes {
            undos.push(net.prepare(c).unwrap());
            net.apply(c).unwrap();
        }
        assert!(net.snapshot().ipv6_blocked);
        for u in undos.iter().rev() {
            net.revert(u).unwrap();
            // Idempotent.
            net.revert(u).unwrap();
        }
        let mut after = net.snapshot().net_only();
        after.links.remove(&tun.name);
        assert_eq!(after, before);
    }

    #[test]
    fn route_to_longest_prefix() {
        let mut net = FakeNet::new(Arc::new(Mutex::new(FakeState::typical_host())));
        let r = Route {
            dest: "10.0.0.0/8".parse().unwrap(),
            via: RouteVia::Interface("faketun0".into()),
        };
        net.apply(&NetChange::AddRoute(r)).unwrap();
        assert_eq!(
            net.route_to("10.1.1.1".parse().unwrap()).unwrap(),
            Some(RouteVia::Interface("faketun0".into()))
        );
        assert_eq!(
            net.route_to("8.8.8.8".parse().unwrap()).unwrap(),
            Some(RouteVia::Gateway {
                gateway: "192.0.2.1".parse().unwrap(),
                ifname: Some("en0".into())
            })
        );
    }

    #[tokio::test]
    async fn tun_packets_flow() {
        let mut net = FakeNet::new(Arc::default());
        let mut tun = net.create_tun().unwrap();
        let mut peer = net.take_tun_peer().unwrap();
        peer.to_tunnel.send(vec![0x45, 1, 2]).await.unwrap();
        assert_eq!(tun.io.recv().await.unwrap(), vec![0x45, 1, 2]);
        tun.io.send(&[0x45, 9]).await.unwrap();
        assert_eq!(peer.from_tunnel.recv().await.unwrap(), vec![0x45, 9]);
    }
}
