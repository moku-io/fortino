//! The PPP tunnel over `/remote/sslvpn-tunnel` and the tun device.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use fortino_core::worker::{SplitDnsRule, TunnelConfig, WorkerCommand, WorkerEvent};
use fortino_platform::IpNet;
use fortino_proto_sslvpn::config::TunnelSettings;
use fortino_proto_sslvpn::frame;
use fortino_proto_sslvpn::http::{self, Parsed};
use fortino_proto_sslvpn::identity;
use fortino_proto_sslvpn::ppp::{DownReason, Ipv4Link, Ppp, PppConfig, PppEvent};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::device::LinkParams;
use crate::session::{Ctx, Session};
use crate::{Failure, NativeWorker};

/// FortiClient's SSL VPN MTU.
pub const DEFAULT_MTU: u16 = 1300;
/// How long an orderly PPP close may take.
const CLOSE_GRACE: std::time::Duration = std::time::Duration::from_secs(3);

pub(crate) async fn run(w: &NativeWorker, s: &mut Session, ctx: &mut Ctx) -> Result<(), Failure> {
    let mut tls = ctx.guard(s.gw.connect()).await?;
    let req = identity::tunnel_request(&s.identity, &s.cookie, s.fct_uid.as_deref());
    tls.write_all(&req.encode())
        .await
        .map_err(|e| Failure::Transport(format!("tunnel request: {e}")))?;

    let now = Instant::now();
    let mut ppp = Ppp::new(PppConfig::new(rand::random()), now);
    let mut dec = frame::Decoder::default();
    // Some gateways answer the tunnel request with an HTTP status first; GATEWAY-2 does not.
    let mut preamble: Option<Vec<u8>> = Some(Vec::new());
    let mut buf = vec![0u8; 64 * 1024];
    let (dev_tx, mut dev_rx) = mpsc::channel::<Vec<u8>>(256);
    let mut to_dev: Option<mpsc::Sender<Vec<u8>>> = None;
    let mut up = false;
    let mut stop_deadline: Option<tokio::time::Instant> = None;
    let mut stopping = false;
    let mut out = Vec::with_capacity(16 * 1024);

    loop {
        // Drain the engine.
        while let Some(ev) = ppp.poll_event() {
            match ev {
                PppEvent::Send(p) => {
                    frame::encode(&p, &mut out).map_err(|e| Failure::Backend(e.to_string()))?;
                }
                PppEvent::Packet(p) => {
                    if let Some(t) = &to_dev {
                        // Drop rather than stall the tunnel when the OS side is slow.
                        let _ = t.try_send(p);
                    }
                }
                PppEvent::Up(link) => {
                    let tc = up_config(w, s, &link, dev_tx.clone(), &mut to_dev)?;
                    up = true;
                    ctx.emit(WorkerEvent::Up(tc)).await;
                }
                PppEvent::Down(why) => {
                    if !out.is_empty() {
                        let _ = tls.write_all(&out).await;
                    }
                    return match (why, stopping) {
                        (_, true) | (DownReason::Closed, _) => Ok(()),
                        (DownReason::PeerTerminated, _) => {
                            Err(Failure::Transport("gateway closed the tunnel".into()))
                        }
                        (DownReason::KeepaliveTimeout, _) => {
                            Err(Failure::Transport("gateway stopped answering".into()))
                        }
                        (DownReason::NegotiationFailed(m), _) => Err(Failure::Backend(m.into())),
                        (DownReason::Renegotiated, _) => {
                            Err(Failure::Transport("gateway restarted the link".into()))
                        }
                    };
                }
            }
        }
        if !out.is_empty() {
            tls.write_all(&out)
                .await
                .map_err(|e| Failure::Transport(format!("tunnel write: {e}")))?;
            out.clear();
        }

        let wake = ppp
            .poll_timeout()
            .map(tokio::time::Instant::from_std)
            .into_iter()
            .chain(stop_deadline)
            .min();
        let sleep = async {
            match wake {
                Some(t) => tokio::time::sleep_until(t).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            r = tls.read(&mut buf) => {
                let n = match r {
                    Ok(0) => 0,
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
                    Err(e) => return Err(Failure::Transport(format!("tunnel read: {e}"))),
                };
                if n == 0 {
                    if stopping {
                        return Ok(());
                    }
                    return Err(if up {
                        Failure::Transport("gateway closed the tunnel".into())
                    } else {
                        Failure::Unsupported("gateway closed the tunnel before PPP started".into())
                    });
                }
                let mut data = &buf[..n];
                let owned: Vec<u8>;
                if let Some(pre) = preamble.as_mut() {
                    pre.extend_from_slice(data);
                    if pre.len() < 5 && b"HTTP/".starts_with(pre) {
                        continue;
                    }
                    if pre.starts_with(b"HTTP/") {
                        match http::parse_response(pre, false) {
                            Ok(Parsed::Incomplete) => continue,
                            Ok(Parsed::Done(r, used)) if r.status == 200 => {
                                owned = pre.split_off(used);
                                preamble = None;
                                data = &owned;
                            }
                            Ok(Parsed::Done(r, _)) => {
                                return Err(if r.status == 403 {
                                    Failure::Unsupported("gateway refused tunnel access for this device".into())
                                } else {
                                    Failure::Backend(format!("tunnel request: HTTP {}", r.status))
                                });
                            }
                            Err(e) => return Err(Failure::Backend(format!("tunnel request: {e}"))),
                        }
                    } else {
                        owned = std::mem::take(pre);
                        preamble = None;
                        data = &owned;
                    }
                }
                dec.push(data);
                let now = Instant::now();
                loop {
                    match dec.next_frame() {
                        Ok(Some(p)) => ppp.input(&p, now),
                        Ok(None) => break,
                        Err(e) => return Err(Failure::Backend(format!("tunnel framing: {e}"))),
                    }
                }
            }
            Some(pkt) = dev_rx.recv() => {
                // Oversized or early packets are dropped, as a link would.
                let _ = ppp.send_ip(&pkt);
            }
            c = ctx.commands.recv(), if !stopping => {
                match c {
                    None | Some(WorkerCommand::Stop) => {
                        stopping = true;
                        ppp.close(Instant::now());
                        stop_deadline = Some(tokio::time::Instant::now() + CLOSE_GRACE);
                    }
                    Some(WorkerCommand::Respond { .. }) => {}
                }
            }
            () = sleep => {
                if stop_deadline.is_some_and(|d| d <= tokio::time::Instant::now()) {
                    return Ok(());
                }
                ppp.handle_timeout(Instant::now());
            }
        }
    }
}

/// Creates the device and builds the settings the daemon applies.
fn up_config(
    w: &NativeWorker,
    s: &Session,
    link: &Ipv4Link,
    dev_tx: mpsc::Sender<Vec<u8>>,
    to_dev: &mut Option<mpsc::Sender<Vec<u8>>>,
) -> Result<TunnelConfig, Failure> {
    let st = &s.settings;
    let gateway_ip = match s.gw.resolved.map(|a| a.ip()) {
        Some(IpAddr::V4(ip)) => ip,
        _ => return Err(Failure::Backend("gateway address unknown".into())),
    };
    if !st.exclude_v4.is_empty() {
        return Err(Failure::Unsupported(
            "excluded split routes are not supported yet".into(),
        ));
    }
    if let Some(a) = st.assigned_v4 {
        if a != link.local {
            tracing::warn!("IPCP address differs from the settings XML; using IPCP");
        }
    }
    let (dns_servers, split_dns) = dns_policy(st, link);

    let params = LinkParams {
        local: link.local,
        // The far-side address labels the point-to-point interface and installs a host route to
        // itself via the tunnel. A FortiGate announces its public address as the peer (PPP
        // semantics), but using that here would route the TLS carrier into its own tunnel. Only
        // accept a peer that is a distinct in-tunnel address; otherwise label the link with our
        // own assigned address, which captures nothing external.
        peer: match link.peer {
            Some(p) if p != gateway_ip => p,
            _ => link.local,
        },
        mtu: DEFAULT_MTU.min(link.peer_mru),
    };
    let dev = w
        .devices
        .create(&params)
        .map_err(|e| Failure::LocalNetwork(format!("tun device: {e}")))?;
    let name = dev.name.clone();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
    *to_dev = Some(tx);
    tokio::spawn(pump(dev, rx, dev_tx));

    Ok(TunnelConfig {
        interface: name,
        assigned_ip: link.local,
        routes: st
            .include_v4
            .iter()
            .map(|n| IpNet {
                addr: IpAddr::V4(n.addr),
                prefix: n.prefix,
            })
            .collect(),
        dns_servers,
        dns_domains: Vec::new(),
        split_dns,
        gateway_ip,
        // FortiClient blocks IPv6 on an IPv4-only tunnel.
        block_ipv6: st.assigned_v6.is_none(),
    })
}

/// The gateway's DNS policy for the daemon: global resolvers, and each split-DNS rule with
/// its own servers (a rule without servers uses the global ones).
fn dns_policy(st: &TunnelSettings, link: &Ipv4Link) -> (Vec<Ipv4Addr>, Vec<SplitDnsRule>) {
    let mut servers: Vec<Ipv4Addr> = st
        .dns
        .iter()
        .filter_map(|a| match a {
            IpAddr::V4(v) => Some(*v),
            IpAddr::V6(_) => None,
        })
        .collect();
    if servers.is_empty() {
        servers = link.dns.clone();
    }
    servers.dedup();
    let rules = st
        .split_dns
        .iter()
        .map(|r| SplitDnsRule {
            domains: r.domains.clone(),
            servers: if r.servers.is_empty() {
                servers.clone()
            } else {
                r.servers.clone()
            },
        })
        .filter(|r| !r.servers.is_empty())
        .collect();
    (servers, rules)
}

/// Moves packets between the device and the tunnel task.
async fn pump(
    mut dev: fortino_platform::TunDevice,
    mut from_tunnel: mpsc::Receiver<Vec<u8>>,
    to_tunnel: mpsc::Sender<Vec<u8>>,
) {
    loop {
        tokio::select! {
            r = dev.io.recv() => match r {
                Ok(p) => {
                    if to_tunnel.send(p).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            },
            p = from_tunnel.recv() => match p {
                Some(p) => {
                    if dev.io.send(&p).await.is_err() {
                        return;
                    }
                }
                // The tunnel ended: dropping the device removes the interface.
                None => return,
            },
        }
    }
}
