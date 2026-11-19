//! Live probe: runs the native worker in-process against a real gateway and reports each
//! stage. Development tool, not shipped.
//!
//! ```text
//! ofc-sslvpn-probe <credentials-file> [--device memory|utun] [--ca FILE] [--pin SHA256] [--hold SECS]
//! ofc-sslvpn-probe <credentials-file> --print-pin
//! ```
//!
//! The credentials file has `key: value`
//! lines: `gateway` (host:port), `username`, `password`, optional `otp`, and optional
//! `test endpoint to check if connection succeed`. Secrets are never printed.
//!
//! `--device memory` (default) needs no privileges and changes nothing on the host: it proves
//! TLS, login, tunnel settings and PPP up to IPCP. `--device utun` creates a real interface
//! and needs root; run it only in a disposable VM.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ofc_config::{Endpoint, IpPolicy};
use ofc_core::proto::ChallengeKind;
use ofc_core::worker::{WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory};
use ofc_proto_sslvpn::identity::ClientIdentity;
use ofc_secret::Secret;
use ofc_sslvpn::device::{DeviceFactory, MemoryDevices};
use ofc_sslvpn::{NativeWorker, Trust};

fn read_creds(path: &str) -> Result<HashMap<String, String>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    Ok(text
        .lines()
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect())
}

fn hostname() -> String {
    std::process::Command::new("/bin/hostname")
        .arg("-s")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mac".into())
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("probe: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `https://name:port/path` → port (default by scheme).
fn url_port(u: &str) -> u16 {
    let (scheme, rest) = u.split_once("://").unwrap_or(("https", u));
    let hostport = rest.split('/').next().unwrap_or("");
    hostport
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(if scheme == "http" { 80 } else { 443 })
}

/// `https://name:port/path` → `name`.
fn url_host(u: &str) -> String {
    let rest = u.split_once("://").map_or(u, |(_, r)| r);
    let hostport = rest.split('/').next().unwrap_or("");
    hostport
        .rsplit_once(':')
        .map_or(hostport, |(h, _)| h)
        .to_owned()
}

fn csum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in b.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    let len = (20 + payload.len()) as u16;
    let mut p = vec![0x45, 0];
    p.extend_from_slice(&len.to_be_bytes());
    p.extend_from_slice(&[0x4f, 0x43, 0, 0, 64, proto, 0, 0]);
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let c = csum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn dns_query(id: u16, name: &str) -> Vec<u8> {
    let mut q = id.to_be_bytes().to_vec();
    q.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

/// First A record in a DNS answer.
fn dns_answer(m: &[u8]) -> (u8, Option<Ipv4Addr>) {
    if m.len() < 12 {
        return (255, None);
    }
    let rcode = m[3] & 0x0f;
    let an = u16::from_be_bytes([m[6], m[7]]);
    let mut i = 12;
    while i < m.len() && m[i] != 0 {
        i += 1 + usize::from(m[i]);
    }
    i += 5;
    for _ in 0..an {
        if i >= m.len() {
            break;
        }
        if m[i] & 0xc0 == 0xc0 {
            i += 2;
        } else {
            while i < m.len() && m[i] != 0 {
                i += 1 + usize::from(m[i]);
            }
            i += 1;
        }
        if i + 10 > m.len() {
            break;
        }
        let ty = u16::from_be_bytes([m[i], m[i + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([m[i + 8], m[i + 9]]));
        i += 10;
        if ty == 1 && rdlen == 4 && i + 4 <= m.len() {
            return (
                rcode,
                Some(Ipv4Addr::new(m[i], m[i + 1], m[i + 2], m[i + 3])),
            );
        }
        i += rdlen;
    }
    (rcode, None)
}

fn r_is_synack(v: &str) -> bool {
    v.starts_with("SYN-ACK")
}

async fn recv_matching(
    peer: &mut ofc_sslvpn::device::MemoryPeer,
    f: impl Fn(&[u8]) -> bool,
) -> Option<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, peer.from_tunnel.recv()).await {
            Ok(Some(p)) if f(&p) => return Some(p),
            Ok(Some(_)) => {}
            _ => return None,
        }
    }
}

/// Userspace data-plane check through the in-memory device: DNS over the tunnel, then ICMP.
async fn data_plane(
    mut peer: ofc_sslvpn::device::MemoryPeer,
    tc: &ofc_core::worker::TunnelConfig,
    host: Option<&str>,
    port: u16,
) {
    let me = tc.assigned_ip;
    let mut target = None;
    if let Some(name) = host.filter(|h| h.parse::<Ipv4Addr>().is_err()) {
        for (n, dns) in tc.dns_servers.iter().enumerate() {
            let q = dns_query(0x4f43 + n as u16, name);
            let mut udp = 40000u16.to_be_bytes().to_vec();
            udp.extend_from_slice(&53u16.to_be_bytes());
            udp.extend_from_slice(&((8 + q.len()) as u16).to_be_bytes());
            udp.extend_from_slice(&[0, 0]);
            udp.extend_from_slice(&q);
            let _ = peer.to_tunnel.send(ipv4(17, me, *dns, &udp)).await;
            let r = recv_matching(&mut peer, |p| {
                p.len() > 28 && p[9] == 17 && p[12..16] == dns.octets()
            })
            .await;
            match r {
                Some(p) => {
                    let (rcode, a) = dns_answer(&p[28..]);
                    println!(
                        "          dns server #{n}: answered (rcode {rcode}, A record {})",
                        if a.is_some() { "found" } else { "none" }
                    );
                    if target.is_none() {
                        target = a;
                    }
                }
                None => println!("          dns server #{n}: no answer in 3 s"),
            }
        }
    } else if let Some(ip) = host.and_then(|h| h.parse().ok()) {
        target = Some(ip);
    }
    if let Some(dst) = target {
        // TCP SYN to the endpoint's port; a SYN-ACK or RST proves two-way TCP reachability.
        let mut tcp = 40001u16.to_be_bytes().to_vec();
        tcp.extend_from_slice(&port.to_be_bytes());
        tcp.extend_from_slice(&[
            0x4f, 0x43, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        let mut pseudo = me.octets().to_vec();
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&[0, 6, 0, tcp.len() as u8]);
        pseudo.extend_from_slice(&tcp);
        let c = csum(&pseudo);
        tcp[16..18].copy_from_slice(&c.to_be_bytes());
        let _ = peer.to_tunnel.send(ipv4(6, me, dst, &tcp)).await;
        let r = recv_matching(&mut peer, |p| {
            p.len() >= 40 && p[9] == 6 && p[12..16] == dst.octets()
        })
        .await;
        let verdict = match r.map(|p| p[33]) {
            Some(f) if f & 0x12 == 0x12 => "SYN-ACK (port open)",
            Some(f) if f & 0x04 != 0 => "RST (host reachable, port closed)",
            Some(_) => "other TCP answer",
            None => "no answer in 3 s",
        };
        println!("          tcp {port} to test endpoint: {verdict}");
        // Close the half-open connection the far end may have created.
        if r_is_synack(verdict) {
            let mut rst = tcp.clone();
            rst[13] = 0x04;
            rst[4..8].copy_from_slice(&[0x4f, 0x43, 0, 2]);
            rst[16] = 0;
            rst[17] = 0;
            let mut pseudo = me.octets().to_vec();
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&[0, 6, 0, rst.len() as u8]);
            pseudo.extend_from_slice(&rst);
            let c = csum(&pseudo);
            rst[16..18].copy_from_slice(&c.to_be_bytes());
            let _ = peer.to_tunnel.send(ipv4(6, me, dst, &rst)).await;
        }
    }
    let targets: Vec<(String, Ipv4Addr)> = target
        .map(|t| ("test endpoint".to_owned(), t))
        .into_iter()
        .chain(
            tc.dns_servers
                .iter()
                .enumerate()
                .map(|(n, d)| (format!("dns server #{n}"), *d)),
        )
        .collect();
    for (label, dst) in targets {
        let mut icmp = vec![8, 0, 0, 0, 0x4f, 0x43, 0, 1];
        icmp.extend_from_slice(b"openforticlient-probe");
        let c = csum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let _ = peer.to_tunnel.send(ipv4(1, me, dst, &icmp)).await;
        let r = recv_matching(&mut peer, |p| {
            p.len() >= 28 && p[9] == 1 && p[20] == 0 && p[12..16] == dst.octets()
        })
        .await;
        println!(
            "          ping {label}: {}",
            if r.is_some() {
                "reply"
            } else {
                "no reply in 3 s"
            }
        );
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).ok_or("usage: ofc-sslvpn-probe <credentials-file> [--device memory|utun] [--ca FILE] [--hold SECS]")?;
    let opt = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let device = opt("--device").unwrap_or_else(|| "memory".into());
    let ca = opt("--ca").unwrap_or_else(|| "/etc/ssl/cert.pem".into());
    let hold: u64 = opt("--hold").and_then(|h| h.parse().ok()).unwrap_or(5);

    let c = read_creds(path)?;
    let gateway = c.get("gateway").ok_or("credentials: no gateway")?;
    let (host, port) = match gateway.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().map_err(|_| "credentials: bad port")?),
        None => (gateway.as_str(), 443),
    };
    let username = c.get("username").ok_or("credentials: no username")?.clone();
    let password = Secret::new(
        c.get("password")
            .ok_or("credentials: no password")?
            .as_str(),
    );
    let otp = c.get("otp").map(|o| Secret::new(o.as_str()));
    let host_parsed: ofc_config::Host = host.parse().map_err(|e| format!("gateway host: {e}"))?;

    if args.iter().any(|a| a == "--print-pin") {
        let addr = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| e.to_string())?
            .next()
            .ok_or("gateway does not resolve")?;
        let der = ofc_sslvpn::transport::fetch_leaf(addr, &host_parsed)
            .await
            .map_err(|e| e.message())?;
        println!("{}", ofc_sslvpn::transport::fingerprint(&der));
        return Ok(());
    }
    let pin = opt("--pin").or_else(|| c.get("pin").cloned());
    let trust = match pin {
        Some(p) => Trust::Pinned(vec![
            ofc_sslvpn::transport::parse_pin(&p).ok_or("pin must be 64 hex digits")?,
        ]),
        None => Trust::CaFile(ca.into()),
    };

    let memory = MemoryDevices::default();
    let devices: Arc<dyn DeviceFactory> = match device.as_str() {
        "memory" => Arc::new(memory.clone()),
        #[cfg(target_os = "macos")]
        "utun" => Arc::new(ofc_sslvpn::utun::UtunDevices),
        other => return Err(format!("unknown device {other}")),
    };
    let mut identity = ClientIdentity::forticlient(hostname());
    if opt("--headers").as_deref() == Some("minimal") {
        identity.profile = ofc_proto_sslvpn::identity::HeaderProfile::Minimal;
    }
    let w = NativeWorker {
        trust,
        identity,
        devices,
        connect_override: None,
    };
    let mut h = w.spawn(WorkerConfig {
        attempt_id: "probe".into(),
        endpoint: Endpoint {
            host: host_parsed,
            port,
            realm: c.get("realm").cloned(),
            ems: None,
        },
        username: Some(username),
        trust_id: "probe".into(),
        ip_policy: IpPolicy::SplitIpv4,
    });

    let started = std::time::Instant::now();
    let mut up_at = None;
    loop {
        let wait = match up_at {
            Some(t) => Duration::from_secs(hold).saturating_sub(started.elapsed() - t),
            None => Duration::from_secs(120),
        };
        let ev = match tokio::time::timeout(wait, h.events.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => return Err("worker vanished".into()),
            Err(_) if up_at.is_some() => {
                println!(
                    "[{:>5.1}s] holding done; disconnecting",
                    started.elapsed().as_secs_f32()
                );
                let _ = h.commands.send(WorkerCommand::Stop).await;
                up_at = None;
                continue;
            }
            Err(_) => return Err("timed out".into()),
        };
        let t = started.elapsed().as_secs_f32();
        match ev {
            WorkerEvent::Stage(s) => println!("[{t:>5.1}s] stage {s:?}"),
            WorkerEvent::Challenge { id, kind, prompt } => {
                println!("[{t:>5.1}s] challenge {kind:?}: {prompt}");
                let value = match kind {
                    ChallengeKind::Password => Secret::new(password.expose()),
                    ChallengeKind::Otp => match &otp {
                        Some(o) => Secret::new(o.expose()),
                        None => {
                            println!(
                                "          gateway asks for a one-time code; none in the credentials file"
                            );
                            let _ = h.commands.send(WorkerCommand::Stop).await;
                            continue;
                        }
                    },
                    ChallengeKind::Username => {
                        let _ = h.commands.send(WorkerCommand::Stop).await;
                        continue;
                    }
                };
                let _ = h
                    .commands
                    .send(WorkerCommand::Respond {
                        challenge_id: id,
                        value,
                    })
                    .await;
            }
            WorkerEvent::Up(tc) => {
                println!(
                    "[{t:>5.1}s] UP interface={} address={} gateway={}",
                    tc.interface, tc.assigned_ip, tc.gateway_ip
                );
                println!(
                    "          routes={} dns={} domains={} block_ipv6={}",
                    tc.routes.len(),
                    tc.dns_servers.len(),
                    tc.dns_domains.len(),
                    tc.block_ipv6
                );
                up_at = Some(started.elapsed());
                let peer = memory.peers.lock().ok().and_then(|mut p| p.pop());
                if let Some(peer) = peer {
                    let host = c
                        .get("test endpoint to check if connection succeed")
                        .map(|u| url_host(u));
                    let port = c
                        .get("test endpoint to check if connection succeed")
                        .map_or(443, |u| url_port(u));
                    data_plane(peer, &tc, host.as_deref(), port).await;
                }
            }
            WorkerEvent::Terminated(term) => {
                println!("[{t:>5.1}s] terminated: {:?} {}", term.code, term.message);
                return match term.code {
                    None => Ok(()),
                    Some(c) => Err(format!("{c:?}")),
                };
            }
        }
    }
}
