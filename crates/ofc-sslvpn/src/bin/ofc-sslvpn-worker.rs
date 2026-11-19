//! The production tunnel worker: the native SSL VPN client behind the private worker channel
//!. `ofcd` starts it per attempt with the channel on stdin.
//!
//! Trust: `ca_file` from the daemon is either a PEM CA bundle or, for a gateway whose
//! certificate does not match its address, a pin file with one `sha256:<64 hex>` line per
//! accepted leaf certificate. Both are provisioned by the administrator.

use std::io;
use std::os::fd::AsFd;
use std::sync::Arc;

use ofc_config::{Endpoint, IpPolicy};
use ofc_core::framing::{read_frame, write_frame};
use ofc_core::worker::{WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory};
use ofc_core::worker_wire::{
    DaemonMsg, MAX_WORKER_FRAME, WORKER_PROTOCOL_VERSION, WireReason, WorkerMsg,
};
use ofc_proto_sslvpn::identity::ClientIdentity;
use ofc_secret::Secret;
use ofc_sslvpn::device::DeviceFactory;
use ofc_sslvpn::{NativeWorker, Trust};
use tokio::net::UnixStream;

fn channel() -> io::Result<UnixStream> {
    let fd = io::stdin().as_fd().try_clone_to_owned()?;
    let s = std::os::unix::net::UnixStream::from(fd);
    s.set_nonblocking(true)?;
    UnixStream::from_std(s)
}

async fn send(w: &mut tokio::net::unix::OwnedWriteHalf, m: &WorkerMsg) -> io::Result<()> {
    let b = serde_json::to_vec(m).map_err(io::Error::other)?;
    write_frame(w, &b, MAX_WORKER_FRAME).await
}

fn reason(code: Option<ofc_core::ErrorCode>) -> WireReason {
    use ofc_core::ErrorCode::*;
    match code {
        None => WireReason::Stopped,
        Some(AuthDenied | AuthTimeout) => WireReason::AuthDenied,
        Some(TransportFailure) => WireReason::Transport,
        Some(TrustFailure) => WireReason::InvalidCertificate,
        Some(UnsupportedPolicy) => WireReason::Unsupported,
        Some(NetworkConfigFailure) => WireReason::LocalNetwork,
        Some(Cancelled) => WireReason::Cancelled,
        Some(_) => WireReason::Backend,
    }
}

/// Reads the trust file: pins if it has `sha256:` lines and no PEM, otherwise a CA bundle.
fn trust_from(path: &str) -> io::Result<Trust> {
    let text = std::fs::read_to_string(path)?;
    if text.contains("-----BEGIN") {
        return Ok(Trust::CaFile(path.into()));
    }
    let pins: Vec<[u8; 32]> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.strip_prefix("sha256:"))
        .filter_map(ofc_sslvpn::transport::parse_pin)
        .collect();
    if pins.is_empty() {
        return Err(io::Error::other(
            "trust file has neither certificates nor pins",
        ));
    }
    Ok(Trust::Pinned(pins))
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

fn devices() -> Arc<dyn DeviceFactory> {
    // Tests run the worker unprivileged. The daemon starts workers with an environment of PATH
    // only, so this cannot be set in production.
    if std::env::var_os("OFC_WORKER_MEMORY_DEVICE").is_some() {
        return Arc::new(ofc_sslvpn::device::MemoryDevices::default());
    }
    #[cfg(target_os = "macos")]
    {
        Arc::new(ofc_sslvpn::utun::UtunDevices)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(ofc_sslvpn::device::MemoryDevices::default())
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let (mut rd, mut wr) = channel()?.into_split();
    let Some(frame) = read_frame(&mut rd, MAX_WORKER_FRAME).await? else {
        return Ok(());
    };
    let start = serde_json::from_slice::<DaemonMsg>(&frame).map_err(io::Error::other)?;
    let DaemonMsg::Start {
        v: WORKER_PROTOCOL_VERSION,
        attempt,
        host,
        port,
        realm,
        username,
        ca_file,
    } = &start
    else {
        return Err(io::Error::other("expected start"));
    };
    let attempt = attempt.clone();
    let v = WORKER_PROTOCOL_VERSION;
    let mut seq = 0u64;

    let setup = (|| -> Result<(NativeWorker, WorkerConfig), String> {
        let trust = trust_from(ca_file).map_err(|e| format!("trust: {e}"))?;
        let endpoint = Endpoint {
            host: host.parse().map_err(|e| format!("host: {e}"))?,
            port: *port,
            realm: realm.clone(),
            ems: None,
        };
        Ok((
            NativeWorker {
                trust,
                identity: ClientIdentity::forticlient(hostname()),
                devices: devices(),
                connect_override: None,
            },
            WorkerConfig {
                attempt_id: attempt.clone(),
                endpoint,
                username: username.clone(),
                trust_id: String::new(),
                ip_policy: IpPolicy::SplitIpv4,
            },
        ))
    })();
    drop(start);
    let (worker, cfg) = match setup {
        Ok(x) => x,
        Err(_) => {
            seq += 1;
            let m = WorkerMsg::Terminated {
                v,
                attempt,
                seq,
                reason: WireReason::InvalidCertificate,
                stage: None,
            };
            return send(&mut wr, &m).await;
        }
    };

    let mut h = worker.spawn(cfg);
    loop {
        tokio::select! {
            ev = h.events.recv() => {
                let Some(ev) = ev else { break };
                seq += 1;
                let a = attempt.clone();
                let (msg, last) = match ev {
                    WorkerEvent::Stage(stage) => (WorkerMsg::Stage { v, attempt: a, seq, stage }, false),
                    WorkerEvent::Challenge { id, kind, prompt } => {
                        (WorkerMsg::Challenge { v, attempt: a, seq, id, kind, prompt }, false)
                    }
                    WorkerEvent::Up(tc) => (
                        WorkerMsg::Up {
                            v,
                            attempt: a,
                            seq,
                            interface: tc.interface,
                            assigned_ip: tc.assigned_ip,
                            gateway_ip: tc.gateway_ip,
                            routes: tc.routes.iter().map(ToString::to_string).collect(),
                            dns: tc.dns_servers,
                            dns_domains: tc.dns_domains,
                            block_ipv6: tc.block_ipv6,
                        },
                        false,
                    ),
                    WorkerEvent::Terminated(t) => (
                        WorkerMsg::Terminated { v, attempt: a, seq, reason: reason(t.code), stage: None },
                        true,
                    ),
                };
                send(&mut wr, &msg).await?;
                if last {
                    break;
                }
            }
            f = read_frame(&mut rd, MAX_WORKER_FRAME) => {
                let cmd = match f {
                    // A daemon-side EOF or a broken channel cancels the attempt.
                    Ok(None) | Err(_) => WorkerCommand::Stop,
                    Ok(Some(f)) => match serde_json::from_slice::<DaemonMsg>(&f) {
                        Ok(DaemonMsg::Respond { attempt: ref a, ref challenge, ref value, .. }) if *a == attempt => {
                            WorkerCommand::Respond { challenge_id: challenge.clone(), value: Secret::new(value.as_str()) }
                        }
                        Ok(DaemonMsg::Stop { .. }) => WorkerCommand::Stop,
                        // Anything else is a protocol violation: stop.
                        _ => WorkerCommand::Stop,
                    },
                };
                if h.commands.send(cmd).await.is_err() {
                    // The attempt already ended; its Terminated event is still queued.
                    continue;
                }
            }
        }
    }
    Ok(())
}
