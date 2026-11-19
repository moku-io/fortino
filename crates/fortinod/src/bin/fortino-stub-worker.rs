//! Stub tunnel worker for tests: speaks the private worker protocol on stdin (the inherited
//! socket) and drives the in-process fake worker. Behavior comes from `FORTINO_STUB_WORKER`
//! (a JSON `FakeWorkerConfig`); `FORTINO_STUB_MISBEHAVE` injects protocol faults:
//! `stale-attempt`, `huge-frame`, `ignore-stop`, `exit-early`, `bad-seq`.

use std::io;
use std::os::fd::AsFd;

use fortino_config::{Endpoint, IpPolicy};
use fortino_core::framing::{read_frame, write_frame};
use fortino_core::worker::{
    FakeWorker, FakeWorkerConfig, WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory,
};
use fortino_core::worker_wire::{
    DaemonMsg, MAX_WORKER_FRAME, WORKER_PROTOCOL_VERSION, WireReason, WorkerMsg,
};
use fortino_secret::Secret;
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

fn reason(code: Option<fortino_core::ErrorCode>) -> WireReason {
    use fortino_core::ErrorCode::*;
    match code {
        None => WireReason::Stopped,
        Some(AuthDenied) => WireReason::AuthDenied,
        Some(TransportFailure) => WireReason::Transport,
        Some(TrustFailure) => WireReason::InvalidCertificate,
        Some(UnsupportedPolicy) => WireReason::Unsupported,
        Some(Cancelled) => WireReason::Cancelled,
        Some(_) => WireReason::Backend,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let misbehave = std::env::var("FORTINO_STUB_MISBEHAVE").unwrap_or_default();
    let config: FakeWorkerConfig = std::env::var("FORTINO_STUB_WORKER")
        .ok()
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();
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
        ..
    } = &start
    else {
        return Err(io::Error::other("expected start"));
    };
    let (attempt, host, port, realm, username) = (
        attempt.clone(),
        host.clone(),
        *port,
        realm.clone(),
        username.clone(),
    );
    if misbehave == "exit-early" {
        return Ok(());
    }
    let endpoint = Endpoint {
        host: host.parse().map_err(io::Error::other)?,
        port,
        realm,
        ems: None,
    };
    let mut h = FakeWorker { config }.spawn(WorkerConfig {
        attempt_id: attempt.clone(),
        endpoint,
        username,
        trust_id: "stub".into(),
        ip_policy: IpPolicy::SplitIpv4,
    });
    let wire_attempt = if misbehave == "stale-attempt" {
        "someone-else".to_owned()
    } else {
        attempt.clone()
    };
    let mut seq = 0u64;
    let mut stop_seen = false;
    loop {
        tokio::select! {
            ev = h.events.recv() => {
                let Some(ev) = ev else { break };
                if misbehave == "huge-frame" {
                    let big = vec![b'x'; MAX_WORKER_FRAME + 1];
                    wr.try_write(&((big.len() as u32).to_be_bytes())).ok();
                    let _ = tokio::io::AsyncWriteExt::write_all(&mut wr, &big).await;
                    continue;
                }
                if misbehave != "bad-seq" {
                    seq += 1;
                }
                let a = wire_attempt.clone();
                let v = WORKER_PROTOCOL_VERSION;
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
                            split_dns: tc.split_dns,
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
                let cmd = match f? {
                    // Daemon-side EOF cancels the attempt.
                    None => WorkerCommand::Stop,
                    Some(f) => match serde_json::from_slice::<DaemonMsg>(&f) {
                        Ok(DaemonMsg::Respond { ref challenge, ref value, .. }) => WorkerCommand::Respond {
                            challenge_id: challenge.clone(),
                            value: Secret::new(value.as_str()),
                        },
                        Ok(DaemonMsg::Stop { .. }) => WorkerCommand::Stop,
                        _ => return Err(io::Error::other("unexpected daemon frame")),
                    },
                };
                if matches!(cmd, WorkerCommand::Stop) && misbehave == "ignore-stop" {
                    stop_seen = true;
                    continue;
                }
                if h.commands.send(cmd).await.is_err() {
                    break;
                }
            }
        }
    }
    if stop_seen {
        // Simulate a hung worker.
        std::future::pending::<()>().await;
    }
    Ok(())
}
