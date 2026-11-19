//! End-to-end: the native worker against the mock FortiGate, with an in-memory tun device.
//! Login (password, OTP, temporary-cookie swap), tunnel settings, PPP, and an ICMP round trip.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use fortino_config::{Endpoint, IpPolicy};
use fortino_core::ErrorCode;
use fortino_core::proto::ChallengeKind;
use fortino_core::worker::{WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory, WorkerHandle};
use fortino_mock::fortigate::{self, Scenario, User, checksum};
use fortino_proto_sslvpn::identity::ClientIdentity;
use fortino_secret::Secret;
use fortino_sslvpn::device::MemoryDevices;
use fortino_sslvpn::{NativeWorker, Trust};

struct Rig {
    _mock: fortino_mock::MockHandle,
    devices: MemoryDevices,
    h: WorkerHandle,
}

async fn start(sc: Scenario) -> Rig {
    start_with_uid(sc, None).await
}

/// Starts the worker with the endpoint UID the gateway may ask for (`0x80`).
async fn start_with_uid(sc: Scenario, uid: Option<&str>) -> Rig {
    let mock = fortigate::start(&sc).await.unwrap();
    let devices = MemoryDevices::default();
    let w = NativeWorker {
        trust: Trust::Roots(vec![mock.cert_der.clone()]),
        identity: ClientIdentity::forticlient("test-mac"),
        devices: Arc::new(devices.clone()),
        connect_override: Some(mock.addr),
    };
    let h = w.spawn(WorkerConfig {
        attempt_id: "a-1".into(),
        endpoint: Endpoint {
            host: "sslvpn.test".parse().unwrap(),
            port: mock.addr.port(),
            realm: None,
            ems: None,
        },
        username: Some("alice".into()),
        trust_id: "test".into(),
        ip_policy: IpPolicy::SplitIpv4,
        ems: None,
        fct_uid: uid.map(Into::into),
    });
    Rig {
        _mock: mock,
        devices,
        h,
    }
}

fn scenario() -> Scenario {
    Scenario {
        users: vec![User {
            username: "alice".into(),
            password: "hunter2".into(),
            otp: Some("123456".into()),
        }],
        ..Default::default()
    }
}

async fn next(h: &mut WorkerHandle) -> WorkerEvent {
    tokio::time::timeout(Duration::from_secs(10), h.events.recv())
        .await
        .expect("worker stalled")
        .expect("worker gone")
}

/// Answers challenges from `answers` until something else arrives.
async fn drive(h: &mut WorkerHandle, answers: &[(ChallengeKind, &str)]) -> WorkerEvent {
    let mut i = 0;
    loop {
        match next(h).await {
            WorkerEvent::Stage(_) => {}
            WorkerEvent::Challenge { id, kind, .. } => {
                let (k, v) = answers[i];
                assert_eq!(kind, k);
                i += 1;
                h.commands
                    .send(WorkerCommand::Respond {
                        challenge_id: id,
                        value: Secret::new(v),
                    })
                    .await
                    .unwrap();
            }
            other => return other,
        }
    }
}

fn icmp_echo(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut p = vec![0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0, 1]);
    let c = checksum(&p[20..]);
    p[22..24].copy_from_slice(&c.to_be_bytes());
    let c = checksum(&p[..20]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p
}

#[tokio::test]
async fn connects_pings_and_disconnects() {
    let mut r = start(scenario()).await;
    let ev = drive(
        &mut r.h,
        &[
            (ChallengeKind::Password, "hunter2"),
            (ChallengeKind::Otp, "123456"),
        ],
    )
    .await;
    let WorkerEvent::Up(tc) = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(tc.interface, "faketun0");
    assert_eq!(tc.assigned_ip.to_string(), "10.212.134.200");
    assert_eq!(tc.gateway_ip.to_string(), "127.0.0.1");
    assert_eq!(
        tc.routes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.0.0.0/8"]
    );
    assert_eq!(
        tc.dns_servers
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        ["10.0.0.53"]
    );
    assert!(tc.dns_domains.is_empty());
    assert_eq!(tc.split_dns.len(), 1);
    assert_eq!(tc.split_dns[0].domains, ["intra.example"]);
    assert_eq!(tc.split_dns[0].servers[0].to_string(), "10.0.0.54");
    assert!(tc.block_ipv6);

    let mut peer = r.devices.peers.lock().unwrap().pop().unwrap();
    assert_eq!(peer.link.mtu, 1300);
    assert_eq!(peer.link.peer.to_string(), "203.0.113.10");
    peer.to_tunnel
        .send(icmp_echo([10, 212, 134, 200], [10, 0, 0, 1]))
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), peer.from_tunnel.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[12..16], &[10, 0, 0, 1]);
    assert_eq!(reply[20], 0, "echo reply");

    r.h.commands.send(WorkerCommand::Stop).await.unwrap();
    let WorkerEvent::Terminated(t) = next(&mut r.h).await else {
        panic!()
    };
    assert_eq!(t.code, None, "{t:?}");
}

#[tokio::test]
async fn tunnel_request_carries_the_endpoint_uid_when_asked() {
    const UID: &str = "0A1B2C3D4E5F60718293A4B5C6D7E8F9";
    let mut sc = scenario();
    sc.info.flag = "3cdf".into(); // includes 0x80, the FortiClient UID
    sc.tunnel.require_uid = Some(UID.into());
    let mut r = start_with_uid(sc, Some("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9")).await;
    let ev = drive(
        &mut r.h,
        &[
            (ChallengeKind::Password, "hunter2"),
            (ChallengeKind::Otp, "123456"),
        ],
    )
    .await;
    assert!(matches!(ev, WorkerEvent::Up(_)), "{ev:?}");

    // The same gateway refuses a client that sends no UID.
    let mut sc = scenario();
    sc.info.flag = "3cdf".into();
    sc.tunnel.require_uid = Some(UID.into());
    let mut r = start_with_uid(sc, None).await;
    let ev = drive(
        &mut r.h,
        &[
            (ChallengeKind::Password, "hunter2"),
            (ChallengeKind::Otp, "123456"),
        ],
    )
    .await;
    let WorkerEvent::Terminated(t) = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(t.code, Some(ErrorCode::UnsupportedPolicy));
}

#[tokio::test]
async fn wrong_password_is_auth_denied() {
    let mut r = start(scenario()).await;
    let ev = drive(&mut r.h, &[(ChallengeKind::Password, "nope")]).await;
    let WorkerEvent::Terminated(t) = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(t.code, Some(ErrorCode::AuthDenied));
    assert_eq!(t.message, "Permission denied.");
}

#[tokio::test]
async fn wrong_otp_is_auth_denied() {
    let mut r = start(scenario()).await;
    let ev = drive(
        &mut r.h,
        &[
            (ChallengeKind::Password, "hunter2"),
            (ChallengeKind::Otp, "000000"),
        ],
    )
    .await;
    let WorkerEvent::Terminated(t) = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(t.code, Some(ErrorCode::AuthDenied));
}

#[tokio::test]
async fn untrusted_certificate_fails_before_credentials() {
    let sc = scenario();
    let mock = fortigate::start(&sc).await.unwrap();
    let other = fortigate::start(&sc).await.unwrap();
    let w = NativeWorker {
        // Trust a different server's certificate.
        trust: Trust::Roots(vec![other.cert_der.clone()]),
        identity: ClientIdentity::forticlient("test-mac"),
        devices: Arc::new(MemoryDevices::default()),
        connect_override: Some(mock.addr),
    };
    let mut h = w.spawn(WorkerConfig {
        attempt_id: "a-2".into(),
        endpoint: Endpoint {
            host: "sslvpn.test".parse().unwrap(),
            port: mock.addr.port(),
            realm: None,
            ems: None,
        },
        username: Some("alice".into()),
        trust_id: "t".into(),
        ip_policy: IpPolicy::SplitIpv4,
        ems: None,
        fct_uid: None,
    });
    loop {
        match next(&mut h).await {
            WorkerEvent::Stage(_) => {}
            WorkerEvent::Challenge { .. } => {
                panic!("asked for credentials over an untrusted connection")
            }
            WorkerEvent::Terminated(t) => {
                assert_eq!(t.code, Some(ErrorCode::TrustFailure));
                break;
            }
            e => panic!("{e:?}"),
        }
    }
}

#[tokio::test]
async fn ems_gate_reports_registration_needed() {
    let mut sc = scenario();
    sc.login.require_ems_sn = Some("FCTEMS0000000001".into());
    sc.info.flag = "100".into();
    let mut r = start(sc).await;
    let ev = drive(
        &mut r.h,
        &[
            (ChallengeKind::Password, "hunter2"),
            (ChallengeKind::Otp, "123456"),
        ],
    )
    .await;
    let WorkerEvent::Terminated(t) = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(t.code, Some(ErrorCode::UnsupportedPolicy));
    assert!(t.message.contains("EMS"), "{}", t.message);
}

#[tokio::test]
async fn stop_during_challenge_cancels() {
    let mut r = start(scenario()).await;
    loop {
        if let WorkerEvent::Challenge { .. } = next(&mut r.h).await {
            break;
        }
    }
    r.h.commands.send(WorkerCommand::Stop).await.unwrap();
    let WorkerEvent::Terminated(t) = next(&mut r.h).await else {
        panic!()
    };
    assert_eq!(t.code, Some(ErrorCode::Cancelled));
}
