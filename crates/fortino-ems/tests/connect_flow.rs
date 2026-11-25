#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The EMS wrapper around the native worker: registration before login, the serial on the
//! gateway's requests, and a full keepalive reporting the tunnel interface once it is up.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fortino_config::{Endpoint, IpPolicy};
use fortino_core::ErrorCode;
use fortino_core::proto::ChallengeKind;
use fortino_core::worker::{
    EMS_REGISTRATION_REQUIRED, WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory,
    WorkerHandle,
};
use fortino_ems::forticlient::FortiClientState;
use fortino_ems::service::{EmsWorkers, ServerSettings, Settings};
use fortino_ems::store::Store;
use fortino_mock::ems::{self, EmsScenario};
use fortino_mock::fortigate::{self, Scenario, User};
use fortino_platform::facts::{Facts, Interface};
use fortino_proto_ems::ids::{EmsSerial, Uid};
use fortino_proto_sslvpn::identity::ClientIdentity;
use fortino_secret::Secret;
use fortino_sslvpn::NativeWorker;
use fortino_sslvpn::device::MemoryDevices;
use fortino_tls::Trust;

const SERIAL: &str = "FCTEMS0000000042";

fn base_facts() -> Facts {
    Facts {
        platform_uuid: Some("0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9".into()),
        hostname: "mac-01".into(),
        os_version: "macOS 15.6".into(),
        arch: "ARM",
        interfaces: vec![Interface {
            name: "en0".into(),
            ip: Ipv4Addr::new(192, 0, 2, 10),
            mac: [0xaa, 0, 0, 0, 0, 1],
            gateway: Some(Ipv4Addr::new(192, 0, 2, 1)),
            up: true,
            is_vpn: false,
        }],
        ..Facts::default()
    }
}

struct Rig {
    _gw: fortino_mock::MockHandle,
    ems: ems::MockEms,
    facts: Arc<Mutex<Facts>>,
    h: WorkerHandle,
    _dir: tempfile::TempDir,
    fc: Arc<Mutex<Option<FortiClientState>>>,
}

async fn start(register: bool, key: Option<&str>, ems_sc: EmsScenario) -> Rig {
    start_fc(register, key, ems_sc, None).await
}

async fn start_fc(
    register: bool,
    key: Option<&str>,
    ems_sc: EmsScenario,
    forticlient: Option<FortiClientState>,
) -> Rig {
    let fc = Arc::new(Mutex::new(forticlient));
    let sc = Scenario {
        users: vec![User {
            username: "alice".into(),
            password: "hunter2".into(),
            otp: None,
        }],
        info: fortigate::InfoCfg {
            flag: "100".into(),
            ..Default::default()
        },
        login: fortigate::LoginCfg {
            require_ems_sn: Some(SERIAL.into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let gw = fortigate::start(&sc).await.unwrap();
    let ems = ems::start(&ems_sc).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let key_file = key.map(|k| {
        let p = dir.path().join("key");
        std::fs::write(&p, k).unwrap();
        p
    });
    let facts = Arc::new(Mutex::new(base_facts()));
    let f = facts.clone();
    let inner = NativeWorker {
        trust: Trust::Roots(vec![gw.cert_der.clone()]),
        identity: ClientIdentity::forticlient("mac-01"),
        devices: Arc::new(MemoryDevices::default()),
        connect_override: Some(gw.addr),
    };
    let mut workers = EmsWorkers::new(
        Arc::new(inner),
        Settings {
            package_approvals: None,
            state_dir: dir.path().join("ems"),
            uid: None,
            compat: Default::default(),
            servers: HashMap::from([(
                "ems.test:8013".to_owned(),
                ServerSettings {
                    trust: Trust::Roots(vec![ems.handle.cert_der.clone()]),
                    key_file,
                    register,
                },
            )]),
            settle: Duration::from_millis(50),
            min_ka_interval: Duration::ZERO,
            retry: Duration::from_millis(100),
        },
        Arc::new(move || Some(f.lock().unwrap().clone())),
    );
    workers.connect_override = Some(ems.handle.addr);
    let fc2 = fc.clone();
    let mut workers = workers.with_forticlient(Arc::new(move || fc2.lock().unwrap().clone()));
    workers.connect_override = Some(ems.handle.addr);
    let h = workers.spawn(WorkerConfig {
        attempt_id: "a-1".into(),
        endpoint: Endpoint {
            host: "sslvpn.test".parse().unwrap(),
            port: gw.addr.port(),
            realm: None,
            ems: Some("ems.test:8013".parse().unwrap()),
        },
        username: Some("alice".into()),
        trust_id: "test".into(),
        ip_policy: IpPolicy::SplitIpv4,
        ems: None,
        fct_uid: None,
        debug_ems_sysinfo: Default::default(),
    });
    Rig {
        _gw: gw,
        ems,
        facts,
        h,
        _dir: dir,
        fc,
    }
}

async fn next(h: &mut WorkerHandle) -> WorkerEvent {
    tokio::time::timeout(Duration::from_secs(10), h.events.recv())
        .await
        .expect("worker stalled")
        .expect("worker gone")
}

async fn until_up_or_end(r: &mut Rig) -> WorkerEvent {
    loop {
        match next(&mut r.h).await {
            WorkerEvent::Stage(_) => {}
            WorkerEvent::Challenge { id, kind, .. } => {
                assert_eq!(kind, ChallengeKind::Password);
                r.h.commands
                    .send(WorkerCommand::Respond {
                        challenge_id: id,
                        value: Secret::new("hunter2"),
                    })
                    .await
                    .unwrap();
            }
            other => return other,
        }
    }
}

fn ems_scenario() -> EmsScenario {
    EmsScenario {
        serial: SERIAL.into(),
        key: Some("k3y".into()),
        ..EmsScenario::default()
    }
}

#[tokio::test]
async fn registers_presents_serial_and_reports_the_tunnel() {
    let mut r = start(true, Some("k3y"), ems_scenario()).await;
    let ev = until_up_or_end(&mut r).await;
    let WorkerEvent::Up(tc) = ev else {
        panic!("gateway refused the tunnel: {ev:?}")
    };
    // What the platform shows once the tunnel interface exists.
    r.facts.lock().unwrap().interfaces.push(Interface {
        name: tc.interface.clone(),
        ip: tc.assigned_ip,
        mac: [0; 6],
        gateway: None,
        up: true,
        is_vpn: true,
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let nwifs = loop {
        let got = {
            let st = r.ems.state.lock().unwrap();
            st.seen
                .iter()
                .any(|s| s.kind == "KA")
                .then(|| st.endpoints.values().next().cloned())
                .flatten()
        };
        if let Some(ep) = got {
            let info = ep.sysinfo.iter().find(|(k, _)| k == "NWIFS").cloned();
            break info.map(|(_, v)| v).unwrap_or_default();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no keepalive after tunnel up"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    assert!(
        nwifs.contains(&format!("{}|{}|*|*|*|1|*|1", tc.interface, tc.assigned_ip)),
        "tunnel interface not reported: {nwifs}"
    );

    {
        let st = r.ems.state.lock().unwrap();
        let kinds: Vec<_> = st.seen.iter().map(|s| s.kind.as_str()).collect();
        assert_eq!(&kinds[..3], ["PROBE", "REGISTER", "KA"]);
        // The connection key never lands in what the server keeps.
        let ep = st.endpoints.values().next().unwrap();
        assert!(ep.sysinfo.iter().all(|(k, _)| k != "REG_KEY"));
    }

    r.h.commands.send(WorkerCommand::Stop).await.unwrap();
    loop {
        if let WorkerEvent::Terminated(t) = next(&mut r.h).await {
            assert_eq!(t.code, None);
            break;
        }
    }
    // The keepalive loop stops with the tunnel.
    let n = r.ems.state.lock().unwrap().seen.len();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(r.ems.state.lock().unwrap().seen.len(), n);
}

#[tokio::test]
async fn refused_registration_ends_the_attempt_before_login() {
    let mut r = start(true, Some("wrong"), ems_scenario()).await;
    match until_up_or_end(&mut r).await {
        WorkerEvent::Terminated(t) => {
            assert_eq!(t.code, Some(ErrorCode::UnsupportedPolicy));
            assert!(t.message.contains("key"), "{}", t.message);
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn without_permission_to_register_nothing_is_created() {
    let mut r = start(false, None, ems_scenario()).await;
    // The gateway requires the serial, so the tunnel is refused, but no device record appears.
    let ev = until_up_or_end(&mut r).await;
    let WorkerEvent::Terminated(t) = ev else {
        panic!("{ev:?}")
    };
    // The message says why there was no serial.
    assert!(t.message.contains("isn't enabled"), "{}", t.message);
    assert!(!t.message.contains("FortiClient"), "{}", t.message);
    let st = r.ems.state.lock().unwrap();
    assert!(st.seen.iter().all(|s| s.kind != "REGISTER"));
    assert!(st.endpoints.is_empty());
}

#[tokio::test]
async fn forticlient_under_another_uid_is_named_when_the_serial_is_missing() {
    let mut fc = forticlient(SERIAL, &[("ems.test", 8013)]);
    fc.uid = Some(Uid::parse("277963E3DEAC437E9BB2B91DE1C49AFE").unwrap());
    let mut r = start_fc(false, None, ems_scenario(), Some(fc)).await;
    let ev = until_up_or_end(&mut r).await;
    let WorkerEvent::Terminated(t) = ev else {
        panic!("{ev:?}")
    };
    assert_eq!(t.code, Some(ErrorCode::UnsupportedPolicy));
    assert!(
        t.message.starts_with(EMS_REGISTRATION_REQUIRED),
        "{}",
        t.message
    );
    assert!(t.message.contains("FortiClient"), "{}", t.message);
    // Its serial was not borrowed: nothing reached the EMS either.
    assert!(r.ems.state.lock().unwrap().seen.is_empty());
}

#[tokio::test]
async fn forticlient_under_another_uid_keeps_fortino_from_registering() {
    // The EMS keeps one registration per Mac: registering here would end FortiClient's.
    let mut fc = forticlient(SERIAL, &[("ems.test", 8013)]);
    fc.uid = Some(Uid::parse("277963E3DEAC437E9BB2B91DE1C49AFE").unwrap());
    let mut r = start_fc(true, Some("k3y"), ems_scenario(), Some(fc)).await;
    let ev = until_up_or_end(&mut r).await;
    let WorkerEvent::Terminated(t) = ev else {
        panic!("{ev:?}")
    };
    assert!(
        t.message.contains("one registration per Mac"),
        "{}",
        t.message
    );
    assert!(r.ems.state.lock().unwrap().seen.is_empty());
}

#[tokio::test]
async fn forticlient_under_another_uid_found_by_probe_also_holds() {
    let mut fc = forticlient(SERIAL, &[("192.0.2.50", 8013)]);
    fc.uid = Some(Uid::parse("277963E3DEAC437E9BB2B91DE1C49AFE").unwrap());
    let mut r = start_fc(true, Some("k3y"), ems_scenario(), Some(fc)).await;
    let ev = until_up_or_end(&mut r).await;
    assert!(matches!(ev, WorkerEvent::Terminated(_)), "{ev:?}");
    let kinds: Vec<_> = r
        .ems
        .state
        .lock()
        .unwrap()
        .seen
        .iter()
        .map(|s| s.kind.clone())
        .collect();
    assert_eq!(kinds, ["PROBE"]);
}

#[test]
fn status_counts_forticlient_only_with_this_uid() {
    let dir = tempfile::tempdir().unwrap();
    let server: fortino_config::EmsServer = "ems.test:8013".parse().unwrap();
    let status = |fc: FortiClientState| {
        EmsWorkers::new(
            Arc::new(fortino_sslvpn::NativeWorker {
                trust: Trust::Roots(vec![]),
                identity: ClientIdentity::forticlient("mac-01"),
                devices: Arc::new(MemoryDevices::default()),
                connect_override: None,
            }),
            Settings {
                package_approvals: None,
                state_dir: dir.path().join("ems"),
                uid: None,
                compat: Default::default(),
                servers: HashMap::from([(
                    "ems.test:8013".to_owned(),
                    ServerSettings {
                        trust: Trust::Roots(vec![]),
                        key_file: None,
                        register: true,
                    },
                )]),
                settle: Duration::ZERO,
                min_ka_interval: Duration::ZERO,
                retry: Duration::from_millis(100),
            },
            Arc::new(|| Some(base_facts())),
        )
        .with_forticlient(Arc::new(move || Some(fc.clone())))
        .status(&server)
        .unwrap()
        .state
        .as_str()
    };
    let same = forticlient(SERIAL, &[("ems.test", 8013)]);
    assert_eq!(status(same.clone()), "managed-by-forticlient");
    let mut other = same;
    other.uid = Some(Uid::parse("277963E3DEAC437E9BB2B91DE1C49AFE").unwrap());
    assert_eq!(status(other.clone()), "held-by-forticlient");
    other.running = false;
    assert_eq!(status(other), "not-registered");
}

#[tokio::test]
async fn registration_is_stored_for_that_server() {
    let mut r = start(true, Some("k3y"), ems_scenario()).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    r.h.commands.send(WorkerCommand::Stop).await.unwrap();
    while !matches!(next(&mut r.h).await, WorkerEvent::Terminated(_)) {}
    let store = Store::open(r._dir.path().join("ems")).unwrap();
    let regs = store.list().unwrap();
    assert_eq!(regs.len(), 1);
    assert_eq!(regs[0].serial, SERIAL);
    assert_eq!(regs[0].server, "ems.test:8013");
}

/// FortiClient's agent, running and registered with this Mac's UID.
fn forticlient(serial: &str, addresses: &[(&str, u16)]) -> FortiClientState {
    FortiClientState {
        uid: Some(Uid::parse("0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9").unwrap()),
        serial: Some(EmsSerial::parse(serial).unwrap()),
        addresses: addresses
            .iter()
            .map(|(h, p)| ((*h).to_owned(), *p))
            .collect(),
        tenant: None,
        running: true,
    }
}

async fn stop(r: &mut Rig) {
    r.h.commands.send(WorkerCommand::Stop).await.unwrap();
    while !matches!(next(&mut r.h).await, WorkerEvent::Terminated(_)) {}
}

#[tokio::test]
async fn defers_to_forticlient_on_the_same_ems() {
    let fc = forticlient(SERIAL, &[("ems.test", 8013)]);
    let mut r = start_fc(true, Some("k3y"), ems_scenario(), Some(fc)).await;
    // The gateway still gets the serial (FortiClient's registration of this same device).
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop(&mut r).await;
    // Fortino sent nothing to the EMS: no probe, no registration, no keepalive.
    assert!(r.ems.state.lock().unwrap().seen.is_empty());
}

#[tokio::test]
async fn same_ems_under_another_name_is_found_by_probe() {
    let fc = forticlient(SERIAL, &[("192.0.2.50", 8013)]);
    let mut r = start_fc(true, Some("k3y"), ems_scenario(), Some(fc)).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    stop(&mut r).await;
    let kinds: Vec<_> = r
        .ems
        .state
        .lock()
        .unwrap()
        .seen
        .iter()
        .map(|s| s.kind.clone())
        .collect();
    assert_eq!(kinds, ["PROBE"]);
}

#[tokio::test]
async fn acts_itself_when_forticlient_uses_another_ems() {
    let fc = forticlient("FCTEMS0000000099", &[("other-ems.test", 8013)]);
    let mut r = start_fc(true, Some("k3y"), ems_scenario(), Some(fc)).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    stop(&mut r).await;
    let st = r.ems.state.lock().unwrap();
    assert!(st.seen.iter().any(|s| s.kind == "REGISTER"));
}

#[tokio::test]
async fn acts_itself_when_forticlient_is_not_running() {
    let mut fc = forticlient(SERIAL, &[("ems.test", 8013)]);
    fc.running = false;
    let mut r = start_fc(true, Some("k3y"), ems_scenario(), Some(fc)).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    stop(&mut r).await;
    assert!(
        r.ems
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .any(|s| s.kind == "REGISTER")
    );
}

#[tokio::test]
async fn forticlient_taking_over_stops_the_keepalives() {
    let sc = EmsScenario {
        ka_interval: 1,
        ..ems_scenario()
    };
    let mut r = start(true, Some("k3y"), sc).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    let kas = |r: &Rig| {
        r.ems
            .state
            .lock()
            .unwrap()
            .seen
            .iter()
            .filter(|s| s.kind == "KA")
            .count()
    };
    // Keepalives run every second (the scenario's KA_INTERVAL)…
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while kas(&r) < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "keepalives did not repeat"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // …until FortiClient registers this device to the same EMS.
    *r.fc.lock().unwrap() = Some(forticlient(SERIAL, &[("ems.test", 8013)]));
    let n = kas(&r);
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        kas(&r) <= n + 1,
        "keepalives continued after FortiClient took over"
    );
    let settled = kas(&r);
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(kas(&r), settled);
    stop(&mut r).await;
}

#[tokio::test]
async fn device_uid_reaches_a_gateway_that_asks_even_without_ems() {
    let sc = Scenario {
        users: vec![User {
            username: "alice".into(),
            password: "hunter2".into(),
            otp: None,
        }],
        info: fortigate::InfoCfg {
            flag: "80".into(),
            ..Default::default()
        },
        tunnel: fortigate::TunnelCfg {
            require_uid: Some("0A1B2C3D4E5F60718293A4B5C6D7E8F9".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    let gw = fortigate::start(&sc).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let inner = NativeWorker {
        trust: Trust::Roots(vec![gw.cert_der.clone()]),
        identity: ClientIdentity::forticlient("mac-01"),
        devices: Arc::new(MemoryDevices::default()),
        connect_override: Some(gw.addr),
    };
    let workers = EmsWorkers::new(
        Arc::new(inner),
        Settings {
            package_approvals: None,
            state_dir: dir.path().join("ems"),
            uid: None,
            compat: Default::default(),
            servers: HashMap::new(),
            settle: Duration::from_millis(50),
            min_ka_interval: Duration::ZERO,
            retry: Duration::from_millis(100),
        },
        Arc::new(|| Some(base_facts())),
    );
    let h = workers.spawn(WorkerConfig {
        attempt_id: "a-1".into(),
        endpoint: Endpoint {
            host: "sslvpn.test".parse().unwrap(),
            port: gw.addr.port(),
            realm: None,
            ems: None,
        },
        username: Some("alice".into()),
        trust_id: "test".into(),
        ip_policy: IpPolicy::SplitIpv4,
        ems: None,
        fct_uid: None,
        debug_ems_sysinfo: Default::default(),
    });
    let ems = ems::start(&EmsScenario::default()).await.unwrap();
    let mut r = Rig {
        _gw: gw,
        ems,
        facts: Arc::new(Mutex::new(base_facts())),
        h,
        _dir: dir,
        fc: Arc::new(Mutex::new(None)),
    };
    // The mock refuses the tunnel (403) unless `?uuid=` carries this device's UID.
    let ev = until_up_or_end(&mut r).await;
    assert!(matches!(ev, WorkerEvent::Up(_)), "{ev:?}");
    stop(&mut r).await;
    // No EMS was configured, so none was contacted.
    assert!(r.ems.state.lock().unwrap().seen.is_empty());
}

#[tokio::test]
async fn package_enrollment_is_scoped_and_idempotent() {
    use fortino_core::worker::{FakeWorker, FakeWorkerConfig};

    let mock = ems::start(&EmsScenario::default()).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let server: fortino_config::EmsServer = "ems.test:8013".parse().unwrap();
    let mut workers = EmsWorkers::new(
        Arc::new(FakeWorker {
            config: FakeWorkerConfig::default(),
        }),
        Settings {
            state_dir: dir.path().into(),
            package_approvals: None,
            uid: None,
            compat: Default::default(),
            servers: HashMap::from([(
                "ems.test:8013".into(),
                ServerSettings {
                    trust: Trust::Roots(vec![mock.handle.cert_der.clone()]),
                    register: true,
                    key_file: None,
                },
            )]),
            settle: Duration::ZERO,
            min_ka_interval: Duration::ZERO,
            retry: Duration::from_millis(100),
        },
        Arc::new(|| Some(base_facts())),
    );
    workers.connect_override = Some(mock.handle.addr);
    assert!(
        workers
            .enroll("other.test".parse().unwrap(), Some("pkg-a"))
            .await
            .is_err()
    );
    assert!(
        workers
            .enroll(server.clone(), Some("bad\nvalue"))
            .await
            .is_err()
    );
    let (a, b) = tokio::join!(
        workers.enroll(server.clone(), Some("pkg-a")),
        workers.enroll(server.clone(), Some("pkg-a"))
    );
    assert_eq!(a.unwrap().0, "registered");
    assert_eq!(b.unwrap().0, "registered");
    assert_eq!(
        workers
            .enroll(server.clone(), Some("pkg-b"))
            .await
            .unwrap()
            .0,
        "existing-registration"
    );
    // Register Now (no package) keeps the existing registration.
    assert_eq!(workers.enroll(server, None).await.unwrap().0, "registered");
    let state = mock.state.lock().unwrap();
    assert_eq!(
        state.seen.iter().filter(|r| r.kind == "REGISTER").count(),
        1
    );
    assert!(
        state
            .endpoints
            .values()
            .next()
            .unwrap()
            .sysinfo
            .iter()
            .any(|(k, v)| k == "INSTALLUID" && v == "pkg-a")
    );
    let r = Store::open(dir.path())
        .unwrap()
        .load("ems.test:8013")
        .unwrap()
        .unwrap();
    let ka = fortino_ems::report::full(&base_facts(), &Default::default(), Some(&r)).unwrap();
    assert_eq!(ka.get("INSTALLUID"), Some("pkg-a"));
}

/// Counts the requests of `kind` the mock EMS has seen.
fn seen(r: &Rig, kind: &str) -> usize {
    r.ems
        .state
        .lock()
        .unwrap()
        .seen
        .iter()
        .filter(|s| s.kind == kind)
        .count()
}

/// Waits until `cond` holds, failing after five seconds.
async fn until(r: &Rig, what: &str, cond: impl Fn(&Rig) -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !cond(r) {
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Makes the mock EMS forget every device, so its next keepalive is answered `CONT|0`.
fn forget_devices(r: &Rig) {
    r.ems.state.lock().unwrap().endpoints.clear();
}

#[tokio::test]
async fn dropped_during_a_session_registers_again() {
    let sc = EmsScenario {
        ka_interval: 1,
        ..ems_scenario()
    };
    let mut r = start(true, Some("k3y"), sc).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    until(&r, "first keepalive", |r| seen(r, "KA") >= 1).await;
    assert_eq!(seen(&r, "REGISTER"), 1);
    forget_devices(&r);
    until(&r, "a new registration", |r| seen(r, "REGISTER") == 2).await;
    // Keepalives go on for the new registration, and the EMS knows the device again.
    let kas = seen(&r, "KA");
    until(&r, "keepalives after registering again", |r| {
        seen(r, "KA") > kas
    })
    .await;
    assert_eq!(r.ems.state.lock().unwrap().endpoints.len(), 1);
    stop(&mut r).await;
}

#[tokio::test]
async fn dropped_again_soon_after_stops_the_keepalives() {
    let sc = EmsScenario {
        ka_interval: 1,
        ..ems_scenario()
    };
    let mut r = start(true, Some("k3y"), sc).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    until(&r, "first keepalive", |r| seen(r, "KA") >= 1).await;
    forget_devices(&r);
    until(&r, "a new registration", |r| seen(r, "REGISTER") == 2).await;
    let kas = seen(&r, "KA");
    until(&r, "a keepalive after registering again", |r| {
        seen(r, "KA") > kas
    })
    .await;
    forget_devices(&r);
    // The next keepalive is dropped; no third registration, and the keepalives stop.
    let kas = seen(&r, "KA");
    until(&r, "the dropped keepalive", |r| seen(r, "KA") > kas).await;
    let settled = seen(&r, "KA");
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(seen(&r, "REGISTER"), 2);
    assert_eq!(seen(&r, "KA"), settled);
    stop(&mut r).await;
}

#[tokio::test]
async fn dropped_while_forticlient_is_on_the_ems_is_left_to_it() {
    let sc = EmsScenario {
        ka_interval: 1,
        ..ems_scenario()
    };
    let mut r = start(true, Some("k3y"), sc).await;
    assert!(matches!(until_up_or_end(&mut r).await, WorkerEvent::Up(_)));
    until(&r, "first keepalive", |r| seen(r, "KA") >= 1).await;
    // FortiClient registers this Mac with the same EMS under its own UID, which ends ours.
    let mut fc = forticlient(SERIAL, &[("ems.test", 8013)]);
    fc.uid = Some(Uid::parse("277963E3DEAC437E9BB2B91DE1C49AFE").unwrap());
    *r.fc.lock().unwrap() = Some(fc);
    forget_devices(&r);
    let kas = seen(&r, "KA");
    until(&r, "the dropped keepalive", |r| seen(r, "KA") > kas).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert_eq!(seen(&r, "REGISTER"), 1);
    stop(&mut r).await;
}

/// The first full keepalive after the tunnel comes up tells the EMS the tunnel address, which
/// gateways that admit by tag depend on. When it fails, the retry is a full keepalive again,
/// not a mini one a full interval (hours) before the address gets through.
#[tokio::test]
async fn a_failed_first_keepalive_is_retried_in_full() {
    let mut r = start(true, Some("k3y"), ems_scenario()).await;
    r.ems.state.lock().unwrap().fail_keepalives = 1;
    let WorkerEvent::Up(tc) = until_up_or_end(&mut r).await else {
        panic!("no tunnel")
    };
    r.facts.lock().unwrap().interfaces.push(Interface {
        name: tc.interface.clone(),
        ip: tc.assigned_ip,
        mac: [0; 6],
        gateway: None,
        up: true,
        is_vpn: true,
    });
    let reported = |r: &Rig| {
        r.ems
            .state
            .lock()
            .unwrap()
            .endpoints
            .values()
            .next()
            .and_then(|ep| ep.sysinfo.iter().find(|(k, _)| k == "NWIFS").cloned())
            .is_some_and(|(_, v)| v.contains(&format!("{}|{}", tc.interface, tc.assigned_ip)))
    };
    until(
        &r,
        "tunnel address reported after a failed keepalive",
        reported,
    )
    .await;
    assert!(seen(&r, "KA") >= 2);
    stop(&mut r).await;
}
