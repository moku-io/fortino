//! End-to-end daemon tests over a real Unix socket, using the fake worker and fake network.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fortino_config::{EmsServer, IpPolicy, ProfileSpec, ProfileStore};
use fortino_core::client::Client;
use fortino_core::proto::{
    ChallengeKind, ConnectParams, Event, ProfileImportParams, RestartWhen, State, Status, method,
};
use fortino_core::worker::{FakeFailure, FakeWorker, FakeWorkerConfig};
use fortino_core::{ErrorCode, ProtoError};
use fortino_platform::fake::{FakeNet, FakeState};
use fortino_platform::journal::Journaled;
use fortinod::auth::{Authorizer, Peer};
use fortinod::config::Timeouts;
use fortinod::netctl::JournaledController;
use fortinod::session::Session;
use tokio::sync::mpsc::UnboundedReceiver;

struct Harness {
    _dir: tempfile::TempDir,
    sock: PathBuf,
    net: Arc<Mutex<FakeState>>,
    session: Arc<Session>,
    uid: u32,
}

fn my_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

fn fake(f: impl FnOnce(&mut FakeWorkerConfig)) -> FakeWorkerConfig {
    let mut c = FakeWorkerConfig {
        step_delay_ms: 5,
        password: Some("hunter2".into()),
        ..Default::default()
    };
    f(&mut c);
    c
}

async fn start(worker: FakeWorkerConfig, timeouts: Timeouts) -> Harness {
    start_with(worker, timeouts, FakeState::typical_host(), None).await
}

async fn start_with(
    worker: FakeWorkerConfig,
    timeouts: Timeouts,
    net_state: FakeState,
    dir: Option<tempfile::TempDir>,
) -> Harness {
    let dir = dir.unwrap_or_else(|| tempfile::tempdir().unwrap());
    let sock = dir.path().join("fortinod.sock");
    let net = Arc::new(Mutex::new(net_state));
    let journal =
        Journaled::open(FakeNet::new(net.clone()), dir.path().join("journal.json")).unwrap();
    let store = ProfileStore::open(&dir.path().join("profiles.db")).unwrap();
    let session = Session::new(
        store,
        Box::new(FakeWorker { config: worker }),
        Box::new(JournaledController::new(journal)),
        timeouts,
    );
    let uid = my_uid();
    let auth = Arc::new(Authorizer::new(vec![uid], vec![], None).unwrap());
    let listener = fortinod::bind_socket(&sock, None).unwrap();
    tokio::spawn(fortinod::server::serve(listener, session.clone(), auth));
    Harness {
        _dir: dir,
        sock,
        net,
        session,
        uid,
    }
}

fn quick() -> Timeouts {
    Timeouts {
        transport: Duration::from_secs(5),
        challenge: Duration::from_secs(5),
        shutdown: Duration::from_secs(2),
    }
}

impl Harness {
    async fn client(&self) -> Client {
        Client::connect(&self.sock, "test").await.unwrap()
    }

    async fn profile(&self, c: &Client, name: &str, user: Option<&str>) -> fortino_config::Profile {
        let mut spec = ProfileSpec::new(name, "vpn.example.org".parse().unwrap());
        spec.username_hint = user.map(Into::into);
        c.profile_create(spec).await.unwrap()
    }
}

fn connect_params(p: &fortino_config::Profile, key: &str) -> ConnectParams {
    ConnectParams {
        profile_id: p.id.clone(),
        revision: p.revision,
        request_key: key.into(),
        username: None,
    }
}

/// Waits for a status matching `pred`.
async fn wait_for(
    rx: &mut UnboundedReceiver<Event>,
    mut pred: impl FnMut(&Status) -> bool,
) -> Status {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match rx.recv().await.expect("event stream closed") {
                Event::Status { status } if pred(&status) => return *status,
                _ => {}
            }
        }
    })
    .await
    .expect("timed out waiting for status")
}

async fn answer(c: &Client, rx: &mut UnboundedReceiver<Event>, kind: ChallengeKind, v: &str) {
    let st = wait_for(rx, |s| s.challenge.is_some()).await;
    let ch = st.challenge.unwrap();
    assert_eq!(ch.kind, kind);
    c.respond(st.attempt_id.as_deref().unwrap(), &ch.id, v.into())
        .await
        .unwrap();
}

async fn wait_idle(rx: &mut UnboundedReceiver<Event>) -> Status {
    wait_for(rx, |s| s.state == State::Idle).await
}

#[tokio::test]
async fn connect_otp_status_disconnect_restores_network() {
    let h = start(fake(|_| {}), quick()).await;
    let before = h.net.lock().unwrap().net_only();
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (st, mut rx) = c.subscribe().await.unwrap();
    assert_eq!(st.state, State::Idle);

    let r = c.connect_profile(&connect_params(&p, "k1")).await.unwrap();
    assert_eq!(r.state, State::Starting);
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    answer(&c, &mut rx, ChallengeKind::Otp, "123456").await;
    let st = wait_for(&mut rx, |s| s.state == State::Connected).await;
    assert_eq!(st.assigned_ip.as_deref(), Some("10.212.134.200"));
    assert_eq!(st.interface.as_deref(), Some("ppp0"));
    assert_eq!(st.ip_policy, Some(IpPolicy::SplitIpv4));
    assert!(st.connected_since.is_some());
    {
        let n = h.net.lock().unwrap();
        assert!(n.ipv6_blocked);
        assert!(n.split_dns.contains_key("corp.example"));
    }

    // A second client (e.g. reopened app window) sees the same state.
    let c2 = h.client().await;
    let st2 = c2.status().await.unwrap();
    assert_eq!(st2.state, State::Connected);
    assert_eq!(st2.attempt_id, Some(r.attempt_id.clone()));

    // The active profile cannot be changed.
    let e = c
        .profile_delete(p.id.clone(), p.revision)
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ProfileInUse);

    c2.disconnect(&r.attempt_id).await.unwrap();
    let st = wait_idle(&mut rx).await;
    let last = st.last_result.unwrap();
    assert_eq!(last.code, None);
    assert_eq!(h.net.lock().unwrap().net_only(), before);
    // Repeating disconnect is harmless.
    c.disconnect(&r.attempt_id).await.unwrap();
}

#[tokio::test]
async fn username_challenge_when_no_hint() {
    let h = start(fake(|f| f.otp = None), quick()).await;
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", None).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Username, "alice").await;
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    wait_for(&mut rx, |s| s.state == State::Connected).await;
}

#[tokio::test]
async fn wrong_password_is_auth_denied() {
    let h = start(fake(|_| {}), quick()).await;
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Password, "wrong").await;
    let st = wait_idle(&mut rx).await;
    assert_eq!(st.last_result.unwrap().code, Some(ErrorCode::AuthDenied));
}

#[tokio::test]
async fn challenge_timeout_is_distinct_from_denial() {
    let t = Timeouts {
        challenge: Duration::from_millis(200),
        ..quick()
    };
    let h = start(fake(|_| {}), t).await;
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    let st = wait_for(&mut rx, |s| s.challenge.is_some()).await;
    let st_end = wait_idle(&mut rx).await;
    assert_eq!(
        st_end.last_result.unwrap().code,
        Some(ErrorCode::AuthTimeout)
    );
    // The expired challenge cannot be answered.
    let e = c
        .respond(
            st.attempt_id.as_deref().unwrap(),
            &st.challenge.unwrap().id,
            "x".into(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::StaleChallenge);
}

#[tokio::test]
async fn cancel_during_otp() {
    let h = start(fake(|_| {}), quick()).await;
    let before = h.net.lock().unwrap().net_only();
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    let r = c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    wait_for(&mut rx, |s| {
        s.challenge
            .as_ref()
            .is_some_and(|c| c.kind == ChallengeKind::Otp)
    })
    .await;
    c.disconnect(&r.attempt_id).await.unwrap();
    let st = wait_idle(&mut rx).await;
    assert_eq!(st.last_result.unwrap().code, Some(ErrorCode::Cancelled));
    assert_eq!(h.net.lock().unwrap().net_only(), before);
}

#[tokio::test]
async fn trust_failure_never_prompts() {
    let h = start(fake(|f| f.fail = Some(FakeFailure::Trust)), quick()).await;
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    let st = wait_for(&mut rx, |s| s.state == State::Idle || s.challenge.is_some()).await;
    assert!(st.challenge.is_none());
    assert_eq!(st.last_result.unwrap().code, Some(ErrorCode::TrustFailure));
}

#[tokio::test]
async fn tunnel_drop_restores_network() {
    let h = start(
        fake(|f| {
            f.otp = None;
            f.fail = Some(FakeFailure::DropAfterUp);
        }),
        quick(),
    )
    .await;
    let before = h.net.lock().unwrap().net_only();
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    wait_for(&mut rx, |s| s.state == State::Connected).await;
    let st = wait_idle(&mut rx).await;
    assert_eq!(
        st.last_result.unwrap().code,
        Some(ErrorCode::TransportFailure)
    );
    assert_eq!(h.net.lock().unwrap().net_only(), before);
}

#[tokio::test]
async fn network_failure_rolls_back() {
    let mut state = FakeState::typical_host();
    state.fail_apply_at = Some(2);
    let h = start_with(fake(|f| f.otp = None), quick(), state, None).await;
    let before = h.net.lock().unwrap().net_only();
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    let st = wait_idle(&mut rx).await;
    assert_eq!(
        st.last_result.unwrap().code,
        Some(ErrorCode::NetworkConfigFailure)
    );
    assert_eq!(h.net.lock().unwrap().net_only(), before);
}

#[tokio::test]
async fn concurrent_connects_serialize_and_request_key_is_idempotent() {
    let h = start(fake(|_| {}), quick()).await;
    let c1 = h.client().await;
    let c2 = h.client().await;
    let p = h.profile(&c1, "GATEWAY-2", Some("alice")).await;
    let a = connect_params(&p, "k1");
    let b = connect_params(&p, "k2");
    let (r1, r2) = tokio::join!(c1.connect_profile(&a), c2.connect_profile(&b));
    let oks = [&r1, &r2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(oks, 1);
    let err = r1.as_ref().err().or(r2.as_ref().err()).unwrap();
    assert_eq!(err.code, ErrorCode::Busy);

    // Same key and payload returns the original result; different payload conflicts.
    let (winner, key_params) = if r1.is_ok() {
        (r1.unwrap(), a)
    } else {
        (r2.unwrap(), b)
    };
    let again = c1.connect_profile(&key_params).await.unwrap();
    assert_eq!(again, winner);
    let mut changed = key_params.clone();
    changed.username = Some("bob".into());
    assert_eq!(
        c1.connect_profile(&changed).await.unwrap_err().code,
        ErrorCode::Conflict
    );
}

#[tokio::test]
async fn one_challenge_answer_wins() {
    let h = start(fake(|_| {}), quick()).await;
    let mut c1 = h.client().await;
    let c2 = h.client().await;
    let p = h.profile(&c1, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c1.subscribe().await.unwrap();
    c1.connect_profile(&connect_params(&p, "k")).await.unwrap();
    let st = wait_for(&mut rx, |s| s.challenge.is_some()).await;
    let att = st.attempt_id.unwrap();
    let ch = st.challenge.unwrap().id;
    let (a, b) = tokio::join!(
        c1.respond(&att, &ch, "hunter2".into()),
        c2.respond(&att, &ch, "hunter2".into())
    );
    assert_eq!([&a, &b].iter().filter(|r| r.is_ok()).count(), 1);
    let e = a.err().or(b.err()).unwrap();
    assert_eq!(e.code, ErrorCode::StaleChallenge);
}

#[tokio::test]
async fn stale_revision_and_ems_per_gateway() {
    let h = start(fake(|_| {}), quick()).await;
    let c = h.client().await;
    let mut tg1 = ProfileSpec::new("GATEWAY-1", "tg1.example.org".parse().unwrap());
    tg1.endpoint.ems = Some("ems1.example.org".parse().unwrap());
    let mut tg2 = ProfileSpec::new("GATEWAY-2", "tg2.example.org".parse().unwrap());
    tg2.endpoint.ems = Some("ems2.example.org:9016".parse().unwrap());
    let p1 = c.profile_create(tg1).await.unwrap();
    let p2 = c.profile_create(tg2).await.unwrap();

    // Reopen (new client) and check both kept their own EMS server.
    let c = h.client().await;
    let l = c.profile_list().await.unwrap();
    assert_eq!(l.profiles.len(), 2);
    let ems = |name: &str| {
        l.profiles
            .iter()
            .find(|p| p.spec.name == name)
            .unwrap()
            .spec
            .endpoint
            .ems
            .clone()
            .unwrap()
            .to_string()
    };
    assert_eq!(ems("GATEWAY-1"), "ems1.example.org:8013");
    assert_eq!(ems("GATEWAY-2"), "ems2.example.org:9016");

    // Change GATEWAY-1's EMS; GATEWAY-2 keeps its value.
    let mut s1 = p1.spec.clone();
    s1.endpoint.ems = Some(EmsServer {
        host: "ems1b.example.org".parse().unwrap(),
        port: 10443,
    });
    let p1b = c
        .profile_update(p1.id.clone(), 1, s1.clone())
        .await
        .unwrap();
    assert_eq!(p1b.revision, 2);
    assert_eq!(
        c.profile_get("GATEWAY-2").await.unwrap().spec.endpoint.ems,
        p2.spec.endpoint.ems
    );
    // Stale write.
    let e = c.profile_update(p1.id.clone(), 1, s1).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::StaleRevision);
    assert_eq!(e.current_revision, Some(2));
    // Connecting with a stale revision fails too.
    let e = c
        .connect_profile(&connect_params(&p1, "k"))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::StaleRevision);
}

#[tokio::test]
async fn import_through_daemon() {
    let h = start(fake(|_| {}), quick()).await;
    let c = h.client().await;
    let rev = c.profile_list().await.unwrap().store_revision;
    let r = c
        .profile_import(&ProfileImportParams {
            store_revision: rev,
            entries: vec![
                ProfileSpec::new("A", "a.example".parse().unwrap()),
                ProfileSpec::new("B", "b.example".parse().unwrap()),
            ],
            replace: vec![],
        })
        .await
        .unwrap();
    assert_eq!(r.results.len(), 2);
    let e = c
        .profile_import(&ProfileImportParams {
            store_revision: rev,
            entries: vec![ProfileSpec::new("C", "c.example".parse().unwrap())],
            replace: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::StaleRevision);
}

#[tokio::test]
async fn other_user_sees_only_in_use() {
    let h = start(fake(|_| {}), quick()).await;
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    let r = c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    let st = wait_for(&mut rx, |s| s.challenge.is_some()).await;

    let other = Peer {
        uid: h.uid + 1,
        admin: false,
    };
    let v = h.session.status(other);
    assert_eq!(v.state, State::InUse);
    // The other user's sequence number does not move with this attempt's progress.
    let seq_before = v.seq;
    assert!(v.challenge.is_none() && v.gateway.is_none() && v.profile_name.is_none());
    assert!(h.session.with_store(|s| s.get(other.uid, &p.id)).is_err());
    let e = h
        .session
        .respond(
            other,
            &r.attempt_id,
            &st.challenge.as_ref().unwrap().id,
            "hunter2".into(),
        )
        .unwrap_err();
    // Indistinguishable from an unknown attempt, so attempt IDs cannot be probed.
    assert_eq!(e.code, ErrorCode::StaleChallenge);
    h.session.disconnect(other, &r.attempt_id).unwrap();
    assert_eq!(h.session.status(h_peer(&h)).state, State::AwaitingInput);
    c.respond(
        &r.attempt_id,
        &st.challenge.as_ref().unwrap().id,
        "hunter2".into(),
    )
    .await
    .unwrap();
    wait_for(&mut rx, |s| {
        s.challenge
            .as_ref()
            .is_some_and(|c| c.kind == ChallengeKind::Otp)
    })
    .await;
    assert_eq!(h.session.status(other).seq, seq_before);
    // An administrator may stop it but still does not see the challenge.
    let admin = Peer {
        uid: h.uid + 2,
        admin: true,
    };
    assert!(h.session.status(admin).challenge.is_none());
    h.session.disconnect(admin, &r.attempt_id).unwrap();
    wait_idle(&mut rx).await;
}

#[tokio::test]
async fn restart_recovers_stale_journal() {
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(Mutex::new(FakeState::typical_host()));
    let before = state.lock().unwrap().net_only();
    {
        // Simulate a crashed daemon that left changes behind.
        let mut j =
            Journaled::open(FakeNet::new(state.clone()), dir.path().join("journal.json")).unwrap();
        j.apply(&fortino_platform::NetChange::BlockIpv6).unwrap();
        assert!(state.lock().unwrap().ipv6_blocked);
    }
    let snapshot = state.lock().unwrap().clone();
    let h = start_with(fake(|_| {}), quick(), snapshot, Some(dir)).await;
    assert_eq!(h.net.lock().unwrap().net_only(), before);
    let c = h.client().await;
    assert_eq!(c.status().await.unwrap().state, State::Idle);
}

#[tokio::test]
async fn unauthorized_uid_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("s.sock");
    let session = Session::new(
        ProfileStore::in_memory().unwrap(),
        Box::new(FakeWorker::default()),
        Box::new(JournaledController::new(
            Journaled::open(
                FakeNet::new(Arc::new(Mutex::new(FakeState::typical_host()))),
                dir.path().join("j.json"),
            )
            .unwrap(),
        )),
        quick(),
    );
    // Allow only a different UID.
    let auth = Arc::new(Authorizer::new(vec![my_uid() + 1], vec![], None).unwrap());
    tokio::spawn(fortinod::server::serve(
        fortinod::bind_socket(&sock, None).unwrap(),
        session,
        auth,
    ));
    if my_uid() == 0 {
        return; // root is always allowed
    }
    let e = Client::connect(&sock, "t").await.unwrap_err();
    assert_eq!(e.code, ErrorCode::PermissionDenied);
}

#[tokio::test]
async fn protocol_rejections() {
    use fortino_core::framing::{MAX_CONTROL_FRAME, read_frame, write_frame};
    use tokio::net::UnixStream;

    let h = start(fake(|_| {}), quick()).await;
    let c = h.client().await;
    let e = c
        .call::<_, serde_json::Value>("bogus", &serde_json::json!({}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);
    let e = c
        .call::<_, serde_json::Value>(method::STATUS, &serde_json::json!({"x": 1}))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);

    async fn raw(sock: &std::path::Path, body: &[u8]) -> serde_json::Value {
        let mut s = UnixStream::connect(sock).await.unwrap();
        write_frame(&mut s, body, MAX_CONTROL_FRAME).await.unwrap();
        let f = read_frame(&mut s, MAX_CONTROL_FRAME)
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&f).unwrap()
    }
    let r = raw(&h.sock, br#"{"v":1,"id":"a","method":"status"}"#).await;
    assert_eq!(r["error"]["code"], "invalid_request"); // hello required
    let r = raw(&h.sock, br#"{"v":2,"id":"a","method":"hello"}"#).await;
    assert_eq!(r["error"]["code"], "unsupported_version");
    let r = raw(
        &h.sock,
        br#"{"v":1,"id":"a","id":"b","method":"hello","params":{"versions":[1],"client":"x"}}"#,
    )
    .await;
    assert_eq!(r["error"]["code"], "invalid_request");

    // Oversized frame.
    let mut s = UnixStream::connect(&h.sock).await.unwrap();
    use tokio::io::AsyncWriteExt;
    s.write_all(&(MAX_CONTROL_FRAME as u32 + 1).to_be_bytes())
        .await
        .unwrap();
    let f = read_frame(&mut s, MAX_CONTROL_FRAME)
        .await
        .unwrap()
        .unwrap();
    let r: serde_json::Value = serde_json::from_slice(&f).unwrap();
    assert_eq!(r["error"]["code"], "too_large");
    let _: Result<(), ProtoError> = Ok(());
}

fn h_peer(h: &Harness) -> Peer {
    Peer {
        uid: h.uid,
        admin: false,
    }
}

#[tokio::test]
async fn answer_just_before_expiry_does_not_time_out() {
    // The prompt expires after 300 ms, but the gateway takes 600 ms to check the answer.
    let t = Timeouts {
        challenge: Duration::from_millis(300),
        ..quick()
    };
    let h = start(
        fake(|f| {
            f.otp = None;
            f.step_delay_ms = 600;
        }),
        t,
    )
    .await;
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    let st = wait_for(&mut rx, |s| {
        matches!(s.state, State::Connected | State::Idle)
    })
    .await;
    assert_eq!(st.state, State::Connected, "{:?}", st.last_result);
}

#[tokio::test]
async fn silent_gateway_hits_progress_deadline() {
    // Each gateway step takes longer than the progress deadline.
    let t = Timeouts {
        transport: Duration::from_millis(300),
        ..quick()
    };
    let h = start(
        fake(|f| {
            f.otp = None;
            f.step_delay_ms = 1500;
        }),
        t,
    )
    .await;
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k")).await.unwrap();
    let st = wait_idle(&mut rx).await;
    assert_eq!(
        st.last_result.unwrap().code,
        Some(ErrorCode::TransportFailure)
    );
}

/// Resolves when the session has asked the daemon to exit, or fails after `ms`.
async fn exits_within(session: &Arc<Session>, ms: u64) -> bool {
    tokio::time::timeout(Duration::from_millis(ms), session.exit_requested())
        .await
        .is_ok()
}

#[tokio::test]
async fn hello_reports_the_build() {
    let h = start(fake(|_| {}), quick()).await;
    h.session.set_build(Some("build-a".into()));
    let c = h.client().await;
    assert_eq!(c.hello.build.as_deref(), Some("build-a"));

    // A daemon without a stamped build omits the field.
    h.session.set_build(None);
    let c = h.client().await;
    assert_eq!(c.hello.build, None);
}

#[tokio::test]
async fn restart_is_refused_for_the_same_or_an_unstamped_build() {
    let h = start(fake(|_| {}), quick()).await;
    let c = h.client().await;
    // Development daemon: nothing to compare with.
    let e = c.daemon_restart("build-b").await.unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);

    h.session.set_build(Some("build-a".into()));
    let e = c.daemon_restart("build-a").await.unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);
    let e = c.daemon_restart(&"x".repeat(200)).await.unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidRequest);
    assert!(!exits_within(&h.session, 100).await);
}

#[tokio::test]
async fn restart_when_idle_exits_now_and_refuses_new_attempts() {
    let h = start(fake(|_| {}), quick()).await;
    h.session.set_build(Some("build-a".into()));
    let c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let r = c.daemon_restart("build-b").await.unwrap();
    assert_eq!(r.when, RestartWhen::Now);
    assert!(exits_within(&h.session, 1000).await);
    // Between the answer and the exit, a new attempt is refused rather than started.
    let e = c
        .connect_profile(&connect_params(&p, "k"))
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::ServiceUnavailable);
    // Asking again is harmless.
    assert_eq!(
        c.daemon_restart("build-b").await.unwrap().when,
        RestartWhen::Now
    );
}

#[tokio::test]
async fn restart_while_connected_waits_for_disconnect_and_cleanup() {
    let h = start(fake(|_| {}), quick()).await;
    h.session.set_build(Some("build-a".into()));
    let before = h.net.lock().unwrap().net_only();
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    let r = c.connect_profile(&connect_params(&p, "k1")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    answer(&c, &mut rx, ChallengeKind::Otp, "123456").await;
    wait_for(&mut rx, |s| s.state == State::Connected).await;

    let w = c.daemon_restart("build-b").await.unwrap();
    assert_eq!(w.when, RestartWhen::AfterDisconnect);
    // The tunnel stays up.
    assert!(!exits_within(&h.session, 200).await);
    assert_eq!(c.status().await.unwrap().state, State::Connected);

    c.disconnect(&r.attempt_id).await.unwrap();
    wait_idle(&mut rx).await;
    assert!(exits_within(&h.session, 2000).await);
    // The exit comes after the network state was rolled back.
    assert_eq!(h.net.lock().unwrap().net_only(), before);
}

/// Stopping the service (SIGTERM from launchd on uninstall or bootout) while connected stops
/// the tunnel and restores the network before the process exits.
#[tokio::test]
async fn shutdown_while_connected_restores_network() {
    let h = start(fake(|_| {}), quick()).await;
    let before = h.net.lock().unwrap().net_only();
    let mut c = h.client().await;
    let p = h.profile(&c, "GATEWAY-2", Some("alice")).await;
    let (_, mut rx) = c.subscribe().await.unwrap();
    c.connect_profile(&connect_params(&p, "k1")).await.unwrap();
    answer(&c, &mut rx, ChallengeKind::Password, "hunter2").await;
    answer(&c, &mut rx, ChallengeKind::Otp, "123456").await;
    wait_for(&mut rx, |s| s.state == State::Connected).await;
    assert_ne!(h.net.lock().unwrap().net_only(), before);

    tokio::time::timeout(Duration::from_secs(5), h.session.shutdown())
        .await
        .expect("shutdown waits for the rollback, within its timeout");
    assert_eq!(h.net.lock().unwrap().net_only(), before);
    let st = c.status().await.unwrap();
    assert_eq!(st.state, State::Idle);
    assert_eq!(
        st.last_result.unwrap().code,
        Some(ErrorCode::ServiceUnavailable)
    );
}

/// Every client that subscribes and leaves gives its connection back: the per-user limit
/// counts open connections, and an idle service sends no event that would close them.
#[tokio::test]
async fn clients_that_leave_free_their_connection() {
    let h = start(fake(|_| {}), quick()).await;
    for _ in 0..fortinod::server::MAX_CONNECTIONS_PER_UID + 8 {
        let mut c = h.client().await;
        c.subscribe().await.unwrap();
        drop(c);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let ok = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(c) = Client::connect(&h.sock, "test").await
                && c.status().await.is_ok()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(ok.is_ok(), "new connections refused after clients left");
}

/// An answer too large for one message is refused with `too_large`; the connection stays up.
#[tokio::test]
async fn oversized_answer_is_refused_not_dropped() {
    let h = start(fake(|_| {}), quick()).await;
    let c = h.client().await;
    for n in 0..20 {
        let mut spec = ProfileSpec::new(format!("P{n}"), "vpn.example.org".parse().unwrap());
        for i in 0..4 {
            spec.debug_ems_sysinfo
                .insert(format!("K{i}"), "v".repeat(3900));
        }
        c.profile_create(spec).await.unwrap();
    }
    let e = c.profile_list().await.unwrap_err();
    assert_eq!(e.code, ErrorCode::TooLarge);
    assert!(c.status().await.is_ok(), "the connection survives");
}
