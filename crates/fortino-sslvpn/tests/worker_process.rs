//! The daemon's session driving the `fortino-sslvpn-worker` process over the private channel,
//! against the mock FortiGate. Trust comes from a pin file; the worker uses an in-memory tun
//! device and the daemon a fake network, so no root is needed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fortino_config::{ProfileSpec, ProfileStore};
use fortino_core::ErrorCode;
use fortino_core::proto::{ChallengeKind, ConnectParams, State, Status};
use fortino_mock::fortigate::{self, Scenario, User};
use fortino_platform::fake::{FakeNet, FakeState};
use fortino_platform::journal::Journaled;
use fortinod::auth::Peer;
use fortinod::config::Timeouts;
use fortinod::netctl::JournaledController;
use fortinod::procworker::ProcessWorker;
use fortinod::session::Session;

const PEER: Peer = Peer {
    uid: 501,
    admin: false,
};

struct H {
    _dir: tempfile::TempDir,
    _mock: fortino_mock::MockHandle,
    session: Arc<Session>,
    net: Arc<Mutex<FakeState>>,
}

async fn harness(pin_ok: bool) -> H {
    let sc = Scenario {
        users: vec![User {
            username: "alice".into(),
            password: "hunter2".into(),
            otp: Some("123456".into()),
        }],
        ..Default::default()
    };
    let mock = fortigate::start(&sc).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let pin = if pin_ok {
        mock.cert_sha256.clone()
    } else {
        "00".repeat(32)
    };
    std::fs::write(
        dir.path().join("lab.pem"),
        format!("# mock gateway leaf\nsha256:{pin}\n"),
    )
    .unwrap();
    let net = Arc::new(Mutex::new(FakeState::typical_host()));
    let session = Session::new(
        ProfileStore::in_memory().unwrap(),
        Box::new(ProcessWorker {
            path: env!("CARGO_BIN_EXE_fortino-sslvpn-worker").into(),
            args: vec![],
            ca_dir: dir.path().into(),
            env: vec![("FORTINO_WORKER_MEMORY_DEVICE".into(), "1".into())],
        }),
        Box::new(JournaledController::new(
            Journaled::open(FakeNet::new(net.clone()), dir.path().join("j.json")).unwrap(),
        )),
        Timeouts {
            transport: Duration::from_secs(10),
            challenge: Duration::from_secs(10),
            shutdown: Duration::from_secs(8),
        },
    );
    let mut spec = ProfileSpec::new("Lab", "127.0.0.1".parse().unwrap());
    spec.endpoint.port = mock.addr.port();
    spec.trust_id = "lab".into();
    spec.username_hint = Some("alice".into());
    let p = session.with_store(|s| s.create(PEER.uid, spec)).unwrap();
    session
        .connect(
            PEER,
            ConnectParams {
                profile_id: p.id,
                revision: p.revision,
                request_key: "k".into(),
                username: None,
            },
        )
        .unwrap();
    H {
        _dir: dir,
        _mock: mock,
        session,
        net,
    }
}

impl H {
    async fn wait(&self, mut pred: impl FnMut(&Status) -> bool) -> Status {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let s = self.session.status(PEER);
                if pred(&s) {
                    return s;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("timed out")
    }

    async fn answer(&self, kind: ChallengeKind, v: &str) {
        let s = self
            .wait(|s| s.challenge.as_ref().is_some_and(|c| c.kind == kind))
            .await;
        self.session
            .respond(
                PEER,
                s.attempt_id.as_deref().unwrap(),
                &s.challenge.unwrap().id,
                v.into(),
            )
            .unwrap();
    }
}

/// The mock listens on loopback, which the daemon must refuse as a gateway address. Reaching
/// that check proves the worker process completed login, settings and PPP and sent `Up`; the
/// connected path itself is covered in-process (`mock_gateway.rs`) and in the VM.
#[tokio::test]
async fn worker_process_reaches_up_and_daemon_validates_it() {
    let h = harness(true).await;
    let before = h.net.lock().unwrap().net_only();
    h.answer(ChallengeKind::Password, "hunter2").await;
    h.answer(ChallengeKind::Otp, "123456").await;
    let s = h.wait(|s| s.state == State::Idle).await;
    let r = s.last_result.unwrap();
    assert_eq!(r.code, Some(ErrorCode::NetworkConfigFailure), "{r:?}");
    assert!(r.message.contains("gateway address"), "{r:?}");
    assert_eq!(h.net.lock().unwrap().net_only(), before);
}

#[tokio::test]
async fn wrong_pin_is_a_trust_failure_before_any_prompt() {
    let h = harness(false).await;
    let s = h
        .wait(|s| s.state == State::Idle || s.challenge.is_some())
        .await;
    assert!(
        s.challenge.is_none(),
        "prompted over an untrusted connection"
    );
    assert_eq!(
        s.last_result.and_then(|r| r.code),
        Some(ErrorCode::TrustFailure)
    );
}
