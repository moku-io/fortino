//! Session tests through a real worker process (`fortino-stub-worker`) over the private channel.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fortino_config::{ProfileSpec, ProfileStore};
use fortino_core::ErrorCode;
use fortino_core::proto::{ChallengeKind, ConnectParams, State, Status};
use fortino_core::worker::FakeWorkerConfig;
use fortino_platform::fake::{FakeNet, FakeState};
use fortino_platform::journal::Journaled;
use fortinod::auth::Peer;
use fortinod::config::Timeouts;
use fortinod::netctl::JournaledController;
use fortinod::procworker::ProcessWorker;
use fortinod::session::Session;

struct H {
    _dir: tempfile::TempDir,
    session: Arc<Session>,
    net: Arc<Mutex<FakeState>>,
    peer: Peer,
}

fn harness(misbehave: Option<&str>, f: impl FnOnce(&mut FakeWorkerConfig)) -> H {
    let dir = tempfile::tempdir().unwrap();
    let mut wc = FakeWorkerConfig {
        password: Some("hunter2".into()),
        step_delay_ms: 5,
        ..Default::default()
    };
    f(&mut wc);
    let mut env = vec![(
        "FORTINO_STUB_WORKER".to_owned(),
        serde_json::to_string(&wc).unwrap(),
    )];
    if let Some(m) = misbehave {
        env.push(("FORTINO_STUB_MISBEHAVE".into(), m.into()));
    }
    let net = Arc::new(Mutex::new(FakeState::typical_host()));
    let session = Session::new(
        ProfileStore::in_memory().unwrap(),
        Box::new(ProcessWorker {
            path: env!("CARGO_BIN_EXE_fortino-stub-worker").into(),
            ca_dir: dir.path().into(),
            env,
        }),
        Box::new(JournaledController::new(
            Journaled::open(FakeNet::new(net.clone()), dir.path().join("j.json")).unwrap(),
        )),
        Timeouts {
            transport: Duration::from_secs(5),
            challenge: Duration::from_secs(5),
            shutdown: Duration::from_secs(8),
        },
    );
    H {
        _dir: dir,
        session,
        net,
        peer: Peer {
            uid: 501,
            admin: false,
        },
    }
}

impl H {
    fn start(&self) -> String {
        let mut spec = ProfileSpec::new("GATEWAY-2", "vpn.example.org".parse().unwrap());
        spec.username_hint = Some("alice".into());
        let p = self
            .session
            .with_store(|s| s.create(self.peer.uid, spec))
            .unwrap();
        self.session
            .connect(
                self.peer,
                ConnectParams {
                    profile_id: p.id,
                    revision: p.revision,
                    request_key: "k".into(),
                    username: None,
                },
            )
            .unwrap()
            .attempt_id
    }

    async fn wait(&self, mut pred: impl FnMut(&Status) -> bool) -> Status {
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                let s = self.session.status(self.peer);
                if pred(&s) {
                    return s;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
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
                self.peer,
                s.attempt_id.as_deref().unwrap(),
                &s.challenge.unwrap().id,
                v.into(),
            )
            .unwrap();
    }

    async fn idle_code(&self) -> Option<ErrorCode> {
        self.wait(|s| s.state == State::Idle)
            .await
            .last_result
            .and_then(|r| r.code)
    }
}

#[tokio::test]
async fn full_flow_through_process() {
    let h = harness(None, |_| {});
    let before = h.net.lock().unwrap().net_only();
    let a = h.start();
    h.answer(ChallengeKind::Password, "hunter2").await;
    h.answer(ChallengeKind::Otp, "123456").await;
    let s = h.wait(|s| s.state == State::Connected).await;
    assert_eq!(s.interface.as_deref(), Some("ppp0"));
    h.session.disconnect(h.peer, &a).unwrap();
    assert_eq!(h.idle_code().await, None);
    assert_eq!(h.net.lock().unwrap().net_only(), before);
}

#[tokio::test]
async fn denial_through_process() {
    let h = harness(None, |_| {});
    h.start();
    h.answer(ChallengeKind::Password, "nope").await;
    assert_eq!(h.idle_code().await, Some(ErrorCode::AuthDenied));
}

#[tokio::test]
async fn trust_failure_through_process() {
    let h = harness(None, |c| {
        c.fail = Some(fortino_core::worker::FakeFailure::Trust)
    });
    h.start();
    assert_eq!(h.idle_code().await, Some(ErrorCode::TrustFailure));
}

#[tokio::test]
async fn stale_attempt_frames_are_rejected() {
    let h = harness(Some("stale-attempt"), |_| {});
    h.start();
    assert_eq!(h.idle_code().await, Some(ErrorCode::BackendFailure));
}

#[tokio::test]
async fn oversized_frame_is_rejected() {
    let h = harness(Some("huge-frame"), |_| {});
    h.start();
    assert_eq!(h.idle_code().await, Some(ErrorCode::BackendFailure));
}

#[tokio::test]
async fn non_increasing_sequence_is_rejected() {
    let h = harness(Some("bad-seq"), |_| {});
    h.start();
    assert_eq!(h.idle_code().await, Some(ErrorCode::BackendFailure));
}

#[tokio::test]
async fn early_exit_is_reported() {
    let h = harness(Some("exit-early"), |_| {});
    h.start();
    assert_eq!(h.idle_code().await, Some(ErrorCode::BackendFailure));
}

#[tokio::test]
async fn hung_worker_is_killed_and_network_restored() {
    let h = harness(Some("ignore-stop"), |c| c.otp = None);
    let before = h.net.lock().unwrap().net_only();
    let a = h.start();
    h.answer(ChallengeKind::Password, "hunter2").await;
    h.wait(|s| s.state == State::Connected).await;
    h.session.disconnect(h.peer, &a).unwrap();
    // The worker ignores stop; the supervisor kills it after its grace period.
    let code = h.idle_code().await;
    assert_eq!(code, None, "a user disconnect stays a clean result");
    assert_eq!(h.net.lock().unwrap().net_only(), before);
}

#[tokio::test]
async fn missing_executable_fails_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    let session = Session::new(
        ProfileStore::in_memory().unwrap(),
        Box::new(ProcessWorker {
            path: dir.path().join("does-not-exist"),
            ca_dir: dir.path().into(),
            env: vec![],
        }),
        Box::new(JournaledController::new(
            Journaled::open(
                FakeNet::new(Arc::new(Mutex::new(FakeState::typical_host()))),
                dir.path().join("j.json"),
            )
            .unwrap(),
        )),
        Timeouts::default(),
    );
    let h = H {
        _dir: dir,
        session,
        net: Arc::new(Mutex::new(FakeState::default())),
        peer: Peer {
            uid: 501,
            admin: false,
        },
    };
    h.start();
    assert_eq!(h.idle_code().await, Some(ErrorCode::BackendFailure));
}

#[test]
fn executable_ownership_check() {
    // Test binaries are owned by the developer, not root.
    let r =
        fortinod::procworker::check_executable(env!("CARGO_BIN_EXE_fortino-stub-worker").as_ref());
    if nix::unistd::getuid().is_root() {
        return;
    }
    assert!(r.is_err());
    assert!(fortinod::procworker::check_executable("/bin/sh".as_ref()).is_ok());
}
