//! The daemon's session driving the `fortino-sslvpn-worker` process over the private channel,
//! against the mock FortiGate. Trust comes from a pin file; the worker uses an in-memory tun
//! device and the daemon a fake network, so no root is needed.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fortino_config::{CredentialMode, ProfileSpec, ProfileStore};
use fortino_core::ErrorCode;
use fortino_core::proto::{ChallengeKind, ConnectParams, State, Status};
use fortino_mock::fortigate::{self, SamlCfg, Scenario, User};
use fortino_platform::fake::{FakeNet, FakeState};
use fortino_platform::journal::Journaled;
use fortino_proto_sslvpn::identity::{self, ClientIdentity};
use fortino_sslvpn::Trust;
use fortino_sslvpn::transport::Gateway;
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
    mock: fortino_mock::MockHandle,
    session: Arc<Session>,
    net: Arc<Mutex<FakeState>>,
}

/// Single sign-on callback port the mock names in `/remote/info`.
const SSO_PORT: u16 = 18030;

async fn harness(pin_ok: bool) -> H {
    harness_as(pin_ok, CredentialMode::Password).await
}

async fn harness_as(pin_ok: bool, credential_mode: CredentialMode) -> H {
    let mut sc = Scenario {
        users: vec![User {
            username: "alice".into(),
            password: "hunter2".into(),
            otp: Some("123456".into()),
        }],
        ..Default::default()
    };
    if credential_mode == CredentialMode::Saml {
        sc.info.sso_port = Some(SSO_PORT);
        sc.saml = Some(SamlCfg::default());
    }
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
            gateway_pins: None,
            env: vec![("FORTINO_WORKER_MEMORY_DEVICE".into(), "1".into())],
        }),
        Box::new(JournaledController::new(
            Journaled::open(FakeNet::new(net.clone()), dir.path().join("j.json")).unwrap(),
        )),
        Timeouts {
            transport: Duration::from_secs(10),
            challenge: Duration::from_secs(10),
            saml: Duration::from_secs(10),
            shutdown: Duration::from_secs(8),
        },
    );
    let mut spec = ProfileSpec::new("Lab", "127.0.0.1".parse().unwrap());
    spec.endpoint.port = mock.addr.port();
    spec.trust_id = "lab".into();
    spec.username_hint = Some("alice".into());
    spec.credential_mode = credential_mode;
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
        mock,
        session,
        net,
    }
}

/// Plays the browser's last step: the mock's sign-in result, a redirect to the local callback.
/// Returns that callback's query string.
async fn browser_callback(mock: &fortino_mock::MockHandle) -> String {
    let trust = Trust::Roots(vec![mock.cert_der.clone()]);
    let mut gw = Gateway::new("sslvpn.test".parse().unwrap(), mock.addr.port(), &trust).unwrap();
    gw.connect_override = Some(mock.addr);
    let req = identity::build(
        &ClientIdentity::forticlient("browser"),
        "GET",
        "/remote/saml/login?redirect=1",
        &gw.host_header(),
        &[],
        None,
    );
    let r = gw.exchange(&req).await.unwrap();
    let location = r.header("location").unwrap();
    location
        .strip_prefix(&format!("http://127.0.0.1:{SSO_PORT}/?"))
        .unwrap()
        .to_owned()
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

/// The same through a single sign-on: the daemon names the sign-in page from the profile and
/// the worker's callback port, and the worker exchanges the browser's session id.
#[tokio::test]
async fn worker_process_signs_in_with_single_sign_on() {
    let h = harness_as(true, CredentialMode::Saml).await;
    let s = h.wait(|s| s.challenge.is_some()).await;
    let ch = s.challenge.unwrap();
    assert_eq!(ch.kind, ChallengeKind::Saml);
    let login = ch.saml.unwrap();
    assert_eq!(login.callback_port, SSO_PORT);
    assert_eq!(
        login.url,
        format!(
            "https://127.0.0.1:{}/remote/saml/start?redirect=1",
            h.mock.addr.port()
        )
    );
    assert!(ch.expires_in_secs > 0);
    let query = browser_callback(&h.mock).await;
    h.answer(ChallengeKind::Saml, &query).await;
    let s = h.wait(|s| s.state == State::Idle).await;
    let r = s.last_result.unwrap();
    assert_eq!(r.code, Some(ErrorCode::NetworkConfigFailure), "{r:?}");
    assert!(r.message.contains("gateway address"), "{r:?}");
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
