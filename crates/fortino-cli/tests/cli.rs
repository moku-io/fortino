//! Drives the `fortino` binary against an in-process daemon with the fake worker.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use fortino_config::ProfileStore;
use fortino_core::worker::{FakeWorker, FakeWorkerConfig};
use fortino_platform::fake::{FakeNet, FakeState};
use fortino_platform::journal::Journaled;
use fortinod::auth::Authorizer;
use fortinod::config::Timeouts;
use fortinod::netctl::JournaledController;
use fortinod::session::Session;

struct Daemon {
    dir: tempfile::TempDir,
    sock: PathBuf,
    _rt: tokio::runtime::Runtime,
}

fn daemon() -> Daemon {
    daemon_with(FakeWorkerConfig {
        password: Some("hunter2".into()),
        step_delay_ms: 5,
        ..Default::default()
    })
}

fn daemon_with(config: FakeWorkerConfig) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("d.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let session = Session::new(
        ProfileStore::in_memory().unwrap(),
        Box::new(FakeWorker { config }),
        Box::new(JournaledController::new(
            Journaled::open(
                FakeNet::new(Arc::new(Mutex::new(FakeState::typical_host()))),
                dir.path().join("j.json"),
            )
            .unwrap(),
        )),
        Timeouts::default(),
    );
    let uid = nix::unistd::getuid().as_raw();
    let auth = Arc::new(Authorizer::new(vec![uid], vec![], None).unwrap());
    let s = sock.clone();
    rt.block_on(async move {
        let l = fortinod::bind_socket(&s, None).unwrap();
        tokio::spawn(fortinod::server::serve(l, session, auth));
    });
    Daemon { dir, sock, _rt: rt }
}

impl Daemon {
    fn run(&self, args: &str) -> Output {
        self.sh(&format!("\"$FORTINO_CLI\" {args}"))
    }

    fn sh(&self, script: &str) -> Output {
        Command::new("sh")
            .arg("-c")
            .arg(script)
            .env("FORTINO_CLI", env!("CARGO_BIN_EXE_fortino"))
            .env("FORTINO_SOCKET", &self.sock)
            .current_dir(self.dir.path())
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }

    fn write(&self, name: &str, body: &str) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    }
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|_| panic!("not JSON: {}", stdout(o)))
}

#[test]
fn profile_lifecycle_and_exit_codes() {
    let d = daemon();
    let o =
        d.run("profile add GATEWAY-2 --host tg2.example.org --ems-server ems2.example.org:9016");
    assert_eq!(code(&o), 0, "{o:?}");
    let o = d.run("profile add gateway-2 --host x.example.org");
    assert_eq!(code(&o), 3); // name taken
    let o = d.run("profile add bad --host 'not a host'");
    assert_eq!(code(&o), 2);
    let o = d.run("--json profile show GATEWAY-2");
    let v = json(&o);
    assert_eq!(v["result"]["spec"]["endpoint"]["ems"]["port"], 9016);
    let id = v["result"]["id"].as_str().unwrap().to_owned();
    let o = d.run("profile edit GATEWAY-2 --rename Gateway2 --ems-server ems3.example.org");
    assert_eq!(code(&o), 0, "{o:?}");
    let v = json(&d.run("--json profile show Gateway2"));
    assert_eq!(v["result"]["id"], id.as_str());
    assert_eq!(v["result"]["spec"]["endpoint"]["ems"]["port"], 8013);
    assert_eq!(code(&d.run("profile remove Gateway2")), 0);
    assert_eq!(code(&d.run("profile show Gateway2")), 2);
}

#[test]
fn connect_with_descriptors_then_disconnect() {
    let d = daemon();
    assert_eq!(
        code(&d.run("profile add GATEWAY-2 --host tg2.example.org --username alice")),
        0
    );
    let pw = d.write("pw", "hunter2\n");
    let otp = d.write("otp", "123456\n");
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" --json connect GATEWAY-2 --password-fd 3 --otp-fd 4 3<{} 4<{}",
        pw.display(),
        otp.display()
    ));
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(json(&o)["status"]["state"], "connected");
    let st = json(&d.run("--json status"));
    assert_eq!(st["status"]["state"], "connected");
    assert_eq!(st["status"]["ipPolicy"], "split-ipv4");
    // Secrets never appear in output.
    assert!(!stdout(&o).contains("hunter2"));

    assert_eq!(code(&d.run("disconnect")), 0);
    assert_eq!(json(&d.run("--json status"))["status"]["state"], "idle");
    assert_eq!(code(&d.run("disconnect")), 0); // already idle
}

#[test]
fn missing_otp_without_terminal_is_interaction_required() {
    let d = daemon();
    assert_eq!(
        code(&d.run("profile add GATEWAY-2 --host tg2.example.org --username alice")),
        0
    );
    let pw = d.write("pw", "hunter2\n");
    // No controlling terminal is available to the child when started this way in CI; if one
    // is, the prompt would block, so detach stdin and rely on /dev/tty being unavailable.
    if std::fs::File::open("/dev/tty").is_ok() {
        return;
    }
    let started = std::time::Instant::now();
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" --json connect GATEWAY-2 --password-fd 3 3<{}",
        pw.display()
    ));
    assert_eq!(code(&o), 4, "{o:?}");
    assert_eq!(json(&o)["error"]["code"], "interaction_required");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
    assert_eq!(json(&d.run("--json status"))["status"]["state"], "idle");
}

/// A loopback port nothing listens on right now.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn sso_daemon(port: u16) -> Daemon {
    daemon_with(FakeWorkerConfig {
        step_delay_ms: 5,
        saml_port: port,
        saml_id: Some("abc-1".into()),
        ..Default::default()
    })
}

#[test]
fn connect_with_single_sign_on() {
    use std::io::{Read, Write};
    let port = free_port();
    let d = sso_daemon(port);
    assert_eq!(
        code(&d.run("profile add SSO --host sso.example.org --port 10443 --auth saml")),
        0
    );
    let v = json(&d.run("--json profile show SSO"));
    assert_eq!(v["result"]["spec"]["credentialMode"], "saml");
    assert!(stdout(&d.run("profile list")).contains("sso"));

    // The browser: once the CLI listens, the gateway's redirect lands on it.
    let browser = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            match std::net::TcpStream::connect(("127.0.0.1", port)) {
                Ok(mut s) => {
                    write!(
                        s,
                        "GET /?id=abc-1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
                    )
                    .unwrap();
                    let mut page = String::new();
                    s.read_to_string(&mut page).unwrap();
                    return page;
                }
                Err(_) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(e) => panic!("the CLI never listened: {e}"),
            }
        }
    });
    let o = d.run("--json connect SSO --no-browser");
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(json(&o)["status"]["state"], "connected");
    let page = browser.join().unwrap();
    assert!(page.starts_with("HTTP/1.1 200"), "{page}");
    assert!(!page.contains("abc-1"), "the page must not echo the id");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("https://sso.example.org:10443/remote/saml/start?redirect=1"),
        "{err}"
    );
    assert!(!err.contains("abc-1"), "{err}");
    assert_eq!(code(&d.run("disconnect")), 0);
}

#[test]
fn single_sign_on_without_the_port_or_a_terminal_is_interaction_required() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = taken.local_addr().unwrap().port();
    let d = sso_daemon(port);
    assert_eq!(
        code(&d.run("profile add SSO --host sso.example.org --auth saml")),
        0
    );
    let o = d.run("--json connect SSO --no-browser");
    assert_eq!(code(&o), 4, "{o:?}");
    assert_eq!(json(&o)["error"]["code"], "interaction_required");
    assert_eq!(json(&d.run("--json status"))["status"]["state"], "idle");
    drop(taken);
}

#[test]
fn wrong_password_exit_code() {
    let d = daemon();
    assert_eq!(
        code(&d.run("profile add GATEWAY-2 --host tg2.example.org --username alice")),
        0
    );
    let pw = d.write("pw", "nope\n");
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" --json connect GATEWAY-2 --password-fd 3 3<{}",
        pw.display()
    ));
    assert_eq!(code(&o), 4);
    assert_eq!(json(&o)["error"]["code"], "auth_denied");
}

#[test]
fn previews_conf_backup_without_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("forticlient.conf");
    std::fs::write(
        &backup,
        "<forticlient_configuration><vpn><sslvpn><connections><connection>\
         <name>Example</name><server>vpn.example.test</server>\
         </connection></connections></sslvpn></vpn></forticlient_configuration>",
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_fortino"))
        .env("FORTINO_SOCKET", dir.path().join("absent.sock"))
        .args(["--json", "profile", "import", "--dry-run"])
        .arg(backup)
        .output()
        .unwrap();
    assert!(out.status.success());
    let preview: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(preview["result"]["entries"][0]["spec"]["name"], "Example");
}

#[test]
fn import_dry_run_and_commit() {
    let d = daemon();
    let x = d.write(
        "export.xml",
        "<forticlient_configuration><vpn><sslvpn><connections>\
         <connection><name>Engineering</name><server>vpn.example.test:10443/staff</server>\
         <password>SENTINEL_PW</password></connection>\
         </connections></sslvpn></vpn></forticlient_configuration>",
    );
    let o = d.run(&format!("profile import {} --dry-run", x.display()));
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("eligible"));
    assert!(!stdout(&o).contains("SENTINEL"));
    assert_eq!(
        json(&d.run("--json profile list"))["result"]["profiles"],
        serde_json::json!([])
    );
    let o = d.run(&format!("--json profile import {}", x.display()));
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(json(&o)["result"]["results"][0]["action"], "created");
    let v = json(&d.run("--json profile show Engineering"));
    assert_eq!(v["result"]["spec"]["endpoint"]["realm"], "staff");

    let bad = d.write("bad.xml", "not xml at all");
    assert_eq!(
        code(&d.run(&format!("profile import {}", bad.display()))),
        2
    );
}

#[test]
fn service_unavailable() {
    let o = Command::new(env!("CARGO_BIN_EXE_fortino"))
        .args(["--socket", "/nonexistent/fortinod.sock", "status"])
        .output()
        .unwrap();
    assert_eq!(code(&o), 7);
}

/// The app's Info.plist carries the release version; the Rust workspace version
/// must match it so `fortino -V` and `fortinod` report the same release.
#[test]
fn version_matches_app_release() {
    let plist = include_str!("../../../apps/macos/Resources/Info.plist");
    let key = "<key>CFBundleShortVersionString</key>";
    let rest = &plist[plist.find(key).expect("CFBundleShortVersionString") + key.len()..];
    let start = rest.find("<string>").unwrap() + "<string>".len();
    let release = &rest[start..start + rest[start..].find("</string>").unwrap()];
    assert_eq!(env!("CARGO_PKG_VERSION"), release);

    let o = Command::new(env!("CARGO_BIN_EXE_fortino"))
        .arg("-V")
        .output()
        .unwrap();
    assert_eq!(stdout(&o).trim(), format!("fortino {release}"));
}
