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
    rt: tokio::runtime::Runtime,
}

fn daemon() -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("d.sock");
    let rt = tokio::runtime::Runtime::new().unwrap();
    let session = Session::new(
        ProfileStore::in_memory().unwrap(),
        Box::new(FakeWorker {
            config: FakeWorkerConfig {
                password: Some("hunter2".into()),
                step_delay_ms: 5,
                ..Default::default()
            },
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
    let uid = nix::unistd::getuid().as_raw();
    let auth = Arc::new(Authorizer::new(vec![uid], vec![], None).unwrap());
    let s = sock.clone();
    rt.block_on(async move {
        let l = fortinod::bind_socket(&s, None).unwrap();
        tokio::spawn(fortinod::server::serve(l, session, auth));
    });
    Daemon { dir, sock, rt }
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
            // Saved passwords go to a file in the test directory, never the real keychain.
            .env(
                "FORTINO_CREDENTIAL_STORE",
                format!("file:{}", self.dir.path().join("creds.json").display()),
            )
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

/// The saved-password file the CLI writes in tests.
fn creds(d: &Daemon) -> serde_json::Value {
    std::fs::read(d.dir.path().join("creds.json"))
        .map(|b| serde_json::from_slice(&b).unwrap())
        .unwrap_or_else(|_| serde_json::json!({}))
}

fn profile_id(d: &Daemon, name: &str) -> String {
    json(&d.run(&format!("--json profile show {name}")))["result"]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn saved_password_answers_the_prompt_and_is_never_printed() {
    let d = daemon();
    assert_eq!(
        code(&d.run("profile add GW --host tg2.example.org --username alice")),
        0
    );
    let o = d.sh("printf 'hunter2\\n' | \"$FORTINO_CLI\" password save GW --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    assert!(stdout(&o).contains("for alice"), "{o:?}");
    let id = profile_id(&d, "GW");
    assert_eq!(creds(&d)[&id]["username"], "alice");
    // Saving turned the option on.
    let v = json(&d.run("--json profile show GW"));
    assert_eq!(v["result"]["spec"]["savePassword"], true);

    let st = json(&d.run("--json password status GW"));
    assert_eq!(st["result"]["saved"], true);
    assert_eq!(st["result"]["username"], "alice");
    assert_eq!(st["result"]["rejected"], false);
    assert!(!stdout(&d.run("--json password status GW")).contains("hunter2"));

    // Only the code comes from a descriptor; the password comes from the store.
    let otp = d.write("otp", "123456\n");
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" connect GW --otp-fd 4 4<{}",
        otp.display()
    ));
    assert_eq!(code(&o), 0, "{o:?}");
    assert!(stderr(&o).contains("Using the password saved in"), "{o:?}");
    assert!(!stdout(&o).contains("hunter2") && !stderr(&o).contains("hunter2"));
    assert_eq!(code(&d.run("disconnect")), 0);
}

#[test]
fn rejected_saved_password_is_not_sent_again() {
    let d = daemon();
    assert_eq!(
        code(&d.run("profile add GW --host tg2.example.org --username alice")),
        0
    );
    let o = d.sh("printf 'stale\\n' | \"$FORTINO_CLI\" password save GW --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    let o = d.run("--json connect GW");
    assert_eq!(code(&o), 4, "{o:?}");
    assert_eq!(json(&o)["error"]["code"], "auth_denied");
    let id = profile_id(&d, "GW");
    assert_eq!(creds(&d)[&id]["rejected"], true);
    let st = json(&d.run("--json password status GW"));
    assert_eq!(st["result"]["rejected"], true);

    // Without a terminal the next attempt can't ask, and the rejected password stays unused.
    if std::fs::File::open("/dev/tty").is_err() {
        let o = d.run("--json connect GW");
        assert_eq!(code(&o), 4, "{o:?}");
        assert_eq!(json(&o)["error"]["code"], "interaction_required");
    }

    // Saving again clears the mark.
    let o = d.sh("printf 'hunter2\\n' | \"$FORTINO_CLI\" password save GW --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(creds(&d)[&id]["rejected"], false);
}

#[test]
fn password_from_a_descriptor_leaves_the_store_alone() {
    let d = daemon();
    assert_eq!(
        code(&d.run("profile add GW --host tg2.example.org --username alice --save-password")),
        0
    );
    let o = d.sh("printf 'stale\\n' | \"$FORTINO_CLI\" password save GW --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    let pw = d.write("pw", "hunter2\n");
    let otp = d.write("otp", "123456\n");
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" connect GW --password-fd 3 --otp-fd 4 3<{} 4<{}",
        pw.display(),
        otp.display()
    ));
    assert_eq!(code(&o), 0, "{o:?}");
    let id = profile_id(&d, "GW");
    assert_eq!(creds(&d)[&id]["password"], "stale");
    assert_eq!(creds(&d)[&id]["rejected"], false);
    assert_eq!(code(&d.run("disconnect")), 0);
}

#[test]
fn turning_the_option_off_or_removing_the_profile_forgets_the_password() {
    let d = daemon();
    for n in ["A", "B", "C"] {
        assert_eq!(
            code(&d.run(&format!(
                "profile add {n} --host tg2.example.org --username alice"
            ))),
            0
        );
        let o = d.sh(&format!(
            "printf 'pw\\n' | \"$FORTINO_CLI\" password save {n} --stdin"
        ));
        assert_eq!(code(&o), 0, "{o:?}");
    }
    let (a, b, c) = (
        profile_id(&d, "A"),
        profile_id(&d, "B"),
        profile_id(&d, "C"),
    );

    let o = d.run("profile edit A --no-save-password");
    assert_eq!(code(&o), 0, "{o:?}");
    assert!(stdout(&o).contains("Removed the saved password"), "{o:?}");
    assert!(creds(&d).get(&a).is_none());

    assert_eq!(code(&d.run("profile remove B")), 0);
    assert!(creds(&d).get(&b).is_none());

    let o = d.run("--json password forget C");
    assert_eq!(json(&o)["result"]["removed"], true);
    assert!(creds(&d).get(&c).is_none());
    // Forgetting keeps the choice, so the next connection saves again.
    let v = json(&d.run("--json profile show C"));
    assert_eq!(v["result"]["spec"]["savePassword"], true);
    // The ID of a profile that is gone is still accepted, for cleanup.
    let o = d.run(&format!("--json password forget {b}"));
    assert_eq!(code(&o), 0, "{o:?}");
    assert_eq!(json(&o)["result"]["removed"], false);
}

/// Starts an attempt as the app does and returns it with its password prompt.
fn start_attempt(d: &Daemon, name: &str) -> (fortino_core::client::Client, String, String) {
    use fortino_core::proto::{ChallengeKind, ConnectParams};
    d.rt.block_on(async {
        let c = fortino_core::client::Client::connect(&d.sock, "test")
            .await
            .unwrap();
        let p = c.profile_get(name).await.unwrap();
        let r = c
            .connect_profile(&ConnectParams {
                profile_id: p.id.clone(),
                revision: p.revision,
                request_key: uuid::Uuid::new_v4().to_string(),
                username: None,
            })
            .await
            .unwrap();
        for _ in 0..200 {
            let st = c.status().await.unwrap();
            if let Some(ch) = st.challenge.filter(|ch| ch.kind == ChallengeKind::Password) {
                return (c, r.attempt_id, ch.id);
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("no password prompt");
    })
}

#[test]
fn app_helper_answers_from_the_store_and_marks_a_refusal() {
    use fortino_core::proto::{ChallengeKind, State};
    let d = daemon();
    assert_eq!(
        code(&d.run("profile add GW --host tg2.example.org --username alice")),
        0
    );
    // Disabled: nothing is read.
    let (c, attempt, ch) = start_attempt(&d, "GW");
    let o = d.run(&format!(
        "--json password answer GW --attempt {attempt} --challenge {ch}"
    ));
    assert_eq!(json(&o)["result"]["reason"], "disabled", "{o:?}");
    d.rt.block_on(c.disconnect(&attempt)).unwrap();

    let o = d.sh("printf 'hunter2\\n' | \"$FORTINO_CLI\" password save GW --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    let (c, attempt, ch) = start_attempt(&d, "GW");
    let o = d.run(&format!(
        "--json password answer GW --attempt {attempt} --challenge {ch}"
    ));
    assert_eq!(code(&o), 0, "{o:?}");
    let r = &json(&o)["result"];
    assert_eq!(
        (r["answered"].as_bool(), r["reason"].as_str()),
        (Some(true), Some("accepted"))
    );
    // The app answers the code; the tunnel comes up.
    d.rt.block_on(async {
        let st = c.status().await.unwrap();
        let otp = st.challenge.unwrap();
        assert_eq!(otp.kind, ChallengeKind::Otp);
        c.respond(&attempt, &otp.id, "123456".into()).await.unwrap();
        for _ in 0..300 {
            if c.status().await.unwrap().state == State::Connected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("not connected");
    });
    assert_eq!(code(&d.run("disconnect")), 0);

    // A wrong saved password: answered, refused, marked; the next prompt isn't answered.
    let o = d.sh("printf 'stale\\n' | \"$FORTINO_CLI\" password save GW --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    let (_c, attempt, ch) = start_attempt(&d, "GW");
    let o = d.run(&format!(
        "--json password answer GW --attempt {attempt} --challenge {ch}"
    ));
    assert_eq!(json(&o)["result"]["reason"], "rejected", "{o:?}");
    assert_eq!(json(&o)["result"]["answered"], true);
    let (c, attempt, ch) = start_attempt(&d, "GW");
    let o = d.run(&format!(
        "--json password answer GW --attempt {attempt} --challenge {ch}"
    ));
    assert_eq!(json(&o)["result"]["answered"], false, "{o:?}");
    assert_eq!(json(&o)["result"]["reason"], "rejected");
    // A prompt that is no longer outstanding is left alone.
    let o = d.run(&format!(
        "--json password answer GW --attempt {attempt} --challenge other"
    ));
    assert_eq!(json(&o)["result"]["reason"], "stale", "{o:?}");
    d.rt.block_on(c.disconnect(&attempt)).unwrap();
}

#[test]
fn save_password_needs_the_profile_username() {
    let d = daemon();
    // Turning it on without a username is refused with a clear message.
    let o = d.run("profile add GW --host tg2.example.org --save-password");
    assert_eq!(code(&o), 2, "{o:?}");
    assert_eq!(code(&d.run("profile add GW --host tg2.example.org")), 0);
    let o = d.run("profile edit GW --save-password");
    assert_eq!(code(&o), 2, "{o:?}");
    assert!(
        stderr(&o).contains("needs the username you sign in with"),
        "{o:?}"
    );

    // Saving a password for a profile without one sets the username and the option.
    let o =
        d.sh("printf 'hunter2\\n' | \"$FORTINO_CLI\" password save GW --username alice --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    let v = json(&d.run("--json profile show GW"));
    assert_eq!(v["result"]["spec"]["usernameHint"], "alice");
    assert_eq!(v["result"]["spec"]["savePassword"], true);
    // Another account than the profile's is refused, and nothing changes.
    let o = d.sh("printf 'x\\n' | \"$FORTINO_CLI\" password save GW --username bob --stdin");
    assert_eq!(code(&o), 2, "{o:?}");
    assert!(stderr(&o).contains("signs in as alice"), "{o:?}");
    assert_eq!(creds(&d)[&profile_id(&d, "GW")]["password"], "hunter2");

    // Neither the username nor the password is asked: only the code.
    let otp = d.write("otp", "123456\n");
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" connect GW --otp-fd 4 4<{}",
        otp.display()
    ));
    assert_eq!(code(&o), 0, "{o:?}");
    assert!(stderr(&o).contains("Using the password saved in"), "{o:?}");
    assert_eq!(code(&d.run("disconnect")), 0);

    // A connected profile without a username can't take one now: nothing is saved.
    assert_eq!(code(&d.run("profile add Other --host tg2.example.org")), 0);
    let pw = d.write("pw", "hunter2\n");
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" connect Other --username bob --password-fd 3 --otp-fd 4 3<{} 4<{}",
        pw.display(),
        otp.display()
    ));
    assert_eq!(code(&o), 0, "{o:?}");
    let o =
        d.sh("printf 'hunter2\\n' | \"$FORTINO_CLI\" password save Other --username bob --stdin");
    assert_ne!(code(&o), 0, "{o:?}");
    assert!(stderr(&o).contains("disconnect first"), "{o:?}");
    assert!(creds(&d).get(profile_id(&d, "Other")).is_none());
    assert_eq!(code(&d.run("disconnect")), 0);

    // With a username but the option off, a connected profile keeps the password and says the
    // option waits for the disconnect.
    assert_eq!(
        code(&d.run("profile add Third --host tg2.example.org --username carol")),
        0
    );
    let o = d.sh(&format!(
        "\"$FORTINO_CLI\" connect Third --password-fd 3 --otp-fd 4 3<{} 4<{}",
        pw.display(),
        otp.display()
    ));
    assert_eq!(code(&o), 0, "{o:?}");
    let o = d.sh("printf 'hunter2\\n' | \"$FORTINO_CLI\" password save Third --stdin");
    assert_eq!(code(&o), 0, "{o:?}");
    assert!(stderr(&o).contains("Save password stays off"), "{o:?}");
    assert_eq!(creds(&d)[&profile_id(&d, "Third")]["username"], "carol");
    assert_eq!(code(&d.run("disconnect")), 0);
}
