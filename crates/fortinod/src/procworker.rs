//! Supervises one external worker process per attempt over a private socket pair.
//!
//! The worker executable has a fixed path: the daemon itself (`fortinod --worker`) or an
//! administrator-configured binary. It gets a minimal environment, fixed arguments, `/dev/null` for output, and its end of the socket pair as
//! standard input. It runs in its own process group so its PPP child is stopped with it.
//! See [`fortino_core::worker_wire`].

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

use fortino_core::ErrorCode;
use fortino_core::framing::{FrameReader, write_frame};
use fortino_core::worker::{
    Termination, WorkerCommand, WorkerConfig, WorkerEvent, WorkerFactory, WorkerHandle,
};
use fortino_core::worker_wire::{DaemonMsg, MAX_WORKER_FRAME, WORKER_PROTOCOL_VERSION, WorkerMsg};

/// Grace period for the worker to exit after `stop` before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(5);

/// Starts worker processes.
#[derive(Debug, Clone)]
pub struct ProcessWorker {
    /// Fixed worker executable.
    pub path: PathBuf,
    /// Fixed arguments (`--worker` when the daemon runs itself as the worker).
    pub args: Vec<String>,
    /// Directory with `<trust-id>.pem` CA bundles.
    pub ca_dir: PathBuf,
    /// Gateway certificate pins the administrator accepted in the app, or `None`.
    pub gateway_pins: Option<GatewayPins>,
    /// Extra environment (tests only; production passes none).
    pub env: Vec<(String, String)>,
}

/// Prepares the daemon's own executable for use as the worker (`fortinod --worker`).
///
/// An app installed by dragging is owned by the user, so its `Contents/MacOS/fortinod` could be
/// replaced while the service runs. Unless the running executable is already root-owned and not
/// writable by others, it is copied into `dir` (root-owned, 0755) and, when the build knows its
/// signing team (`FORTINO_TEAM_ID`), the copy must pass `codesign --verify` for that team before
/// it is used. launchd checked the original's signature when it started the service.
pub fn stage_worker(dir: &std::path::Path, team: Option<&str>) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("own executable: {e}"))?;
    if check_executable(&exe).is_ok() {
        return Ok(exe);
    }
    stage_copy(&exe, dir, team)
}

fn stage_copy(
    exe: &std::path::Path,
    dir: &std::path::Path,
    team: Option<&str>,
) -> Result<PathBuf, String> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    let err = |what: &str, e: std::io::Error| format!("worker copy, {what}: {e}");
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)
        .map_err(|e| err("directory", e))?;
    let dst = dir.join("fortinod");
    let tmp = dir.join(".fortinod.new");
    let _ = std::fs::remove_file(&tmp);
    // A new file written by this process, not `fs::copy`: on macOS that clones the file and,
    // run as root, keeps the original (user) owner.
    let bytes = std::fs::read(exe).map_err(|e| err("read", e))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(&tmp)
        .map_err(|e| err("create", e))?;
    f.write_all(&bytes).map_err(|e| err("write", e))?;
    f.sync_all().map_err(|e| err("sync", e))?;
    drop(f);
    if let Some(team) = team {
        verify_signature(&tmp, team)?;
    }
    std::fs::rename(&tmp, &dst).map_err(|e| err("rename", e))?;
    // Root-owned when run as root (the service); tests run unprivileged.
    if nix::unistd::geteuid().is_root() {
        check_executable(&dst)?;
    }
    Ok(dst)
}

/// Requires `path` to carry a valid Developer ID signature from `team` as `org.fortino.fortinod`.
fn verify_signature(path: &std::path::Path, team: &str) -> Result<(), String> {
    if team.len() != 10 || !team.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err("invalid FORTINO_TEAM_ID in this build".into());
    }
    // `-R` takes the requirement as text prefixed with `=`.
    let req = format!(
        "=identifier \"org.fortino.fortinod\" and anchor apple generic \
         and certificate leaf[subject.OU] = \"{team}\""
    );
    let ok = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict", "-R"])
        .arg(&req)
        .arg(path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err("the daemon's executable is not signed by this build's team; reinstall Fortino".into())
    }
}

/// The system CA bundle, used for the default trust when none is provisioned.
pub const SYSTEM_CA_BUNDLE: &str = "/etc/ssl/cert.pem";

/// The trust file for `trust_id`: `<ca_dir>/<trust_id>.pem`, or for the default `system` trust
/// the system CA bundle when the administrator has not provisioned one.
pub fn ca_file_for(ca_dir: &std::path::Path, trust_id: &str) -> PathBuf {
    let f = ca_dir.join(format!("{trust_id}.pem"));
    if trust_id == fortino_config::DEFAULT_TRUST_ID && !f.exists() {
        return PathBuf::from(SYSTEM_CA_BUNDLE);
    }
    f
}

/// Root-created gateway pin markers: one file per gateway (`host:port`), named by its SHA-256
/// and holding `sha256:<hex>`, written by the app after the administrator accepted a gateway
/// certificate macOS doesn't trust (typically a gateway reached by an address its certificate
/// doesn't name). The worker then trusts exactly that leaf certificate for that gateway.
#[derive(Debug, Clone)]
pub struct GatewayPins {
    /// Marker directory.
    pub dir: PathBuf,
    /// Required owner of the directory and markers (root in production).
    pub owner: u32,
}

/// Default gateway pin directory.
pub const GATEWAY_PIN_DIR: &str = "/private/var/db/fortino-gateway-pins";

impl GatewayPins {
    /// The protected pin marker for `host:port`, if one holds a valid pin.
    pub fn marker_for(&self, host: &str, port: u16) -> Option<PathBuf> {
        let key = format!("{}:{port}", host.to_ascii_lowercase());
        let (path, content) = fortino_tls::markers::read_protected(&self.dir, &key, self.owner)?;
        if fortino_tls::markers::gateway_pin(&content).is_none() {
            tracing::warn!("gateway pin marker does not hold a SHA-256 pin; ignoring it");
            return None;
        }
        Some(path)
    }
}

/// The worker's trust file: an accepted gateway pin when the profile uses the default trust,
/// otherwise [`ca_file_for`]. An administrator-provisioned trust ID always wins.
pub fn trust_file_for(
    ca_dir: &std::path::Path,
    pins: Option<&GatewayPins>,
    trust_id: &str,
    host: &str,
    port: u16,
) -> PathBuf {
    if trust_id == fortino_config::DEFAULT_TRUST_ID
        && let Some(marker) = pins.and_then(|p| p.marker_for(host, port))
    {
        tracing::info!("using the gateway certificate pin accepted in the app");
        return marker;
    }
    ca_file_for(ca_dir, trust_id)
}

/// Checks that the worker executable is a root-owned regular file not writable by others.
pub fn check_executable(path: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.is_file() {
        return Err(format!("{} is not a file", path.display()));
    }
    if m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err(format!(
            "{} must be owned by root and not writable by group or others",
            path.display()
        ));
    }
    Ok(())
}

impl WorkerFactory for ProcessWorker {
    fn spawn(&self, cfg: WorkerConfig) -> WorkerHandle {
        let (ev_tx, ev_rx) = mpsc::channel(16);
        let (cmd_tx, cmd_rx) = mpsc::channel(4);
        let me = self.clone();
        tokio::spawn(async move {
            let t = me.run(cfg, &ev_tx, cmd_rx).await;
            let _ = ev_tx.send(WorkerEvent::Terminated(t)).await;
        });
        WorkerHandle {
            events: ev_rx,
            commands: cmd_tx,
        }
    }
}

fn backend(msg: &str) -> Termination {
    Termination {
        code: Some(ErrorCode::BackendFailure),
        message: msg.into(),
    }
}

async fn send(w: &mut tokio::net::unix::OwnedWriteHalf, m: &DaemonMsg) -> bool {
    let Ok(b) = serde_json::to_vec(m).map(zeroize::Zeroizing::new) else {
        return false;
    };
    write_frame(w, &b, MAX_WORKER_FRAME).await.is_ok()
}

/// Stops the worker and everything in its process group (`pgid`, the worker's PID captured at
/// spawn), then reaps it.
///
/// While any member of the group is alive its ID cannot be reused, so signalling the group
/// after the leader exited only reaches leftovers such as the PPP child.
async fn reap(child: &mut Child, pgid: Option<Pid>, graceful: bool) {
    if graceful && tokio::time::timeout(STOP_GRACE, child.wait()).await.is_ok() {
        if let Some(g) = pgid {
            let _ = killpg(g, Signal::SIGKILL);
        }
        return;
    }
    if let Some(g) = pgid {
        let _ = killpg(g, Signal::SIGTERM);
        if tokio::time::timeout(Duration::from_secs(1), child.wait())
            .await
            .is_err()
        {
            let _ = killpg(g, Signal::SIGKILL);
        }
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

impl ProcessWorker {
    async fn run(
        &self,
        cfg: WorkerConfig,
        ev: &mpsc::Sender<WorkerEvent>,
        mut cmd: mpsc::Receiver<WorkerCommand>,
    ) -> Termination {
        let (ours, theirs) = match std::os::unix::net::UnixStream::pair() {
            Ok(p) => p,
            Err(_) => return backend("could not create the worker channel"),
        };
        let mut command = Command::new(&self.path);
        command
            .args(&self.args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .envs(self.env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let mut child = match command.spawn() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, path = %self.path.display(), "worker failed to start");
                return backend("tunnel worker could not start");
            }
        };
        drop(command);
        let pgid = child
            .id()
            .and_then(|p| i32::try_from(p).ok())
            .map(Pid::from_raw);
        let stream = match ours
            .set_nonblocking(true)
            .and_then(|()| UnixStream::from_std(ours))
        {
            Ok(s) => s,
            Err(_) => {
                reap(&mut child, pgid, false).await;
                return backend("could not open the worker channel");
            }
        };
        let (mut rd, mut wr) = stream.into_split();
        let host = cfg.endpoint.host.to_string();
        let ca_file = trust_file_for(
            &self.ca_dir,
            self.gateway_pins.as_ref(),
            &cfg.trust_id,
            &host,
            cfg.endpoint.port,
        );
        let start = DaemonMsg::Start {
            v: WORKER_PROTOCOL_VERSION,
            attempt: cfg.attempt_id.clone(),
            host,
            port: cfg.endpoint.port,
            realm: cfg.endpoint.realm.clone(),
            username: cfg.username.clone(),
            ca_file: ca_file.display().to_string(),
            ems_serial: cfg.ems.as_ref().map(|e| e.serial.clone()),
            ems_tenant: cfg.ems.as_ref().map(|e| e.tenant.clone()),
            fct_uid: cfg.fct_uid.clone(),
        };
        if !send(&mut wr, &start).await {
            reap(&mut child, pgid, false).await;
            return backend("tunnel worker exited during start");
        }
        drop(start);

        let mut last_seq = 0u64;
        let mut stopping = false;
        let mut stop_deadline: Option<tokio::time::Instant> = None;
        let mut timed_out = false;
        let mut frames = FrameReader::new(MAX_WORKER_FRAME);
        let result = loop {
            let deadline = async {
                match stop_deadline {
                    Some(d) => tokio::time::sleep_until(d).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                c = cmd.recv(), if !stopping => {
                    let msg = match c {
                        Some(WorkerCommand::Respond { challenge_id, value }) => DaemonMsg::Respond {
                            v: WORKER_PROTOCOL_VERSION,
                            attempt: cfg.attempt_id.clone(),
                            challenge: challenge_id,
                            value: value.expose().to_owned(),
                        },
                        // `None`: the session dropped us; treat as a stop.
                        Some(WorkerCommand::Stop) | None => {
                            stopping = true;
                            stop_deadline = Some(tokio::time::Instant::now() + STOP_GRACE);
                            DaemonMsg::Stop {
                                v: WORKER_PROTOCOL_VERSION,
                                attempt: cfg.attempt_id.clone(),
                            }
                        }
                    };
                    if !send(&mut wr, &msg).await && !stopping {
                        break backend("tunnel worker channel closed");
                    }
                }
                f = frames.next(&mut rd) => {
                    let frame = match f {
                        Ok(Some(f)) => f,
                        // Worker-side EOF: the session reconciles network state.
                        Ok(None) => break if stopping {
                            Termination { code: None, message: "stopped".into() }
                        } else {
                            backend("tunnel worker exited unexpectedly")
                        },
                        Err(_) => break backend("tunnel worker sent an invalid frame"),
                    };
                    let event = serde_json::from_slice::<WorkerMsg>(&frame)
                        .map_err(|_| fortino_core::worker_wire::Violation("malformed message"))
                        .and_then(|m| m.into_event(&cfg.attempt_id, &mut last_seq));
                    match event {
                        Ok(WorkerEvent::Terminated(t)) => break t,
                        Ok(e) => {
                            if ev.send(e).await.is_err() {
                                stopping = true;
                                stop_deadline = Some(tokio::time::Instant::now() + STOP_GRACE);
                                let _ = send(&mut wr, &DaemonMsg::Stop {
                                    v: WORKER_PROTOCOL_VERSION,
                                    attempt: cfg.attempt_id.clone(),
                                }).await;
                            }
                        }
                        Err(v) => {
                            tracing::warn!(violation = %v, "worker protocol violation");
                            break backend("tunnel worker protocol violation");
                        }
                    }
                }
                () = deadline => {
                    timed_out = true;
                    break backend("tunnel worker did not stop in time");
                }
            }
        };
        drop(wr);
        drop(rd);
        // A worker that already let its stop grace pass gets no second one: it is signalled
        // now, well before the session's own shutdown deadline frees the VPN for a new attempt.
        let graceful = !timed_out && (result.code.is_none() || stopping);
        reap(&mut child, pgid, graceful).await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_copy_is_private_and_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::write(&src, b"#!/bin/sh\n").unwrap();
        let out = stage_copy(&src, &dir.path().join("libexec"), None).unwrap();
        assert_eq!(out, dir.path().join("libexec/fortinod"));
        let m = std::fs::metadata(&out).unwrap();
        let mode = m.permissions().mode();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            m.uid(),
            nix::unistd::geteuid().as_raw(),
            "owned by the daemon's user"
        );
        assert_eq!(mode & 0o777, 0o755);
        // A team requirement an unsigned file cannot meet.
        assert!(stage_copy(&src, &dir.path().join("x"), Some("ABCDE12345")).is_err());
        assert!(stage_copy(&src, &dir.path().join("y"), Some("bad team")).is_err());
    }

    #[test]
    fn system_trust_falls_back_to_the_system_bundle() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            ca_file_for(dir.path(), "system"),
            PathBuf::from(SYSTEM_CA_BUNDLE)
        );
        std::fs::write(dir.path().join("system.pem"), "x").unwrap();
        assert_eq!(
            ca_file_for(dir.path(), "system"),
            dir.path().join("system.pem")
        );
        assert_eq!(ca_file_for(dir.path(), "tg2"), dir.path().join("tg2.pem"));
    }

    #[test]
    fn an_accepted_gateway_pin_replaces_the_default_trust_only() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        let ca = d.path().join("ca");
        let dir = d.path().join("pins");
        std::fs::create_dir_all(&ca).unwrap();
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let pins = GatewayPins {
            owner: std::fs::metadata(&dir).unwrap().uid(),
            dir: dir.clone(),
        };
        let marker = dir.join(fortino_tls::markers::marker_name("vpn.example.com:443"));
        let sys = PathBuf::from(SYSTEM_CA_BUNDLE);

        let f = |trust: &str, host: &str, port| trust_file_for(&ca, Some(&pins), trust, host, port);
        assert_eq!(f("system", "vpn.example.com", 443), sys);

        std::fs::write(&marker, format!("sha256:{}\n", "ab".repeat(32))).unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(f("system", "vpn.example.com", 443), marker);
        assert_eq!(f("system", "VPN.example.com", 443), marker);
        assert_eq!(f("system", "vpn.example.com", 8443), sys);
        assert_eq!(f("tg2", "vpn.example.com", 443), ca.join("tg2.pem"));
        assert_eq!(
            trust_file_for(&ca, None, "system", "vpn.example.com", 443),
            sys
        );

        std::fs::write(&marker, "not a pin").unwrap();
        assert_eq!(f("system", "vpn.example.com", 443), sys);
    }
}
