//! `fortino`: the Fortino command-line interface.
//!
//! Talks to `fortinod` over its control socket. Prompts go to the controlling terminal, results to
//! stdout, diagnostics to stderr. Exit codes follow the design notes.

mod prompt;
mod render;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use fortino_config::{EmsServer, Host, IpPolicy, Profile, ProfileSpec};
use fortino_core::client::{Client, DEFAULT_SOCKET};
use fortino_core::proto::{
    ChallengeKind, ConnectParams, Empty, Event, ProfileImportParams, State, Status,
};
use fortino_core::{ErrorCode, ProtoError};

use crate::prompt::{SecretSource, TermGuard};

#[derive(Debug, Parser)]
#[command(name = "fortino", version, about = "Fortino VPN control")]
struct Cli {
    /// Daemon control socket.
    #[arg(long, global = true, env = "FORTINO_SOCKET", default_value = DEFAULT_SOCKET)]
    socket: PathBuf,
    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Manage VPN profiles.
    #[command(subcommand)]
    Profile(ProfileCmd),
    /// Connect and wait until connected or failed.
    Connect(ConnectArgs),
    /// Show connection status.
    Status {
        /// Keep printing status changes until interrupted.
        #[arg(long)]
        watch: bool,
    },
    /// Disconnect and wait until networking is restored.
    Disconnect,
    /// Show or change the daemon's log level (error, warn, info, debug, trace).
    LogLevel {
        /// New level; omit to show the current one.
        level: Option<String>,
    },
    /// Show this Mac's registration with an EMS server (`host[:port]`), from local records.
    EmsStatus {
        /// EMS server, `host` or `host:port` (default port 8013).
        server: String,
    },
}

#[derive(Debug, Subcommand)]
enum ProfileCmd {
    /// Create a profile (strict TLS, IPv4).
    Add(AddArgs),
    /// List profiles.
    List,
    /// Show one profile.
    Show {
        /// Profile name or ID.
        name: String,
    },
    /// Change a profile. The ID is kept when renaming.
    Edit(EditArgs),
    /// Delete a profile.
    Remove {
        /// Profile name or ID.
        name: String,
    },
    /// Import profiles from a FortiClient XML export.
    Import(ImportArgs),
}

#[derive(Debug, Args)]
struct AddArgs {
    /// Profile name.
    name: String,
    /// VPN gateway host name or IPv4 address.
    #[arg(long)]
    host: String,
    /// VPN gateway port.
    #[arg(long, default_value_t = fortino_config::DEFAULT_VPN_PORT)]
    port: u16,
    /// Realm.
    #[arg(long)]
    realm: Option<String>,
    /// EMS server as HOST[:PORT] (default port 8013).
    #[arg(long, value_name = "HOST[:PORT]")]
    ems_server: Option<String>,
    /// Username to use by default.
    #[arg(long)]
    username: Option<String>,
    /// Description.
    #[arg(long)]
    description: Option<String>,
    /// Route all IPv4 traffic through the VPN (IPv6 is not tunneled).
    #[arg(long)]
    full_ipv4: bool,
}

#[derive(Debug, Args)]
struct EditArgs {
    /// Profile name or ID.
    name: String,
    /// New name.
    #[arg(long)]
    rename: Option<String>,
    /// VPN gateway host.
    #[arg(long)]
    host: Option<String>,
    /// VPN gateway port.
    #[arg(long)]
    port: Option<u16>,
    /// Realm.
    #[arg(long, conflicts_with = "no_realm")]
    realm: Option<String>,
    /// Remove the realm.
    #[arg(long)]
    no_realm: bool,
    /// EMS server as HOST[:PORT].
    #[arg(long, value_name = "HOST[:PORT]", conflicts_with = "no_ems_server")]
    ems_server: Option<String>,
    /// Remove the EMS server.
    #[arg(long)]
    no_ems_server: bool,
    /// Default username.
    #[arg(long)]
    username: Option<String>,
    /// Description.
    #[arg(long)]
    description: Option<String>,
    /// Route all IPv4 traffic through the VPN.
    #[arg(long, conflicts_with = "split_ipv4")]
    full_ipv4: bool,
    /// Route only gateway-pushed networks through the VPN.
    #[arg(long)]
    split_ipv4: bool,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// FortiClient XML export.
    file: PathBuf,
    /// Only show what would be imported.
    #[arg(long)]
    dry_run: bool,
    /// Replace an existing profile with this name (repeatable).
    #[arg(long, value_name = "NAME")]
    replace: Vec<String>,
    /// Import only these entries (repeatable). Required with warnings in non-interactive use.
    #[arg(long, value_name = "NAME")]
    select: Vec<String>,
}

#[derive(Debug, Args)]
struct ConnectArgs {
    /// Profile name or ID.
    name: String,
    /// Username (otherwise the profile's default, otherwise prompt).
    #[arg(long)]
    username: Option<String>,
    /// Read the password from this inherited file descriptor (one line).
    #[arg(long, value_name = "N")]
    password_fd: Option<u32>,
    /// Read the one-time code from this inherited file descriptor (one line).
    #[arg(long, value_name = "N")]
    otp_fd: Option<u32>,
}

/// A command failure with its exit status.
#[derive(Debug)]
struct Failure(ProtoError);

impl From<ProtoError> for Failure {
    fn from(e: ProtoError) -> Self {
        Self(e)
    }
}

fn invalid(msg: impl Into<String>) -> Failure {
    Failure(ProtoError::new(ErrorCode::InvalidRequest, msg))
}

fn field_err(field: &str, code: &str) -> Failure {
    Failure(
        ProtoError::new(
            ErrorCode::InvalidProfile,
            format!("invalid {field}: {code}"),
        )
        .with_field(field),
    )
}

type CmdResult = Result<(), Failure>;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let json = cli.json;
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fortino: {e}");
            return ExitCode::FAILURE;
        }
    };
    let res = rt.block_on(run(cli));
    // A terminal prompt may still be blocked in a reader thread; don't wait for it.
    rt.shutdown_timeout(std::time::Duration::from_millis(50));
    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure(e)) => {
            if json {
                println!("{}", serde_json::json!({"v": 1, "error": e}));
            } else {
                eprintln!("fortino: {}", e.message);
                if let Some(f) = &e.field {
                    eprintln!("  field: {f}");
                }
            }
            ExitCode::from(u8::try_from(e.code.exit_code()).unwrap_or(1))
        }
    }
}

async fn run(cli: Cli) -> CmdResult {
    let json = cli.json;
    if let Cmd::Profile(ProfileCmd::Import(a)) = &cli.cmd
        && a.dry_run
    {
        let preview = read_import_preview(&a.file)?;
        if json {
            print_json(&preview);
        } else {
            render::import_preview(&preview);
        }
        return Ok(());
    }
    let mut client = Client::connect(&cli.socket, "fortino").await?;
    match cli.cmd {
        Cmd::Profile(p) => profile(&client, p, json).await,
        Cmd::Connect(a) => connect(&mut client, a, json).await,
        Cmd::Status { watch } => status(&mut client, watch, json).await,
        Cmd::Disconnect => disconnect(&mut client, json).await,
        Cmd::LogLevel { level } => log_level(&client, level.as_deref(), json).await,
        Cmd::EmsStatus { server } => ems_status(&client, &server, json).await,
    }
}

async fn ems_status(c: &Client, server: &str, json: bool) -> CmdResult {
    let server = parse_ems(server)?;
    let v: serde_json::Value = c
        .call(
            fortino_core::proto::method::EMS_STATUS,
            &serde_json::json!({"server": server.to_string()}),
        )
        .await?;
    if json {
        print_json(&v);
        return Ok(());
    }
    let state = v["state"].as_str().unwrap_or("unknown");
    println!("State:      {state}");
    if let Some(t) = v["lastKeepalive"].as_u64() {
        println!("Check-in:   unix {t}");
    }
    match v["rules"].as_bool() {
        Some(true) => println!("Rules:      received"),
        Some(false) if v["lastKeepalive"].is_u64() => println!(
            "Rules:      none; the EMS may not recognize this Mac or its policy may not accept it"
        ),
        Some(false) => println!("Rules:      none yet (no check-in since registering)"),
        None => {}
    }
    Ok(())
}

async fn log_level(c: &Client, level: Option<&str>, json: bool) -> CmdResult {
    use fortino_core::proto::{LogLevel, LogLevelResult, LogSetLevelParams, method};
    let r: LogLevelResult = match level {
        None => c.call(method::LOG_GET_LEVEL, &Empty {}).await?,
        Some(s) => {
            let level = LogLevel::parse(s).ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::InvalidRequest,
                    "level must be error, warn, info, debug or trace",
                )
            })?;
            c.call(method::LOG_SET_LEVEL, &LogSetLevelParams { level })
                .await?
        }
    };
    if json {
        print_json(&r);
    } else {
        println!("{}", r.level.map_or("custom (RUST_LOG)", LogLevel::as_str));
    }
    Ok(())
}

fn parse_host(s: &str) -> Result<Host, Failure> {
    s.parse().map_err(|c| field_err("host", c))
}

fn parse_ems(s: &str) -> Result<EmsServer, Failure> {
    s.parse().map_err(|c| field_err("ems-server", c))
}

fn print_json<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::json!({"v": 1, "result": v}));
}

async fn profile(c: &Client, cmd: ProfileCmd, json: bool) -> CmdResult {
    match cmd {
        ProfileCmd::Add(a) => {
            let mut spec = ProfileSpec::new(a.name, parse_host(&a.host)?);
            spec.endpoint.port = a.port;
            spec.endpoint.realm = a.realm;
            spec.endpoint.ems = a.ems_server.as_deref().map(parse_ems).transpose()?;
            spec.username_hint = a.username;
            spec.description = a.description;
            if a.full_ipv4 {
                spec.ip_policy = IpPolicy::FullIpv4;
            }
            let p = c.profile_create(spec).await?;
            if json {
                print_json(&p);
            } else {
                println!("Created profile {} ({})", p.spec.name, p.id);
                println!("Scope: {}", p.spec.ip_policy.describe());
            }
        }
        ProfileCmd::List => {
            let l = c.profile_list().await?;
            if json {
                print_json(&l);
            } else if l.profiles.is_empty() {
                println!("No profiles. Create one with: fortino profile add NAME --host HOST");
            } else {
                render::profile_table(&l.profiles);
            }
        }
        ProfileCmd::Show { name } => {
            let p = c.profile_get(&name).await?;
            if json {
                print_json(&p);
            } else {
                render::profile_details(&p);
            }
        }
        ProfileCmd::Edit(e) => {
            let p = c.profile_get(&e.name).await?;
            let spec = apply_edit(&p, e)?;
            let u = c.profile_update(p.id.clone(), p.revision, spec).await?;
            if json {
                print_json(&u);
            } else {
                println!("Updated profile {} (revision {})", u.spec.name, u.revision);
            }
        }
        ProfileCmd::Remove { name } => {
            let p = c.profile_get(&name).await?;
            c.profile_delete(p.id.clone(), p.revision).await?;
            if json {
                print_json(&serde_json::json!({"removed": p.id}));
            } else {
                println!("Removed profile {}", p.spec.name);
            }
        }
        ProfileCmd::Import(a) => import(c, a, json).await?,
    }
    Ok(())
}

fn apply_edit(p: &Profile, e: EditArgs) -> Result<ProfileSpec, Failure> {
    let mut s = p.spec.clone();
    if let Some(n) = e.rename {
        s.name = n;
    }
    if let Some(h) = e.host {
        let h = parse_host(&h)?;
        if h != s.endpoint.host && e.ems_server.is_none() && s.endpoint.ems.is_some() {
            eprintln!(
                "note: the EMS server is kept ({}); change it with --ems-server if the new gateway uses another",
                s.endpoint
                    .ems
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            );
        }
        s.endpoint.host = h;
    }
    if let Some(port) = e.port {
        s.endpoint.port = port;
    }
    if e.no_realm {
        s.endpoint.realm = None;
    } else if let Some(r) = e.realm {
        s.endpoint.realm = Some(r);
    }
    if e.no_ems_server {
        s.endpoint.ems = None;
    } else if let Some(x) = e.ems_server {
        s.endpoint.ems = Some(parse_ems(&x)?);
    }
    if let Some(u) = e.username {
        s.username_hint = Some(u);
    }
    if let Some(d) = e.description {
        s.description = Some(d);
    }
    if e.full_ipv4 {
        s.ip_policy = IpPolicy::FullIpv4;
    }
    if e.split_ipv4 {
        s.ip_policy = IpPolicy::SplitIpv4;
    }
    Ok(s)
}

fn read_import_preview(file: &std::path::Path) -> Result<fortino_config::import::Preview, Failure> {
    let bytes =
        std::fs::read(file).map_err(|e| invalid(format!("cannot read {}: {e}", file.display())))?;
    fortino_config::import::parse(&bytes)
        .map_err(|e| Failure(ProtoError::new(ErrorCode::InvalidProfile, e.to_string())))
}

async fn import(c: &Client, a: ImportArgs, json: bool) -> CmdResult {
    let preview = read_import_preview(&a.file)?;
    let mut entries: Vec<_> = preview.eligible().cloned().collect();
    if !a.select.is_empty() {
        let keys: Vec<String> = a
            .select
            .iter()
            .filter_map(|n| fortino_config::normalize_name(n).ok())
            .map(|n| fortino_config::name_key(&n))
            .collect();
        entries.retain(|e| keys.contains(&fortino_config::name_key(&e.spec.name)));
    }
    if !json {
        render::import_preview(&preview);
    }
    if entries.is_empty() {
        return Err(invalid("nothing to import"));
    }
    let has_warnings = entries.iter().any(|e| !e.warnings.is_empty());
    if has_warnings && a.select.is_empty() && !prompt::confirm("Import the eligible profiles?") {
        return Err(Failure(ProtoError::new(
            ErrorCode::InteractionRequired,
            "the preview has warnings; confirm interactively or name entries with --select",
        )));
    }
    let rev = c.profile_list().await?.store_revision;
    let r = c
        .profile_import(&ProfileImportParams {
            store_revision: rev,
            entries: entries.into_iter().map(|e| e.spec).collect(),
            replace: a.replace,
        })
        .await?;
    if json {
        print_json(&r);
    } else {
        for x in &r.results {
            println!(
                "{:<10} {}",
                format!("{:?}", x.action).to_lowercase(),
                x.name
            );
        }
    }
    Ok(())
}

/// Build identifier stamped by `apps/macos/scripts/bundle.sh`; none in development builds.
const BUILD_ID: Option<&str> = option_env!("FORTINO_BUILD_ID");

/// A note when the daemon runs a different build than this tool, typically a service left
/// running from before an app update.
fn build_mismatch(daemon: Option<&str>) -> Option<String> {
    let mine = BUILD_ID?;
    match daemon {
        Some(d) if d == mine => None,
        Some(d) => Some(format!(
            "the VPN service runs build {d}, this tool is build {mine}; \
             open Fortino to restart the service"
        )),
        None => Some(
            "the VPN service predates this build; open Fortino to restart it, or run \
             `sudo launchctl kickstart -k system/org.fortino.fortinod` while disconnected"
                .into(),
        ),
    }
}

async fn status(c: &mut Client, watch: bool, json: bool) -> CmdResult {
    if !json {
        if let Some(note) = build_mismatch(c.hello.build.as_deref()) {
            eprintln!("fortino: note: {note}");
        }
    }
    let show = |s: &Status| {
        if json {
            println!("{}", serde_json::json!({"v": 1, "status": s}));
        } else {
            render::status(s);
        }
    };
    if !watch {
        show(&c.status().await?);
        return Ok(());
    }
    let (st, mut rx) = c.subscribe().await?;
    show(&st);
    loop {
        tokio::select! {
            ev = rx.recv() => match ev {
                Some(Event::Status { status }) => {
                    if !json {
                        println!();
                    }
                    show(&status);
                }
                Some(Event::ResyncRequired) => show(&c.status().await?),
                None => {
                    return Err(Failure(ProtoError::new(
                        ErrorCode::ServiceUnavailable,
                        "lost connection to the VPN service",
                    )));
                }
            },
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

/// Waits until `attempt` reaches idle or recovery-required. Returns the final status.
async fn wait_finished(
    c: &Client,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    attempt: &str,
) -> Result<Status, Failure> {
    let done = |s: &Status| {
        matches!(s.state, State::Idle | State::RecoveryRequired)
            && s.attempt_id.as_deref().is_none_or(|a| a == attempt)
    };
    let st = c.status().await?;
    if done(&st) {
        return Ok(st);
    }
    loop {
        let st = match rx.recv().await {
            Some(Event::Status { status }) => *status,
            Some(Event::ResyncRequired) => c.status().await?,
            None => {
                return Err(Failure(ProtoError::new(
                    ErrorCode::ServiceUnavailable,
                    "lost connection to the VPN service",
                )));
            }
        };
        if done(&st) {
            return Ok(st);
        }
    }
}

fn result_of(st: &Status, attempt: &str) -> Result<(), Failure> {
    if st.state == State::RecoveryRequired {
        return Err(Failure(ProtoError::new(
            ErrorCode::RecoveryRequired,
            "network cleanup failed; the daemon will retry before the next connection",
        )));
    }
    match &st.last_result {
        Some(r) if r.attempt_id == attempt => match r.code {
            None => Ok(()),
            Some(code) => Err(Failure(ProtoError::new(code, r.message.clone()))),
        },
        _ => Ok(()),
    }
}

async fn connect(c: &mut Client, a: ConnectArgs, json: bool) -> CmdResult {
    let mut secrets = SecretSource::new(a.password_fd, a.otp_fd)?;
    let _term = TermGuard::save();
    let (_, mut rx) = c.subscribe().await?;
    let p = c.profile_get(&a.name).await?;
    if !json {
        eprintln!(
            "Connecting to {} ({}:{}), scope: {}",
            p.spec.name,
            p.spec.endpoint.host,
            p.spec.endpoint.port,
            p.spec.ip_policy.describe()
        );
    }
    let r = c
        .connect_profile(&ConnectParams {
            profile_id: p.id.clone(),
            revision: p.revision,
            request_key: uuid::Uuid::new_v4().to_string(),
            username: a.username.clone(),
        })
        .await?;
    let attempt = r.attempt_id.clone();
    let mut answered: Option<String> = None;
    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());

    loop {
        let st = tokio::select! {
            ev = rx.recv() => match ev {
                Some(Event::Status { status }) => *status,
                Some(Event::ResyncRequired) => c.status().await?,
                None => return Err(Failure(ProtoError::new(
                    ErrorCode::ServiceUnavailable,
                    "lost connection to the VPN service",
                ))),
            },
            _ = &mut ctrl_c => {
                eprintln!("\nCancelling…");
                c.disconnect(&attempt).await?;
                let st = wait_finished(c, &mut rx, &attempt).await?;
                result_of(&st, &attempt)?;
                return Err(Failure(ProtoError::new(ErrorCode::Cancelled, "cancelled")));
            }
        };
        if st.attempt_id.as_deref() != Some(attempt.as_str()) {
            continue;
        }
        match st.state {
            State::Connected => {
                if json {
                    println!("{}", serde_json::json!({"v": 1, "status": st}));
                } else {
                    println!(
                        "Connected: {} via {}",
                        st.assigned_ip.as_deref().unwrap_or("?"),
                        st.interface.as_deref().unwrap_or("?")
                    );
                }
                return Ok(());
            }
            State::Idle | State::RecoveryRequired => {
                result_of(&st, &attempt)?;
                return Err(Failure(ProtoError::new(
                    ErrorCode::BackendFailure,
                    "connection ended",
                )));
            }
            _ => {}
        }
        let Some(ch) = st.challenge else { continue };
        if answered.as_deref() == Some(ch.id.as_str()) {
            continue;
        }
        answered = Some(ch.id.clone());
        let value = match ch.kind {
            ChallengeKind::Username => a.username.clone().map(Ok),
            ChallengeKind::Password => secrets.password(),
            ChallengeKind::Otp => secrets.otp(),
        };
        let value = match value {
            Some(v) => v?,
            None => {
                // Prompt on the terminal, still honoring Ctrl-C and daemon-side changes.
                let kind = ch.kind;
                let text = ch.prompt.clone();
                let prompt = tokio::task::spawn_blocking(move || prompt::ask(kind, &text));
                tokio::select! {
                    v = prompt => match v {
                        Ok(Some(v)) => v,
                        _ => {
                            c.disconnect(&attempt).await?;
                            let _ = wait_finished(c, &mut rx, &attempt).await;
                            return Err(Failure(ProtoError::new(
                                ErrorCode::InteractionRequired,
                                format!("{} required but no terminal is available", kind_name(kind)),
                            )));
                        }
                    },
                    _ = &mut ctrl_c => {
                        eprintln!("\nCancelling…");
                        c.disconnect(&attempt).await?;
                        let st = wait_finished(c, &mut rx, &attempt).await?;
                        result_of(&st, &attempt)?;
                        return Err(Failure(ProtoError::new(ErrorCode::Cancelled, "cancelled")));
                    }
                }
            }
        };
        match c.respond(&attempt, &ch.id, value).await {
            Ok(()) => {}
            // Expired or answered elsewhere (e.g. from the desktop app): keep following.
            Err(e) if e.code == ErrorCode::StaleChallenge => {}
            Err(e) => return Err(e.into()),
        }
    }
}

fn kind_name(k: ChallengeKind) -> &'static str {
    match k {
        ChallengeKind::Username => "username",
        ChallengeKind::Password => "password",
        ChallengeKind::Otp => "one-time code",
    }
}

async fn disconnect(c: &mut Client, json: bool) -> CmdResult {
    let (st, mut rx) = c.subscribe().await?;
    let attempt = match (&st.attempt_id, st.state) {
        (Some(a), s) if s.is_active() => a.clone(),
        (_, State::InUse) => {
            return Err(Failure(ProtoError::new(
                ErrorCode::PermissionDenied,
                "VPN in use by another user",
            )));
        }
        (_, State::RecoveryRequired) => {
            return Err(Failure(ProtoError::new(
                ErrorCode::RecoveryRequired,
                "network cleanup from an earlier session failed",
            )));
        }
        _ => {
            if json {
                print_json(&serde_json::json!({"state": "idle"}));
            } else {
                println!("Not connected.");
            }
            return Ok(());
        }
    };
    c.disconnect(&attempt).await?;
    let st = wait_finished(c, &mut rx, &attempt).await?;
    if st.state == State::RecoveryRequired {
        return result_of(&st, &attempt);
    }
    if json {
        print_json(&serde_json::json!({"state": "idle", "attemptId": attempt}));
    } else {
        println!("Disconnected.");
    }
    Ok(())
}
