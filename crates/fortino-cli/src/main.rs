//! `fortino`: the Fortino command-line interface.
//!
//! Talks to `fortinod` over its control socket. Prompts go to the controlling terminal, results to
//! stdout, diagnostics to stderr.

mod credstore;
mod prompt;
mod render;
mod saved;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use fortino_config::{DnsMode, EmsServer, Host, IpPolicy, Profile, ProfileSpec};
use fortino_core::client::{Client, DEFAULT_SOCKET};
use fortino_core::proto::{
    ChallengeKind, ConnectParams, Empty, Event, ProfileImportParams, State, Status,
};
use fortino_core::{ErrorCode, ProtoError};

use crate::prompt::{SecretSource, TermGuard};
use crate::saved::{AfterConnect, Keeper};

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
    /// Manage a profile's saved password (kept in your login keychain, never by the service).
    #[command(subcommand)]
    Password(PasswordCmd),
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
    /// Register this Mac with an EMS server now, without connecting. Creates a device record
    /// on the EMS. The server must be approved on this Mac (the app's EMS Setup does that).
    EmsRegister {
        /// EMS server, `host` or `host:port` (default port 8013).
        server: String,
    },
    /// Manage the connection key an EMS asks for when registering (kept by the service, never
    /// shown again).
    #[command(subcommand)]
    EmsKey(EmsKeyCmd),
    /// Leave an EMS server no profile uses any more: remove this Mac's device record on the
    /// EMS, and forget the server's registration, connection key and approval on this Mac.
    EmsLeave {
        /// EMS server, `host` or `host:port` (default port 8013).
        server: String,
    },
}

#[derive(Debug, Subcommand)]
enum EmsKeyCmd {
    /// Save the connection key your IT administrator gave you for an EMS server. The next
    /// registration sends it.
    Set {
        /// EMS server, `host` or `host:port` (default port 8013).
        server: String,
        /// Read the key from one line of standard input instead of the terminal.
        #[arg(long)]
        stdin: bool,
    },
    /// Remove the saved connection key for an EMS server.
    Forget {
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
    /// Export profiles as a FortiClient XML configuration (no usernames or passwords).
    Export(ExportArgs),
}

#[derive(Debug, Subcommand)]
enum PasswordCmd {
    /// Save a profile's password and turn on Save password for it.
    Save {
        /// Profile name or ID.
        name: String,
        /// The username you sign in with, for a profile that has none yet (it becomes the
        /// profile's username). Otherwise it must match the profile's.
        #[arg(long)]
        username: Option<String>,
        /// Read the password from one line of standard input instead of the terminal.
        #[arg(long)]
        stdin: bool,
    },
    /// Remove a profile's saved password. Save password stays as it is.
    Forget {
        /// Profile name or ID.
        name: String,
    },
    /// Show whether a profile has a saved password (never the password itself).
    Status {
        /// Profile name or ID.
        name: String,
    },
    /// Answer an outstanding password prompt with the saved password (used by the app).
    #[command(hide = true)]
    Answer {
        /// Profile name or ID.
        name: String,
        /// The attempt that asks.
        #[arg(long)]
        attempt: String,
        /// The password prompt's ID.
        #[arg(long)]
        challenge: String,
        /// Account (otherwise the profile's default username).
        #[arg(long)]
        username: Option<String>,
    },
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
    /// Which DNS answers while connected.
    #[arg(long, value_enum)]
    dns: Option<DnsArg>,
    /// Save the password in your login keychain after the first successful connection
    /// (needs --username).
    #[arg(long, requires = "username")]
    save_password: bool,
}

/// `--dns`: which resolvers answer while connected.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum DnsArg {
    /// As the gateway sets it (default): its DNS for the domains it names.
    Gateway,
    /// This Mac's own DNS for every name; the gateway's DNS is not applied.
    Local,
}

impl From<DnsArg> for DnsMode {
    fn from(a: DnsArg) -> Self {
        match a {
            DnsArg::Gateway => DnsMode::Gateway,
            DnsArg::Local => DnsMode::Local,
        }
    }
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
    /// Which DNS answers while connected.
    #[arg(long, value_enum)]
    dns: Option<DnsArg>,
    /// Save the password in your login keychain after the next successful connection (the
    /// profile needs a username).
    #[arg(long, conflicts_with = "no_save_password")]
    save_password: bool,
    /// Stop saving the password and remove the saved one.
    #[arg(long)]
    no_save_password: bool,
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
struct ExportArgs {
    /// Profiles to export by name or ID (default: all).
    names: Vec<String>,
    /// Write to this file instead of standard output.
    #[arg(short, long)]
    output: Option<PathBuf>,
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
                if e.code == ErrorCode::TrustFailure && e.message.starts_with("gateway certificate")
                {
                    eprintln!(
                        "  If you expected this certificate (for example, a gateway reached by an \
                         address its certificate doesn't name), review and trust it in Fortino.app."
                    );
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
        Cmd::Status { watch } => status(&mut client, &cli.socket, watch, json).await,
        Cmd::Disconnect => disconnect(&mut client, json).await,
        Cmd::Password(p) => password(&mut client, p, json).await,
        Cmd::LogLevel { level } => log_level(&client, level.as_deref(), json).await,
        Cmd::EmsStatus { server } => ems_status(&client, &server, json).await,
        Cmd::EmsRegister { server } => ems_register(&client, &server, json).await,
        Cmd::EmsKey(k) => ems_key(&client, k, json).await,
        Cmd::EmsLeave { server } => ems_leave(&client, &server, json).await,
    }
}

async fn ems_leave(c: &Client, server: &str, json: bool) -> CmdResult {
    let server = parse_ems(server)?;
    let v: serde_json::Value = c
        .call(
            fortino_core::proto::method::EMS_LEAVE,
            &serde_json::json!({"server": server.to_string()}),
        )
        .await?;
    if json {
        print_json(&v);
        return Ok(());
    }
    if v["deregistered"].as_bool() == Some(true) {
        println!("The EMS removed this Mac's device record.");
    } else if let Some(k) = v["kept"].as_str() {
        println!(
            "The EMS kept this Mac's device record ({k}); ask your IT administrator to delete it if needed."
        );
    }
    println!("Fortino forgot {server} on this Mac (registration, connection key and approval).");
    Ok(())
}

async fn ems_key(c: &Client, cmd: EmsKeyCmd, json: bool) -> CmdResult {
    let (server, key) = match cmd {
        EmsKeyCmd::Set { server, stdin } => {
            let server = parse_ems(&server)?;
            let key = if stdin {
                read_stdin_line()?
            } else {
                zeroize::Zeroizing::new(
                    ask_here(
                        ChallengeKind::Password,
                        &format!("Connection key for {server}"),
                    )
                    .await?
                    .ok_or_else(|| {
                        Failure(ProtoError::new(
                            ErrorCode::InteractionRequired,
                            "connection key required but no terminal is available; use --stdin",
                        ))
                    })?,
                )
            };
            (server, Some(key))
        }
        EmsKeyCmd::Forget { server } => (parse_ems(&server)?, None),
    };
    let params = match &key {
        Some(k) => serde_json::json!({"server": server.to_string(), "key": k.as_str()}),
        None => serde_json::json!({"server": server.to_string()}),
    };
    let v: serde_json::Value = c
        .call(fortino_core::proto::method::EMS_SET_KEY, &params)
        .await?;
    if json {
        print_json(&v);
        return Ok(());
    }
    let status = v["status"].as_str().unwrap_or("unknown");
    println!(
        "{}",
        match status {
            "saved" => "Connection key saved. Register with: fortino ems-register <server>",
            "removed" => "Connection key removed.",
            "none" => "No connection key was saved for this server.",
            "configured" => {
                "This server's key is set in the service configuration; nothing changed."
            }
            "approval-required" => {
                "Approve this EMS server on this Mac first (app: EMS Setup), then save the key."
            }
            other => other,
        }
    );
    Ok(())
}

async fn ems_register(c: &Client, server: &str, json: bool) -> CmdResult {
    let server = parse_ems(server)?;
    let v: serde_json::Value = c
        .call(
            fortino_core::proto::method::EMS_ENROLL,
            &serde_json::json!({"server": server.to_string()}),
        )
        .await?;
    if json {
        print_json(&v);
        return Ok(());
    }
    let status = v["status"].as_str().unwrap_or("unknown");
    println!("Result:     {status}");
    if let Some(next) = ems_next_step(status) {
        println!("Next:       {next}");
    }
    Ok(())
}

/// What the user does next in each registration state, for terminal output.
fn ems_next_step(state: &str) -> Option<&'static str> {
    Some(match state {
        "unconfigured" | "approval-required" => {
            "approve this EMS server on this Mac (app: EMS Setup, or Enroll with EMS Package)"
        }
        "not-registered" => "fortino ems-register <server>, or connect: Fortino registers then",
        "held-by-forticlient" => {
            "FortiClient holds this Mac's registration with this EMS (one per Mac): disconnect it in FortiClient (Zero Trust Telemetry, Disconnect) or uninstall FortiClient, then fortino ems-register <server>"
        }
        "quarantined" => "your IT administrator quarantined this Mac on the EMS",
        _ => return None,
    })
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
    let refusal = &v["refusal"];
    if let Some(reason) = refusal["reason"].as_str() {
        println!("Refused:    {reason}");
        if refusal["key"].as_bool() == Some(true) {
            println!(
                "Next:       fortino ems-key set <server> with the key from IT, then fortino ems-register <server>"
            );
        } else {
            println!("Next:       ask your IT administrator; the EMS gave the reason above");
        }
    } else if let Some(next) = ems_next_step(state) {
        println!("Next:       {next}");
    }
    if v["key"].as_bool() == Some(true) {
        println!("Key:        saved");
    }
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
            if let Some(d) = a.dns {
                spec.dns_mode = d.into();
            }
            spec.save_password = a.save_password;
            require_username_for_saved_password(&spec)?;
            let p = c.profile_create(spec).await?;
            if json {
                print_json(&p);
            } else {
                println!("Created profile {} ({})", p.spec.name, p.id);
                println!("Scope: {}", p.spec.ip_policy.describe());
                println!("DNS:   {}", p.spec.dns_mode.describe());
                if p.spec.save_password {
                    println!(
                        "The password is saved in {} after the first connection.",
                        credstore::open().location()
                    );
                }
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
            // A password can be saved while the option is off (`password save` on a connected
            // profile), so --no-save-password removes it either way.
            let no_save = e.no_save_password;
            let spec = apply_edit(&p, e)?;
            require_username_for_saved_password(&spec)?;
            let u = c.profile_update(p.id.clone(), p.revision, spec).await?;
            let forgot = no_save || (p.spec.save_password && !u.spec.save_password);
            let forgot = forgot && forget_saved(&u.id.0);
            if json {
                print_json(&u);
            } else {
                println!("Updated profile {} (revision {})", u.spec.name, u.revision);
                if forgot {
                    println!("Removed the saved password.");
                }
            }
        }
        ProfileCmd::Remove { name } => {
            let p = c.profile_get(&name).await?;
            c.profile_delete(p.id.clone(), p.revision).await?;
            // Also when the option is off: a password can be saved without it.
            forget_saved(&p.id.0);
            if json {
                print_json(&serde_json::json!({"removed": p.id}));
            } else {
                println!("Removed profile {}", p.spec.name);
            }
        }
        ProfileCmd::Import(a) => import(c, a, json).await?,
        ProfileCmd::Export(a) => export(c, a, json).await?,
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
    if let Some(d) = e.dns {
        s.dns_mode = d.into();
    }
    if e.save_password {
        s.save_password = true;
    }
    if e.no_save_password {
        s.save_password = false;
    }
    Ok(s)
}

/// Save password needs the username it is saved for. Checked here for a clear message; the
/// service enforces the same rule.
fn require_username_for_saved_password(spec: &ProfileSpec) -> Result<(), Failure> {
    let has_user = spec
        .username_hint
        .as_deref()
        .is_some_and(|u| !u.trim().is_empty());
    if spec.save_password && !has_user {
        return Err(Failure(
            ProtoError::new(
                ErrorCode::InvalidProfile,
                "Save password needs the username you sign in with: add --username NAME",
            )
            .with_field("usernameHint"),
        ));
    }
    Ok(())
}

/// Removes a profile's saved password; a failure is reported, not fatal. True when one existed.
fn forget_saved(profile_id: &str) -> bool {
    match credstore::open().remove(profile_id) {
        Ok(had) => had,
        Err(e) => {
            eprintln!("fortino: note: could not remove the saved password: {e}");
            false
        }
    }
}

fn read_import_preview(file: &std::path::Path) -> Result<fortino_config::import::Preview, Failure> {
    use std::io::Read;
    // One byte over the importer's limit is enough for it to refuse the file; a huge file or a
    // pipe is never read whole.
    let limit = u64::try_from(fortino_config::import::MAX_INPUT).unwrap_or(u64::MAX);
    let mut bytes = Vec::new();
    std::fs::File::open(file)
        .and_then(|f| f.take(limit.saturating_add(1)).read_to_end(&mut bytes))
        .map_err(|e| invalid(format!("cannot read {}: {e}", file.display())))?;
    fortino_config::import::parse(&bytes)
        .map_err(|e| Failure(ProtoError::new(ErrorCode::InvalidProfile, e.to_string())))
}

async fn export(c: &Client, a: ExportArgs, json: bool) -> CmdResult {
    let specs = if a.names.is_empty() {
        c.profile_list()
            .await?
            .profiles
            .into_iter()
            .map(|p| p.spec)
            .collect::<Vec<_>>()
    } else {
        let mut v = Vec::new();
        for n in &a.names {
            v.push(c.profile_get(n).await?.spec);
        }
        v
    };
    let xml = fortino_config::export::to_forticlient_xml(&specs);
    match &a.output {
        Some(path) => {
            std::fs::write(path, &xml)
                .map_err(|e| invalid(format!("cannot write {}: {e}", path.display())))?;
            if json {
                print_json(&serde_json::json!({"exported": specs.len()}));
            } else {
                println!("Exported {} profile(s) to {}", specs.len(), path.display());
            }
        }
        None => print!("{xml}"),
    }
    Ok(())
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
    let before = c.profile_list().await?;
    let r = c
        .profile_import(&ProfileImportParams {
            store_revision: before.store_revision,
            entries: entries.into_iter().map(|e| e.spec).collect(),
            replace: a.replace,
        })
        .await?;
    // A replacement that moved a profile to another gateway or realm turned Save password off:
    // its saved password belongs to the old gateway.
    let mut forgotten = Vec::new();
    for x in r
        .results
        .iter()
        .filter(|x| x.action == fortino_config::ImportAction::Replaced)
    {
        let was_saving = before
            .profiles
            .iter()
            .any(|p| p.id == x.id && p.spec.save_password);
        if was_saving && !c.profile_get(&x.id.0).await?.spec.save_password && forget_saved(&x.id.0)
        {
            forgotten.push(x.name.clone());
        }
    }
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
        for n in forgotten {
            println!("Removed the saved password of {n}: its gateway changed.");
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

async fn status(c: &mut Client, socket: &std::path::Path, watch: bool, json: bool) -> CmdResult {
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
    let mut ctrl_c = std::pin::pin!(tokio::signal::ctrl_c());
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
                // The service restarted (an update, launchd): follow the new one.
                None => {
                    if !json {
                        eprintln!("fortino: lost the VPN service; waiting for it to come back…");
                    }
                    loop {
                        tokio::select! {
                            () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
                            _ = &mut ctrl_c => return Ok(()),
                        }
                        let Ok(mut next) = Client::connect(socket, "fortino").await else {
                            continue;
                        };
                        if let Ok((st, next_rx)) = next.subscribe().await {
                            *c = next;
                            rx = next_rx;
                            if !json {
                                println!();
                            }
                            show(&st);
                            break;
                        }
                    }
                }
            },
            _ = &mut ctrl_c => return Ok(()),
        }
    }
}

/// Asks on the terminal for a command that runs no attempt; Ctrl-C cancels, and the terminal
/// mode is restored either way.
async fn ask_here(kind: ChallengeKind, text: &str) -> Result<Option<String>, Failure> {
    let _term = TermGuard::save();
    tokio::select! {
        v = prompt::Prompt::start(kind, text) => Ok(v),
        _ = tokio::signal::ctrl_c() => {
            eprintln!();
            Err(Failure(ProtoError::new(ErrorCode::Cancelled, "cancelled")))
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
    // A password supplied on a descriptor is the caller's choice: the store is left alone.
    let store = credstore::open();
    let store = store.as_ref();
    let mut keeper = Keeper::new(
        store,
        &p.id.0,
        &p.spec.name,
        p.spec
            .username_hint
            .as_deref()
            .filter(|_| p.spec.save_password && a.password_fd.is_none()),
        &saved::gateway(&p.spec),
    );
    // The daemon uses the same rule; a username prompt replaces it.
    let mut username = a.username.clone().or_else(|| p.spec.username_hint.clone());
    let mut note = |n: String| {
        if !json {
            eprintln!("{n}");
        }
    };
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
    // A status that arrived while a terminal prompt was open, handled next.
    let mut next: Option<Status> = None;

    loop {
        let st = match next.take() {
            Some(st) => st,
            None => tokio::select! {
                ev = rx.recv() => next_status(c, ev).await?,
                _ = &mut ctrl_c => return cancel(c, &mut rx, &attempt).await,
            },
        };
        if st.attempt_id.as_deref() != Some(attempt.as_str()) {
            continue;
        }
        match st.state {
            State::Connected => {
                after_connect(&mut keeper, store, json);
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
                let code = st
                    .last_result
                    .as_ref()
                    .filter(|r| r.attempt_id == attempt)
                    .and_then(|r| r.code);
                if keeper.finished(store, code) {
                    note(
                        "The gateway rejected the saved password; the next connection asks for it."
                            .into(),
                    );
                }
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
        keeper.saw_challenge(ch.kind);
        let value = match ch.kind {
            ChallengeKind::Username => a.username.clone().map(Ok),
            ChallengeKind::Password => secrets.password().or_else(|| {
                keeper
                    .saved_answer(store, username.as_deref(), &mut note)
                    .map(|s| Ok(s.expose().to_owned()))
            }),
            ChallengeKind::Otp => secrets.otp(),
        };
        let (value, typed) = match value {
            Some(Ok(v)) => (v, false),
            // An unreadable or empty descriptor ends this attempt now, instead of leaving it
            // holding the VPN until the prompt times out.
            Some(Err(e)) => {
                give_up(c, &mut rx, &attempt).await;
                return Err(e);
            }
            None => {
                // Prompt on the terminal while following the attempt: the desktop app shows the
                // same prompt and may answer it, the attempt may end, and Ctrl-C cancels.
                let mut prompt = std::pin::pin!(prompt::Prompt::start(ch.kind, &ch.prompt));
                let outcome = loop {
                    tokio::select! {
                        v = &mut prompt => break Ok(v),
                        ev = rx.recv() => {
                            let s = next_status(c, ev).await?;
                            let still_asked = s.attempt_id.as_deref() != Some(attempt.as_str())
                                || s.challenge.as_ref().is_some_and(|x| x.id == ch.id);
                            if !still_asked {
                                break Err(s);
                            }
                        }
                        _ = &mut ctrl_c => return cancel(c, &mut rx, &attempt).await,
                    }
                };
                match outcome {
                    Ok(Some(v)) => (v, true),
                    Ok(None) => {
                        give_up(c, &mut rx, &attempt).await;
                        return Err(Failure(ProtoError::new(
                            ErrorCode::InteractionRequired,
                            format!(
                                "{} required but no terminal is available",
                                kind_name(ch.kind)
                            ),
                        )));
                    }
                    // Answered elsewhere, timed out or cancelled: the prompt is gone.
                    Err(s) => {
                        if !json {
                            eprintln!();
                            if s.state.is_active() && s.state != State::Stopping {
                                eprintln!("Answered elsewhere.");
                            }
                        }
                        next = Some(s);
                        continue;
                    }
                }
            }
        };
        let remembered = typed.then(|| value.clone());
        match c.respond(&attempt, &ch.id, value).await {
            Ok(()) => {
                // Only an answer the service took counts: a username for the password that
                // follows, a password to save once connected.
                if let Some(v) = remembered {
                    match ch.kind {
                        ChallengeKind::Username => username = Some(v),
                        ChallengeKind::Password => keeper.typed(username.as_deref(), &v),
                        ChallengeKind::Otp => {}
                    }
                }
            }
            // Expired or answered elsewhere (e.g. from the desktop app): keep following.
            Err(e) if e.code == ErrorCode::StaleChallenge => {}
            Err(e) => {
                give_up(c, &mut rx, &attempt).await;
                return Err(e.into());
            }
        }
    }
}

/// The status an event carries; a gap is filled by asking for it.
async fn next_status(c: &Client, ev: Option<Event>) -> Result<Status, Failure> {
    match ev {
        Some(Event::Status { status }) => Ok(*status),
        Some(Event::ResyncRequired) => Ok(c.status().await?),
        None => Err(Failure(ProtoError::new(
            ErrorCode::ServiceUnavailable,
            "lost connection to the VPN service",
        ))),
    }
}

/// Ctrl-C while connecting: cancels the attempt and waits for the cleanup.
async fn cancel(
    c: &Client,
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>,
    attempt: &str,
) -> CmdResult {
    eprintln!("\nCancelling…");
    c.disconnect(attempt).await?;
    let st = wait_finished(c, rx, attempt).await?;
    result_of(&st, attempt)?;
    Err(Failure(ProtoError::new(ErrorCode::Cancelled, "cancelled")))
}

/// Ends an attempt this command can't carry on with, and waits for the cleanup, so the VPN is
/// free again when the command exits.
async fn give_up(c: &Client, rx: &mut tokio::sync::mpsc::UnboundedReceiver<Event>, attempt: &str) {
    if c.disconnect(attempt).await.is_ok() {
        let _ = wait_finished(c, rx, attempt).await;
    }
}

/// Saves a password typed during a connection that just succeeded, when the profile saves it.
fn after_connect(keeper: &mut Keeper, store: &dyn fortino_secret::CredentialStore, json: bool) {
    let save = match keeper.connected() {
        AfterConnect::Nothing => false,
        AfterConnect::Save => true,
        // Non-interactive runs keep the old one; the next interactive connection asks again.
        AfterConnect::AskToReplace => {
            !json && prompt::confirm("Replace the saved password with the one you typed?")
        }
    };
    if !save {
        return;
    }
    match keeper.save_typed(store) {
        Ok(()) if !json => eprintln!("Saved the password in {}.", store.location()),
        Ok(()) => {}
        Err(e) => eprintln!("fortino: note: could not save the password: {e}"),
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

/// Reads one line from standard input (a password piped in by the app or a script).
fn read_stdin_line() -> Result<zeroize::Zeroizing<String>, Failure> {
    use std::io::{BufRead, Read};
    let mut line = zeroize::Zeroizing::new(String::new());
    std::io::BufReader::new(std::io::stdin().take(1024))
        .read_line(&mut line)
        .map_err(|e| invalid(format!("cannot read standard input: {e}")))?;
    let v = zeroize::Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_owned());
    if v.is_empty() {
        return Err(invalid("standard input supplied no password"));
    }
    Ok(v)
}

fn store_failure(e: &fortino_secret::StoreError) -> Failure {
    Failure(ProtoError::new(ErrorCode::Internal, e.to_string()))
}

async fn password(c: &mut Client, cmd: PasswordCmd, json: bool) -> CmdResult {
    let store = credstore::open();
    let store = store.as_ref();
    match cmd {
        PasswordCmd::Save {
            name,
            username,
            stdin,
        } => {
            let p = c.profile_get(&name).await?;
            let username = username.map(|u| u.trim().to_owned());
            // The password belongs to the profile's username. A profile without one gets it here,
            // before anything is saved, so a password is never kept for an account the profile
            // doesn't sign in as.
            let username = match (&p.spec.username_hint, username) {
                (Some(h), Some(u)) if *h != u => {
                    return Err(Failure(
                        ProtoError::new(
                            ErrorCode::InvalidProfile,
                            format!(
                                "{} signs in as {h}; to save a password for {u}, change its \
                                 username first: fortino profile edit {} --username {u}",
                                p.spec.name, p.spec.name
                            ),
                        )
                        .with_field("usernameHint"),
                    ));
                }
                (Some(h), _) => h.clone(),
                (None, Some(u)) => u,
                (None, None) => ask_here(ChallengeKind::Username, "Username")
                    .await?
                    .ok_or_else(|| {
                        Failure(ProtoError::new(
                            ErrorCode::InteractionRequired,
                            "this profile has no username: pass --username",
                        ))
                    })?,
            };
            let p = if p.spec.username_hint.is_none() {
                let mut spec = p.spec.clone();
                spec.username_hint = Some(username.clone());
                spec.save_password = true;
                c.profile_update(p.id.clone(), p.revision, spec)
                    .await
                    .map_err(|e| {
                        if e.code == ErrorCode::ProfileInUse {
                            Failure(ProtoError::new(
                                ErrorCode::ProfileInUse,
                                "disconnect first: saving the password also sets this profile's \
                                 username",
                            ))
                        } else {
                            Failure(e)
                        }
                    })?
            } else {
                p
            };
            // Saved under the username as the service stored it (trimmed, normalized), which is
            // the one connections look the password up by.
            let username = p.spec.username_hint.clone().unwrap_or(username);
            let pw = if stdin {
                read_stdin_line()?
            } else {
                zeroize::Zeroizing::new(
                    ask_here(ChallengeKind::Password, &format!("Password for {username}"))
                        .await?
                        .ok_or_else(|| {
                            Failure(ProtoError::new(
                                ErrorCode::InteractionRequired,
                                "password required but no terminal is available; use --stdin",
                            ))
                        })?,
                )
            };
            store
                .save(
                    &p.id.0,
                    &p.spec.name,
                    &username,
                    &saved::gateway(&p.spec),
                    &fortino_secret::Secret::new(pw.as_str()),
                )
                .map_err(|e| store_failure(&e))?;
            if !p.spec.save_password {
                let mut spec = p.spec.clone();
                spec.save_password = true;
                // The password is saved either way; a connected profile can't change until it
                // disconnects.
                if let Err(e) = c.profile_update(p.id.clone(), p.revision, spec).await {
                    eprintln!(
                        "fortino: note: Save password stays off for {} ({}); turn it on with \
                         fortino profile edit {} --save-password",
                        p.spec.name, e.message, p.spec.name
                    );
                }
            }
            if json {
                print_json(&serde_json::json!({"saved": true, "username": username}));
            } else {
                println!(
                    "Saved the password for {username} in {}. Connecting with {} uses it.",
                    store.location(),
                    p.spec.name
                );
            }
        }
        PasswordCmd::Forget { name } => {
            // Also accepts the ID of a profile that no longer exists, to clean up after it.
            let id = match c.profile_get(&name).await {
                Ok(p) => p.id.0,
                Err(e) if e.code == ErrorCode::NotFound && uuid::Uuid::parse_str(&name).is_ok() => {
                    name
                }
                Err(e) => return Err(e.into()),
            };
            let had = store.remove(&id).map_err(|e| store_failure(&e))?;
            if json {
                print_json(&serde_json::json!({"removed": had}));
            } else if had {
                println!("Removed the saved password.");
            } else {
                println!("No saved password.");
            }
        }
        PasswordCmd::Status { name } => {
            let p = c.profile_get(&name).await?;
            let info = store.info(&p.id.0);
            let gateway = saved::gateway(&p.spec);
            // Saved for another gateway than the profile's: it is not used.
            let elsewhere =
                |i: &fortino_secret::SavedPassword| i.gateway.as_deref() != Some(gateway.as_str());
            if json {
                let (saved, username, rejected, other, error) = match &info {
                    Ok(Some(i)) => (
                        true,
                        Some(i.username.clone()),
                        i.rejected,
                        elsewhere(i),
                        None,
                    ),
                    Ok(None) => (false, None, false, false, None),
                    Err(e) => (false, None, false, false, Some(e.to_string())),
                };
                print_json(&serde_json::json!({
                    "enabled": p.spec.save_password,
                    "saved": saved,
                    "username": username,
                    "rejected": rejected,
                    "otherGateway": other,
                    "location": store.location(),
                    "error": error,
                }));
                return Ok(());
            }
            println!(
                "Save password: {}",
                if p.spec.save_password { "on" } else { "off" }
            );
            match info {
                Ok(Some(i)) if elsewhere(&i) => println!(
                    "Saved:         for {} in {}, for another gateway, so it is not used",
                    i.username,
                    store.location()
                ),
                Ok(Some(i)) if i.rejected => println!(
                    "Saved:         for {} in {}; the gateway rejected it, so it is not used",
                    i.username,
                    store.location()
                ),
                Ok(Some(i)) => {
                    println!("Saved:         for {} in {}", i.username, store.location())
                }
                Ok(None) => println!("Saved:         no"),
                Err(e) => println!("Saved:         unknown ({e})"),
            }
        }
        PasswordCmd::Answer {
            name,
            attempt,
            challenge,
            username,
        } => answer_saved(c, store, &name, &attempt, &challenge, username, json).await?,
    }
    Ok(())
}

/// How long `password answer` keeps following the attempt to see whether the gateway took the
/// saved password. A code prompt in between can take the user a while.
const ANSWER_FOLLOW: std::time::Duration = std::time::Duration::from_secs(300);

/// Answers the app's outstanding password prompt from the store, then follows the attempt until
/// the gateway accepted or refused the password, and marks a refused one.
async fn answer_saved(
    c: &mut Client,
    store: &dyn fortino_secret::CredentialStore,
    name: &str,
    attempt: &str,
    challenge: &str,
    username: Option<String>,
    json: bool,
) -> CmdResult {
    let report = |answered: bool, reason: &str| {
        if json {
            print_json(&serde_json::json!({"answered": answered, "reason": reason}));
        } else if answered {
            println!("Answered with the saved password ({reason}).");
        } else {
            println!("Not answered: {reason}.");
        }
    };
    let p = c.profile_get(name).await?;
    if !p.spec.save_password {
        report(false, "disabled");
        return Ok(());
    }
    let (st, mut rx) = c.subscribe().await?;
    let asking = st.attempt_id.as_deref() == Some(attempt)
        && st.profile_id.as_ref() == Some(&p.id)
        && st
            .challenge
            .as_ref()
            .is_some_and(|ch| ch.id == challenge && ch.kind == ChallengeKind::Password);
    if !asking {
        report(false, "stale");
        return Ok(());
    }
    let Some(username) = username.or_else(|| p.spec.username_hint.clone()) else {
        report(false, "missing");
        return Ok(());
    };
    let gateway = saved::gateway(&p.spec);
    let mut keeper = Keeper::new(
        store,
        &p.id.0,
        &p.spec.name,
        p.spec.username_hint.as_deref(),
        &gateway,
    );
    let mut quiet = |_: String| {};
    let Some(secret) = keeper.saved_answer(store, Some(&username), &mut quiet) else {
        report(
            false,
            saved::lookup(store, &p.id.0, &username, &gateway).reason(),
        );
        return Ok(());
    };
    match c
        .respond(attempt, challenge, secret.expose().to_owned())
        .await
    {
        Ok(()) => {}
        Err(e) if e.code == ErrorCode::StaleChallenge => {
            report(false, "stale");
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    }
    drop(secret);
    let outcome = tokio::time::timeout(ANSWER_FOLLOW, async {
        loop {
            let st = match rx.recv().await {
                Some(Event::Status { status }) => *status,
                Some(Event::ResyncRequired) => c.status().await?,
                None => return Ok::<_, ProtoError>("unknown"),
            };
            if st.attempt_id.as_deref() != Some(attempt) {
                continue;
            }
            // A code prompt after the password means the gateway took it.
            if st
                .challenge
                .as_ref()
                .is_some_and(|ch| ch.id != challenge && ch.kind == ChallengeKind::Otp)
            {
                return Ok("accepted");
            }
            match st.state {
                State::Connected => return Ok("accepted"),
                State::Idle | State::RecoveryRequired => {
                    let code = st
                        .last_result
                        .as_ref()
                        .filter(|r| r.attempt_id == attempt)
                        .and_then(|r| r.code);
                    return Ok(if keeper.finished(store, code) {
                        "rejected"
                    } else {
                        "ended"
                    });
                }
                _ => {}
            }
        }
    })
    .await
    .unwrap_or(Ok("unknown"))?;
    report(true, outcome);
    Ok(())
}
