//! One connection attempt: login, tunnel settings, then the tunnel.

use std::future::Future;

use fortino_core::proto::ChallengeKind;
use fortino_core::worker::{
    EMS_REGISTRATION_REQUIRED, Termination, WorkerCommand, WorkerConfig, WorkerEvent, WorkerStage,
};
use fortino_proto_sslvpn::config::{self, TunnelSettings};
use fortino_proto_sslvpn::identity::{self, Body, ClientIdentity};
use fortino_proto_sslvpn::info::{self, ServerInfo};
use fortino_proto_sslvpn::login::{self, LoginOutcome, TokenKind};
use fortino_secret::Secret;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use crate::transport::Gateway;
use crate::{Failure, NativeWorker, tunnel};

/// The attempt's link to the daemon.
pub(crate) struct Ctx {
    pub events: mpsc::Sender<WorkerEvent>,
    pub commands: mpsc::Receiver<WorkerCommand>,
    next_challenge: u32,
}

impl Ctx {
    pub async fn emit(&self, e: WorkerEvent) {
        let _ = self.events.send(e).await;
    }

    /// Runs `fut`, abandoning it if the daemon stops the attempt meanwhile.
    pub async fn guard<T>(
        &mut self,
        fut: impl Future<Output = Result<T, Failure>>,
    ) -> Result<T, Failure> {
        tokio::pin!(fut);
        loop {
            tokio::select! {
                r = &mut fut => return r,
                c = self.commands.recv() => match c {
                    None | Some(WorkerCommand::Stop) => return Err(Failure::Cancelled),
                    // An answer with no question outstanding: stale, ignore.
                    Some(WorkerCommand::Respond { .. }) => {}
                },
            }
        }
    }

    /// Asks the user through the daemon and waits for the answer. The daemon owns the
    /// deadline; it stops the attempt when the challenge expires.
    pub async fn ask(&mut self, kind: ChallengeKind, prompt: &str) -> Result<Secret, Failure> {
        self.next_challenge += 1;
        let id = format!("c{}", self.next_challenge);
        self.emit(WorkerEvent::Challenge {
            id: id.clone(),
            kind,
            prompt: prompt
                .chars()
                .filter(|c| !c.is_control())
                .take(128)
                .collect(),
        })
        .await;
        loop {
            match self.commands.recv().await {
                None | Some(WorkerCommand::Stop) => return Err(Failure::Cancelled),
                Some(WorkerCommand::Respond {
                    challenge_id,
                    value,
                }) if challenge_id == id => {
                    return Ok(value);
                }
                Some(WorkerCommand::Respond { .. }) => {}
            }
        }
    }
}

pub(crate) async fn run(
    w: NativeWorker,
    cfg: WorkerConfig,
    events: mpsc::Sender<WorkerEvent>,
    commands: mpsc::Receiver<WorkerCommand>,
) {
    let mut ctx = Ctx {
        events,
        commands,
        next_challenge: 0,
    };
    let result = attempt(&w, &cfg, &mut ctx).await;
    let term = match result {
        Ok(()) => Termination {
            code: None,
            message: "stopped".into(),
        },
        Err(f) => {
            tracing::info!(attempt = %cfg.attempt_id, code = ?f.code(), "attempt ended: {}", f.message());
            Termination {
                code: Some(f.code()),
                message: f.message(),
            }
        }
    };
    ctx.emit(WorkerEvent::Terminated(term)).await;
}

/// A logged-in session: what the tunnel and logout need.
pub(crate) struct Session {
    pub gw: Gateway,
    pub identity: ClientIdentity,
    pub cookie: Zeroizing<String>,
    pub settings: TunnelSettings,
    /// `?uuid=` value for the tunnel request, only when `/remote/info` asks for it.
    pub fct_uid: Option<String>,
}

/// The endpoint UID to send, if the gateway asked for it.
fn uid_for_gateway(cfg: &WorkerConfig, wanted: bool) -> Option<String> {
    if !wanted {
        return None;
    }
    let uid = cfg.fct_uid.as_deref()?;
    if uid.trim().chars().filter(|c| *c != '-').count() != 32 {
        tracing::warn!("endpoint UID is not a UUID; not sent to the gateway");
        return None;
    }
    tracing::debug!("tunnel request carries the endpoint UID (/remote/info 0x80)");
    Some(uid.to_owned())
}

async fn attempt(w: &NativeWorker, cfg: &WorkerConfig, ctx: &mut Ctx) -> Result<(), Failure> {
    ctx.emit(WorkerEvent::Stage(WorkerStage::Transport)).await;
    let ep = &cfg.endpoint;
    let mut gw = Gateway::new(ep.host.clone(), ep.port, &w.trust)?;
    gw.connect_override = w.connect_override;
    // Like FortiClient, present the EMS serial only once `/remote/info` asks for it.
    let mut identity = w.identity.clone();
    let registered = cfg
        .ems
        .as_ref()
        .map(|e| identity::EmsIdentity {
            serial: e.serial.clone(),
            tenant: e.tenant.clone(),
        })
        .or_else(|| identity.ems.clone());
    identity.ems = None;
    let host = gw.host_header();

    // Pre-flight. GATEWAY-3 and GATEWAY-4 answer 403 here; only a parsed answer is used.
    let req = identity::build(&identity, "GET", "/remote/info", &host, &[], None);
    let info = match ctx.guard(gw.exchange(&req)).await? {
        r if r.status == 200 => info::parse(&r.text()).unwrap_or_default(),
        _ => ServerInfo::default(),
    };
    tracing::info!(
        fct_uid = info.wants_fct_uid(),
        ems_sn = info.wants_ems_sn(),
        "gateway info flags (0x80 endpoint UID, 0x100 EMS serial)"
    );
    if info.encmethod.is_some_and(|m| m != 0) {
        return Err(Failure::Unsupported(
            "gateway encrypts credentials (encmethod)".into(),
        ));
    }
    if info.wants_ems_sn() {
        identity.ems = registered;
    }
    let ems_required = info.wants_ems_sn() && identity.ems.is_none();

    ctx.emit(WorkerEvent::Stage(WorkerStage::Authenticating))
        .await;
    let realm = ep.realm.clone().unwrap_or_default();
    let login_path = if realm.is_empty() {
        "/remote/login".to_owned()
    } else {
        format!("/remote/login?realm={realm}")
    };
    let page = ctx
        .guard(gw.exchange(&identity::build(
            &identity,
            "GET",
            &login_path,
            &host,
            &[],
            None,
        )))
        .await?;
    // A non-200 login page is only logged; the login is still sent. The exception: a gateway
    // that asked for an EMS serial we lack and answers 503 refuses the login too (observed),
    // so stop before asking for the password.
    if page.status != 200 {
        tracing::info!(status = page.status, "login page status");
    }
    if page.status == 503 && ems_required {
        return Err(ems_serial_refused());
    }
    if page.text().contains("CheckHostXML") {
        return Err(Failure::Unsupported("gateway requires a host check".into()));
    }

    let username = match &cfg.username {
        Some(u) => u.clone(),
        None => ctx
            .ask(ChallengeKind::Username, "Username")
            .await?
            .expose()
            .to_owned(),
    };
    let password = ctx.ask(ChallengeKind::Password, "Password").await?;
    let form = login::password_form(&username, password.expose(), &realm);
    drop(password);
    let req = identity::build(
        &identity,
        "POST",
        "/remote/logincheck",
        &host,
        &[],
        Some(Body::form(form)),
    );
    let mut resp = ctx.guard(gw.exchange(&req)).await?;
    drop(req);

    let mut cookie: Option<Zeroizing<String>> = None;
    for _step in 0..4 {
        match login::classify(&resp) {
            LoginOutcome::Authenticated { cookie: c } => {
                cookie = Some(c);
                break;
            }
            LoginOutcome::SecondFactor(ch) => {
                let prompt = ch.message.clone().unwrap_or_else(|| "Token code".into());
                let code = ctx.ask(ChallengeKind::Otp, &prompt).await?;
                // An empty answer requests a FortiToken Mobile push where offered.
                let push = code.expose().is_empty() && ch.kind == TokenKind::Push;
                let form = login::token_form(
                    &username,
                    &realm,
                    &ch.state,
                    (!push).then_some(code.expose()),
                );
                drop(code);
                let req = identity::build(
                    &identity,
                    "POST",
                    "/remote/logincheck",
                    &host,
                    &[],
                    Some(Body::form(form)),
                );
                resp = ctx.guard(gw.exchange(&req)).await?;
            }
            LoginOutcome::CookieSwap { tmp_cookie, path } => {
                let req = identity::build(
                    &identity,
                    "GET",
                    &path,
                    &host,
                    &[("SVPNTMPCOOKIE", tmp_cookie.as_str())],
                    None,
                );
                resp = ctx.guard(gw.exchange(&req)).await?;
            }
            LoginOutcome::HostCheckRequired => {
                return Err(Failure::Unsupported("gateway requires a host check".into()));
            }
            LoginOutcome::LimitReached => {
                return Err(Failure::AuthDenied("gateway user limit reached".into()));
            }
            LoginOutcome::Denied { message } => {
                return Err(Failure::AuthDenied(
                    message.unwrap_or_else(|| "credentials rejected".into()),
                ));
            }
            LoginOutcome::Unexpected { status: 503 } if ems_required => {
                return Err(ems_serial_refused());
            }
            LoginOutcome::Unexpected { status: 503 } if identity.ems.is_some() => {
                return Err(Failure::Backend(
                    "gateway refused the login with this Mac's EMS serial (HTTP 503)".into(),
                ));
            }
            LoginOutcome::Unexpected { status: 503 } => {
                return Err(Failure::Backend(
                    "gateway login is unavailable (HTTP 503)".into(),
                ));
            }
            LoginOutcome::Unexpected { status } => {
                return Err(Failure::Backend(format!(
                    "unexpected login answer (HTTP {status})"
                )));
            }
        }
    }
    let Some(cookie) = cookie else {
        return Err(Failure::Backend("login did not complete".into()));
    };

    ctx.emit(WorkerEvent::Stage(WorkerStage::Negotiating)).await;
    let mut cookie = cookie;
    // VPN allocation: the login's own redirect target, then the portal page (openfortivpn's
    // `auth_request_vpn_allocation`; FortiClient's login form names `/remote/index` as redir).
    // Both are "non-essential" for their status but may refresh the cookie.
    for path in ["/remote/index", "/remote/fortisslvpn"] {
        let r = ctx
            .guard(gw.exchange(&identity::build(
                &identity,
                "GET",
                path,
                &host,
                &[("SVPNCOOKIE", cookie.as_str())],
                None,
            )))
            .await?;
        refresh_cookie(&r, &mut cookie);
    }
    let mut path = "/remote/fortisslvpn_xml".to_owned();
    let mut xml = fortino_proto_sslvpn::http::Response::default();
    for _hop in 0..3 {
        xml = ctx
            .guard(gw.exchange(&identity::build(
                &identity,
                "GET",
                &path,
                &host,
                &[("SVPNCOOKIE", cookie.as_str())],
                None,
            )))
            .await?;
        refresh_cookie(&xml, &mut cookie);
        if !matches!(xml.status, 301 | 302 | 303 | 307) {
            break;
        }
        // Follow a same-origin redirect (session activation), then ask for the XML again.
        let loc = xml.header("location").unwrap_or("").to_owned();
        let target = same_origin(&loc);
        tracing::debug!(
            status = xml.status,
            same_origin = target.is_some(),
            "tunnel settings redirected"
        );
        match target {
            Some(t) if t.starts_with("/remote/login") => break,
            Some(t) => {
                let r = ctx
                    .guard(gw.exchange(&identity::build(
                        &identity,
                        "GET",
                        &t,
                        &host,
                        &[("SVPNCOOKIE", cookie.as_str())],
                        None,
                    )))
                    .await?;
                refresh_cookie(&r, &mut cookie);
                path = "/remote/fortisslvpn_xml".into();
            }
            None => break,
        }
    }
    let mut session = Session {
        gw,
        identity,
        cookie: cookie.clone(),
        settings: TunnelSettings::default(),
        fct_uid: uid_for_gateway(cfg, info.wants_fct_uid()),
    };
    if xml.status != 200 {
        let f = if xml.status == 403 && ems_required {
            Failure::Unsupported(EMS_REGISTRATION_REQUIRED.into())
        } else if xml.status == 403 {
            Failure::Unsupported("gateway refused tunnel access for this device".into())
        } else {
            Failure::Backend(format!(
                "tunnel settings: HTTP {}{}",
                xml.status,
                xml.header("location")
                    .map(|l| format!(
                        " to {}",
                        same_origin(l).unwrap_or_else(|| "another site".into())
                    ))
                    .unwrap_or_default()
            ))
        };
        logout(&mut session).await;
        return Err(f);
    }
    session.settings = match config::parse(&xml.text()) {
        Ok(s) => s,
        Err(e) => {
            logout(&mut session).await;
            return Err(Failure::Backend(e.to_string()));
        }
    };
    {
        let st = &session.settings;
        // Shape only: no addresses or names.
        tracing::debug!(
            "settings: method={:?} include={} exclude={} dns={} suffixes={} split_rules={} split_server_sets={} split_domains={} distinct_dns={} ipv6={} unknown={:?} rejected={:?}",
            st.tunnel_method,
            st.include_v4.len(),
            st.exclude_v4.len(),
            st.dns.len(),
            st.dns_suffixes.len(),
            st.split_dns.len(),
            st.split_server_sets(),
            st.split_dns.iter().map(|r| r.domains.len()).sum::<usize>(),
            st.dns_count(),
            st.has_ipv6,
            st.unknown,
            st.rejected,
        );
    }
    if !session.settings.rejected.is_empty() {
        let why = session.settings.rejected.join("; ");
        logout(&mut session).await;
        return Err(Failure::Unsupported(format!("tunnel settings: {why}")));
    }

    let r = tunnel::run(w, &mut session, ctx).await;
    logout(&mut session).await;
    r
}

/// Takes a new non-empty `SVPNCOOKIE` from a response.
/// The gateway set `/remote/info` `0x100`, this attempt has no EMS serial, and the login
/// answered 503.
fn ems_serial_refused() -> Failure {
    Failure::Unsupported(format!(
        "{EMS_REGISTRATION_REQUIRED}: it refused the login without this Mac's EMS serial (HTTP 503)"
    ))
}

fn refresh_cookie(r: &fortino_proto_sslvpn::http::Response, cookie: &mut Zeroizing<String>) {
    if let Some(c) = r.cookie("SVPNCOOKIE").filter(|c| !c.is_empty()) {
        *cookie = Zeroizing::new(c.to_owned());
    }
}

/// The path of a redirect to the same gateway, without query secrets, or `None`.
fn same_origin(loc: &str) -> Option<String> {
    let path = if let Some(rest) = loc.strip_prefix("https://") {
        rest.find('/').map(|i| &rest[i..])?
    } else {
        loc
    };
    let ok = path.starts_with("/remote/")
        && !path.starts_with("//")
        && path.len() <= 2048
        && !path
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\');
    ok.then(|| path.to_owned())
}

/// Best-effort logout, bounded.
async fn logout(s: &mut Session) {
    let host = s.gw.host_header();
    let req = identity::build(
        &s.identity,
        "GET",
        "/remote/logout",
        &host,
        &[("SVPNCOOKIE", s.cookie.as_str())],
        None,
    );
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), s.gw.exchange(&req)).await;
}
