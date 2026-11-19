//! Mock FortiGate SSL VPN, built from the design notes and the observations.
//!
//! It reproduces the GATEWAY-1/GATEWAY-2 login sequence (password → `ret=2` token request → `ret=1`
//! with `SVPNTMPCOOKIE` → `hostcheck_install` swap → `SVPNCOOKIE`), serves the tunnel XML, and
//! runs a PPP peer on `/remote/sslvpn-tunnel` that waits for the client's LCP, assigns an
//! address and DNS through IPCP, and answers ICMP echo.
//!
//! Every behaviour that is inferred rather than observed
//! carries an `UNVERIFIED` comment and must match the client's assumption.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use ofc_proto_sslvpn::frame;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::http::{Request, Response};
use crate::server::{self, MockError, MockHandle, MockStream, Reply, Router, TlsOptions};

/// `/remote/info` values.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InfoCfg {
    /// `encmethod`; anything but 0 means encrypted credentials.
    pub encmethod: u32,
    /// `salt`.
    pub salt: String,
    /// `remoteauthtimeout` in seconds.
    pub remoteauthtimeout: u32,
    /// `f` flag field (decimal).
    pub flag: String,
}

impl Default for InfoCfg {
    fn default() -> Self {
        Self {
            encmethod: 0,
            salt: "5a1t5a1t".into(),
            remoteauthtimeout: 600,
            flag: "0".into(),
        }
    }
}

/// An account on the mock.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct User {
    /// Username.
    pub username: String,
    /// Password.
    pub password: String,
    /// Token code; when set, the password step asks for a second factor.
    pub otp: Option<String>,
}

/// Login behaviour.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoginCfg {
    /// After the token, answer `ret=1,redir=/remote/hostcheck_install…` with
    /// `SVPNTMPCOOKIE`, as GATEWAY-1 and GATEWAY-2 do. Otherwise issue `SVPNCOOKIE` directly.
    pub cookie_swap: bool,
    /// `tokeninfo` value sent with the second-factor request.
    pub tokeninfo: String,
    /// Tunnel-phase paths answer 403 unless this `FSV_EMS_SN` is presented (GATEWAY-1).
    pub require_ems_sn: Option<String>,
    /// Answer the login page with a host-check script.
    pub host_check: bool,
}

impl Default for LoginCfg {
    fn default() -> Self {
        Self {
            cookie_swap: true,
            tokeninfo: "remote_token_auth".into(),
            require_ems_sn: None,
            host_check: false,
        }
    }
}

/// Tunnel settings served in the XML and over IPCP.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct TunnelCfg {
    /// `tunnel-method` value.
    pub method: String,
    /// Address assigned to the client.
    pub assigned_ip: Ipv4Addr,
    /// The gateway's PPP address (its public address on GATEWAY-3).
    pub gateway_ip: Ipv4Addr,
    /// Global DNS servers.
    pub dns: Vec<Ipv4Addr>,
    /// DNS suffix.
    pub dns_suffix: Option<String>,
    /// Split DNS rules: domains (comma-separated) and up to two servers.
    pub split_dns: Vec<SplitDnsCfg>,
    /// Split routes as `a.b.c.d/m.m.m.m`.
    pub routes: Vec<String>,
}

/// One split-DNS rule.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct SplitDnsCfg {
    /// Comma-separated domains.
    pub domains: String,
    /// Servers.
    pub servers: Vec<Ipv4Addr>,
}

impl Default for TunnelCfg {
    fn default() -> Self {
        Self {
            method: "ppp".into(),
            assigned_ip: Ipv4Addr::new(10, 212, 134, 200),
            gateway_ip: Ipv4Addr::new(203, 0, 113, 10),
            dns: vec![Ipv4Addr::new(10, 0, 0, 53)],
            dns_suffix: Some("corp.example".into()),
            split_dns: vec![SplitDnsCfg {
                domains: "intra.example".into(),
                servers: vec![Ipv4Addr::new(10, 0, 0, 54)],
            }],
            routes: vec!["10.0.0.0/255.0.0.0".into()],
        }
    }
}

/// A mock gateway scenario. Loaded from YAML (see `fixtures/mock/*.yaml`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Scenario {
    /// `/remote/info`.
    pub info: InfoCfg,
    /// TLS behaviour.
    pub tls: TlsCfg,
    /// Accounts.
    pub users: Vec<User>,
    /// Login behaviour.
    pub login: LoginCfg,
    /// Tunnel settings.
    pub tunnel: TunnelCfg,
}

/// TLS behaviour of the mock.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TlsCfg {
    /// Send an optional CertificateRequest with no CA names.
    pub request_optional_client_cert: bool,
    /// Only offer TLS 1.3.
    pub tls13_only: bool,
}

impl Scenario {
    /// Parses a YAML scenario.
    pub fn from_yaml(s: &str) -> Result<Self, MockError> {
        serde_yaml::from_str(s).map_err(|e| MockError::Other(format!("scenario: {e}")))
    }
}

/// Body of `/remote/info`.
///
/// Both gateways returned these values as attributes on an `api` element.
/// The envelope and values here are synthetic.
pub fn info_body(i: &InfoCfg) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><info><api encmethod=\"{}\" salt=\"{}\" \
         remoteauthtimeout=\"{}\" f=\"{}\"/></info>",
        i.encmethod, i.salt, i.remoteauthtimeout, i.flag
    )
}

/// Body of `/remote/fortisslvpn_xml`.
// UNVERIFIED: element and attribute shapes follow the public openconnect parser; the
// GATEWAY-2 element list is matched, the values are synthetic.
pub fn tunnel_xml(t: &TunnelCfg) -> String {
    let mut x = String::from(
        "<?xml version='1.0' encoding='utf-8'?><sslvpn-tunnel ver='2' dtls='1' patch='1'>\
         <dtls-config heartbeat-interval='10' heartbeat-fail-count='10' heartbeat-idle-timeout='10' client-hello-timeout='10'/>",
    );
    x.push_str(&format!("<tunnel-method value='{}'/>", t.method));
    x.push_str("<auth-timeout val='28800'/><idle-timeout val='3600'/>");
    x.push_str(&format!("<ipv4><assigned-addr ipv4='{}'/>", t.assigned_ip));
    for d in &t.dns {
        x.push_str(&format!("<dns ip='{d}'/>"));
    }
    if let Some(s) = &t.dns_suffix {
        x.push_str(&format!("<dns domain='{s}'/>"));
    }
    for r in &t.split_dns {
        x.push_str(&format!("<split-dns domains='{}'", r.domains));
        for (i, s) in r.servers.iter().take(2).enumerate() {
            x.push_str(&format!(" dnsserver{}='{s}'", i + 1));
        }
        x.push_str("/>");
    }
    if !t.routes.is_empty() {
        x.push_str("<split-tunnel-info>");
        for r in &t.routes {
            let (ip, mask) = r.split_once('/').unwrap_or((r, "255.255.255.255"));
            x.push_str(&format!("<addr ip='{ip}' mask='{mask}'/>"));
        }
        x.push_str("</split-tunnel-info>");
    }
    x.push_str("</ipv4></sslvpn-tunnel>");
    x
}

#[derive(Default)]
struct State {
    counter: u64,
    /// reqid → username, awaiting a token.
    pending_token: HashMap<String, String>,
    /// SVPNTMPCOOKIE values awaiting the swap.
    tmp: HashSet<String>,
    /// Valid SVPNCOOKIE values.
    sessions: HashSet<String>,
}

impl State {
    fn token(&mut self, kind: &str) -> String {
        self.counter += 1;
        let h = Sha256::digest(format!("{kind}-{}", self.counter));
        hex::encode(&h[..12])
    }
}

/// Builds the router for a scenario.
pub fn router(sc: &Scenario) -> Router {
    let info = info_body(&sc.info);
    let st = Arc::new(Mutex::new(State::default()));
    let sc = Arc::new(sc.clone());

    let login_page = if sc.login.host_check {
        "<html><script>parent.CheckHostXML(\"<hostcheck/>\")</script></html>"
    } else {
        "<html><body>login</body></html>"
    };

    let (s1, c1) = (st.clone(), sc.clone());
    let (s2, c2) = (st.clone(), sc.clone());
    let (s3, c3) = (st.clone(), sc.clone());
    let (s4, c4) = (st.clone(), sc.clone());
    let s5 = st.clone();
    Router::new()
        .route("GET", "/remote/info", move |_| {
            Response::ok("application/xml", info.clone()).into()
        })
        .route("GET", "/remote/login", move |_| {
            Response::ok("text/html", login_page).into()
        })
        .route("POST", "/remote/logincheck", move |req| {
            logincheck(&s1, &c1, req).into()
        })
        .route("GET", "/remote/hostcheck_install", move |req| {
            let mut s = lock(&s2);
            let _ = &c2;
            match req.cookie("SVPNTMPCOOKIE") {
                Some(t) if s.tmp.remove(t) => {
                    let c = s.token("svpn");
                    s.sessions.insert(c.clone());
                    Response::ok(
                        "text/html",
                        "<html><script>location='/remote/index'</script></html>",
                    )
                    .with_header(
                        "Set-Cookie",
                        format!("SVPNCOOKIE={c}; path=/; secure; httponly"),
                    )
                    .with_header(
                        "Set-Cookie",
                        "SVPNTMPCOOKIE=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT",
                    )
                    .into()
                }
                _ => Response::status(403).into(),
            }
        })
        .route("GET", "/remote/fortisslvpn", move |req| {
            if admitted(&s3, &c3, req) {
                Response::ok("text/html", "<html>portal</html>").into()
            } else {
                Response::status(403).into()
            }
        })
        .route("GET", "/remote/fortisslvpn_xml", {
            let (s, c) = (st.clone(), sc.clone());
            move |req| {
                if admitted(&s, &c, req) {
                    Response::ok("application/xml", tunnel_xml(&c.tunnel)).into()
                } else {
                    Response::status(403).into()
                }
            }
        })
        .route("GET", "/remote/sslvpn-tunnel", move |req| {
            if !admitted(&s4, &c4, req) {
                return Response::status(403).into();
            }
            let t = c4.tunnel.clone();
            Reply::Takeover(Box::new(move |s, _| Box::pin(ppp_peer(s, t))))
        })
        .route("GET", "/remote/logout", move |req| {
            if let Some(c) = req.cookie("SVPNCOOKIE") {
                lock(&s5).sessions.remove(c);
            }
            Response::ok("text/html", "<html>bye</html>")
                .with_header("Set-Cookie", "SVPNCOOKIE=; path=/")
                .into()
        })
}

fn lock(s: &Mutex<State>) -> std::sync::MutexGuard<'_, State> {
    s.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn admitted(st: &Mutex<State>, sc: &Scenario, req: &Request) -> bool {
    let ok = req
        .cookie("SVPNCOOKIE")
        .is_some_and(|c| lock(st).sessions.contains(c));
    let ems_ok = sc
        .login
        .require_ems_sn
        .as_ref()
        .is_none_or(|want| req.header("FSV_EMS_SN") == Some(want.as_str()));
    ok && ems_ok
}

fn logincheck(st: &Mutex<State>, sc: &Scenario, req: &Request) -> Response {
    let mut s = lock(st);
    let user = req.form("username").unwrap_or_default();
    let clear = |r: Response| {
        r.with_header("Set-Cookie", "SVPNCOOKIE=; path=/")
            .with_header("Set-Cookie", "SVPNNETWORKCOOKIE=; path=/")
    };
    let denied = || {
        clear(Response::ok(
            "text/html",
            "<html><!--sslvpnerrmsg=Permission denied.--></html>",
        ))
    };
    let issue = |s: &mut State| {
        if sc.login.cookie_swap {
            let t = s.token("tmp");
            s.tmp.insert(t.clone());
            clear(Response::ok(
                "text/plain",
                format!(
                    "ret=1,redir=/remote/hostcheck_install?auth_type=16&user={user}&redir=/remote/index&grpname=Staff&portal=full&rip=0.0.0.0&realm="
                ),
            ))
            .with_header("Set-Cookie", format!("SVPNTMPCOOKIE={t}; path=/; secure"))
        } else {
            let c = s.token("svpn");
            s.sessions.insert(c.clone());
            Response::ok("text/plain", "ret=1,redir=/remote/index")
                .with_header("Set-Cookie", format!("SVPNCOOKIE={c}; path=/; secure"))
        }
    };

    // Token step.
    if let Some(reqid) = req.form("reqid") {
        let Some(expected_user) = s.pending_token.remove(&reqid) else {
            return denied();
        };
        let code = req.form("code").unwrap_or_default();
        let otp = sc
            .users
            .iter()
            .find(|u| u.username == expected_user)
            .and_then(|u| u.otp.clone());
        return if expected_user == user && otp.as_deref() == Some(code.as_str()) {
            issue(&mut s)
        } else {
            denied()
        };
    }

    // Password step.
    let pw = req.form("credential").unwrap_or_default();
    let Some(u) = sc
        .users
        .iter()
        .find(|u| u.username == user && u.password == pw)
    else {
        return denied();
    };
    if u.otp.is_some() {
        let reqid = s.counter.to_string();
        s.counter += 1;
        s.pending_token.insert(reqid.clone(), user.clone());
        return clear(Response::ok(
            "text/plain",
            format!(
                "ret=2,reqid={reqid},polid=1-1-3,grp=Staff,portal=full,magic=1-{reqid},tokeninfo={},chal_msg=Please enter your token code",
                sc.login.tokeninfo
            ),
        ));
    }
    issue(&mut s)
}

// ---------------------------------------------------------------- PPP peer

const LCP: u16 = 0xc021;
const IPCP: u16 = 0x8021;
const IP: u16 = 0x0021;

fn ctl(proto: u16, code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    // Like GATEWAY-2: no ff03 prefix.
    let mut f = proto.to_be_bytes().to_vec();
    f.push(code);
    f.push(id);
    f.extend_from_slice(&u16::try_from(data.len() + 4).unwrap_or(0).to_be_bytes());
    f.extend_from_slice(data);
    f
}

fn opts(mut b: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();
    while b.len() >= 2 {
        let l = usize::from(b[1]);
        if l < 2 || l > b.len() {
            break;
        }
        out.push((b[0], b[2..l].to_vec()));
        b = &b[l..];
    }
    out
}

/// A FortiGate-like PPP peer: silent until the client's LCP Configure-Request.
async fn ppp_peer(mut s: MockStream, t: TunnelCfg) {
    let mut dec = frame::Decoder::default();
    let mut buf = vec![0u8; 16 * 1024];
    let mut sent_lcp = false;
    let mut sent_ipcp = false;
    loop {
        let n = match s.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        dec.push(&buf[..n]);
        loop {
            let p = match dec.next_frame() {
                Ok(Some(p)) => p,
                Ok(None) => break,
                Err(_) => return,
            };
            let p = p.strip_prefix(&[0xff, 0x03]).unwrap_or(&p).to_vec();
            if p.len() < 2 {
                continue;
            }
            let proto = u16::from_be_bytes([p[0], p[1]]);
            let body = &p[2..];
            let mut out: Vec<Vec<u8>> = Vec::new();
            match proto {
                LCP if body.len() >= 4 => {
                    let (code, id) = (body[0], body[1]);
                    match code {
                        1 => {
                            out.push(ctl(LCP, 2, id, &body[4..]));
                            if !sent_lcp {
                                sent_lcp = true;
                                out.push(ctl(LCP, 1, 1, &[5, 6, 0x0f, 0x0e, 0x0d, 0x0c]));
                            }
                        }
                        9 => {
                            let mut r = vec![0x0f, 0x0e, 0x0d, 0x0c];
                            r.extend_from_slice(body.get(8..).unwrap_or(&[]));
                            out.push(ctl(LCP, 10, id, &r));
                        }
                        5 => {
                            out.push(ctl(LCP, 6, id, &[]));
                            for f in out {
                                let mut w = Vec::new();
                                let _ = frame::encode(&f, &mut w);
                                let _ = s.write_all(&w).await;
                            }
                            return;
                        }
                        _ => {}
                    }
                }
                IPCP if body.len() >= 4 => {
                    let (code, id) = (body[0], body[1]);
                    if code == 1 {
                        if !sent_ipcp {
                            sent_ipcp = true;
                            let mut o = vec![3, 6];
                            o.extend_from_slice(&t.gateway_ip.octets());
                            out.push(ctl(IPCP, 1, 1, &o));
                        }
                        let req = opts(&body[4..]);
                        let mut nak = Vec::new();
                        for (ty, v) in &req {
                            let want = match ty {
                                3 => Some(t.assigned_ip),
                                129 => t.dns.first().copied(),
                                131 => t.dns.get(1).copied().or(t.dns.first().copied()),
                                _ => None,
                            };
                            if let Some(w) = want {
                                if v.as_slice() != w.octets() {
                                    nak.push(*ty);
                                    nak.push(6);
                                    nak.extend_from_slice(&w.octets());
                                }
                            }
                        }
                        if nak.is_empty() {
                            out.push(ctl(IPCP, 2, id, &body[4..]));
                        } else {
                            out.push(ctl(IPCP, 3, id, &nak));
                        }
                    }
                }
                IP => {
                    if let Some(reply) = icmp_echo_reply(body) {
                        let mut f = IP.to_be_bytes().to_vec();
                        f.extend_from_slice(&reply);
                        out.push(f);
                    }
                }
                _ => {}
            }
            for f in out {
                let mut w = Vec::new();
                if frame::encode(&f, &mut w).is_err() || s.write_all(&w).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Turns an IPv4 ICMP echo request into its reply.
fn icmp_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return None;
    }
    let ihl = usize::from(pkt[0] & 0x0f) * 4;
    if pkt.len() < ihl + 8 || pkt[ihl] != 8 {
        return None;
    }
    let mut r = pkt.to_vec();
    r[12..16].copy_from_slice(&pkt[16..20]);
    r[16..20].copy_from_slice(&pkt[12..16]);
    r[ihl] = 0;
    r[ihl + 2] = 0;
    r[ihl + 3] = 0;
    let c = checksum(&r[ihl..]);
    r[ihl + 2..ihl + 4].copy_from_slice(&c.to_be_bytes());
    r[10] = 0;
    r[11] = 0;
    let c = checksum(&r[..ihl]);
    r[10..12].copy_from_slice(&c.to_be_bytes());
    Some(r)
}

/// Internet checksum.
pub fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for c in b.chunks(2) {
        let w = u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]);
        sum += u32::from(w);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(u16::try_from(sum).unwrap_or(0))
}

/// Starts a mock FortiGate for `sc`.
pub async fn start(sc: &Scenario) -> Result<MockHandle, MockError> {
    let opts = TlsOptions {
        request_optional_client_cert: sc.tls.request_optional_client_cert,
        tls13_only: sc.tls.tls13_only,
    };
    server::start(router(sc), opts).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_round_trips_through_the_client_parser() {
        let x = tunnel_xml(&TunnelCfg::default());
        let s = ofc_proto_sslvpn::config::parse(&x).unwrap();
        assert_eq!(s.assigned_v4, Some(Ipv4Addr::new(10, 212, 134, 200)));
        assert_eq!(s.include_v4.len(), 1);
        assert_eq!(s.split_dns[0].domains, ["intra.example"]);
        assert!(s.rejected.is_empty());
    }

    #[test]
    fn echo_reply() {
        let mut p = vec![
            0x45, 0, 0, 28, 0, 1, 0, 0, 64, 1, 0, 0, 10, 212, 134, 200, 10, 0, 0, 1, 8, 0, 0, 0, 0,
            1, 0, 1,
        ];
        let c = checksum(&p[20..]);
        p[22..24].copy_from_slice(&c.to_be_bytes());
        let r = icmp_echo_reply(&p).unwrap();
        assert_eq!(&r[12..16], &[10, 0, 0, 1]);
        assert_eq!(r[20], 0);
        assert_eq!(checksum(&r[20..]), 0);
        assert_eq!(checksum(&r[..20]), 0);
    }
}
