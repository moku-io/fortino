//! The client's identity on the wire, and request building with a fixed header order.
//!
//! The default profile matches FortiClient 7.4 for macOS on the wire. GATEWAY-1 refuses
//! tunnel access without `FSV_EMS_SN`, so these headers decide admission. The values the
//! headers carry (hostname, EMS serial) must be true for this host: an EMS serial is only sent
//! once this client is registered to that EMS.

use zeroize::Zeroizing;

use crate::http::Request;

/// FortiClient 7.4.4 for macOS `User-Agent`.
pub const FORTICLIENT_MAC_UA: &str = "FortiSSLVPN (Mac OS X; SV1 [SV{v=02.01; f=07;}])";
/// FortiClient `Accept` header.
pub const FORTICLIENT_ACCEPT: &str =
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
/// The `Host` value sent on the tunnel request.
pub const TUNNEL_HOST: &str = "sslvpn";

/// Which request shape to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderProfile {
    /// FortiClient 7.4 for macOS. The default.
    #[default]
    FortiClient74Mac,
    /// openfortivpn-like minimal headers, for debugging only.
    Minimal,
}

/// EMS registration facts carried in requests when the gateway asks for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmsIdentity {
    /// EMS server serial (`FCTEMS…`), from this client's own registration.
    pub serial: String,
    /// Tenant ID (32 hex digits; all zeros on-premises).
    pub tenant: String,
}

/// What this client says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdentity {
    /// Header profile.
    pub profile: HeaderProfile,
    /// Local host name (`FSV_HOSTNAME`).
    pub hostname: String,
    /// Present only when registered to an EMS and the gateway's `/remote/info` flag asks for
    /// it (bit `0x100`).
    pub ems: Option<EmsIdentity>,
}

impl ClientIdentity {
    /// FortiClient profile without EMS.
    pub fn forticlient(hostname: impl Into<String>) -> Self {
        Self {
            profile: HeaderProfile::FortiClient74Mac,
            hostname: sanitize(&hostname.into()).chars().take(255).collect(),
            ems: None,
        }
    }
}

/// Header values must not carry CR, LF or other controls.
/// Longest header value or request target sent. Session cookies run to several hundred bytes,
/// so this must stay well above them.
pub const MAX_HEADER_VALUE: usize = 4096;

/// Header values must not carry CR, LF or other controls. Over-long values are cut.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_HEADER_VALUE)
        .collect()
}

/// A request body with its content type.
#[derive(Debug, Clone)]
pub struct Body {
    /// `Content-Type`.
    pub content_type: &'static str,
    /// Bytes (wiped on drop).
    pub bytes: Zeroizing<Vec<u8>>,
}

impl Body {
    /// A urlencoded form. The string is moved, not copied, so a password in it is wiped
    /// with the body.
    pub fn form(s: Zeroizing<String>) -> Self {
        let mut s = s;
        Self {
            content_type: "application/x-www-form-urlencoded",
            bytes: Zeroizing::new(std::mem::take(&mut *s).into_bytes()),
        }
    }
}

/// Builds a login-phase request.
///
/// `host` is the gateway as configured (`name` or `name:port`). `cookies` are sent in order as
/// one `Cookie` header.
// UNVERIFIED: the identity headers go in the order User-Agent, Accept, FSV_HOSTNAME,
// FSV_EMS_SN, EMSSN_tenant. Where Host, Cookie, Content-Type, Content-Length and Connection sit
// relative to them is not known; this order is a placeholder until a header order is confirmed.
pub fn build(
    id: &ClientIdentity,
    method: &'static str,
    target: &str,
    host: &str,
    cookies: &[(&str, &str)],
    body: Option<Body>,
) -> Request {
    let mut h: Vec<(String, String)> = Vec::with_capacity(10);
    let mut push = |k: &str, v: &str| h.push((k.to_owned(), sanitize(v)));
    push("Host", host);
    match id.profile {
        HeaderProfile::FortiClient74Mac => {
            push("User-Agent", FORTICLIENT_MAC_UA);
            push("Accept", FORTICLIENT_ACCEPT);
            push("FSV_HOSTNAME", &id.hostname);
            if let Some(ems) = &id.ems {
                push("FSV_EMS_SN", &ems.serial);
                // UNVERIFIED: wire name of the tenant header.
                push("EMSSN_tenant", &ems.tenant);
            }
        }
        HeaderProfile::Minimal => {
            push("User-Agent", "Mozilla/5.0 SV1");
            push("Accept", "*/*");
        }
    }
    if !cookies.is_empty() {
        let c = cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        push("Cookie", &c);
    }
    let bytes = match body {
        Some(b) => {
            push("Content-Type", b.content_type);
            push("Content-Length", &b.bytes.len().to_string());
            b.bytes
        }
        None => Zeroizing::default(),
    };
    push("Connection", "close");
    Request {
        method,
        target: sanitize(target),
        headers: h,
        body: bytes,
    }
}

/// The request that switches the TLS connection into PPP tunnel mode.
///
/// `fct_uid` is appended as `?uuid=` when the gateway's `/remote/info` sets `0x80` (the
/// FortiClient UID flag).
// UNVERIFIED: which identity headers the gateway expects here. GATEWAY-2 accepted Host + User-Agent +
// Cookie.
pub fn tunnel_request(id: &ClientIdentity, cookie: &str, fct_uid: Option<&str>) -> Request {
    let mut target = "/remote/sslvpn-tunnel".to_owned();
    if let Some(uid) = fct_uid.and_then(uid_param) {
        target.push_str("?uuid=");
        target.push_str(&uid);
    }
    let mut h = vec![("Host".to_owned(), TUNNEL_HOST.to_owned())];
    if id.profile == HeaderProfile::FortiClient74Mac {
        h.push(("User-Agent".into(), FORTICLIENT_MAC_UA.into()));
        h.push(("FSV_HOSTNAME".into(), id.hostname.clone()));
        if let Some(ems) = &id.ems {
            h.push(("FSV_EMS_SN".into(), ems.serial.clone()));
            h.push(("EMSSN_tenant".into(), ems.tenant.clone()));
        }
    }
    h.push(("Cookie".into(), format!("SVPNCOOKIE={}", sanitize(cookie))));
    Request {
        method: "GET",
        target,
        headers: h,
        body: Zeroizing::default(),
    }
}

/// `?uuid=` takes the 32 hex digits of the endpoint UID in upper case; anything else is
/// dropped rather than sent.
fn uid_param(text: &str) -> Option<String> {
    let hex: String = text.trim().chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forticlient_headers_in_order() {
        let mut id = ClientIdentity::forticlient("mac-1");
        id.ems = Some(EmsIdentity {
            serial: "FCTEMS0000000001".into(),
            tenant: "0".repeat(32),
        });
        let r = build(
            &id,
            "POST",
            "/remote/logincheck",
            "vpn.example.org:10443",
            &[("SVPNTMPCOOKIE", "x")],
            Some(Body::form(Zeroizing::new("a=b".into()))),
        );
        let names: Vec<&str> = r.headers.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "Host",
                "User-Agent",
                "Accept",
                "FSV_HOSTNAME",
                "FSV_EMS_SN",
                "EMSSN_tenant",
                "Cookie",
                "Content-Type",
                "Content-Length",
                "Connection"
            ]
        );
        assert_eq!(r.header("content-length"), Some("3"));
        assert_eq!(r.header("user-agent"), Some(FORTICLIENT_MAC_UA));
    }

    #[test]
    fn header_injection_is_stripped() {
        let id = ClientIdentity::forticlient("evil\r\nX-Injected: 1");
        let r = build(&id, "GET", "/remote/info\r\n", "h", &[], None);
        let wire = String::from_utf8(r.encode().to_vec()).unwrap();
        assert!(!wire.contains("\r\nX-Injected"));
        assert!(wire.starts_with("GET /remote/info HTTP/1.1\r\n"));
    }

    #[test]
    fn long_cookies_survive() {
        let cookie = "a/b+c=".repeat(150);
        let id = ClientIdentity::forticlient("m");
        let r = build(
            &id,
            "GET",
            "/remote/fortisslvpn",
            "h",
            &[("SVPNCOOKIE", &cookie)],
            None,
        );
        assert_eq!(r.header("cookie").map(str::len), Some(cookie.len() + 11));
        let t = tunnel_request(&id, &cookie, None);
        assert_eq!(
            t.header("cookie"),
            Some(format!("SVPNCOOKIE={cookie}").as_str())
        );
    }

    #[test]
    fn no_ems_headers_without_registration() {
        let r = build(
            &ClientIdentity::forticlient("m"),
            "GET",
            "/",
            "h",
            &[],
            None,
        );
        assert!(r.header("FSV_EMS_SN").is_none());
        let t = tunnel_request(&ClientIdentity::forticlient("m"), "c", None);
        assert_eq!(t.header("cookie"), Some("SVPNCOOKIE=c"));
        assert_eq!(t.header("host"), Some("sslvpn"));
        assert_eq!(t.target, "/remote/sslvpn-tunnel");
    }

    #[test]
    fn tunnel_request_carries_the_uid_when_asked() {
        let id = ClientIdentity::forticlient("m");
        let t = tunnel_request(&id, "c", Some("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"));
        assert_eq!(
            t.target,
            "/remote/sslvpn-tunnel?uuid=0A1B2C3D4E5F60718293A4B5C6D7E8F9"
        );
        // Anything that is not 32 hex digits is dropped, never sent.
        assert_eq!(
            tunnel_request(&id, "c", Some("not-a-uid")).target,
            "/remote/sslvpn-tunnel"
        );
        assert_eq!(
            tunnel_request(&id, "c", Some("0A1B2C3D\r\nX: 1")).target,
            "/remote/sslvpn-tunnel"
        );
    }
}
