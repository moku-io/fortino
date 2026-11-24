//! Single sign-on (SAML) through the system browser.
//!
//! 1. The user's browser opens [`start_url`]: `/remote/saml/start?redirect=1` on the gateway,
//!    plus `&realm=…` for a realm. The gateway sends the browser on to the identity provider.
//! 2. After the sign-in, the gateway redirects the browser to a listener on this computer:
//!    `http://127.0.0.1:<port>/?id=<session id>`, where the port is `sso_port` from
//!    `/remote/info`.
//! 3. The client exchanges the id once: `GET` [`auth_id_path`] answers with `SVPNCOOKIE`, and the
//!    login continues as after a password login.
//!
//! [`callback_request`] classifies what the local listener receives, [`session_id`] reads the id
//! from the callback's query string, and [`pasted_callback`] accepts the address a user copies
//! from the browser when the listener can't receive it.

use zeroize::Zeroizing;

use crate::urlenc;

/// Callback port when `/remote/info` names none.
// UNVERIFIED: the gateway's default redirect port; a gateway that reports `sso_port` overrides it.
pub const DEFAULT_CALLBACK_PORT: u16 = 8020;

/// Longest session id accepted.
pub const MAX_SESSION_ID: usize = 1023;

/// Longest callback query string accepted, and so the longest answer a client hands back.
pub const MAX_QUERY: usize = 2048;

/// Largest request head the callback listener reads.
pub const MAX_REQUEST_HEAD: usize = 8 * 1024;

/// The sign-in page to open in the system browser. `host` is a DNS name or IPv4 address.
pub fn start_url(host: &str, port: u16, realm: Option<&str>) -> String {
    let mut url = if port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{port}")
    };
    url.push_str("/remote/saml/start?redirect=1");
    if let Some(r) = realm.filter(|r| !r.is_empty()) {
        url.push_str("&realm=");
        url.push_str(&urlenc::encode(r));
    }
    url
}

/// A session id from the gateway's redirect. Secret: it can be exchanged once for the session
/// cookie.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId<'a>(&'a str);

impl<'a> SessionId<'a> {
    /// The id as received.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl std::fmt::Debug for SessionId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionId(<redacted>)")
    }
}

/// The path that exchanges a session id for the session cookie.
pub fn auth_id_path(id: SessionId<'_>) -> Zeroizing<String> {
    Zeroizing::new(format!("/remote/saml/auth_id?id={}", id.0))
}

/// The session id in a callback query string (`id=…`; other parameters are ignored). A missing,
/// repeated or malformed id gives `None`.
// UNVERIFIED: ids seen so far are ASCII letters, digits and `-`. Anything else is refused rather
// than sent to the gateway.
pub fn session_id(query: &str) -> Option<SessionId<'_>> {
    if query.len() > MAX_QUERY {
        return None;
    }
    let mut found = None;
    for part in query.split('&') {
        if let Some(v) = part.strip_prefix("id=") {
            if found.is_some() {
                return None;
            }
            found = Some(v);
        }
    }
    let v = found?;
    let ok = !v.is_empty()
        && v.len() <= MAX_SESSION_ID
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    ok.then_some(SessionId(v))
}

/// What the callback listener received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Callback {
    /// The gateway's redirect. Carries the query string (`id=…`) to hand to the attempt. Secret.
    Login(Zeroizing<String>),
    /// A well-formed request for something else, such as `/favicon.ico`: answer 404 and keep
    /// listening.
    NotFound,
    /// A request this listener doesn't accept (method, framing or `Host`): answer 400 and keep
    /// listening.
    Bad,
}

/// Classifies a request head (the request line and headers, without the blank line) received on
/// `127.0.0.1:port`.
///
/// Only `GET /?<query>` with a valid id and a `Host` naming this listener (`127.0.0.1:port` or
/// `localhost:port`) is a login. Checking the host keeps a page that reaches the listener
/// through a rebound DNS name from delivering an id.
pub fn callback_request(head: &[u8], port: u16) -> Callback {
    if head.len() > MAX_REQUEST_HEAD {
        return Callback::Bad;
    }
    let Ok(text) = std::str::from_utf8(head) else {
        return Callback::Bad;
    };
    let mut lines = text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l));
    let Some(request_line) = lines.next() else {
        return Callback::Bad;
    };
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Callback::Bad;
    };
    if !matches!(version, "HTTP/1.1" | "HTTP/1.0") {
        return Callback::Bad;
    }
    let mut host = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Callback::Bad;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Callback::Bad;
            }
            host = Some(value.trim());
        }
    }
    let host_ok = host.is_some_and(|h| {
        h.rsplit_once(':').is_some_and(|(name, p)| {
            p.parse::<u16>().ok() == Some(port)
                && (name == "127.0.0.1" || name.eq_ignore_ascii_case("localhost"))
        })
    });
    if !host_ok || method != "GET" {
        return Callback::Bad;
    }
    match target.strip_prefix("/?") {
        Some(query) if session_id(query).is_some() => {
            Callback::Login(Zeroizing::new(query.to_owned()))
        }
        _ => Callback::NotFound,
    }
}

/// The callback query from what a user pasted: the address the browser ended on
/// (`http://127.0.0.1:8020/?id=…`), its path (`/?id=…`), the query (`id=…`) or a bare id.
pub fn pasted_callback(input: &str) -> Option<Zeroizing<String>> {
    let s = input.trim();
    if s.len() > MAX_QUERY + 64 {
        return None;
    }
    let query = match s.split_once('?') {
        Some((_, q)) => q,
        None if s.contains('=') => s,
        None => {
            let q = Zeroizing::new(format!("id={s}"));
            return session_id(&q).is_some().then_some(q);
        }
    };
    let query = query.split('#').next().unwrap_or_default();
    session_id(query)?;
    Some(Zeroizing::new(query.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_urls() {
        assert_eq!(
            start_url("vpn.example.org", 443, None),
            "https://vpn.example.org/remote/saml/start?redirect=1"
        );
        assert_eq!(
            start_url("192.0.2.1", 10443, Some("staff")),
            "https://192.0.2.1:10443/remote/saml/start?redirect=1&realm=staff"
        );
        assert_eq!(
            start_url("vpn.example.org", 8443, Some("R&D lab")),
            "https://vpn.example.org:8443/remote/saml/start?redirect=1&realm=R%26D%20lab"
        );
        assert_eq!(
            start_url("vpn.example.org", 443, Some("")),
            "https://vpn.example.org/remote/saml/start?redirect=1"
        );
    }

    #[test]
    fn session_ids() {
        let id = session_id("id=3f9A-0b").map(|i| i.as_str());
        assert_eq!(id, Some("3f9A-0b"));
        assert_eq!(
            session_id("x=1&id=abc&y=2").map(|i| i.as_str()),
            Some("abc")
        );
        for bad in [
            "",
            "id=",
            "x=1",
            "id=a&id=b",
            "id=a b",
            "id=a%20b",
            "id=a/b",
            "id=a_b",
        ] {
            assert!(session_id(bad).is_none(), "{bad}");
        }
        let long = format!("id={}", "a".repeat(MAX_SESSION_ID + 1));
        assert!(session_id(&long).is_none());
        let max = format!("id={}", "a".repeat(MAX_SESSION_ID));
        assert!(session_id(&max).is_some());
        assert_eq!(
            *auth_id_path(session_id("id=abc-1").unwrap()),
            "/remote/saml/auth_id?id=abc-1"
        );
        assert!(!format!("{:?}", session_id("id=s3cret").unwrap()).contains("s3cret"));
    }

    fn head(lines: &[&str]) -> Vec<u8> {
        lines.join("\r\n").into_bytes()
    }

    #[test]
    fn callback_requests() {
        let login = head(&[
            "GET /?id=abc123 HTTP/1.1",
            "Host: 127.0.0.1:8020",
            "Accept: */*",
        ]);
        assert_eq!(
            callback_request(&login, 8020),
            Callback::Login(Zeroizing::new("id=abc123".into()))
        );
        let local = head(&["GET /?id=abc&x=1 HTTP/1.1", "host: LOCALHOST:8020"]);
        assert_eq!(
            callback_request(&local, 8020),
            Callback::Login(Zeroizing::new("id=abc&x=1".into()))
        );
        let bare_lf = b"GET /?id=abc HTTP/1.1\nHost: 127.0.0.1:8020".to_vec();
        assert!(matches!(
            callback_request(&bare_lf, 8020),
            Callback::Login(_)
        ));
        let host = "Host: 127.0.0.1:8020";
        let cases: &[(&[&str], Callback)] = &[
            (&["GET /favicon.ico HTTP/1.1", host], Callback::NotFound),
            (&["GET /?x=1 HTTP/1.1", host], Callback::NotFound),
            (&["GET /?id=a!b HTTP/1.1", host], Callback::NotFound),
            (
                &["GET /?id=abc HTTP/1.1", "Host: 127.0.0.1:9000"],
                Callback::Bad,
            ),
            (
                &["GET /?id=abc HTTP/1.1", "Host: evil.example:8020"],
                Callback::Bad,
            ),
            (&["GET /?id=abc HTTP/1.1"], Callback::Bad),
            (&["GET /?id=abc HTTP/1.1", host, host], Callback::Bad),
            (&["POST /?id=abc HTTP/1.1", host], Callback::Bad),
            (&["GET /?id=abc HTTP/2", host], Callback::Bad),
            (&["GET  /?id=abc HTTP/1.1", host], Callback::Bad),
            (&["GET /?id=abc HTTP/1.1", "no colon"], Callback::Bad),
        ];
        for (lines, want) in cases {
            assert_eq!(callback_request(&head(lines), 8020), *want, "{lines:?}");
        }
        assert_eq!(callback_request(b"\xff\xfe", 8020), Callback::Bad);
        assert_eq!(
            callback_request(&vec![b'a'; MAX_REQUEST_HEAD + 1], 8020),
            Callback::Bad
        );
    }

    #[test]
    fn pasted_addresses() {
        for input in [
            "http://127.0.0.1:8020/?id=abc-1",
            "  http://localhost:8020/?id=abc-1#top \n",
            "/?id=abc-1",
            "id=abc-1",
            "abc-1",
        ] {
            assert_eq!(
                pasted_callback(input).as_deref().map(String::as_str),
                Some("id=abc-1"),
                "{input}"
            );
        }
        for bad in ["", "http://127.0.0.1:8020/", "id=", "not an id", "x=1"] {
            assert!(pasted_callback(bad).is_none(), "{bad}");
        }
    }

    proptest::proptest! {
        #[test]
        fn parsers_never_panic(bytes: Vec<u8>, s: String, port: u16) {
            let _ = callback_request(&bytes, port);
            let _ = session_id(&s);
            let _ = pasted_callback(&s);
            let _ = start_url(&s, port, Some(&s));
        }

        #[test]
        fn accepted_ids_stay_in_the_alphabet(s: String) {
            if let Some(id) = session_id(&s) {
                proptest::prop_assert!(id.as_str().bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
            }
        }
    }
}
