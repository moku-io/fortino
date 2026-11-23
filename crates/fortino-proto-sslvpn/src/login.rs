//! `/remote/logincheck` : request forms and classification of the gateway's answer.
//!
//! The forms are the ones a client of ours already used successfully on GATEWAY-1 and GATEWAY-2
//! and match what FortiClient sends.
//!
//! Observed GATEWAY-1/GATEWAY-2 sequence:
//! 1. password form → `ret=2,…,tokeninfo=remote_token_auth` (second factor needed);
//! 2. token form → `ret=1,redir=/remote/hostcheck_install?…` with `SVPNTMPCOOKIE`;
//! 3. `GET` of that path with the temporary cookie → `SVPNCOOKIE`.

use zeroize::Zeroizing;

use crate::http::Response;
use crate::urlenc;

const TRAILER: &str = "&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1";

/// Most bytes of a gateway message kept for display.
pub const MAX_MESSAGE: usize = 200;

/// The password form.
pub fn password_form(username: &str, password: &str, realm: &str) -> Zeroizing<String> {
    let pw = Zeroizing::new(urlenc::encode(password));
    Zeroizing::new(format!(
        "username={}&credential={}&realm={}{TRAILER}",
        urlenc::encode(username),
        pw.as_str(),
        urlenc::encode(realm)
    ))
}

/// State the gateway returns with a second-factor request; it goes back with the code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenState {
    /// `reqid`.
    pub reqid: String,
    /// `polid`.
    pub polid: String,
    /// `grp`.
    pub grp: String,
    /// `peer`.
    pub peer: String,
    /// `portal`.
    pub portal: String,
    /// `magic` (used by the RADIUS challenge forms).
    pub magic: String,
}

/// What kind of second factor the gateway offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenKind {
    /// A code typed by the user (FortiToken, email, SMS, RADIUS token).
    Code,
    /// FortiToken Mobile push; a code is also accepted.
    Push,
}

/// A second-factor request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChallenge {
    /// Echoed back with the code.
    pub state: TokenState,
    /// Code or push.
    pub kind: TokenKind,
    /// Raw `tokeninfo` value.
    pub tokeninfo: String,
    /// Prompt text from the gateway (`chal_msg`), sanitized.
    pub message: Option<String>,
}

/// The token form. An empty `code` with `push` asks for an FTM push.
pub fn token_form(
    username: &str,
    realm: &str,
    st: &TokenState,
    code: Option<&str>,
) -> Zeroizing<String> {
    let base = format!(
        "username={}&reqid={}&polid={}&grp={}&realm={}&peer={}",
        urlenc::encode(username),
        urlenc::encode(&st.reqid),
        urlenc::encode(&st.polid),
        urlenc::encode(&st.grp),
        urlenc::encode(realm),
        urlenc::encode(&st.peer),
    );
    match code {
        Some(c) => {
            let c = Zeroizing::new(urlenc::encode(c));
            Zeroizing::new(format!("{base}&code={}&code2={TRAILER}", c.as_str()))
        }
        None => Zeroizing::new(format!("{base}{TRAILER}&ftmpush=1")),
    }
}

/// What a login step produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    /// `SVPNCOOKIE` was issued.
    Authenticated {
        /// Session cookie. Secret.
        cookie: Zeroizing<String>,
    },
    /// A second factor is needed.
    SecondFactor(TokenChallenge),
    /// The gateway issued a temporary cookie to exchange at a same-origin path.
    CookieSwap {
        /// `SVPNTMPCOOKIE`. Secret.
        tmp_cookie: Zeroizing<String>,
        /// Path to `GET`, validated as same-origin under `/remote/`.
        path: String,
    },
    /// The portal runs a host check this client does not implement (not implemented yet).
    HostCheckRequired,
    /// The user limit is reached (`<!--fgt limit user-->`).
    LimitReached,
    /// Credentials refused.
    Denied {
        /// Gateway's message, sanitized.
        message: Option<String>,
    },
    /// Anything else: an unexpected status or body.
    Unexpected {
        /// HTTP status.
        status: u16,
    },
}

/// Classifies a `/remote/logincheck` (or cookie-swap) response.
pub fn classify(resp: &Response) -> LoginOutcome {
    let body = resp.text();
    if body.contains("CheckHostXML") || body.contains("hostcheck_validate") {
        return LoginOutcome::HostCheckRequired;
    }
    if let Some(c) = resp.cookie("SVPNCOOKIE").filter(|c| !c.is_empty()) {
        return LoginOutcome::Authenticated {
            cookie: Zeroizing::new(c.to_owned()),
        };
    }
    if body.contains("<!--fgt limit user-->") {
        return LoginOutcome::LimitReached;
    }
    if resp.status == 401 || resp.status == 403 {
        return LoginOutcome::Denied {
            message: err_message(&body),
        };
    }
    if resp.status != 200 {
        return LoginOutcome::Unexpected {
            status: resp.status,
        };
    }
    let kv = ret_kv(&body);
    let get = |k: &str| {
        kv.iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or("")
    };
    let ret = get("ret");
    if !get("tokeninfo").is_empty() || (ret == "2" && !get("reqid").is_empty()) {
        let tokeninfo = get("tokeninfo").to_owned();
        let kind = if tokeninfo.starts_with("ftm_push") {
            TokenKind::Push
        } else {
            TokenKind::Code
        };
        let message = Some(get("chal_msg"))
            .filter(|m| !m.is_empty())
            .map(|m| sanitize(&urlenc::decode(m)));
        return LoginOutcome::SecondFactor(TokenChallenge {
            state: TokenState {
                reqid: get("reqid").into(),
                polid: get("polid").into(),
                grp: get("grp").into(),
                peer: get("peer").into(),
                portal: get("portal").into(),
                magic: get("magic").into(),
            },
            kind,
            tokeninfo,
            message,
        });
    }
    if ret == "1" {
        let redir = get("redir");
        if let Some(tmp) = resp.cookie("SVPNTMPCOOKIE").filter(|c| !c.is_empty()) {
            return match same_origin_path(redir) {
                Some(path) if path.starts_with("/remote/hostcheck_install") => {
                    LoginOutcome::CookieSwap {
                        tmp_cookie: Zeroizing::new(tmp.to_owned()),
                        path,
                    }
                }
                _ => LoginOutcome::Unexpected {
                    status: resp.status,
                },
            };
        }
    }
    LoginOutcome::Denied {
        message: err_message(&body),
    }
}

/// Splits `ret=…,key=value,…`. A part without a key continues the previous value, so commas
/// inside `chal_msg` survive.
fn ret_kv(body: &str) -> Vec<(String, String)> {
    let body = body.trim();
    if !body.starts_with("ret=") {
        return Vec::new();
    }
    let mut out: Vec<(String, String)> = Vec::new();
    for part in body.split(',') {
        let key_ok = part.split_once('=').is_some_and(|(k, _)| {
            !k.is_empty()
                && k.len() <= 32
                && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        });
        match (key_ok, out.last_mut()) {
            (true, _) => {
                if out.len() >= 64 {
                    break;
                }
                if let Some((k, v)) = part.split_once('=') {
                    out.push((k.to_owned(), v.to_owned()));
                }
            }
            (false, Some((_, v))) => {
                v.push(',');
                v.push_str(part);
            }
            (false, None) => {}
        }
    }
    out
}

/// A gateway redirect is followed only to a path on the same gateway under `/remote/`.
fn same_origin_path(redir: &str) -> Option<String> {
    let p = urlenc::decode(redir);
    let ok = p.starts_with("/remote/")
        && !p.starts_with("//")
        && p.len() <= 2048
        && !p
            .bytes()
            .any(|b| b.is_ascii_control() || b == b' ' || b == b'\\')
        && !p.contains("/../");
    // Keep the original encoding on the wire.
    ok.then(|| redir.to_owned())
        .filter(|r| !r.bytes().any(|b| b.is_ascii_control() || b == b' '))
}

/// `<!--sslvpnerrmsg=…-->`, the gateway's human-readable refusal.
fn err_message(body: &str) -> Option<String> {
    for key in ["sslvpnerrmsg", "sslvpnerrmsgkey", "sslvpnerrkey"] {
        let pat = format!("<!--{key}=");
        if let Some(i) = body.find(&pat) {
            let rest = &body[i + pat.len()..];
            let end = rest.find("-->").unwrap_or(rest.len());
            let m = sanitize(&rest[..end]);
            if !m.is_empty() {
                return Some(m);
            }
        }
    }
    None
}

fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(MAX_MESSAGE)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, cookies: &[&str], body: &str) -> Response {
        Response {
            status,
            headers: cookies
                .iter()
                .map(|c| ("Set-Cookie".to_owned(), format!("{c}; path=/; secure")))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn forms() {
        assert_eq!(
            *password_form("alice@x", "p&ss", ""),
            "username=alice%40x&credential=p%26ss&realm=&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1"
        );
        let st = TokenState {
            reqid: "12".into(),
            polid: "1-1-2".into(),
            grp: "G".into(),
            peer: "".into(),
            ..Default::default()
        };
        assert_eq!(
            *token_form("alice", "", &st, Some("123456")),
            "username=alice&reqid=12&polid=1-1-2&grp=G&realm=&peer=&code=123456&code2=&ajax=1&redir=%2Fremote%2Findex&just_logged_in=1"
        );
        assert!(token_form("a", "", &st, None).ends_with("&just_logged_in=1&ftmpush=1"));
    }

    #[test]
    fn second_factor() {
        let r = resp(
            200,
            &["SVPNCOOKIE=", "SVPNNETWORKCOOKIE="],
            "ret=2,reqid=99,polid=1-1-3,grp=Staff,portal=full,magic=1-abc,tokeninfo=remote_token_auth,chal_msg=Enter code, please",
        );
        match classify(&r) {
            LoginOutcome::SecondFactor(c) => {
                assert_eq!(c.kind, TokenKind::Code);
                assert_eq!(c.state.reqid, "99");
                assert_eq!(c.state.grp, "Staff");
                assert_eq!(c.message.as_deref(), Some("Enter code, please"));
            }
            o => panic!("{o:?}"),
        }
        let p = resp(200, &[], "ret=2,reqid=1,tokeninfo=ftm_push");
        assert!(matches!(
            classify(&p),
            LoginOutcome::SecondFactor(TokenChallenge {
                kind: TokenKind::Push,
                ..
            })
        ));
    }

    #[test]
    fn cookie_swap_then_cookie() {
        let r = resp(
            200,
            &["SVPNTMPCOOKIE=tmp123", "SVPNCOOKIE="],
            "ret=1,redir=/remote/hostcheck_install?auth_type=16&user=x&redir=/remote/index",
        );
        match classify(&r) {
            LoginOutcome::CookieSwap { tmp_cookie, path } => {
                assert_eq!(*tmp_cookie, "tmp123");
                assert!(path.starts_with("/remote/hostcheck_install?"));
            }
            o => panic!("{o:?}"),
        }
        let done = resp(
            200,
            &["SVPNCOOKIE=sess", "SVPNTMPCOOKIE="],
            "<html>/remote/index</html>",
        );
        assert!(
            matches!(classify(&done), LoginOutcome::Authenticated { cookie } if *cookie == "sess")
        );
    }

    #[test]
    fn redirects_off_origin_are_refused() {
        for bad in [
            "https://evil.example/remote/hostcheck_install",
            "//evil.example/remote/hostcheck_install",
            "/remote/hostcheck_install/../../x",
            "/other",
        ] {
            let r = resp(200, &["SVPNTMPCOOKIE=t"], &format!("ret=1,redir={bad}"));
            assert!(
                matches!(classify(&r), LoginOutcome::Unexpected { .. }),
                "{bad}"
            );
        }
    }

    #[test]
    fn denial_and_limits() {
        let r = resp(
            200,
            &[],
            "<html><!--sslvpnerrmsg=Permission denied.--></html>",
        );
        assert_eq!(
            classify(&r),
            LoginOutcome::Denied {
                message: Some("Permission denied.".into())
            }
        );
        assert_eq!(
            classify(&resp(200, &[], "ret=0,redir=/remote/login")),
            LoginOutcome::Denied { message: None }
        );
        assert_eq!(
            classify(&resp(200, &[], "<!--fgt limit user-->")),
            LoginOutcome::LimitReached
        );
        assert_eq!(
            classify(&resp(200, &[], "<script>.CheckHostXML(\"x\")</script>")),
            LoginOutcome::HostCheckRequired
        );
        assert_eq!(
            classify(&resp(500, &[], "")),
            LoginOutcome::Unexpected { status: 500 }
        );
    }

    proptest::proptest! {
        #[test]
        fn classify_never_panics(body: String, status in 100u16..600) {
            let _ = classify(&resp(status, &["SVPNTMPCOOKIE=x"], &body));
        }
    }
}
