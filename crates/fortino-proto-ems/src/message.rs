//! Requests:
//!
//! ```text
//! MSG_HEADER: FCTUID=<uid>\n        header lines KEY=value\n (LF only)
//! …
//! SIZE=<8 digits>\n                  exact byte length of the whole message
//! \r\n
//! X-FCCK-<TYPE>: KEY|value|…|
//! \r\n
//! X-FCCK-<TYPE>-END\r\n
//! \r\n
//! ```
//!
//! `X-FCCK-TAG` is different: no `MSG_HEADER` and no `SIZE`, see [`encode_tag`].

use std::net::Ipv4Addr;

use zeroize::Zeroizing;

use crate::fields::{FieldError, Fields};
use crate::ids::{EmsSerial, Mac, Uid};
use crate::sysinfo::SysInfo;

/// `PROTO_VER` sent by FortiClient 7.4.
pub const PROTO_VER: &str = "1.0.1";

/// Width of the `SIZE` value (decimal, space-padded to eight characters).
const SIZE_WIDTH: usize = 8;

/// `SIZE` is the exact length of the message. FortiClient's own log can show a
/// smaller value because it censors its log copy; the wire carries the exact length.
pub const SIZE_DELTA: usize = 0;

/// Request types that use `MSG_HEADER`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Server check before registering.
    Probe,
    /// Registration.
    Register,
    /// Mini or full keepalive, and deregistration.
    Keepalive,
}

impl Kind {
    /// The `X-FCCK-` suffix.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Probe => "PROBE",
            Self::Register => "REGISTER",
            Self::Keepalive => "KA",
        }
    }
}

/// Errors building a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// A header value has a line break or NUL.
    #[error("header {0} contains a line break")]
    Header(&'static str),
    /// A body field is invalid.
    #[error(transparent)]
    Field(#[from] FieldError),
    /// The message does not fit in `SIZE`.
    #[error("message too large")]
    TooLarge,
}

/// The `MSG_HEADER` values. `FCTVER` and `CAPS` come from the declared compatibility profile;
/// everything else describes this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// `FCTUID`.
    pub uid: Uid,
    /// `FCTVER`.
    pub version: String,
    /// `EMSSN`: only once registered to this server.
    pub serial: Option<EmsSerial>,
    /// `IP`: the address of the default-route interface.
    pub ip: Ipv4Addr,
    /// `MAC` of that interface.
    pub mac: Mac,
    /// `FCT_ONNET`.
    pub on_net: bool,
    /// `CAPS`.
    pub caps: u32,
    /// `VDOM`.
    pub vdom: String,
    /// `EC_QUARANTINED`.
    pub quarantined: bool,
}

fn line(out: &mut Vec<u8>, name: &'static str, value: &str) -> Result<(), BuildError> {
    if value.contains(['\n', '\r', '\0']) {
        return Err(BuildError::Header(name));
    }
    out.extend_from_slice(name.as_bytes());
    out.push(b'=');
    out.extend_from_slice(value.as_bytes());
    out.push(b'\n');
    Ok(())
}

/// Like [`line`], but leaves the line out when the value is empty, as FortiClient does for
/// string-valued header fields.
fn opt_line(out: &mut Vec<u8>, name: &'static str, value: &str) -> Result<(), BuildError> {
    if value.is_empty() {
        Ok(())
    } else {
        line(out, name, value)
    }
}

fn flag(b: bool) -> &'static str {
    if b { "1" } else { "0" }
}

/// Encodes a request. The result is wiped on drop: a REGISTER may carry a key.
pub fn encode(
    header: &Header,
    kind: Kind,
    body: &Fields,
) -> Result<Zeroizing<Vec<u8>>, BuildError> {
    let mut out = Zeroizing::new(Vec::with_capacity(512));
    out.extend_from_slice(b"MSG_HEADER: ");
    line(&mut out, "FCTUID", header.uid.as_str())?;
    line(&mut out, "FCTVER", &header.version)?;
    if let Some(sn) = &header.serial {
        line(&mut out, "EMSSN", sn.as_str())?;
    }
    line(&mut out, "PROTO_VER", PROTO_VER)?;
    if !header.ip.is_unspecified() {
        line(&mut out, "IP", &header.ip.to_string())?;
    }
    if header.mac != Mac::default() {
        line(&mut out, "MAC", &header.mac.to_string())?;
    }
    line(&mut out, "FCT_ONNET", flag(header.on_net))?;
    line(&mut out, "CAPS", &header.caps.to_string())?;
    opt_line(&mut out, "VDOM", &header.vdom)?;
    line(&mut out, "EC_QUARANTINED", flag(header.quarantined))?;
    out.extend_from_slice(b"SIZE=");
    let size_at = out.len();
    out.extend_from_slice(&[b'x'; SIZE_WIDTH]);
    out.extend_from_slice(b"\n\r\n");

    let tag = kind.as_str();
    out.extend_from_slice(b"X-FCCK-");
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(b": ");
    body.encode_into(&mut out);
    out.extend_from_slice(b"\r\nX-FCCK-");
    out.extend_from_slice(tag.as_bytes());
    out.extend_from_slice(b"-END\r\n\r\n");

    let size = format!("{:>width$}", out.len() + SIZE_DELTA, width = SIZE_WIDTH);
    if size.len() != SIZE_WIDTH {
        return Err(BuildError::TooLarge);
    }
    out[size_at..size_at + SIZE_WIDTH].copy_from_slice(size.as_bytes());
    Ok(out)
}

/// The `X-FCCK-TAG` request: host-verification results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagRequest {
    /// `UID`.
    pub uid: Uid,
    /// `FCTVER`.
    pub version: String,
    /// `EMSSN`.
    pub serial: EmsSerial,
    /// `VDOM`.
    pub vdom: String,
    /// `IP`.
    pub ip: Ipv4Addr,
    /// `MAC`.
    pub mac: Mac,
    /// `NWIFS`.
    pub nwifs: String,
    /// `RULES` bitstring.
    pub rules: String,
    /// `CAPS`.
    pub caps: u32,
}

/// Encodes `X-FCCK-TAG`: no `MSG_HEADER` and no `SIZE`, just `KEY=value` lines between the
/// opening `X-FCCK-TAG: UID=<uid>` line and `X-FCCK-TAG-END`.
pub fn encode_tag(t: &TagRequest) -> Result<Zeroizing<Vec<u8>>, BuildError> {
    let mut out = Zeroizing::new(Vec::with_capacity(256));
    out.extend_from_slice(b"X-FCCK-TAG: ");
    line(&mut out, "UID", t.uid.as_str())?;
    line(&mut out, "FCTVER", &t.version)?;
    line(&mut out, "EMSSN", t.serial.as_str())?;
    line(&mut out, "PROTO_VER", PROTO_VER)?;
    opt_line(&mut out, "VDOM", &t.vdom)?;
    line(&mut out, "IP", &t.ip.to_string())?;
    line(&mut out, "MAC", &t.mac.to_string())?;
    opt_line(&mut out, "NWIFS", &t.nwifs)?;
    line(&mut out, "RULES", &t.rules)?;
    line(&mut out, "CAPS", &t.caps.to_string())?;
    out.extend_from_slice(b"X-FCCK-TAG-END\r\n\r\n");
    Ok(out)
}

/// `X-FCCK-PROBE` body.
pub fn probe() -> Fields {
    let mut f = Fields::new();
    // Constant key and value: cannot fail.
    let _ = f.push("PROBE_FEATURE_BITMAP", "1");
    f
}

/// `X-FCCK-REGISTER` body: only `SYSINFO`. A connection key travels inside it as `REG_KEY`, in
/// clear within the base64.
pub fn register(sysinfo: &SysInfo, key: Option<&str>) -> Result<Fields, BuildError> {
    let mut s = sysinfo.clone();
    if let Some(key) = key {
        s.push("REG_KEY", key)
            .map_err(|_| BuildError::Header("REG_KEY"))?;
    }
    let mut f = Fields::new();
    f.push("SYSINFO", s.encode())?;
    Ok(f)
}

/// The user identity reported in keepalives. Empty strings when unknown.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct User {
    /// `USR_NAME`.
    pub name: String,
    /// `USR_EMAIL`.
    pub email: String,
    /// `PHONE`.
    pub phone: String,
    /// `SERVICE`.
    pub service: String,
}

/// `X-FCCK-KA` body for a mini or full keepalive (the difference is the SYSINFO contents).
pub fn keepalive(sysinfo: &SysInfo, user: &User) -> Result<Fields, BuildError> {
    let mut f = Fields::new();
    f.push("SYSINFO", sysinfo.encode())?;
    f.push("USR_NAME", user.name.as_str())?;
    f.push("USR_EMAIL", user.email.as_str())?;
    f.push("PHONE", user.phone.as_str())?;
    f.push("SERVICE", user.service.as_str())?;
    Ok(f)
}

/// Deregistration: a keepalive whose SYSINFO holds only `HOSTNAME` and `FCT_UNREG=<uid>`.
pub fn deregister(hostname: &str, uid: &Uid) -> Result<Fields, BuildError> {
    let mut s = SysInfo::new();
    s.push("HOSTNAME", hostname)
        .map_err(|_| BuildError::Header("HOSTNAME"))?;
    s.push("FCT_UNREG", uid.as_str())
        .map_err(|_| BuildError::Header("FCT_UNREG"))?;
    let mut f = Fields::new();
    f.push("SYSINFO", s.encode())?;
    Ok(f)
}

/// Largest request the server side accepts.
pub const MAX_REQUEST: usize = 1 << 20;

/// A request as a server reads it. Used by the mock EMS and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Header lines in order (`MSG_HEADER` block, or the `KEY=value` lines of a TAG).
    pub header: Vec<(String, String)>,
    /// The `X-FCCK-` suffix (`PROBE`, `KA`, `TAG`, …).
    pub kind: String,
    /// The body (empty for TAG).
    pub fields: Fields,
    /// Bytes consumed.
    pub len: usize,
}

impl Request {
    /// First header value for `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.header
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Errors reading a request.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RequestError {
    /// The `-END` line has not arrived yet.
    #[error("incomplete request")]
    Incomplete,
    /// Larger than [`MAX_REQUEST`].
    #[error("request too large")]
    TooLarge,
    /// Not the expected layout.
    #[error("malformed request: {0}")]
    Malformed(&'static str),
}

fn header_lines(block: &str) -> Result<Vec<(String, String)>, RequestError> {
    block
        .lines()
        .map(|l| {
            l.split_once('=')
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .ok_or(RequestError::Malformed("header line"))
        })
        .collect()
}

/// Parses one request. Returns [`RequestError::Incomplete`] until the closing `-END` trailer
/// is in `buf`.
pub fn parse_request(buf: &[u8]) -> Result<Request, RequestError> {
    if buf.len() > MAX_REQUEST {
        return Err(RequestError::TooLarge);
    }
    let text = match std::str::from_utf8(buf) {
        Ok(t) => t,
        // A read may end inside a multi-byte character.
        Err(e) if e.error_len().is_none() => return Err(RequestError::Incomplete),
        Err(_) => return Err(RequestError::Malformed("not text")),
    };
    const MSG: &str = "MSG_HEADER: ";
    const TAG: &str = "X-FCCK-TAG: ";
    if text.len() < MSG.len() && (MSG.starts_with(text) || TAG.starts_with(text)) {
        return Err(RequestError::Incomplete);
    }
    if let Some(rest) = text.strip_prefix(TAG) {
        const END: &str = "X-FCCK-TAG-END\r\n\r\n";
        let at = rest.find(END).ok_or(RequestError::Incomplete)?;
        return Ok(Request {
            header: header_lines(rest.get(..at).unwrap_or_default())?,
            kind: "TAG".into(),
            fields: Fields::new(),
            len: TAG.len() + at + END.len(),
        });
    }
    let rest = text
        .strip_prefix(MSG)
        .ok_or(RequestError::Malformed("no MSG_HEADER"))?;
    let (head, rest) = rest.split_once("\n\r\n").ok_or(RequestError::Incomplete)?;
    let header = header_lines(head)?;
    let rest = rest
        .strip_prefix("X-FCCK-")
        .ok_or(RequestError::Malformed("no X-FCCK line"))?;
    let Some((kind, body)) = rest.split_once(": ") else {
        return if rest.len() < 40 && !rest.contains('\n') {
            Err(RequestError::Incomplete)
        } else {
            Err(RequestError::Malformed("no type"))
        };
    };
    if kind.is_empty() || kind.len() > 32 || !kind.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(RequestError::Malformed("type"));
    }
    let end = format!("\r\nX-FCCK-{kind}-END\r\n\r\n");
    let at = body.find(&end).ok_or(RequestError::Incomplete)?;
    let fields = Fields::parse(body.get(..at).unwrap_or_default())
        .map_err(|_| RequestError::Malformed("body"))?;
    let len = text.len() - body.len() + at + end.len();
    Ok(Request {
        header,
        kind: kind.to_owned(),
        fields,
        len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn header() -> Header {
        Header {
            uid: Uid::parse("0A1B2C3D4E5F60718293A4B5C6D7E8F9").unwrap(),
            version: "7.4.4.1831".into(),
            serial: None,
            ip: Ipv4Addr::new(192, 0, 2, 10),
            mac: Mac([0xaa, 0xbb, 0xcc, 0, 0, 1]),
            on_net: false,
            caps: 0,
            vdom: "default".into(),
            quarantined: false,
        }
    }

    #[test]
    fn probe_layout() {
        let msg = encode(&header(), Kind::Probe, &probe()).unwrap();
        let text = std::str::from_utf8(&msg).unwrap();
        assert!(text.starts_with("MSG_HEADER: FCTUID=0A1B2C3D4E5F60718293A4B5C6D7E8F9\nFCTVER="));
        assert!(!text.contains("EMSSN="));
        assert!(text.contains(
            "\nIP=192.0.2.10\nMAC=aa-bb-cc-00-00-01\nFCT_ONNET=0\nCAPS=0\nVDOM=default\nEC_QUARANTINED=0\nSIZE="
        ));
        assert!(
            text.ends_with(
                "\n\r\nX-FCCK-PROBE: PROBE_FEATURE_BITMAP|1|\r\nX-FCCK-PROBE-END\r\n\r\n"
            )
        );
        let size: usize = text
            .split("SIZE=")
            .nth(1)
            .unwrap()
            .get(..8)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(size, text.len());
    }

    #[test]
    fn serial_once_registered() {
        let mut h = header();
        h.serial = Some(EmsSerial::parse("FCTEMS0000000001").unwrap());
        let msg = encode(&h, Kind::Keepalive, &Fields::new()).unwrap();
        let text = std::str::from_utf8(&msg).unwrap();
        assert!(text.contains("\nFCTVER=7.4.4.1831\nEMSSN=FCTEMS0000000001\nPROTO_VER=1.0.1\n"));
    }

    #[test]
    fn header_injection_refused() {
        let mut h = header();
        h.vdom = "default\nEMSSN=x".into();
        assert_eq!(
            encode(&h, Kind::Probe, &probe()).err(),
            Some(BuildError::Header("VDOM"))
        );
    }

    #[test]
    fn server_reads_what_client_writes() {
        let body = keepalive(&SysInfo::new(), &User::default()).unwrap();
        let msg = encode(&header(), Kind::Keepalive, &body).unwrap();
        for cut in [0, 10, 11, 12, msg.len() / 2, msg.len() - 2] {
            assert_eq!(
                parse_request(&msg[..cut]).err(),
                Some(RequestError::Incomplete),
                "cut at {cut}"
            );
        }
        let req = parse_request(&msg).unwrap();
        assert_eq!(req.kind, "KA");
        assert_eq!(req.len, msg.len());
        assert_eq!(req.header("FCTUID"), Some(header().uid.as_str()));
        assert_eq!(req.fields, body);
    }

    #[test]
    fn tag_layout() {
        let t = TagRequest {
            uid: header().uid,
            version: "7.4.4.1831".into(),
            serial: EmsSerial::parse("FCTEMS0000000001").unwrap(),
            vdom: "default".into(),
            ip: Ipv4Addr::new(192, 0, 2, 10),
            mac: Mac([0xaa, 0xbb, 0xcc, 0, 0, 1]),
            nwifs: "en0|192.0.2.10|AA:BB:CC:00:00:01|*|*|1|*|0".into(),
            rules: "010".into(),
            caps: 0,
        };
        let msg = encode_tag(&t).unwrap();
        let text = std::str::from_utf8(&msg).unwrap();
        assert!(text.starts_with("X-FCCK-TAG: UID=0A1B2C3D4E5F60718293A4B5C6D7E8F9\nFCTVER="));
        assert!(!text.contains("SIZE="));
        assert!(text.ends_with("\nRULES=010\nCAPS=0\nX-FCCK-TAG-END\r\n\r\n"));
        let req = parse_request(&msg).unwrap();
        assert_eq!(req.kind, "TAG");
        assert_eq!(req.header("RULES"), Some("010"));
        assert_eq!(req.len, msg.len());
        assert_eq!(
            parse_request(&msg[..msg.len() - 1]).err(),
            Some(RequestError::Incomplete)
        );
    }

    #[test]
    fn register_key_inside_sysinfo() {
        let mut s = SysInfo::new();
        s.push("HOSTNAME", "mac-01").unwrap();
        let f = register(&s, Some("k3y")).unwrap();
        assert_eq!(f.iter().map(|(k, _)| k).collect::<Vec<_>>(), ["SYSINFO"]);
        let inner = SysInfo::decode(f.get("SYSINFO").unwrap()).unwrap();
        assert_eq!(inner.get("REG_KEY"), Some("k3y"));
    }

    #[test]
    fn deregister_sysinfo() {
        let f = deregister("mac-01", &header().uid).unwrap();
        let s = SysInfo::decode(f.get("SYSINFO").unwrap()).unwrap();
        assert_eq!(s.get("FCT_UNREG"), Some("0A1B2C3D4E5F60718293A4B5C6D7E8F9"));
        assert_eq!(s.iter().count(), 2);
    }
}
