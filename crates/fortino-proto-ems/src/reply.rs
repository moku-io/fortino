//! Replies: `<REPLYTYPE>: KEY|value|…|`, and typed views of the four the agent
//! uses.
//!
//! Every typed view sorts keys into three groups: understood, refused (remote commands,
//! upgrades, forensics and AV control are never acted on) and unknown. The agent logs the names
//! of the last two; values are never logged.

use crate::fields::{Fields, ParseError};
use crate::ids::{EmsSerial, Tenant};
use crate::tags::Bits;

/// Largest reply accepted. Replies carrying a full profile are tens of kilobytes.
pub const MAX_REPLY: usize = 4 << 20;

/// A parsed reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// `FCPROBERPLY`, `FCREGRPLY`, `FCKARPLY`, `FCTAGRPLY`, …
    pub kind: String,
    /// The fields.
    pub fields: Fields,
}

/// Parses a complete reply.
pub fn parse(buf: &[u8]) -> Result<Reply, ParseError> {
    if buf.len() > MAX_REPLY {
        return Err(ParseError::TooLarge);
    }
    let text = std::str::from_utf8(buf).map_err(|_| ParseError::NotText)?;
    let text = text.trim_start_matches(|c: char| c.is_ascii_whitespace());
    let (kind, rest) = text.split_once(':').ok_or(ParseError::NoType)?;
    let kind_ok = !kind.is_empty()
        && kind.len() <= 32
        && kind
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !kind_ok {
        return Err(ParseError::NoType);
    }
    let rest = rest.strip_prefix(' ').unwrap_or(rest);
    Ok(Reply {
        kind: kind.to_owned(),
        fields: Fields::parse(rest)?,
    })
}

/// Keys that are never acted on.
pub fn is_refused(key: &str) -> bool {
    const EXACT: &[&str] = &[
        "RUN_SRV_CMD",
        "UPGRADE_PATH",
        "SCH_ID",
        "FILESHA256",
        "VULN_PATCH",
        "AVTR",
        "AV_SIG",
        "AVSCANINFO",
    ];
    const PREFIX: &[&str] = &["FSR_", "AVAL", "AVWL"];
    EXACT.contains(&key) || PREFIX.iter().any(|p| key.starts_with(p))
}

/// What a typed view did with each key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyNotes {
    /// Present and refused by policy.
    pub refused: Vec<String>,
    /// Present and not understood.
    pub unknown: Vec<String>,
}

impl KeyNotes {
    fn sort(fields: &Fields, known: &[&str]) -> Self {
        let mut notes = Self::default();
        for (k, _) in fields.iter() {
            if is_refused(k) {
                notes.refused.push(k.to_owned());
            } else if !known.contains(&k) {
                notes.unknown.push(k.to_owned());
            }
        }
        notes
    }
}

/// Errors interpreting a reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    /// The reply type is not the one expected.
    #[error("expected {expected}, got {got}")]
    Kind {
        /// Expected type.
        expected: &'static str,
        /// Received type.
        got: String,
    },
    /// A required field is missing.
    #[error("{0} missing from reply")]
    Missing(&'static str),
    /// A field is malformed.
    #[error("{0} malformed in reply")]
    Malformed(&'static str),
    /// The server is not an EMS (serial prefix check).
    #[error("server serial is not an EMS serial")]
    NotEms,
}

fn expect_kind(reply: &Reply, kind: &'static str) -> Result<(), ReplyError> {
    if reply.kind == kind {
        Ok(())
    } else {
        Err(ReplyError::Kind {
            expected: kind,
            got: reply.kind.chars().take(32).collect(),
        })
    }
}

fn num<T: std::str::FromStr>(f: &Fields, key: &'static str) -> Result<Option<T>, ReplyError> {
    f.get(key)
        .filter(|v| !v.is_empty())
        .map(|v| v.parse().map_err(|_| ReplyError::Malformed(key)))
        .transpose()
}

/// `FCPROBERPLY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReply {
    /// The server's serial, from `FGT|<serial>:<host>`.
    pub serial: EmsSerial,
    /// The host the server names itself.
    pub host: String,
    /// `EMSVER` (7002010 = 7.2.10).
    pub ems_version: Option<u32>,
    /// `PROTO_VERSION`.
    pub proto_version: Option<String>,
    /// `FEATURE_BITMAP`.
    pub feature_bitmap: Option<u64>,
    /// Keys refused or not understood.
    pub notes: KeyNotes,
}

impl ProbeReply {
    /// Interprets a reply. Rejects a server whose serial is not an EMS serial, as FortiClient does.
    pub fn from_reply(reply: &Reply) -> Result<Self, ReplyError> {
        expect_kind(reply, "FCPROBERPLY")?;
        let f = &reply.fields;
        let fgt = f.get("FGT").ok_or(ReplyError::Missing("FGT"))?;
        let (serial, host) = fgt.split_once(':').unwrap_or((fgt, ""));
        let serial = EmsSerial::parse(serial).map_err(|_| ReplyError::NotEms)?;
        Ok(Self {
            serial,
            host: host.to_owned(),
            ems_version: num(f, "EMSVER")?,
            proto_version: f.get("PROTO_VERSION").map(str::to_owned),
            feature_bitmap: num(f, "FEATURE_BITMAP")?,
            notes: KeyNotes::sort(
                f,
                &["FGT", "EMSVER", "PROTO_VERSION", "FEATURE_BITMAP", "PERCON"],
            ),
        })
    }
}

/// Profile objects EMS may push in a reply, with the checksum the client echoes back
/// Values stay encoded; the agent decodes the ones it applies.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pushed {
    /// `ZCONF` + `CSUM`: main profile.
    pub conf: Option<(String, String)>,
    /// `ZHVR` + `HVCS`: host-verification rules.
    pub host_rules: Option<(String, String)>,
    /// `ZFGTIP` + `CS`: server list.
    pub server_list: Option<(String, String)>,
    /// `ONNET` + `ONNET_CS`: on-fabric profile.
    pub on_net: Option<(String, String)>,
    /// `OFFCONF` + `OFFSUM`: off-fabric profile.
    pub off_net: Option<(String, String)>,
}

const PUSHED_KEYS: &[&str] = &[
    "ZCONF", "CSUM", "ZHVR", "HVCS", "ZFGTIP", "CS", "ONNET", "ONNET_CS", "OFFCONF", "OFFSUM",
];

impl Pushed {
    fn from_fields(f: &Fields) -> Self {
        let pair = |data: &str, sum: &str| {
            f.get(data)
                .filter(|v| !v.is_empty())
                .map(|v| (v.to_owned(), f.get(sum).unwrap_or_default().to_owned()))
        };
        Self {
            conf: pair("ZCONF", "CSUM"),
            host_rules: pair("ZHVR", "HVCS"),
            server_list: pair("ZFGTIP", "CS"),
            on_net: pair("ONNET", "ONNET_CS"),
            off_net: pair("OFFCONF", "OFFSUM"),
        }
    }
}

/// Why a registration was refused: the number before the `-` of `REG`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegStatus {
    /// 1.
    EndpointBlocked,
    /// 2.
    OutOfLicenses,
    /// 3: also sent when no key was given.
    KeyMismatch,
    /// 5.
    InvalidSite,
    /// 8.
    InvitationRequired,
    /// 9.
    InvitationInvalid,
    /// 10.
    InvitationExpired,
    /// 11.
    InvitationUsed,
    /// 12.
    InvitationTokenInvalid,
    /// 14.
    UserAuthRequired,
    /// 15.
    UserAuthBlocked,
    /// Anything else.
    Other(i64),
}

impl RegStatus {
    fn from_code(c: i64) -> Self {
        match c {
            1 => Self::EndpointBlocked,
            2 => Self::OutOfLicenses,
            3 => Self::KeyMismatch,
            5 => Self::InvalidSite,
            8 => Self::InvitationRequired,
            9 => Self::InvitationInvalid,
            10 => Self::InvitationExpired,
            11 => Self::InvitationUsed,
            12 => Self::InvitationTokenInvalid,
            14 => Self::UserAuthRequired,
            15 => Self::UserAuthBlocked,
            c => Self::Other(c),
        }
    }
}

impl std::fmt::Display for RegStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::EndpointBlocked => "the EMS blocks this endpoint",
            Self::OutOfLicenses => "the EMS has no free licence",
            Self::KeyMismatch => "a connection key is required or the key is wrong",
            Self::InvalidSite => "invalid site",
            Self::InvitationRequired => "an invitation code is required",
            Self::InvitationInvalid => "the invitation code is invalid",
            Self::InvitationExpired => "the invitation code has expired",
            Self::InvitationUsed => "the invitation code was already used",
            Self::InvitationTokenInvalid => "the invitation token is invalid",
            Self::UserAuthRequired => "the EMS requires user authentication",
            Self::UserAuthBlocked => "user authentication is blocked",
            Self::Other(c) => return write!(f, "registration failed with status {c}"),
        };
        f.write_str(s)
    }
}

/// An accepted registration: `REG|0-<serial>:<n>:<host>:<vdom>:<miniKA>:<fullKA>:…`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    /// The server serial.
    pub serial: EmsSerial,
    /// The server host.
    pub host: String,
    /// The VDOM.
    pub vdom: String,
    /// Mini keepalive interval, seconds.
    pub mini_ka: Option<u32>,
    /// Full keepalive interval, seconds.
    pub full_ka: Option<u32>,
}

/// The status FortiClient reads with `atoi`: leading digits, 0 when there are none.
fn leading_int(v: &str) -> i64 {
    let digits: String = v
        .trim_start()
        .chars()
        .take_while(char::is_ascii_digit)
        .take(9)
        .collect();
    digits.parse().unwrap_or(0)
}

fn parse_reg(v: &str) -> Result<Result<Registration, RegStatus>, ReplyError> {
    let code = leading_int(v);
    if code != 0 {
        return Ok(Err(RegStatus::from_code(code)));
    }
    let bad = || ReplyError::Malformed("REG");
    let rest = v.trim_start().strip_prefix("0-").ok_or_else(bad)?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() < 6 {
        return Err(bad());
    }
    let serial = EmsSerial::parse(parts[0]).map_err(|_| ReplyError::NotEms)?;
    let secs = |s: &str| s.parse::<u32>().ok();
    Ok(Ok(Registration {
        serial,
        host: parts[2].to_owned(),
        vdom: parts[3].to_owned(),
        mini_ka: secs(parts[4]),
        full_ka: secs(parts[5]),
    }))
}

/// `FCREGRPLY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterReply {
    /// The accepted registration, or why it was refused.
    pub outcome: Result<Registration, RegStatus>,
    /// `ERR_MSG`, if the server sent one.
    pub message: Option<String>,
    /// `NEW_GUID`: the server assigned a new endpoint UID.
    pub new_uid: Option<String>,
    /// `LIC_FEATS`.
    pub licensed_features: Option<u64>,
    /// `EMS_ONNET`.
    pub ems_on_net: Option<bool>,
    /// Pushed profile objects.
    pub pushed: Pushed,
    /// Keys refused or not understood.
    pub notes: KeyNotes,
}

impl RegisterReply {
    /// Interprets a reply.
    pub fn from_reply(reply: &Reply) -> Result<Self, ReplyError> {
        expect_kind(reply, "FCREGRPLY")?;
        let f = &reply.fields;
        let outcome = parse_reg(f.get("REG").ok_or(ReplyError::Missing("REG"))?)?;
        let message = f
            .get("ERR_MSG")
            .filter(|v| !v.is_empty())
            .map(|v| v.chars().take(512).collect());
        let mut known = vec![
            "REG",
            "ERR_MSG",
            "NEW_GUID",
            "LIC_FEATS",
            "LIC_ED",
            "SOFT_CRC",
            "EMS_ONNET",
            "PROTO_VERSION",
            "PERCON",
        ];
        known.extend_from_slice(PUSHED_KEYS);
        Ok(Self {
            outcome,
            message,
            new_uid: f
                .get("NEW_GUID")
                .filter(|v| !v.is_empty())
                .map(str::to_owned),
            licensed_features: num(f, "LIC_FEATS")?,
            ems_on_net: num::<u8>(f, "EMS_ONNET")?.map(|v| v != 0),
            pushed: Pushed::from_fields(f),
            notes: KeyNotes::sort(f, &known),
        })
    }
}

/// Quarantine state from a keepalive reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantine {
    /// `QMSG`.
    pub message: String,
    /// `QREASON`.
    pub reason: String,
}

/// `FCKARPLY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeepaliveReply {
    /// `CONT`: false means EMS dropped the endpoint.
    pub keep: bool,
    /// Serial from `EMSSN|<serial>:<host>`.
    pub serial: Option<EmsSerial>,
    /// `KA_INTERVAL`, seconds.
    pub interval: Option<u32>,
    /// `TAGS`.
    pub tags: Option<Bits>,
    /// `TENANT`.
    pub tenant: Option<Tenant>,
    /// `QUAR|1` with its message.
    pub quarantine: Option<Quarantine>,
    /// `EC_UNQUARANTINED`.
    pub unquarantined: bool,
    /// `RENEW_REG`: register again.
    pub renew: bool,
    /// `EMS_ONNET`.
    pub ems_on_net: Option<bool>,
    /// Pushed profile objects.
    pub pushed: Pushed,
    /// Keys refused or not understood.
    pub notes: KeyNotes,
}

fn flag(f: &Fields, key: &'static str) -> Result<bool, ReplyError> {
    Ok(num::<u8>(f, key)?.is_some_and(|v| v != 0))
}

impl KeepaliveReply {
    /// Interprets a reply.
    pub fn from_reply(reply: &Reply) -> Result<Self, ReplyError> {
        expect_kind(reply, "FCKARPLY")?;
        let f = &reply.fields;
        let keep = num::<u8>(f, "CONT")?.ok_or(ReplyError::Missing("CONT"))? != 0;
        let serial = f
            .get("EMSSN")
            .filter(|v| !v.is_empty())
            .map(|v| EmsSerial::parse(v.split(':').next().unwrap_or(v)))
            .transpose()
            .map_err(|_| ReplyError::NotEms)?;
        let tags = f
            .get("TAGS")
            .filter(|v| !v.is_empty())
            .map(Bits::parse)
            .transpose()
            .map_err(|_| ReplyError::Malformed("TAGS"))?;
        let tenant = f
            .get("TENANT")
            .filter(|v| !v.is_empty())
            .map(Tenant::parse)
            .transpose()
            .map_err(|_| ReplyError::Malformed("TENANT"))?;
        let text = |k: &str| f.get(k).unwrap_or_default().chars().take(512).collect();
        let quarantine = flag(f, "QUAR")?.then(|| Quarantine {
            message: text("QMSG"),
            reason: text("QREASON"),
        });
        let mut known = vec![
            "CONT",
            "EMSSN",
            "UPLD_PRT",
            "KA_INTERVAL",
            "LIC_FEATS",
            "LIC_ED",
            "SNAPTIME",
            "QUAR",
            "QCODE",
            "QMSG",
            "QREASON",
            "EC_UNQUARANTINED",
            "EMS_ONNET",
            "TAGS",
            "SERIAL",
            "TENANT",
            "PROTO_VERSION",
            "PERCON",
            "ZTNATOKENSUPPORT",
            "EMSVER",
            "EMS_CAPS",
            "VDOM",
            "RENEW_REG",
        ];
        known.extend_from_slice(PUSHED_KEYS);
        Ok(Self {
            keep,
            serial,
            interval: num(f, "KA_INTERVAL")?,
            tags,
            tenant,
            quarantine,
            unquarantined: flag(f, "EC_UNQUARANTINED")?,
            renew: flag(f, "RENEW_REG")?,
            ems_on_net: num::<u8>(f, "EMS_ONNET")?.map(|v| v != 0),
            pushed: Pushed::from_fields(f),
            notes: KeyNotes::sort(f, &known),
        })
    }
}

/// `FCTAGRPLY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagReply {
    /// `TAGS`.
    pub tags: Option<Bits>,
    /// `ERR`, when not empty or zero.
    pub error: Option<String>,
    /// Keys refused or not understood.
    pub notes: KeyNotes,
}

impl TagReply {
    /// Interprets a reply.
    pub fn from_reply(reply: &Reply) -> Result<Self, ReplyError> {
        expect_kind(reply, "FCTAGRPLY")?;
        let f = &reply.fields;
        let tags = f
            .get("TAGS")
            .filter(|v| !v.is_empty())
            .map(Bits::parse)
            .transpose()
            .map_err(|_| ReplyError::Malformed("TAGS"))?;
        Ok(Self {
            tags,
            error: f
                .get("ERR")
                .filter(|v| !v.is_empty() && *v != "0")
                .map(|v| v.chars().take(512).collect()),
            notes: KeyNotes::sort(f, &["TAGS", "ERR", "PROTO_VERSION", "PERCON", "VDOM"]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Reply {
        parse(s.as_bytes()).unwrap()
    }

    #[test]
    fn probe_reply() {
        let r = p(
            "FCPROBERPLY: FGT|FCTEMS0000000001:ems.example.test|FEATURE_BITMAP|7|EMSVER|7002010|PROTO_VERSION|1.0.1|PERCON|0|\n",
        );
        let pr = ProbeReply::from_reply(&r).unwrap();
        assert_eq!(pr.serial.as_str(), "FCTEMS0000000001");
        assert_eq!(pr.host, "ems.example.test");
        assert_eq!(pr.ems_version, Some(7_002_010));
        assert!(pr.notes.unknown.is_empty());
    }

    #[test]
    fn probe_rejects_non_ems() {
        let r = p("FCPROBERPLY: FGT|FGT60F0000000001:fw|");
        assert_eq!(ProbeReply::from_reply(&r), Err(ReplyError::NotEms));
    }

    #[test]
    fn keepalive_reply() {
        let blob = crate::blob::encode(b"<forticlient_configuration/>");
        let s = format!(
            "FCKARPLY: CONT|1|EMSSN|FCTEMS0000000001:ems.example.test|KA_INTERVAL|60|QUAR|0|TAGS|0000000010|TENANT|{}|RUN_SRV_CMD|x|FSR_UPLD_TOKEN|y|NEWTHING|z|ZHVR|{blob}|HVCS|abc|PERCON|0|",
            "0".repeat(32)
        );
        let ka = KeepaliveReply::from_reply(&p(&s)).unwrap();
        assert!(ka.keep);
        assert_eq!(ka.interval, Some(60));
        assert!(ka.tags.unwrap().get(8));
        assert_eq!(ka.tenant, Some(Tenant::on_premises()));
        assert!(ka.quarantine.is_none());
        assert_eq!(ka.notes.refused, vec!["RUN_SRV_CMD", "FSR_UPLD_TOKEN"]);
        assert_eq!(ka.notes.unknown, vec!["NEWTHING"]);
        assert_eq!(ka.pushed.host_rules.unwrap().1, "abc");
    }

    #[test]
    fn keepalive_dropped_and_quarantined() {
        let ka = KeepaliveReply::from_reply(&p("FCKARPLY: CONT|0|")).unwrap();
        assert!(!ka.keep);
        let ka = KeepaliveReply::from_reply(&p(
            "FCKARPLY: CONT|1|QUAR|1|QCODE|secret|QMSG|Isolated|QREASON|policy|",
        ))
        .unwrap();
        assert_eq!(ka.quarantine.unwrap().message, "Isolated");
    }

    #[test]
    fn register_reply() {
        let r = p(
            "FCREGRPLY: REG|0-FCTEMS0000000001:1:ems.example.test:default:60:43230:0:0:995|LIC_FEATS|5|\r\n",
        );
        let reg = RegisterReply::from_reply(&r).unwrap().outcome.unwrap();
        assert_eq!(reg.host, "ems.example.test");
        assert_eq!(reg.mini_ka, Some(60));
        assert_eq!(reg.full_ka, Some(43_230));
        let r = p("FCREGRPLY: REG|3|ERR_MSG|Connection key mismatch|");
        let rr = RegisterReply::from_reply(&r).unwrap();
        assert_eq!(rr.outcome, Err(RegStatus::KeyMismatch));
        assert_eq!(rr.message.as_deref(), Some("Connection key mismatch"));
        let r = p("FCREGRPLY: REG|14-x|");
        assert_eq!(
            RegisterReply::from_reply(&r).unwrap().outcome,
            Err(RegStatus::UserAuthRequired)
        );
        assert!(RegisterReply::from_reply(&p("FCREGRPLY: PERCON|0|")).is_err());
        assert!(RegisterReply::from_reply(&p("FCREGRPLY: REG|0-x|")).is_err());
    }

    #[test]
    fn wrong_kind() {
        assert!(TagReply::from_reply(&p("FCKARPLY: CONT|1|")).is_err());
    }

    #[test]
    fn junk_is_an_error() {
        assert!(parse(b"HTTP/1.1 400 Bad Request\r\n").is_err());
        assert!(parse(b"").is_err());
        assert!(parse(&[0xff, 0xfe]).is_err());
    }
}
