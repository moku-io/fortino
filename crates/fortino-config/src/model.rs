//! Profile data types and validation.
//!
//! Everything a client sends is parsed into these types with [`ProfileSpec::validate`] before
//! the daemon stores it. The daemon revalidates every proposed profile; it never trusts a
//! client's validation.

use std::collections::BTreeMap;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Default SSL VPN port.
pub const DEFAULT_VPN_PORT: u16 = 443;
/// Default EMS port.
pub const DEFAULT_EMS_PORT: u16 = 8013;
/// Maximum length of a profile name, in characters.
pub const MAX_NAME_CHARS: usize = 64;
/// Maximum length of a description or username hint, in characters.
pub const MAX_TEXT_CHARS: usize = 256;
/// Maximum length of a realm, in bytes.
pub const MAX_REALM_LEN: usize = 128;
/// Maximum length of a DNS name, in bytes.
pub const MAX_HOST_LEN: usize = 253;

/// A field-level validation error. Carries a stable code and the field name; never the value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{field}: {code}")]
pub struct FieldError {
    /// Field path, e.g. `endpoint.host`.
    pub field: String,
    /// Stable machine-readable code, e.g. `invalid_port`.
    pub code: String,
}

impl FieldError {
    /// Builds an error for `field` with `code`.
    pub fn new(field: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            code: code.into(),
        }
    }
}

/// Opaque profile identifier (a random UUID).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(pub String);

impl ProfileId {
    /// A fresh random ID.
    pub fn random() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A gateway or EMS host: a DNS name or an IPv4 literal. The original DNS name is kept for TLS
/// hostname verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Host {
    /// A DNS name, lowercased.
    Dns(String),
    /// An IPv4 literal.
    Ipv4(Ipv4Addr),
}

impl FromStr for Host {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err("empty");
        }
        if s.len() > MAX_HOST_LEN {
            return Err("too_long");
        }
        if s.starts_with('[') || s.contains(':') {
            return Err("ipv6_unsupported");
        }
        if s.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return s
                .parse::<Ipv4Addr>()
                .map(Host::Ipv4)
                .map_err(|_| "invalid_ipv4");
        }
        let name = s.strip_suffix('.').unwrap_or(s);
        for label in name.split('.') {
            let ok = !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-');
            if !ok {
                return Err("invalid_hostname");
            }
        }
        Ok(Host::Dns(name.to_ascii_lowercase()))
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::Dns(n) => f.write_str(n),
            Host::Ipv4(a) => write!(f, "{a}"),
        }
    }
}

impl TryFrom<String> for Host {
    type Error = String;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse().map_err(|e: &str| e.to_owned())
    }
}

impl From<Host> for String {
    fn from(h: Host) -> Self {
        h.to_string()
    }
}

/// Splits `host[:port]`. Returns the host part and the port, if any.
fn split_host_port(s: &str) -> Result<(&str, Option<u16>), &'static str> {
    match s.rsplit_once(':') {
        None => Ok((s, None)),
        Some((h, p)) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 5 {
                return Err("invalid_port");
            }
            let n: u32 = p.parse().map_err(|_| "invalid_port")?;
            let port = u16::try_from(n)
                .ok()
                .filter(|p| *p != 0)
                .ok_or("invalid_port")?;
            Ok((h, Some(port)))
        }
    }
}

/// An EMS server address. Parsed from `host[:port]`; the port defaults to 8013.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EmsServer {
    /// Host name or IPv4 address.
    pub host: Host,
    /// TCP port.
    pub port: u16,
}

impl FromStr for EmsServer {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.contains("://") || s.contains('/') || s.contains('@') || s.contains('?') {
            return Err("invalid_address");
        }
        if s.chars().any(char::is_control) || s.contains(char::is_whitespace) {
            return Err("invalid_address");
        }
        let (h, port) = split_host_port(s)?;
        Ok(Self {
            host: h.parse()?,
            port: port.unwrap_or(DEFAULT_EMS_PORT),
        })
    }
}

impl fmt::Display for EmsServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// One VPN gateway endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// Gateway host.
    pub host: Host,
    /// Gateway TCP port.
    pub port: u16,
    /// Realm (case preserved), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    /// EMS server for this gateway, if configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ems: Option<EmsServer>,
}

/// Validates a realm: one path segment of printable, non-space ASCII without `/?#%`.
pub fn validate_realm(r: &str) -> Result<(), &'static str> {
    if r.is_empty() {
        return Err("empty");
    }
    if r.len() > MAX_REALM_LEN {
        return Err("too_long");
    }
    let ok = r
        .bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'/' | b'?' | b'#' | b'%' | b'\\'));
    if ok { Ok(()) } else { Err("invalid_realm") }
}

/// How the user authenticates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialMode {
    /// Username and password, plus an OTP if the gateway asks for one.
    #[default]
    Password,
}

/// Which IPv4 traffic the tunnel carries. Both are IPv4-only; tunneling IPv6 is unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpPolicy {
    /// Only the routes the gateway pushes.
    #[default]
    SplitIpv4,
    /// All IPv4 traffic.
    FullIpv4,
}

impl IpPolicy {
    /// Human-readable scope.
    pub fn describe(self) -> &'static str {
        match self {
            IpPolicy::SplitIpv4 => "split IPv4 (gateway routes only)",
            IpPolicy::FullIpv4 => "full IPv4 (IPv6 not tunneled)",
        }
    }
}

/// Which resolvers answer while connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    /// As the gateway sets it: its DNS servers answer the domains it names (all names in a
    /// full tunnel); everything else keeps the Mac's resolvers.
    #[default]
    Gateway,
    /// The Mac's own resolvers answer every name; the gateway's DNS settings are not applied.
    /// Names only the VPN's DNS knows then do not resolve.
    Local,
}

impl DnsMode {
    /// Human-readable DNS choice.
    pub fn describe(self) -> &'static str {
        match self {
            DnsMode::Gateway => "as the gateway sets it",
            DnsMode::Local => "this Mac's own DNS (gateway DNS not applied)",
        }
    }
}

/// Default trust configuration ID: the shipped CA store.
pub const DEFAULT_TRUST_ID: &str = "system";

fn default_trust() -> String {
    DEFAULT_TRUST_ID.to_owned()
}

// `skip_serializing_if` passes a reference.
fn is_false(b: &bool) -> bool {
    !*b
}

/// User-editable profile fields, as sent by a client. Validate with [`ProfileSpec::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileSpec {
    /// Display name.
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional username to pre-fill.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username_hint: Option<String>,
    /// Gateway endpoint. V1 supports exactly one.
    pub endpoint: Endpoint,
    /// Authentication mode.
    #[serde(default)]
    pub credential_mode: CredentialMode,
    /// IPv4 routing policy.
    #[serde(default)]
    pub ip_policy: IpPolicy,
    /// Which resolvers answer while connected.
    #[serde(default)]
    pub dns_mode: DnsMode,
    /// Keep the password in the user's secret store (the login Keychain on macOS) and answer the
    /// password prompt with it. Only the client in the user's session reads or writes the
    /// secret; the profile store holds just this choice. Left out when false, so an older
    /// service still accepts the profile.
    #[serde(default, skip_serializing_if = "is_false")]
    pub save_password: bool,
    /// Administrator-provisioned trust configuration (CA bundle) ID.
    #[serde(default = "default_trust")]
    pub trust_id: String,
    /// Debug only: SYSINFO key/value overrides the EMS agent injects into what it reports for
    /// this profile. Empty in normal use. Keys are SYSINFO
    /// keys (`[A-Z0-9_]`); this deliberately bypasses the truthful-posture guarantee, so it is a
    /// hand-entered expert escape hatch with no field picker, kept isolated for easy removal.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub debug_ems_sysinfo: BTreeMap<String, String>,
}

/// Most debug SYSINFO overrides accepted on one profile.
pub const MAX_DEBUG_OVERRIDES: usize = 64;
/// Longest debug SYSINFO key accepted.
pub const MAX_DEBUG_KEY_LEN: usize = 64;
/// Longest debug SYSINFO value accepted.
pub const MAX_DEBUG_VALUE_LEN: usize = 4096;

/// Validates the debug SYSINFO overrides: bounded count, `[A-Z0-9_]` keys, and values with no
/// control characters. Never inspects or echoes a value.
fn validate_debug_overrides(m: &BTreeMap<String, String>) -> Result<(), FieldError> {
    if m.len() > MAX_DEBUG_OVERRIDES {
        return Err(FieldError::new("debugEmsSysinfo", "too_many"));
    }
    for (k, v) in m {
        let key_ok = !k.is_empty()
            && k.len() <= MAX_DEBUG_KEY_LEN
            && k.bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if !key_ok {
            return Err(FieldError::new("debugEmsSysinfo", "invalid_key"));
        }
        if v.len() > MAX_DEBUG_VALUE_LEN || v.bytes().any(|b| matches!(b, b'\n' | b'\r' | b'\0')) {
            return Err(FieldError::new("debugEmsSysinfo", "invalid_value"));
        }
    }
    Ok(())
}

/// Normalizes a profile name: trim, Unicode NFC, reject control characters and empty names.
pub fn normalize_name(name: &str) -> Result<String, &'static str> {
    let n: String = name.trim().nfc().collect();
    if n.is_empty() {
        return Err("empty");
    }
    if n.chars().any(char::is_control) {
        return Err("control_character");
    }
    if n.chars().count() > MAX_NAME_CHARS {
        return Err("too_long");
    }
    Ok(n)
}

/// Key used for name uniqueness: normalized and case-folded.
pub fn name_key(normalized: &str) -> String {
    normalized.to_lowercase()
}

fn clean_text(field: &str, v: Option<String>) -> Result<Option<String>, FieldError> {
    let Some(v) = v else { return Ok(None) };
    let t: String = v.trim().nfc().collect();
    if t.is_empty() {
        return Ok(None);
    }
    if t.chars().any(char::is_control) {
        return Err(FieldError::new(field, "control_character"));
    }
    if t.chars().count() > MAX_TEXT_CHARS {
        return Err(FieldError::new(field, "too_long"));
    }
    Ok(Some(t))
}

impl ProfileSpec {
    /// Builds a minimal spec for `name` and `host` with defaults.
    pub fn new(name: impl Into<String>, host: Host) -> Self {
        Self {
            name: name.into(),
            description: None,
            username_hint: None,
            endpoint: Endpoint {
                host,
                port: DEFAULT_VPN_PORT,
                realm: None,
                ems: None,
            },
            credential_mode: CredentialMode::Password,
            ip_policy: IpPolicy::SplitIpv4,
            dns_mode: DnsMode::Gateway,
            save_password: false,
            trust_id: default_trust(),
            debug_ems_sysinfo: BTreeMap::new(),
        }
    }

    /// Validates and normalizes every field. Returns the canonical spec.
    pub fn validate(self) -> Result<Self, FieldError> {
        let name = normalize_name(&self.name).map_err(|c| FieldError::new("name", c))?;
        let description = clean_text("description", self.description)?;
        let username_hint = clean_text("usernameHint", self.username_hint)?;
        if self.endpoint.port == 0 {
            return Err(FieldError::new("endpoint.port", "invalid_port"));
        }
        if let Some(r) = &self.endpoint.realm {
            validate_realm(r).map_err(|c| FieldError::new("endpoint.realm", c))?;
        }
        if let Some(ems) = &self.endpoint.ems
            && ems.port == 0
        {
            return Err(FieldError::new("endpoint.ems", "invalid_port"));
        }
        let trust_ok = !self.trust_id.is_empty()
            && self.trust_id.len() <= 64
            && self
                .trust_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !trust_ok {
            return Err(FieldError::new("trustId", "invalid_trust_id"));
        }
        validate_debug_overrides(&self.debug_ems_sysinfo)?;
        Ok(Self {
            name,
            description,
            username_hint,
            ..self
        })
    }
}

/// A stored profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    /// Opaque ID. Stable across renames and replacement.
    pub id: ProfileId,
    /// Owning UID. Set by the daemon from peer credentials, never from a message.
    pub owner: u32,
    /// Incremented on each change. Mutations must supply the expected revision.
    pub revision: u64,
    /// The profile fields.
    pub spec: ProfileSpec,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_mode_defaults_to_the_gateway_and_round_trips() {
        let old = r#"{"name":"A","endpoint":{"host":"vpn.example.com","port":443}}"#;
        let spec: ProfileSpec = serde_json::from_str(old).unwrap();
        assert_eq!(spec.dns_mode, DnsMode::Gateway);
        let mut local = spec.clone();
        local.dns_mode = DnsMode::Local;
        let json = serde_json::to_value(&local).unwrap();
        assert_eq!(json["dnsMode"], "local");
        let back: ProfileSpec = serde_json::from_value(json).unwrap();
        assert_eq!(back.dns_mode, DnsMode::Local);
        let unknown =
            r#"{"name":"A","endpoint":{"host":"vpn.example.com","port":443},"dnsMode":"vpn"}"#;
        assert!(serde_json::from_str::<ProfileSpec>(unknown).is_err());
    }

    #[test]
    fn save_password_defaults_off_and_is_omitted_when_off() {
        let old = r#"{"name":"A","endpoint":{"host":"vpn.example.com","port":443}}"#;
        let spec: ProfileSpec = serde_json::from_str(old).unwrap();
        assert!(!spec.save_password);
        let json = serde_json::to_value(&spec).unwrap();
        assert!(json.get("savePassword").is_none(), "{json}");
        let mut on = spec;
        on.save_password = true;
        let json = serde_json::to_value(&on).unwrap();
        assert_eq!(json["savePassword"], true);
        let back: ProfileSpec = serde_json::from_value(json).unwrap();
        assert!(back.save_password);
    }

    #[test]
    fn hosts() {
        assert_eq!(
            "VPN.Example.ORG".parse(),
            Ok(Host::Dns("vpn.example.org".into()))
        );
        assert_eq!(
            "10.0.0.1".parse(),
            Ok(Host::Ipv4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!("10.0.0.256".parse::<Host>(), Err("invalid_ipv4"));
        assert_eq!("[::1]".parse::<Host>(), Err("ipv6_unsupported"));
        assert_eq!("a_b.example".parse::<Host>(), Err("invalid_hostname"));
        assert_eq!("-a.example".parse::<Host>(), Err("invalid_hostname"));
        assert_eq!("".parse::<Host>(), Err("empty"));
    }

    #[test]
    fn ems_server() {
        let e: EmsServer = "ems.example.org:9016".parse().unwrap();
        assert_eq!(e.port, 9016);
        let e: EmsServer = "ems.example.org".parse().unwrap();
        assert_eq!(e.port, DEFAULT_EMS_PORT);
        assert_eq!(e.to_string(), "ems.example.org:8013");
        for bad in [
            "ems:0",
            "ems:65536",
            "ems:",
            "https://ems",
            "u@ems",
            "ems/x",
            "ems:12a",
            "",
        ] {
            assert!(bad.parse::<EmsServer>().is_err(), "{bad}");
        }
        assert_eq!("ems:65535".parse::<EmsServer>().unwrap().port, 65535);
    }

    #[test]
    fn names() {
        assert_eq!(normalize_name("  Work VPN "), Ok("Work VPN".into()));
        assert_eq!(normalize_name("   "), Err("empty"));
        assert_eq!(normalize_name("a\u{7}b"), Err("control_character"));
        // NFD "é" normalizes to NFC.
        assert_eq!(normalize_name("e\u{301}"), Ok("\u{e9}".into()));
    }

    #[test]
    fn spec_validation() {
        let mut s = ProfileSpec::new(" GATEWAY-2 ", "vpn.example.org".parse().unwrap());
        s.endpoint.realm = Some("Staff".into());
        s.description = Some("  ".into());
        let v = s.clone().validate().unwrap();
        assert_eq!(v.name, "GATEWAY-2");
        assert_eq!(v.description, None);
        assert_eq!(v.endpoint.realm.as_deref(), Some("Staff"));

        s.endpoint.realm = Some("a/b".into());
        assert_eq!(s.clone().validate().unwrap_err().field, "endpoint.realm");
        s.endpoint.realm = None;
        s.endpoint.port = 0;
        assert_eq!(s.validate().unwrap_err().code, "invalid_port");
    }

    #[test]
    fn debug_overrides_validation() {
        let base = ProfileSpec::new("x", "a.example".parse().unwrap());
        let with = |m: BTreeMap<String, String>| {
            let mut s = base.clone();
            s.debug_ems_sysinfo = m;
            s.validate()
        };
        // Accepts valid SYSINFO keys and round-trips them.
        let mut ok = BTreeMap::new();
        ok.insert("OSVER".to_string(), "macOS 26.1.0".to_string());
        ok.insert("AVSIG_VER".to_string(), "9.9.9".to_string());
        assert_eq!(with(ok.clone()).unwrap().debug_ems_sysinfo, ok);
        // Lower-case / spaced keys are rejected.
        let bad_key = BTreeMap::from([("os_ver".to_string(), "x".to_string())]);
        assert_eq!(with(bad_key).unwrap_err().code, "invalid_key");
        // Newlines in a value are rejected (they'd break SYSINFO framing).
        let bad_val = BTreeMap::from([("OSVER".to_string(), "a\nb".to_string())]);
        assert_eq!(with(bad_val).unwrap_err().code, "invalid_value");
        // Empty map is the default and serializes away.
        let j = serde_json::to_string(&base).unwrap();
        assert!(!j.contains("debugEmsSysinfo"));
        // The field round-trips through camelCase JSON.
        let full = with(ok).unwrap();
        let j = serde_json::to_string(&full).unwrap();
        assert!(j.contains("debugEmsSysinfo"));
        assert_eq!(serde_json::from_str::<ProfileSpec>(&j).unwrap(), full);
    }

    #[test]
    fn spec_json_rejects_unknown_fields() {
        let j = r#"{"name":"x","endpoint":{"host":"a.example","port":443},"bogus":1}"#;
        assert!(serde_json::from_str::<ProfileSpec>(j).is_err());
        let j = r#"{"name":"x","endpoint":{"host":"a.example","port":443}}"#;
        let s: ProfileSpec = serde_json::from_str(j).unwrap();
        assert_eq!(s.trust_id, "system");
        let j = r#"{"name":"x","endpoint":{"host":"bad host","port":443}}"#;
        assert!(serde_json::from_str::<ProfileSpec>(j).is_err());
    }
}
