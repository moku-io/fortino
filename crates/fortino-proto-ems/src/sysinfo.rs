//! `SYSINFO`: base64 of `KEY=VALUE\n` lines.
//!
//! This module only frames what it is given. What goes in is decided by the agent, which must
//! report truthfully: no AV, firewall or feature the client does not have.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::fields::valid_key;

/// Most lines accepted when decoding (mock EMS and tests).
pub const MAX_LINES: usize = 256;
/// Longest value accepted.
pub const MAX_VALUE: usize = 16 * 1024;

/// Errors building or decoding SYSINFO.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SysInfoError {
    /// Key not `[A-Z0-9_]`.
    #[error("invalid SYSINFO key {0:?}")]
    Key(String),
    /// Value contains a line break or NUL, or is too long.
    #[error("invalid SYSINFO value for {0}")]
    Value(String),
    /// Not base64, not UTF-8, or not `KEY=VALUE` lines.
    #[error("malformed SYSINFO")]
    Malformed,
}

/// SYSINFO entries. FortiClient keeps them in a hash map, so order carries no meaning; this
/// keeps insertion order for stable tests. Values are wiped on drop: REGISTER puts the
/// connection key in here.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SysInfo(Vec<(String, String)>);

impl std::fmt::Debug for SysInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(|(k, _)| k))
            .finish()
    }
}

impl Drop for SysInfo {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for (_, v) in &mut self.0 {
            v.zeroize();
        }
    }
}

impl SysInfo {
    /// Empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends an entry.
    pub fn push(&mut self, key: &str, value: impl Into<String>) -> Result<(), SysInfoError> {
        if !valid_key(key) {
            return Err(SysInfoError::Key(key.to_owned()));
        }
        let value = value.into();
        if value.len() > MAX_VALUE || value.contains(['\n', '\r', '\0']) {
            return Err(SysInfoError::Value(key.to_owned()));
        }
        self.0.push((key.to_owned(), value));
        Ok(())
    }

    /// First value for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Entries in order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The plain `KEY=VALUE\n` text.
    pub fn to_text(&self) -> zeroize::Zeroizing<String> {
        let mut s = zeroize::Zeroizing::new(String::new());
        for (k, v) in &self.0 {
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push('\n');
        }
        s
    }

    /// The `SYSINFO` field value.
    pub fn encode(&self) -> String {
        STANDARD.encode(self.to_text().as_bytes())
    }

    /// Decodes a `SYSINFO` value (mock EMS and tests).
    pub fn decode(value: &str) -> Result<Self, SysInfoError> {
        let raw = STANDARD
            .decode(value.trim())
            .map_err(|_| SysInfoError::Malformed)?;
        let text = String::from_utf8(raw).map_err(|_| SysInfoError::Malformed)?;
        let mut out = Self::new();
        for line in text.lines() {
            if out.0.len() == MAX_LINES {
                return Err(SysInfoError::Malformed);
            }
            let (k, v) = line.split_once('=').ok_or(SysInfoError::Malformed)?;
            out.push(k, v)?;
        }
        Ok(out)
    }
}

/// One `NWIFS` record:
/// `urlenc(ifname)|ip|MAC|gw_ip|gw_MAC|1|urlenc(SSID)|is_vpn`, MACs upper-case with colons,
/// empty values and all-zero MACs written as `*`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetIf {
    /// Interface name (`en0`).
    pub name: String,
    /// IPv4 address.
    pub ip: std::net::Ipv4Addr,
    /// Interface MAC.
    pub mac: crate::ids::Mac,
    /// Default gateway on this interface, if any.
    pub gateway: Option<std::net::Ipv4Addr>,
    /// Gateway MAC, if known.
    pub gateway_mac: Option<crate::ids::Mac>,
    /// Wi-Fi network name, if known.
    pub ssid: Option<String>,
    /// The interface is a VPN tunnel.
    pub is_vpn: bool,
}

/// Most records sent.
pub const MAX_NWIFS: usize = 32;

fn urlenc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn nw_mac(m: Option<crate::ids::Mac>) -> String {
    match m {
        Some(m) if m.0 != [0; 6] => {
            let [a, b, c, d, e, g] = m.0;
            format!("{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
        }
        _ => "*".into(),
    }
}

fn star(s: String) -> String {
    if s.is_empty() { "*".into() } else { s }
}

/// Formats `NWIFS`: up to [`MAX_NWIFS`] records joined by `;`.
pub fn nwifs(ifs: &[NetIf]) -> String {
    ifs.iter()
        .take(MAX_NWIFS)
        .map(|i| {
            [
                star(urlenc(&i.name)),
                i.ip.to_string(),
                nw_mac(Some(i.mac)),
                star(i.gateway.map(|g| g.to_string()).unwrap_or_default()),
                nw_mac(i.gateway_mac),
                // Always 1 in FortiClient.
                "1".into(),
                star(i.ssid.as_deref().map(urlenc).unwrap_or_default()),
                u8::from(i.is_vpn).to_string(),
            ]
            .join("|")
        })
        .collect::<Vec<_>>()
        .join(";")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_is_base64_of_lines() {
        let mut s = SysInfo::new();
        s.push("HOSTNAME", "mac-01").unwrap();
        s.push("FCTOS", "OSX00").unwrap();
        assert_eq!(s.to_text().as_str(), "HOSTNAME=mac-01\nFCTOS=OSX00\n");
        assert_eq!(SysInfo::decode(&s.encode()).unwrap(), s);
    }

    #[test]
    fn values_with_equals_survive() {
        let mut s = SysInfo::new();
        s.push("X", "a=b").unwrap();
        assert_eq!(SysInfo::decode(&s.encode()).unwrap().get("X"), Some("a=b"));
    }

    #[test]
    fn refuses_line_breaks() {
        let mut s = SysInfo::new();
        assert!(s.push("X", "a\nY=b").is_err());
        assert!(s.push("x", "a").is_err());
    }

    #[test]
    fn nwifs_format() {
        let i = NetIf {
            name: "en0".into(),
            ip: "192.0.2.10".parse().unwrap(),
            mac: crate::ids::Mac([0xaa, 0, 0, 0, 0, 1]),
            gateway: Some("192.0.2.1".parse().unwrap()),
            gateway_mac: None,
            ssid: Some("Home Net".into()),
            is_vpn: false,
        };
        let mut t = i.clone();
        t.name = "utun3".into();
        t.gateway = None;
        t.ssid = None;
        t.is_vpn = true;
        assert_eq!(
            nwifs(&[i, t]),
            "en0|192.0.2.10|AA:00:00:00:00:01|192.0.2.1|*|1|Home%20Net|0;utun3|192.0.2.10|AA:00:00:00:00:01|*|*|1|*|1"
        );
    }
}
