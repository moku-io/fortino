//! `/remote/fortisslvpn_xml`: the tunnel settings the gateway assigns.
//!
//! Field list as observed on GATEWAY-2. Element and attribute
//! shapes follow the public openconnect/openfortivpn parsers and are synthetic in tests.
//! Unlike openfortivpn, which keeps two DNS servers and one suffix, this keeps the complete
//! per-domain split-DNS policy (tunnel-backend contract item 5).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

/// Most split routes accepted.
pub const MAX_ROUTES: usize = 1024;
/// Most DNS servers accepted (global plus split).
pub const MAX_DNS_SERVERS: usize = 8;
/// Most DNS domains accepted (suffixes plus split domains).
pub const MAX_DNS_DOMAINS: usize = 64;
/// Most split-DNS rules accepted.
pub const MAX_SPLIT_DNS: usize = 32;
/// Most XML elements read before giving up.
const MAX_ELEMENTS: usize = 16 * 1024;

/// An IPv4 prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Net {
    /// Network address (host bits cleared).
    pub addr: Ipv4Addr,
    /// Prefix length.
    pub prefix: u8,
}

impl Ipv4Net {
    /// From an address and a dotted mask. `None` for a non-contiguous mask.
    pub fn from_mask(addr: Ipv4Addr, mask: Ipv4Addr) -> Option<Self> {
        let m = u32::from(mask);
        let prefix = m.leading_ones();
        if m.checked_shl(prefix).unwrap_or(0) != 0 {
            return None;
        }
        Some(Self {
            addr: Ipv4Addr::from(u32::from(addr) & m),
            prefix: u8::try_from(prefix).ok()?,
        })
    }
}

impl std::fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// How the gateway wants to carry IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelMethod {
    /// PPP in `0x5050` frames (`/remote/sslvpn-tunnel`).
    Ppp,
    /// Raw IP.
    Tun,
    /// Anything else, verbatim (bounded).
    Other(String),
}

/// One per-domain DNS rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SplitDns {
    /// Domains resolved by these servers.
    pub domains: Vec<String>,
    /// IPv4 servers (`dnsserver1`, `dnsserver2`).
    pub servers: Vec<Ipv4Addr>,
    /// IPv6 servers.
    pub servers_v6: Vec<Ipv6Addr>,
}

/// Parsed tunnel settings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelSettings {
    /// `tunnel-method`, if present.
    pub tunnel_method: Option<TunnelMethod>,
    /// `sslvpn-tunnel dtls` attribute.
    pub dtls: bool,
    /// IPv4 address assigned to this client.
    pub assigned_v4: Option<Ipv4Addr>,
    /// IPv6 address assigned to this client.
    pub assigned_v6: Option<(Ipv6Addr, u8)>,
    /// Global DNS servers (`dns ip=`).
    pub dns: Vec<IpAddr>,
    /// DNS search suffixes (`dns domain=`).
    pub dns_suffixes: Vec<String>,
    /// Per-domain DNS rules.
    pub split_dns: Vec<SplitDns>,
    /// IPv4 routes into the tunnel (empty and `!exclude` means full tunnel).
    pub include_v4: Vec<Ipv4Net>,
    /// IPv4 routes to keep outside the tunnel (`split-tunnel-info negate='1'`).
    pub exclude_v4: Vec<Ipv4Net>,
    /// The gateway sent any IPv6 section.
    pub has_ipv6: bool,
    /// `idle-timeout val=` seconds.
    pub idle_timeout: Option<u32>,
    /// `auth-timeout val=` seconds.
    pub auth_timeout: Option<u32>,
    /// Problems that make the policy incomplete if ignored (bad masks, limits hit). A worker
    /// must refuse the session when any is set, rather than apply part of the policy.
    pub rejected: Vec<String>,
    /// Elements not understood (names only, bounded), for diagnostics.
    pub unknown: Vec<String>,
}

impl TunnelSettings {
    /// Every DNS server named anywhere.
    /// Distinct DNS server addresses named anywhere. Gateways repeat the same servers in
    /// every split-DNS rule, so a plain sum overstates them.
    pub fn dns_count(&self) -> usize {
        let mut all: Vec<IpAddr> = self.dns.clone();
        for r in &self.split_dns {
            all.extend(r.servers.iter().map(|a| IpAddr::V4(*a)));
            all.extend(r.servers_v6.iter().map(|a| IpAddr::V6(*a)));
        }
        all.sort();
        all.dedup();
        all.len()
    }

    /// Distinct server sets across split-DNS rules (1 means every rule uses the same servers).
    pub fn split_server_sets(&self) -> usize {
        let mut sets: Vec<Vec<Ipv4Addr>> = self
            .split_dns
            .iter()
            .map(|r| {
                let mut v = r.servers.clone();
                v.sort();
                v
            })
            .collect();
        sets.sort();
        sets.dedup();
        sets.len()
    }

    fn domain_count(&self) -> usize {
        self.dns_suffixes.len()
            + self
                .split_dns
                .iter()
                .map(|s| s.domains.len())
                .sum::<usize>()
    }
}

/// XML errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// Not well-formed.
    #[error("malformed tunnel settings: {0}")]
    Xml(String),
    /// No `sslvpn-tunnel` root.
    #[error("not a tunnel settings document")]
    NotSettings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    None,
    V4,
    V6,
}

/// Parses the XML body.
pub fn parse(body: &str) -> Result<TunnelSettings, ConfigError> {
    let mut r = Reader::from_str(body);
    let mut s = TunnelSettings::default();
    let mut seen_root = false;
    let mut family = Family::None;
    // Inside split-tunnel-info: Some(negate).
    let mut split: Option<bool> = None;
    let mut in_method = false;
    let mut count = 0usize;
    loop {
        let ev = r
            .read_event()
            .map_err(|e| ConfigError::Xml(e.to_string()))?;
        count += 1;
        if count > MAX_ELEMENTS {
            return Err(ConfigError::Xml("document too large".into()));
        }
        match ev {
            Event::Start(e) => {
                let name = e.name().as_ref().to_vec();
                element(&e, &name, &mut s, &mut seen_root, family, split)?;
                match name.as_slice() {
                    b"ipv4" => family = Family::V4,
                    b"ipv6" => {
                        family = Family::V6;
                        s.has_ipv6 = true;
                    }
                    b"split-tunnel-info" => {
                        split = Some(attr(&e, b"negate")?.as_deref() == Some("1"))
                    }
                    b"tunnel-method" => in_method = true,
                    _ => {}
                }
            }
            Event::Empty(e) => {
                let name = e.name().as_ref().to_vec();
                element(&e, &name, &mut s, &mut seen_root, family, split)?;
                if name == b"ipv6" {
                    s.has_ipv6 = true;
                }
            }
            Event::Text(t) if in_method && s.tunnel_method.is_none() => {
                let v = t.unescape().map_err(|e| ConfigError::Xml(e.to_string()))?;
                if !v.trim().is_empty() {
                    s.tunnel_method = Some(method(v.trim()));
                }
            }
            Event::End(e) => match e.name().as_ref() {
                b"ipv4" | b"ipv6" => family = Family::None,
                b"split-tunnel-info" => split = None,
                b"tunnel-method" => in_method = false,
                _ => {}
            },
            Event::Eof => break,
            _ => {}
        }
    }
    if !seen_root {
        return Err(ConfigError::NotSettings);
    }
    if s.dns_count() > MAX_DNS_SERVERS {
        s.rejected
            .push(format!("more than {MAX_DNS_SERVERS} DNS servers"));
    }
    if s.domain_count() > MAX_DNS_DOMAINS {
        s.rejected
            .push(format!("more than {MAX_DNS_DOMAINS} DNS domains"));
    }
    Ok(s)
}

fn method(v: &str) -> TunnelMethod {
    match v.to_ascii_lowercase().as_str() {
        "ppp" => TunnelMethod::Ppp,
        "tun" => TunnelMethod::Tun,
        _ => TunnelMethod::Other(v.chars().take(32).collect()),
    }
}

fn attr(e: &BytesStart<'_>, key: &[u8]) -> Result<Option<String>, ConfigError> {
    for a in e.attributes() {
        let a = a.map_err(|e| ConfigError::Xml(e.to_string()))?;
        if a.key.as_ref() == key {
            let v = a
                .unescape_value()
                .map_err(|e| ConfigError::Xml(e.to_string()))?;
            return Ok(Some(v.trim().chars().take(1024).collect()));
        }
    }
    Ok(None)
}

fn element(
    e: &BytesStart<'_>,
    name: &[u8],
    s: &mut TunnelSettings,
    seen_root: &mut bool,
    family: Family,
    split: Option<bool>,
) -> Result<(), ConfigError> {
    let a = |k: &[u8]| attr(e, k);
    match name {
        b"sslvpn-tunnel" => {
            *seen_root = true;
            s.dtls = a(b"dtls")?.as_deref() == Some("1");
        }
        b"tunnel-method" => {
            if let Some(v) = a(b"value")? {
                s.tunnel_method = Some(method(&v));
            }
        }
        b"assigned-addr" => {
            if let Some(v) = a(b"ipv4")? {
                match v.parse() {
                    Ok(ip) => s.assigned_v4 = Some(ip),
                    Err(_) => s.rejected.push("invalid assigned IPv4 address".into()),
                }
            }
            if let Some(v) = a(b"ipv6")? {
                let prefix = a(b"prefix-len")?
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(128);
                if let Ok(ip) = v.parse() {
                    s.assigned_v6 = Some((ip, prefix));
                }
            }
        }
        b"dns" => {
            for k in [&b"ip"[..], b"ipv6"] {
                if let Some(v) = a(k)? {
                    match v.parse::<IpAddr>() {
                        Ok(ip) if !s.dns.contains(&ip) => s.dns.push(ip),
                        Ok(_) => {}
                        Err(_) => s.rejected.push("invalid DNS server".into()),
                    }
                }
            }
            if let Some(d) = a(b"domain")? {
                for d in split_domains(&d) {
                    if !s.dns_suffixes.contains(&d) {
                        s.dns_suffixes.push(d);
                    }
                }
            }
        }
        b"split-dns" => {
            if s.split_dns.len() >= MAX_SPLIT_DNS {
                s.rejected.push("too many split-DNS rules".into());
                return Ok(());
            }
            let mut rule = SplitDns {
                domains: a(b"domains")?
                    .map(|d| split_domains(&d))
                    .unwrap_or_default(),
                ..Default::default()
            };
            for k in [&b"dnsserver1"[..], b"dnsserver2"] {
                if let Some(v) = a(k)?.filter(|v| !v.is_empty() && v != "0.0.0.0") {
                    match v.parse() {
                        Ok(ip) => rule.servers.push(ip),
                        Err(_) => s.rejected.push("invalid split-DNS server".into()),
                    }
                }
            }
            // `ipv6-dnserver2` is a typo FortiClient also accepts.
            for k in [
                &b"ipv6-dnsserver1"[..],
                b"ipv6-dnsserver2",
                b"ipv6-dnserver2",
            ] {
                if let Some(v) = a(k)?.filter(|v| !v.is_empty() && v != "::") {
                    if let Ok(ip) = v.parse() {
                        if !rule.servers_v6.contains(&ip) {
                            rule.servers_v6.push(ip);
                        }
                    }
                }
            }
            if rule.domains.is_empty() {
                s.rejected.push("split-DNS rule without domains".into());
            } else {
                s.split_dns.push(rule);
            }
        }
        b"addr" if split.is_some() => {
            let negate = split.unwrap_or(false);
            if family == Family::V6 || a(b"ipv6")?.is_some() {
                // IPv6 split routes are not applied (IPv6 is blocked); remember they existed.
                s.has_ipv6 = true;
                return Ok(());
            }
            let ip = a(b"ip")?.and_then(|v| v.parse::<Ipv4Addr>().ok());
            let mask = a(b"mask")?.and_then(|v| v.parse::<Ipv4Addr>().ok());
            match (ip, mask) {
                (Some(ip), Some(mask)) => match Ipv4Net::from_mask(ip, mask) {
                    Some(n) => {
                        let list = if negate {
                            &mut s.exclude_v4
                        } else {
                            &mut s.include_v4
                        };
                        if list.len() + 1 > MAX_ROUTES {
                            s.rejected.push(format!("more than {MAX_ROUTES} routes"));
                        } else if !list.contains(&n) {
                            list.push(n);
                        }
                    }
                    None => s.rejected.push(format!("non-contiguous mask {mask}")),
                },
                _ => s.rejected.push("invalid split route".into()),
            }
        }
        b"idle-timeout" => s.idle_timeout = a(b"val")?.and_then(|v| v.parse().ok()),
        b"auth-timeout" => s.auth_timeout = a(b"val")?.and_then(|v| v.parse().ok()),
        b"ipv4" | b"ipv6" | b"split-tunnel-info" | b"dtls-config" | b"auth-ses"
        | b"client-config" | b"fos" | b"exclusive-routing" | b"wins" | b"fct-reg" | b"addr" => {}
        other => {
            if s.unknown.len() < 32 {
                let n = String::from_utf8_lossy(other).chars().take(64).collect();
                if !s.unknown.contains(&n) {
                    s.unknown.push(n);
                }
            }
        }
    }
    Ok(())
}

/// Domains are separated by `;`, `,` or spaces. Only valid DNS names are kept.
fn split_domains(v: &str) -> Vec<String> {
    v.split([';', ',', ' '])
        .map(|d| {
            d.trim()
                .trim_start_matches("*.")
                .trim_end_matches('.')
                .to_ascii_lowercase()
        })
        .filter(|d| valid_domain(d))
        .take(MAX_DNS_DOMAINS + 1)
        .collect()
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version='1.0' encoding='utf-8'?>
<sslvpn-tunnel ver='2' dtls='1' patch='1'>
  <dtls-config heartbeat-interval='10' heartbeat-fail-count='10' heartbeat-idle-timeout='10' client-hello-timeout='10'/>
  <tunnel-method value='tun'/>
  <auth-timeout val='28800'/>
  <idle-timeout val='3600'/>
  <auth-ses check-src-ip='1' tun-connect-without-reauth='0' tun-user-ses-timeout='30'/>
  <client-config save-password='off' keep-alive='off' auto-connect='off'/>
  <ipv4>
    <assigned-addr ipv4='10.212.134.200'/>
    <dns ip='10.0.0.53'/>
    <dns ip='10.0.0.54'/>
    <dns domain='corp.example'/>
    <split-dns domains='intra.example,lab.example' dnsserver1='10.1.0.53' dnsserver2='10.1.0.54'/>
    <split-dns domains='other.example' dnsserver1='10.2.0.53' dnsserver2='0.0.0.0'/>
    <split-tunnel-info>
      <addr ip='10.0.0.0' mask='255.0.0.0'/>
      <addr ip='172.16.5.0' mask='255.255.255.0'/>
      <addr ip='192.168.1.7' mask='255.255.255.255'/>
    </split-tunnel-info>
  </ipv4>
  <future-thing x='1'/>
</sslvpn-tunnel>"#;

    #[test]
    fn full_document() {
        let s = parse(SAMPLE).unwrap();
        assert_eq!(s.tunnel_method, Some(TunnelMethod::Tun));
        assert!(s.dtls);
        assert_eq!(s.assigned_v4, Some(Ipv4Addr::new(10, 212, 134, 200)));
        assert_eq!(s.dns.len(), 2);
        assert_eq!(s.dns_suffixes, ["corp.example"]);
        assert_eq!(s.split_dns.len(), 2);
        assert_eq!(s.split_dns[0].domains, ["intra.example", "lab.example"]);
        assert_eq!(s.split_dns[0].servers.len(), 2);
        assert_eq!(s.split_dns[1].servers, [Ipv4Addr::new(10, 2, 0, 53)]);
        assert_eq!(
            s.include_v4
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.0/8", "172.16.5.0/24", "192.168.1.7/32"]
        );
        assert!(s.exclude_v4.is_empty());
        assert_eq!(s.idle_timeout, Some(3600));
        assert!(s.rejected.is_empty(), "{:?}", s.rejected);
        assert_eq!(s.unknown, ["future-thing"]);
        assert!(!s.has_ipv6);
    }

    #[test]
    fn negate_and_text_method_and_bad_mask() {
        let s = parse(
            "<sslvpn-tunnel><tunnel-method>ppp</tunnel-method><ipv4><split-tunnel-info negate='1'>\
             <addr ip='192.168.0.0' mask='255.255.0.0'/><addr ip='10.0.0.0' mask='255.0.255.0'/>\
             </split-tunnel-info></ipv4><ipv6><assigned-addr ipv6='fd00::5' prefix-len='64'/></ipv6></sslvpn-tunnel>",
        )
        .unwrap();
        assert_eq!(s.tunnel_method, Some(TunnelMethod::Ppp));
        assert_eq!(s.exclude_v4.len(), 1);
        assert_eq!(s.rejected.len(), 1);
        assert!(s.has_ipv6);
        assert_eq!(s.assigned_v6.map(|a| a.1), Some(64));
    }

    #[test]
    fn repeated_split_servers_count_once() {
        let mut x = String::from("<sslvpn-tunnel><ipv4><dns ip='10.0.0.1'/>");
        for i in 0..20 {
            x.push_str(&format!(
                "<split-dns domains='d{i}.example' dnsserver1='10.0.0.1' dnsserver2='10.0.0.2'/>"
            ));
        }
        x.push_str("</ipv4></sslvpn-tunnel>");
        let s = parse(&x).unwrap();
        assert!(s.rejected.is_empty(), "{:?}", s.rejected);
        assert_eq!(s.dns_count(), 2);
        assert_eq!(s.split_server_sets(), 1);
    }

    #[test]
    fn limits_are_reported() {
        let mut x = String::from("<sslvpn-tunnel><ipv4>");
        for i in 0..10 {
            x.push_str(&format!("<dns ip='10.0.0.{i}'/>"));
        }
        x.push_str("</ipv4></sslvpn-tunnel>");
        let s = parse(&x).unwrap();
        assert!(!s.rejected.is_empty());
    }

    #[test]
    fn not_settings() {
        assert_eq!(parse("<html/>"), Err(ConfigError::NotSettings));
        assert!(parse("<sslvpn-tunnel><ipv4></sslvpn-tunnel>").is_err());
    }

    proptest::proptest! {
        #[test]
        fn never_panics(s: String) {
            let _ = parse(&s);
        }
    }
}
