//! FortiClient XML profile import (client side).
//!
//! Parses a plain XML export in the invoking user's process and produces a [`Preview`]: the
//! eligible [`ProfileSpec`]s plus skipped, blocked and rejected entries with reasons. Account
//! material (usernames, passwords), hooks and UI preferences are discarded. Errors carry codes,
//! ordinals and field names, never raw field values.

use std::collections::HashMap;
use std::fmt;

use quick_xml::Reader;
use quick_xml::events::Event;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::model::{
    DEFAULT_VPN_PORT, Endpoint, Host, ProfileSpec, name_key, normalize_name, validate_realm,
};

/// Maximum input size.
pub const MAX_INPUT: usize = 8 * 1024 * 1024;
/// Maximum element nesting.
pub const MAX_DEPTH: usize = 64;
/// Maximum SSL VPN connections.
pub const MAX_CONNECTIONS: usize = 256;

/// Whole-file errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    /// Not a plain FortiClient XML configuration.
    #[error("unsupported format: supply a plain (unencrypted) FortiClient XML export")]
    UnsupportedFormat,
    /// Larger than [`MAX_INPUT`].
    #[error("file is larger than 8 MiB")]
    TooLarge,
    /// Nesting deeper than [`MAX_DEPTH`].
    #[error("XML nesting is too deep")]
    TooDeep,
    /// More than [`MAX_CONNECTIONS`] connections.
    #[error("too many connections (limit 256)")]
    TooManyConnections,
    /// DTDs and entity declarations are not accepted.
    #[error("XML document type declarations are not accepted")]
    Dtd,
    /// Malformed XML.
    #[error("malformed XML near byte {0}")]
    Malformed(u64),
}

/// An entry that could not be parsed at all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Rejected {
    /// 1-based position among SSL VPN connections.
    pub ordinal: usize,
    /// Field name.
    pub field: String,
    /// Reason code.
    pub code: String,
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.code)
    }
}

/// One parsed connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreviewEntry {
    /// 1-based position among SSL VPN connections.
    pub ordinal: usize,
    /// The profile that would be created.
    pub spec: ProfileSpec,
    /// Warnings the user should review.
    pub warnings: Vec<String>,
    /// Source settings that were dropped.
    pub omitted: Vec<String>,
    /// Reason the entry is skipped (not applicable, e.g. disabled or SAML).
    pub skipped: Option<String>,
    /// Reason the entry is blocked (needs something this client does not support).
    pub blocked: Option<String>,
}

impl PreviewEntry {
    /// True when the entry can be imported.
    pub fn is_eligible(&self) -> bool {
        self.skipped.is_none() && self.blocked.is_none()
    }
}

/// Import preview. Producing it performs no writes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Preview {
    /// Parsed entries.
    pub entries: Vec<PreviewEntry>,
    /// Entries that could not be parsed.
    pub rejected: Vec<Rejected>,
    /// IPsec connections ignored.
    pub excluded_ipsec: usize,
    /// File-level notes.
    pub notes: Vec<String>,
}

impl Preview {
    /// Eligible entries.
    pub fn eligible(&self) -> impl Iterator<Item = &PreviewEntry> {
        self.entries.iter().filter(|e| e.is_eligible())
    }
}

#[derive(Debug, Default)]
struct Node {
    name: String,
    text: String,
    children: Vec<Node>,
}

impl Node {
    fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
        self.children.iter().filter(move |c| c.name == name)
    }

    fn path(&self, names: &[&str]) -> Option<&Node> {
        names.iter().try_fold(self, |n, p| n.child(p))
    }
}

fn parse_tree(bytes: &[u8]) -> Result<Node, ImportError> {
    if bytes.len() > MAX_INPUT {
        return Err(ImportError::TooLarge);
    }
    let start = bytes
        .strip_prefix(b"\xEF\xBB\xBF")
        .unwrap_or(bytes)
        .iter()
        .find(|b| !b.is_ascii_whitespace());
    if start != Some(&b'<') {
        return Err(ImportError::UnsupportedFormat);
    }
    let mut r = Reader::from_reader(bytes);
    r.config_mut().trim_text(true);
    r.config_mut().check_end_names = true;
    let mut stack: Vec<Node> = vec![Node::default()];
    let mut buf = Vec::new();
    let bad = |r: &Reader<&[u8]>| ImportError::Malformed(r.buffer_position());
    loop {
        let ev = r.read_event_into(&mut buf).map_err(|_| bad(&r))?;
        match ev {
            Event::Start(e) => {
                if stack.len() > MAX_DEPTH {
                    return Err(ImportError::TooDeep);
                }
                let name = String::from_utf8(e.name().as_ref().to_vec()).map_err(|_| bad(&r))?;
                stack.push(Node {
                    name,
                    ..Node::default()
                });
            }
            Event::Empty(e) => {
                let name = String::from_utf8(e.name().as_ref().to_vec()).map_err(|_| bad(&r))?;
                if let Some(top) = stack.last_mut() {
                    top.children.push(Node {
                        name,
                        ..Node::default()
                    });
                }
            }
            Event::End(_) => {
                let n = stack.pop().ok_or_else(|| bad(&r))?;
                stack.last_mut().ok_or_else(|| bad(&r))?.children.push(n);
            }
            Event::Text(t) => {
                let s = t.unescape().map_err(|_| bad(&r))?;
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&s);
                }
            }
            Event::CData(t) => {
                let s = std::str::from_utf8(&t).map_err(|_| bad(&r))?.to_owned();
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&s);
                }
            }
            Event::DocType(_) => return Err(ImportError::Dtd),
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
        buf.clear();
    }
    if stack.len() != 1 {
        return Err(bad(&r));
    }
    let mut doc = stack.pop().ok_or(ImportError::Malformed(0))?;
    if doc.children.len() != 1 {
        return Err(ImportError::UnsupportedFormat);
    }
    let root = doc.children.remove(0);
    if root.name != "forticlient_configuration" {
        return Err(ImportError::UnsupportedFormat);
    }
    Ok(root)
}

/// Parses a boolean that must be exactly 0 or 1 after trimming.
fn bool01(n: &Node) -> Result<bool, &'static str> {
    match n.text.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err("invalid_boolean"),
    }
}

/// One gateway from the `server` field.
#[derive(Debug, PartialEq, Eq)]
struct Gateway {
    host: Host,
    port: Option<u16>,
    realm: Option<String>,
}

fn parse_gateway(s: &str) -> Result<Gateway, &'static str> {
    if s.is_empty() {
        return Err("empty_gateway");
    }
    if s.contains("://") {
        return Err("scheme_not_allowed");
    }
    if s.contains(['@', '?', '#']) || s.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("invalid_gateway");
    }
    let (hp, realm) = match s.split_once('/') {
        None => (s, None),
        Some((hp, r)) => {
            if r.contains('/') {
                return Err("ambiguous_realm");
            }
            validate_realm(r)?;
            (hp, Some(r.to_owned()))
        }
    };
    if hp.starts_with('[') {
        return Err("ipv6_unsupported");
    }
    let (h, port) = match hp.rsplit_once(':') {
        None => (hp, None),
        Some((h, p)) => {
            if p.is_empty() || p.len() > 5 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err("invalid_port");
            }
            let n: u32 = p.parse().map_err(|_| "invalid_port")?;
            let port = u16::try_from(n)
                .ok()
                .filter(|p| *p != 0)
                .ok_or("invalid_port")?;
            (h, Some(port))
        }
    };
    Ok(Gateway {
        host: h.parse()?,
        port,
        realm,
    })
}

/// Splits and checks the `server` list. Returns the single endpoint, plus a block reason when
/// the list needs failover or has inconsistent ports/realms, plus warnings.
fn parse_server(s: &str) -> Result<(Endpoint, Option<String>, Vec<String>), &'static str> {
    let gws = s
        .split(';')
        .map(|m| parse_gateway(m.trim()))
        .collect::<Result<Vec<_>, _>>()?;
    let first = gws.first().ok_or("empty_gateway")?;
    let mut warnings = Vec::new();
    let mut block = None;
    let explicit: Vec<u16> = gws.iter().filter_map(|g| g.port).collect();
    let port = match explicit.first() {
        None => DEFAULT_VPN_PORT,
        Some(&p) => {
            if explicit.iter().any(|&q| q != p) {
                block = Some("conflicting_ports".to_owned());
            } else if explicit.len() != gws.len() && p != DEFAULT_VPN_PORT {
                warnings.push(
                    "some gateways omit the port; the shared port was assumed (unverified)"
                        .to_owned(),
                );
            }
            p
        }
    };
    if gws.iter().any(|g| g.realm != first.realm) {
        block = Some("differing_realms".to_owned());
    }
    if gws.len() > 1 && block.is_none() {
        block = Some("multiple_gateways_unsupported".to_owned());
    }
    Ok((
        Endpoint {
            host: first.host.clone(),
            port,
            realm: first.realm.clone(),
            ems: None,
        },
        block,
        warnings,
    ))
}

/// Connection fields that are read and acted on.
const SCALARS: &[&str] = &[
    "name",
    "description",
    "server",
    "username",
    "password",
    "sso_enabled",
    "certificate",
    "prompt_certificate",
    "pkcs11_lib",
    "warn_invalid_server_certificate",
    "disallow_invalid_server_certificate",
    "prompt_username",
    "save_password",
    "keep_running",
    "auto_connect",
];

/// Shared `sslvpn/options` fields with known handling.
const KNOWN_OPTIONS: &[&str] = &[
    "enabled",
    "disallow_invalid_server_certificate",
    "warn_invalid_server_certificate",
    "prefer_sslvpn_dns",
    "dnscache_service_control",
    "keep_connection_alive",
    "show_auth_cert_only",
    "no_dhcp_server_route",
    "use_legacy_ssl_adapter",
    "preferred_dtls_tunnel",
    "block_ipv6",
];

/// Parses an export into a preview.
pub fn parse(bytes: &[u8]) -> Result<Preview, ImportError> {
    let root = parse_tree(bytes)?;
    let mut p = Preview {
        excluded_ipsec: root
            .path(&["vpn", "ipsec", "connections"])
            .map_or(0, |c| c.all("connection").count()),
        ..Preview::default()
    };
    let Some(ssl) = root.path(&["vpn", "sslvpn"]) else {
        return Ok(p);
    };
    let opts = ssl.child("options");
    let mut disabled = false;
    let mut shared_warnings = Vec::new();
    if let Some(o) = opts {
        if let Some(e) = o.child("enabled") {
            match bool01(e) {
                Ok(v) => disabled = !v,
                Err(c) => p.notes.push(format!("options/enabled: {c}")),
            }
        }
        let allow_invalid = o
            .child("disallow_invalid_server_certificate")
            .is_some_and(|n| bool01(n) == Ok(false))
            || o.child("warn_invalid_server_certificate")
                .is_some_and(|n| bool01(n) == Ok(true));
        if allow_invalid {
            shared_warnings.push(
                "the source allowed invalid server certificates; this client always verifies them"
                    .to_owned(),
            );
        }
        if o.child("preferred_dtls_tunnel")
            .is_some_and(|n| bool01(n) == Ok(true))
        {
            shared_warnings.push("DTLS preference ignored; TLS will be used".to_owned());
        }
        for c in &o.children {
            if !KNOWN_OPTIONS.contains(&c.name.as_str()) {
                shared_warnings.push(format!("unknown shared setting sslvpn/options/{}", c.name));
            }
        }
    }
    let conns: Vec<&Node> = ssl
        .child("connections")
        .map(|c| c.all("connection").collect())
        .unwrap_or_default();
    if conns.len() > MAX_CONNECTIONS {
        return Err(ImportError::TooManyConnections);
    }
    for (i, c) in conns.into_iter().enumerate() {
        let ordinal = i + 1;
        match parse_connection(ordinal, c, &shared_warnings, disabled) {
            Ok(e) => p.entries.push(e),
            Err((field, code)) => p.rejected.push(Rejected {
                ordinal,
                field: field.into(),
                code: code.into(),
            }),
        }
    }
    // Two entries with the same normalized name are ambiguous: both must be renamed.
    let mut counts: HashMap<String, usize> = HashMap::new();
    for e in &p.entries {
        *counts.entry(name_key(&e.spec.name)).or_default() += 1;
    }
    for e in &mut p.entries {
        if counts.get(&name_key(&e.spec.name)).copied().unwrap_or(0) > 1 && e.blocked.is_none() {
            e.blocked = Some("duplicate_name_rename_required".into());
        }
    }
    Ok(p)
}

type EntryErr = (&'static str, &'static str);

/// SHA-256 of the exact serialized empty certificate selection for a macOS export.
/// Its meaning was checked against the corresponding local profiles.
const EMPTY_CERTIFICATE_SHA256: [u8; 32] = [
    0xa6, 0x9d, 0x61, 0xb2, 0x81, 0x50, 0x8a, 0x7e, 0xd3, 0x96, 0x51, 0xa6, 0x38, 0x8e, 0x7c, 0x8e,
    0xea, 0xeb, 0xf2, 0x51, 0x5a, 0xb1, 0xfd, 0x40, 0x5b, 0xdf, 0x45, 0x1b, 0x5a, 0xe1, 0xa3, 0x00,
];

fn has_certificate_selection(certificate: &Node) -> bool {
    let text = certificate.text.trim();
    !certificate.children.is_empty()
        || (!text.is_empty() && Sha256::digest(text.as_bytes())[..] != EMPTY_CERTIFICATE_SHA256)
}

fn parse_connection(
    ordinal: usize,
    c: &Node,
    shared_warnings: &[String],
    disabled: bool,
) -> Result<PreviewEntry, EntryErr> {
    for f in SCALARS {
        if c.all(f).count() > 1 {
            return Err((f, "repeated_field"));
        }
    }
    let name = c.child("name").ok_or(("name", "missing"))?;
    let name = normalize_name(&name.text).map_err(|e| ("name", e))?;
    let server = c.child("server").ok_or(("server", "missing"))?;
    let (endpoint, mut blocked, mut warnings) =
        parse_server(server.text.trim()).map_err(|e| ("server", e))?;
    warnings.extend(shared_warnings.iter().cloned());
    let description = c
        .child("description")
        .map(|d| d.text.trim().to_owned())
        .filter(|d| !d.is_empty() && !d.chars().any(char::is_control));

    let mut omitted = Vec::new();
    let mut skipped = disabled.then(|| "ssl_vpn_disabled".to_owned());
    if c.child("username").is_some() || c.child("password").is_some() {
        omitted.push("stored account and password (fresh credentials needed)".to_owned());
    }
    if c.child("sso_enabled")
        .is_some_and(|n| bool01(n) == Ok(true))
    {
        skipped.get_or_insert_with(|| "saml_unsupported".into());
    }
    let has_text = |f: &str| c.child(f).is_some_and(|n| !n.text.trim().is_empty());
    if c.child("certificate")
        .is_some_and(has_certificate_selection)
        || c.child("prompt_certificate")
            .is_some_and(|n| bool01(n) == Ok(true))
        || has_text("pkcs11_lib")
    {
        blocked.get_or_insert_with(|| "client_certificate_unsupported".into());
    }
    if c.child("disallow_invalid_server_certificate")
        .is_some_and(|n| bool01(n) == Ok(false))
        || c.child("warn_invalid_server_certificate")
            .is_some_and(|n| bool01(n) == Ok(true))
    {
        warnings.push(
            "the source allowed invalid server certificates; this client always verifies them"
                .into(),
        );
    }
    for hook in ["on_connect", "on_disconnect"] {
        if c.child(hook).is_some() {
            omitted.push(format!("{hook} script (never run)"));
        }
    }
    if c.child("ui").is_some() {
        omitted.push("ui preferences".into());
    }
    // The source's saved password itself is discarded above; only the choice carries over, and
    // the password is asked for, then saved, on the first connection.
    let save_password = c
        .child("save_password")
        .is_some_and(|n| bool01(n) == Ok(true));
    for k in ["auto_connect", "keep_running", "prompt_username"] {
        if c.child(k).is_some() {
            omitted.push(format!("{k} preference"));
        }
    }
    for ch in &c.children {
        let known = SCALARS.contains(&ch.name.as_str())
            || matches!(ch.name.as_str(), "on_connect" | "on_disconnect" | "ui");
        if !known {
            warnings.push(format!("unknown setting connection/{} (review)", ch.name));
        }
    }
    let spec = ProfileSpec {
        description,
        endpoint,
        save_password,
        ..ProfileSpec::new(name, Host::Dns(String::new()))
    };
    // Validate the canonical spec the daemon will see (realm, text limits).
    let spec = spec
        .validate()
        .map_err(|_| ("connection", "invalid_profile"))?;
    Ok(PreviewEntry {
        ordinal,
        spec,
        warnings,
        omitted,
        skipped,
        blocked,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(conns: &str, opts: &str) -> String {
        format!(
            "<forticlient_configuration><vpn><sslvpn><options>{opts}</options>\
             <connections>{conns}</connections></sslvpn></vpn></forticlient_configuration>"
        )
    }

    #[test]
    fn documented_fixture() {
        let x = r#"<?xml version="1.0" encoding="UTF-8"?>
<forticlient_configuration>
  <vpn>
    <sslvpn>
      <options><enabled>1</enabled></options>
      <connections>
        <connection>
          <name>Engineering</name>
          <server>vpn.example.test:10443/staff</server>
          <sso_enabled>0</sso_enabled>
        </connection>
      </connections>
    </sslvpn>
  </vpn>
</forticlient_configuration>"#;
        let p = parse(x.as_bytes()).unwrap();
        let e: Vec<_> = p.eligible().collect();
        assert_eq!(e.len(), 1);
        let s = &e[0].spec;
        assert_eq!(s.name, "Engineering");
        assert_eq!(s.endpoint.host, Host::Dns("vpn.example.test".into()));
        assert_eq!(s.endpoint.port, 10443);
        assert_eq!(s.endpoint.realm.as_deref(), Some("staff"));
        assert_eq!(s.endpoint.ems, None);
        assert!(e[0].warnings.is_empty());
    }

    #[test]
    fn default_port_and_mixed_exclusions() {
        let x = format!(
            "<forticlient_configuration><vpn>{}<ipsec><connections><connection><name>I</name></connection></connections></ipsec></vpn></forticlient_configuration>",
            "<sslvpn><connections>\
               <connection><name>Pw</name><server>a.example</server></connection>\
               <connection><name>Saml</name><server>b.example</server><sso_enabled>1</sso_enabled></connection>\
             </connections></sslvpn>"
        );
        let p = parse(x.as_bytes()).unwrap();
        let e: Vec<_> = p.eligible().collect();
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].spec.endpoint.port, 443);
        assert_eq!(e[0].spec.endpoint.realm, None);
        assert_eq!(p.entries[1].skipped.as_deref(), Some("saml_unsupported"));
        assert_eq!(p.excluded_ipsec, 1);
    }

    #[test]
    fn disabled_group() {
        let x = wrap(
            "<connection><name>A</name><server>a.example</server></connection>",
            "<enabled>0</enabled>",
        );
        let p = parse(x.as_bytes()).unwrap();
        assert_eq!(p.eligible().count(), 0);
        assert_eq!(p.entries[0].skipped.as_deref(), Some("ssl_vpn_disabled"));
    }

    #[test]
    fn secrets_and_hooks_are_dropped() {
        let x = wrap(
            "<connection><name>A</name><server>a.example</server>\
             <username>SENTINEL_USER</username><password>SENTINEL_PASS</password>\
             <on_connect><script><os>mac</os><script>SENTINEL_SCRIPT</script></script></on_connect>\
             </connection>",
            "",
        );
        let p = parse(x.as_bytes()).unwrap();
        let dump = serde_json::to_string(&p).unwrap() + &format!("{p:?}");
        for s in ["SENTINEL_USER", "SENTINEL_PASS", "SENTINEL_SCRIPT"] {
            assert!(!dump.contains(s), "{s} leaked");
        }
        assert_eq!(p.eligible().count(), 1);
        assert_eq!(p.entries[0].spec.username_hint, None);
        assert!(
            p.entries[0]
                .omitted
                .iter()
                .any(|o| o.contains("on_connect"))
        );
    }

    #[test]
    fn save_password_choice_is_kept_without_the_password() {
        let x = wrap(
            "<connection><name>A</name><server>a.example</server>\
             <password>SENTINEL_PASS</password><save_password>1</save_password></connection>\
             <connection><name>B</name><server>b.example</server>\
             <save_password>0</save_password></connection>\
             <connection><name>C</name><server>c.example</server></connection>",
            "",
        );
        let p = parse(x.as_bytes()).unwrap();
        assert!(!format!("{p:?}").contains("SENTINEL_PASS"));
        let saved: Vec<bool> = p.entries.iter().map(|e| e.spec.save_password).collect();
        assert_eq!(saved, [true, false, false]);
        assert!(
            p.entries
                .iter()
                .all(|e| !e.omitted.iter().any(|o| o.contains("save_password")))
        );
    }

    #[test]
    fn per_entry_errors_keep_others() {
        let x = wrap(
            "<connection><name>Bad</name><server>a.example:99999</server></connection>\
             <connection><name>Dup</name><server>a.example</server><server>b.example</server></connection>\
             <connection><name>Good</name><server>c.example</server></connection>",
            "",
        );
        let p = parse(x.as_bytes()).unwrap();
        assert_eq!(p.rejected.len(), 2);
        assert_eq!(p.rejected[0].code, "invalid_port");
        assert_eq!(p.rejected[1].code, "repeated_field");
        assert_eq!(p.eligible().count(), 1);
        // Raw values never appear in diagnostics.
        assert!(!format!("{:?}", p.rejected).contains("99999"));
    }

    #[test]
    fn multiple_gateways() {
        let x = wrap(
            "<connection><name>A</name><server>a.example:10443;b.example:10443</server></connection>\
             <connection><name>B</name><server>a.example:1;b.example:2</server></connection>\
             <connection><name>C</name><server>a.example/x;b.example/y</server></connection>",
            "",
        );
        let p = parse(x.as_bytes()).unwrap();
        assert_eq!(
            p.entries[0].blocked.as_deref(),
            Some("multiple_gateways_unsupported")
        );
        assert_eq!(p.entries[1].blocked.as_deref(), Some("conflicting_ports"));
        assert_eq!(p.entries[2].blocked.as_deref(), Some("differing_realms"));
    }

    #[test]
    fn whole_file_errors() {
        assert_eq!(
            parse(b"\x00\x01binary"),
            Err(ImportError::UnsupportedFormat)
        );
        assert_eq!(parse(b"<other_root/>"), Err(ImportError::UnsupportedFormat));
        assert_eq!(
            parse(b"<!DOCTYPE x [<!ENTITY e \"boom\">]><forticlient_configuration/>"),
            Err(ImportError::Dtd)
        );
        assert!(matches!(
            parse(b"<forticlient_configuration><vpn></forticlient_configuration>"),
            Err(ImportError::Malformed(_))
        ));
        assert!(matches!(
            parse(b"<forticlient_configuration>&custom;</forticlient_configuration>"),
            Err(ImportError::Malformed(_))
        ));
        let deep = "<a>".repeat(70) + &"</a>".repeat(70);
        let x = format!("<forticlient_configuration>{deep}</forticlient_configuration>");
        assert_eq!(parse(x.as_bytes()), Err(ImportError::TooDeep));
        assert_eq!(
            parse(&vec![b' '; MAX_INPUT + 1]),
            Err(ImportError::TooLarge)
        );
    }

    #[test]
    fn certificates_block_and_duplicates_are_ambiguous() {
        let x = wrap(
            "<connection><name>A</name><server>a.example</server><certificate>CN=x</certificate></connection>\
             <connection><name>B</name><server>b.example</server><certificate></certificate></connection>\
             <connection><name>dup</name><server>c.example</server></connection>\
             <connection><name>DUP</name><server>d.example</server></connection>",
            "<disallow_invalid_server_certificate>0</disallow_invalid_server_certificate>",
        );
        let p = parse(x.as_bytes()).unwrap();
        assert_eq!(
            p.entries[0].blocked.as_deref(),
            Some("client_certificate_unsupported")
        );
        assert!(p.entries[1].is_eligible());
        assert!(!p.entries[1].warnings.is_empty());
        assert!(!p.entries[2].is_eligible() && !p.entries[3].is_eligible());
    }

    #[test]
    fn unknown_encrypted_certificate_and_explicit_prompt_remain_blocked() {
        let encrypted = format!("Enc {}", "0".repeat(50));
        for setting in [
            format!("<certificate>{encrypted}</certificate>"),
            "<certificate/><prompt_certificate>1</prompt_certificate>".to_owned(),
        ] {
            let xml = wrap(
                &format!(
                    "<connection><name>A</name><server>a.example</server>{setting}</connection>"
                ),
                "",
            );
            let preview = parse(xml.as_bytes()).unwrap();
            assert_eq!(
                preview.entries[0].blocked.as_deref(),
                Some("client_certificate_unsupported")
            );
        }
    }

    #[test]
    fn gateway_rules() {
        for bad in [
            "https://a.example",
            "u@a.example",
            "a.example/x/y",
            "[::1]:443",
            "a.example:0",
            "a.example?x",
            "",
        ] {
            assert!(parse_gateway(bad).is_err(), "{bad}");
        }
        let g = parse_gateway("A.Example:8443/Staff").unwrap();
        assert_eq!(g.realm.as_deref(), Some("Staff"));
        assert_eq!(g.port, Some(8443));
    }
}
