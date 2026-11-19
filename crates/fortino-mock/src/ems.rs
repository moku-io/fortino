//! Mock EMS server, built from the design notes.
//!
//! One TLS connection per request: the client sends `MSG_HEADER` + `X-FCCK-<TYPE>` and the
//! server answers one `<REPLYTYPE>: KEY|value|…|` line and closes (`PERCON|0`). It handles
//! PROBE, REGISTER (optionally with a connection key), mini/full keepalives, deregistration
//! (`FCT_UNREG`) and TAG, pushes host-verification rules as `ZHVR`, and maps rule results to tags.
//!
//! Every behaviour that is inferred rather than observed carries an `UNVERIFIED` comment and must
//! match the client's assumption.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use fortino_proto_ems::message::{self, Request, RequestError};
use fortino_proto_ems::sysinfo::SysInfo;
use fortino_proto_ems::{blob, tags::Bits};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::server::{self, MockError, MockHandle, RawStream, TlsOptions};

/// A mock EMS scenario.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct EmsScenario {
    /// Server serial (`FCTEMS…`).
    pub serial: String,
    /// Host name the server reports.
    pub host: String,
    /// Connection key required to register, if any.
    pub key: Option<String>,
    /// Tenant (32 digits).
    pub tenant: String,
    /// `KA_INTERVAL` in seconds.
    pub ka_interval: u32,
    /// `EMSVER`.
    pub version: u32,
    /// Host-verification rules (`hv.conf` XML) pushed as `ZHVR`.
    pub host_rules: Option<String>,
    /// Which tag each rule grants: `rule_flag → tag_flag`. Rules not listed grant nothing.
    pub rule_tags: Vec<RuleTag>,
    /// Quarantine every registered endpoint.
    pub quarantine: bool,
}

/// One rule-to-tag mapping.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct RuleTag {
    /// Bit in `RULES`.
    pub rule: usize,
    /// Bit in `TAGS`.
    pub tag: usize,
}

impl Default for EmsScenario {
    fn default() -> Self {
        Self {
            serial: "FCTEMS0000000001".into(),
            host: "ems.test".into(),
            key: None,
            tenant: "0".repeat(32),
            ka_interval: 60,
            version: 7_004_008,
            host_rules: None,
            rule_tags: Vec::new(),
            quarantine: false,
        }
    }
}

impl EmsScenario {
    /// Parses a YAML scenario.
    pub fn from_yaml(s: &str) -> Result<Self, MockError> {
        serde_yaml::from_str(s).map_err(|e| MockError::Other(format!("scenario: {e}")))
    }
}

/// What the server knows about one endpoint.
#[derive(Debug, Clone, Default)]
pub struct Endpoint {
    /// SYSINFO from the last REGISTER or full keepalive.
    pub sysinfo: Vec<(String, String)>,
    /// Last `RULES` received.
    pub rules: Option<String>,
    /// Keepalives received since registration.
    pub keepalives: u32,
}

/// One request as the server saw it. Values that could be secret are not kept.
#[derive(Debug, Clone)]
pub struct Seen {
    /// `PROBE`, `REGISTER`, `KA`, `TAG`.
    pub kind: String,
    /// `FCTUID` header.
    pub uid: Option<String>,
    /// `EMSSN` header.
    pub serial: Option<String>,
    /// `SIZE` minus the bytes received.
    pub size_delta: Option<i64>,
    /// Body field names in order.
    pub fields: Vec<String>,
    /// SYSINFO keys in order, if the body had SYSINFO.
    pub sysinfo_keys: Vec<String>,
}

/// Server state, shared with the test that started it.
#[derive(Debug, Default)]
pub struct EmsState {
    /// Registered endpoints by UID.
    pub endpoints: HashMap<String, Endpoint>,
    /// Every request, in order.
    pub seen: Vec<Seen>,
}

/// A running mock EMS.
#[derive(Debug)]
pub struct MockEms {
    /// The TLS listener.
    pub handle: MockHandle,
    /// Its state.
    pub state: Arc<Mutex<EmsState>>,
}

/// Checksum the mock gives the rules it pushes. The client only echoes it.
pub fn rules_checksum(xml: &str) -> String {
    hex::encode(&Sha256::digest(xml.as_bytes())[..16])
}

/// Starts a mock EMS on 127.0.0.1 (random port), self-signed for `ems.test` and `localhost`.
pub async fn start(sc: &EmsScenario) -> Result<MockEms, MockError> {
    let bind = "127.0.0.1:0"
        .parse()
        .map_err(|_| MockError::Other("addr".into()))?;
    start_on(sc, bind).await
}

/// Like [`start`], listening on `bind`.
pub async fn start_on(sc: &EmsScenario, bind: std::net::SocketAddr) -> Result<MockEms, MockError> {
    let state = Arc::new(Mutex::new(EmsState::default()));
    let sc = Arc::new(sc.clone());
    let st = state.clone();
    let handle = server::start_raw(
        TlsOptions::default(),
        vec!["ems.test".into(), "localhost".into()],
        bind,
        move |tls| {
            let sc = sc.clone();
            let st = st.clone();
            Box::pin(async move { serve(tls, &sc, &st).await })
        },
    )
    .await?;
    Ok(MockEms { handle, state })
}

async fn serve(mut tls: RawStream, sc: &EmsScenario, st: &Mutex<EmsState>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let req = loop {
        match message::parse_request(&buf) {
            Ok(r) => break r,
            Err(RequestError::Incomplete) => {}
            Err(e) => {
                tracing::debug!(error = %e, "mock ems: bad request");
                return;
            }
        }
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    };
    let reply = {
        let Ok(mut st) = st.lock() else { return };
        record(&mut st, &req, req.len);
        handle(sc, &mut st, &req)
    };
    // Replies end at CRLF; the client reads up to it.
    let _ = tls.write_all(format!("{reply}\r\n").as_bytes()).await;
    let _ = tls.shutdown().await;
}

fn sysinfo_of(req: &Request) -> Option<SysInfo> {
    req.fields
        .get("SYSINFO")
        .and_then(|v| SysInfo::decode(v).ok())
}

fn record(st: &mut EmsState, req: &Request, received: usize) {
    let size_delta = req
        .header("SIZE")
        .and_then(|v| v.trim().parse::<i64>().ok())
        .map(|s| s - received as i64);
    st.seen.push(Seen {
        kind: req.kind.clone(),
        uid: req
            .header("FCTUID")
            .or_else(|| req.header("UID"))
            .map(str::to_owned),
        serial: req.header("EMSSN").map(str::to_owned),
        size_delta,
        fields: req.fields.iter().map(|(k, _)| k.to_owned()).collect(),
        sysinfo_keys: sysinfo_of(req)
            .map(|s| s.iter().map(|(k, _)| k.to_owned()).collect())
            .unwrap_or_default(),
    });
}

fn handle(sc: &EmsScenario, st: &mut EmsState, req: &Request) -> String {
    let uid = req.header("FCTUID").unwrap_or_default().to_owned();
    let tail = "PROTO_VERSION|1.0.1|PERCON|0|";
    match req.kind.as_str() {
        "PROBE" => format!(
            "FCPROBERPLY: FGT|{}:{}|FEATURE_BITMAP|1|EMSVER|{}|{tail}",
            sc.serial, sc.host, sc.version
        ),
        "REGISTER" => {
            let Some(info) = sysinfo_of(req) else {
                return format!("FCREGRPLY: REG|99|{tail}");
            };
            if let Some(key) = &sc.key {
                // The key travels inside SYSINFO; status 3 covers a wrong or missing key.
                // UNVERIFIED: the ERR_MSG text.
                if info.get("REG_KEY") != Some(key.as_str()) {
                    return format!("FCREGRPLY: REG|3|ERR_MSG|Connection key mismatch|{tail}");
                }
            }
            st.endpoints.insert(
                uid,
                Endpoint {
                    sysinfo: info
                        .iter()
                        .filter(|(k, _)| *k != "REG_KEY")
                        .map(|(k, v)| (k.into(), v.into()))
                        .collect(),
                    ..Endpoint::default()
                },
            );
            // UNVERIFIED: the sub-fields after the keepalive intervals.
            format!(
                "FCREGRPLY: REG|0-{}:1:{}:default:{}:43230:0:0:995|LIC_FEATS|1|EMS_ONNET|0|{}{tail}",
                sc.serial,
                sc.host,
                sc.ka_interval,
                pushed_rules(sc, None)
            )
        }
        "KA" => {
            let info = sysinfo_of(req);
            if info.as_ref().and_then(|s| s.get("FCT_UNREG")).is_some() {
                st.endpoints.remove(&uid);
                return format!("FCKARPLY: CONT|0|{tail}");
            }
            let registered_here = req.header("EMSSN") == Some(sc.serial.as_str());
            let Some(ep) = st.endpoints.get_mut(&uid).filter(|_| registered_here) else {
                return format!("FCKARPLY: CONT|0|{tail}");
            };
            ep.keepalives += 1;
            if let Some(info) = &info {
                if info.get("HOSTNAME").is_some() {
                    ep.sysinfo = info.iter().map(|(k, v)| (k.into(), v.into())).collect();
                }
            }
            let tags = tags_for(sc, ep.rules.as_deref());
            let echoed = info.as_ref().and_then(|s| s.get("EP_RULECHKSUM"));
            format!(
                "FCKARPLY: CONT|1|EMSSN|{}:{}|UPLD_PRT|8013|KA_INTERVAL|{}|QUAR|{}|TAGS|{tags}|TENANT|{}|{}{tail}",
                sc.serial,
                sc.host,
                sc.ka_interval,
                u8::from(sc.quarantine),
                sc.tenant,
                pushed_rules(sc, echoed),
            )
        }
        "TAG" => {
            // X-FCCK-TAG carries everything as header lines, keyed by UID.
            let uid = req.header("UID").unwrap_or_default().to_owned();
            let rules = req.header("RULES").map(str::to_owned);
            let Some(ep) = st.endpoints.get_mut(&uid) else {
                return format!("FCTAGRPLY: ERR|1|{tail}");
            };
            ep.rules = rules;
            format!(
                "FCTAGRPLY: TAGS|{}|ERR|0|{tail}",
                tags_for(sc, ep.rules.as_deref())
            )
        }
        other => {
            tracing::debug!(kind = other, "mock ems: unknown request");
            String::new()
        }
    }
}

fn pushed_rules(sc: &EmsScenario, echoed: Option<&str>) -> String {
    match &sc.host_rules {
        Some(xml) if echoed != Some(rules_checksum(xml).as_str()) => {
            format!(
                "ZHVR|{}|HVCS|{}|",
                blob::encode(xml.as_bytes()),
                rules_checksum(xml)
            )
        }
        _ => String::new(),
    }
}

fn tags_for(sc: &EmsScenario, rules: Option<&str>) -> String {
    let rules = rules.and_then(|r| Bits::parse(r).ok()).unwrap_or_default();
    let mut tags = Bits::zeros(sc.rule_tags.iter().map(|m| m.tag + 1).max().unwrap_or(0));
    for m in &sc.rule_tags {
        if rules.get(m.rule) {
            tags.set(m.tag, true);
        }
    }
    tags.to_string()
}
