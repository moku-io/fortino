//! A PPP client (RFC 1661 LCP, RFC 1332 IPCP, RFC 1877 DNS options) for the SSL VPN tunnel
//!. No pppd: the link runs inside the worker.
//!
//! Observed on GATEWAY-2: the gateway stays silent until the client sends an LCP
//! Configure-Request; it asks only for a Magic-Number; its frames carry no `ff 03`
//! address/control prefix; it accepted ours with the prefix. On GATEWAY-3 it rejected VJ
//! compression and Apple's ACSCP (BACKLOG milestone 1). This engine therefore starts LCP
//! itself, requests only a Magic-Number, accepts frames with or without the prefix, and never
//! asks for compression.
//!
//! Sans-IO: feed received payloads with [`Ppp::input`], drive time with
//! [`Ppp::handle_timeout`], and drain [`Ppp::poll_event`] for frames to send and state changes.

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// LCP protocol number.
pub const PROTO_LCP: u16 = 0xc021;
/// IPCP protocol number.
pub const PROTO_IPCP: u16 = 0x8021;
/// IPv4 protocol number.
pub const PROTO_IP: u16 = 0x0021;

const CONF_REQ: u8 = 1;
const CONF_ACK: u8 = 2;
const CONF_NAK: u8 = 3;
const CONF_REJ: u8 = 4;
const TERM_REQ: u8 = 5;
const TERM_ACK: u8 = 6;
const CODE_REJ: u8 = 7;
const PROTO_REJ: u8 = 8;
const ECHO_REQ: u8 = 9;
const ECHO_REP: u8 = 10;
const DISCARD_REQ: u8 = 11;

const LCP_MRU: u8 = 1;
const LCP_ACCM: u8 = 2;
const LCP_MAGIC: u8 = 5;
const LCP_PFC: u8 = 7;
const LCP_ACFC: u8 = 8;

const IPCP_ADDR: u8 = 3;
const IPCP_DNS1: u8 = 129;
const IPCP_DNS2: u8 = 131;

/// Settings.
#[derive(Debug, Clone)]
pub struct PppConfig {
    /// Retransmission interval for unanswered requests.
    pub restart: Duration,
    /// Configure-Requests sent before giving up.
    pub max_configure: u32,
    /// Terminate-Requests sent before giving up.
    pub max_terminate: u32,
    /// Our LCP Magic-Number (must be random and non-zero).
    pub magic: u32,
    /// Ask the gateway for DNS servers in IPCP.
    pub request_dns: bool,
    /// Send `ff 03` before LCP packets (RFC 1662 requires it for LCP).
    pub lcp_address_control: bool,
    /// Send an LCP Echo-Request this often once the link is up (`None` disables).
    pub echo_interval: Option<Duration>,
    /// Unanswered echoes before the link is declared dead.
    pub echo_failures: u32,
}

impl PppConfig {
    /// Defaults with the given magic number.
    pub fn new(magic: u32) -> Self {
        Self {
            restart: Duration::from_secs(3),
            max_configure: 10,
            max_terminate: 2,
            magic: if magic == 0 { 0x4f46_4331 } else { magic },
            request_dns: true,
            lcp_address_control: true,
            echo_interval: Some(Duration::from_secs(10)),
            echo_failures: 6,
        }
    }
}

/// Negotiated IPv4 settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Link {
    /// Our address.
    pub local: Ipv4Addr,
    /// The gateway's PPP address, if it sent one.
    pub peer: Option<Ipv4Addr>,
    /// DNS servers from IPCP.
    pub dns: Vec<Ipv4Addr>,
    /// The gateway's MRU (our largest packet).
    pub peer_mru: u16,
}

/// Why the link went down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DownReason {
    /// We closed it.
    Closed,
    /// The gateway sent Terminate-Request.
    PeerTerminated,
    /// A negotiation failed or timed out.
    NegotiationFailed(&'static str),
    /// Echo replies stopped.
    KeepaliveTimeout,
    /// The gateway restarted LCP on an open link.
    Renegotiated,
}

/// Output of the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PppEvent {
    /// A PPP payload to wrap in a frame and send.
    Send(Vec<u8>),
    /// IPCP is open: the link carries IPv4.
    Up(Ipv4Link),
    /// An IPv4 packet from the gateway.
    Packet(Vec<u8>),
    /// The link is down; nothing more will be produced.
    Down(DownReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Establish,
    Network,
    Open,
    Terminating,
    Dead,
}

/// One control protocol's request/ack bookkeeping.
#[derive(Debug, Default)]
struct Cp {
    id: u8,
    /// Options we are requesting, as (type, value).
    want: Vec<(u8, Vec<u8>)>,
    ours_acked: bool,
    theirs_acked: bool,
    sent: u32,
    deadline: Option<Instant>,
}

/// The PPP engine.
#[derive(Debug)]
pub struct Ppp {
    cfg: PppConfig,
    phase: Phase,
    lcp: Cp,
    ipcp: Cp,
    peer_mru: u16,
    peer_ip: Option<Ipv4Addr>,
    next_echo: Option<Instant>,
    echo_id: u8,
    echo_missed: u32,
    term_sent: u32,
    term_deadline: Option<Instant>,
    events: VecDeque<PppEvent>,
}

/// Packet-level errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PppError {
    /// The link is not carrying IPv4.
    #[error("PPP link is not up")]
    NotUp,
    /// Packet larger than the gateway's MRU.
    #[error("packet larger than the link MRU")]
    TooLarge,
}

impl Ppp {
    /// Starts the link: queues the first LCP Configure-Request.
    pub fn new(cfg: PppConfig, now: Instant) -> Self {
        let mut p = Self {
            lcp: Cp {
                want: vec![(LCP_MAGIC, cfg.magic.to_be_bytes().to_vec())],
                ..Default::default()
            },
            ipcp: Cp::default(),
            cfg,
            phase: Phase::Establish,
            peer_mru: 1500,
            peer_ip: None,
            next_echo: None,
            echo_id: 0,
            echo_missed: 0,
            term_sent: 0,
            term_deadline: None,
            events: VecDeque::new(),
        };
        p.send_conf_req(PROTO_LCP, now);
        p
    }

    /// True once IPv4 flows.
    pub fn is_up(&self) -> bool {
        self.phase == Phase::Open
    }

    /// Next output.
    pub fn poll_event(&mut self) -> Option<PppEvent> {
        self.events.pop_front()
    }

    /// When [`Self::handle_timeout`] must next run.
    pub fn poll_timeout(&self) -> Option<Instant> {
        [
            self.lcp.deadline,
            self.ipcp.deadline,
            self.next_echo,
            self.term_deadline,
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Queues an IPv4 packet.
    pub fn send_ip(&mut self, pkt: &[u8]) -> Result<(), PppError> {
        if self.phase != Phase::Open {
            return Err(PppError::NotUp);
        }
        if pkt.len() > usize::from(self.peer_mru) {
            return Err(PppError::TooLarge);
        }
        let mut f = Vec::with_capacity(pkt.len() + 2);
        f.extend_from_slice(&PROTO_IP.to_be_bytes());
        f.extend_from_slice(pkt);
        self.events.push_back(PppEvent::Send(f));
        Ok(())
    }

    /// Starts an orderly close.
    pub fn close(&mut self, now: Instant) {
        if matches!(self.phase, Phase::Terminating | Phase::Dead) {
            return;
        }
        self.phase = Phase::Terminating;
        self.lcp.deadline = None;
        self.ipcp.deadline = None;
        self.next_echo = None;
        self.term_sent = 0;
        self.send_term_req(now);
    }

    /// Runs timers.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.phase == Phase::Dead {
            return;
        }
        if self.term_deadline.is_some_and(|d| d <= now) {
            if self.term_sent >= self.cfg.max_terminate {
                self.down(DownReason::Closed);
            } else {
                self.send_term_req(now);
            }
            return;
        }
        for proto in [PROTO_LCP, PROTO_IPCP] {
            let cp = self.cp(proto);
            if cp.deadline.is_some_and(|d| d <= now) {
                if cp.sent >= self.cfg.max_configure {
                    self.down(DownReason::NegotiationFailed(if proto == PROTO_LCP {
                        "LCP did not converge"
                    } else {
                        "IPCP did not converge"
                    }));
                    return;
                }
                self.send_conf_req(proto, now);
            }
        }
        if self.next_echo.is_some_and(|d| d <= now) {
            if self.echo_missed >= self.cfg.echo_failures {
                self.down(DownReason::KeepaliveTimeout);
                return;
            }
            self.echo_missed += 1;
            self.echo_id = self.echo_id.wrapping_add(1);
            let magic = self.cfg.magic.to_be_bytes();
            self.send_ctl(PROTO_LCP, ECHO_REQ, self.echo_id, &magic);
            self.next_echo = self.cfg.echo_interval.map(|i| now + i);
        }
    }

    /// Handles one received PPP payload (the content of a `0x5050` frame).
    pub fn input(&mut self, payload: &[u8], now: Instant) {
        if self.phase == Phase::Dead {
            return;
        }
        let mut p = payload;
        if p.starts_with(&[0xff, 0x03]) {
            p = &p[2..];
        }
        // Protocol-field compression: an odd first byte is a one-byte protocol.
        let (proto, data) = match p {
            [b, rest @ ..] if b & 1 == 1 => (u16::from(*b), rest),
            [a, b, rest @ ..] => (u16::from_be_bytes([*a, *b]), rest),
            _ => return,
        };
        // Any traffic proves the link is alive.
        self.echo_missed = 0;
        match proto {
            PROTO_LCP => self.lcp_input(data, now),
            PROTO_IPCP => {
                if matches!(self.phase, Phase::Network | Phase::Open) {
                    self.ipcp_input(data, now);
                }
            }
            PROTO_IP => {
                if self.phase == Phase::Open {
                    self.events.push_back(PppEvent::Packet(data.to_vec()));
                }
            }
            other => {
                // IPv6CP, CCP, ACSCP and the rest: refuse, once LCP is open (RFC 1661 §5.7).
                if matches!(self.phase, Phase::Network | Phase::Open) {
                    let mut body = other.to_be_bytes().to_vec();
                    let room = usize::from(self.peer_mru).saturating_sub(8);
                    body.extend_from_slice(&data[..data.len().min(room)]);
                    self.lcp.id = self.lcp.id.wrapping_add(1);
                    let id = self.lcp.id;
                    self.send_ctl(PROTO_LCP, PROTO_REJ, id, &body);
                }
            }
        }
    }

    fn cp(&mut self, proto: u16) -> &mut Cp {
        if proto == PROTO_LCP {
            &mut self.lcp
        } else {
            &mut self.ipcp
        }
    }

    fn down(&mut self, why: DownReason) {
        if self.phase != Phase::Dead {
            self.phase = Phase::Dead;
            self.lcp.deadline = None;
            self.ipcp.deadline = None;
            self.next_echo = None;
            self.term_deadline = None;
            self.events.push_back(PppEvent::Down(why));
        }
    }

    fn send_ctl(&mut self, proto: u16, code: u8, id: u8, data: &[u8]) {
        let len = u16::try_from(data.len() + 4).unwrap_or(u16::MAX);
        let mut f = Vec::with_capacity(data.len() + 8);
        if proto == PROTO_LCP && self.cfg.lcp_address_control {
            f.extend_from_slice(&[0xff, 0x03]);
        }
        f.extend_from_slice(&proto.to_be_bytes());
        f.push(code);
        f.push(id);
        f.extend_from_slice(&len.to_be_bytes());
        f.extend_from_slice(&data[..data.len().min(usize::from(len) - 4)]);
        self.events.push_back(PppEvent::Send(f));
    }

    fn send_conf_req(&mut self, proto: u16, now: Instant) {
        let restart = self.cfg.restart;
        let cp = self.cp(proto);
        cp.id = cp.id.wrapping_add(1);
        cp.sent += 1;
        cp.deadline = Some(now + restart);
        let id = cp.id;
        let opts = encode_opts(&cp.want);
        self.send_ctl(proto, CONF_REQ, id, &opts);
    }

    fn send_term_req(&mut self, now: Instant) {
        self.term_sent += 1;
        self.term_deadline = Some(now + self.cfg.restart);
        self.lcp.id = self.lcp.id.wrapping_add(1);
        let id = self.lcp.id;
        self.send_ctl(PROTO_LCP, TERM_REQ, id, &[]);
    }

    fn lcp_input(&mut self, data: &[u8], now: Instant) {
        let Some((code, id, body)) = parse_ctl(data) else {
            return;
        };
        match code {
            CONF_REQ => {
                if self.phase == Phase::Terminating {
                    return;
                }
                if matches!(self.phase, Phase::Network | Phase::Open) {
                    // RFC 1661: a Configure-Request on an open link restarts negotiation.
                    // v1 treats that as the end of this session.
                    self.down(DownReason::Renegotiated);
                    return;
                }
                let Some(opts) = parse_opts(body) else {
                    return;
                };
                let mut rej = Vec::new();
                let mut nak = Vec::new();
                for (t, v) in &opts {
                    match (*t, v.len()) {
                        (LCP_MRU, 2) => {
                            let mru = u16::from_be_bytes([v[0], v[1]]);
                            if mru < 576 {
                                nak.push((LCP_MRU, 576u16.to_be_bytes().to_vec()));
                            }
                        }
                        (LCP_ACCM, 4) | (LCP_PFC, 0) | (LCP_ACFC, 0) => {}
                        (LCP_MAGIC, 4) => {
                            if v.as_slice() == self.cfg.magic.to_be_bytes() {
                                // Looped-back link or a collision: ask for another value.
                                let alt = self.cfg.magic.rotate_left(13) ^ 0x5a5a_a5a5;
                                nak.push((LCP_MAGIC, alt.to_be_bytes().to_vec()));
                            }
                        }
                        _ => rej.push((*t, v.clone())),
                    }
                }
                if !rej.is_empty() {
                    self.send_ctl(PROTO_LCP, CONF_REJ, id, &encode_opts(&rej));
                } else if !nak.is_empty() {
                    self.send_ctl(PROTO_LCP, CONF_NAK, id, &encode_opts(&nak));
                } else {
                    for (t, v) in &opts {
                        if *t == LCP_MRU && v.len() == 2 {
                            self.peer_mru = u16::from_be_bytes([v[0], v[1]]);
                        }
                    }
                    self.send_ctl(PROTO_LCP, CONF_ACK, id, body);
                    self.lcp.theirs_acked = true;
                    self.lcp_maybe_open(now);
                }
            }
            CONF_ACK if id == self.lcp.id && self.phase == Phase::Establish => {
                self.lcp.ours_acked = true;
                self.lcp.deadline = None;
                self.lcp_maybe_open(now);
            }
            CONF_NAK | CONF_REJ if id == self.lcp.id && self.phase == Phase::Establish => {
                let Some(opts) = parse_opts(body) else {
                    return;
                };
                for (t, v) in opts {
                    if code == CONF_REJ {
                        self.lcp.want.retain(|(w, _)| *w != t);
                    } else if t == LCP_MAGIC && v.len() == 4 {
                        // Pick a fresh value rather than the one offered.
                        self.cfg.magic = self.cfg.magic.rotate_left(7) ^ 0x1357_9bdf;
                        let m = self.cfg.magic.to_be_bytes().to_vec();
                        for w in &mut self.lcp.want {
                            if w.0 == LCP_MAGIC {
                                w.1 = m.clone();
                            }
                        }
                    }
                }
                self.send_conf_req(PROTO_LCP, now);
            }
            TERM_REQ => {
                self.send_ctl(PROTO_LCP, TERM_ACK, id, &[]);
                self.down(DownReason::PeerTerminated);
            }
            TERM_ACK => {
                if self.phase == Phase::Terminating {
                    self.down(DownReason::Closed);
                }
            }
            ECHO_REQ => {
                if matches!(self.phase, Phase::Network | Phase::Open) {
                    let mut reply = self.cfg.magic.to_be_bytes().to_vec();
                    reply.extend_from_slice(body.get(4..).unwrap_or(&[]));
                    self.send_ctl(PROTO_LCP, ECHO_REP, id, &reply);
                }
            }
            ECHO_REP | DISCARD_REQ => {}
            CODE_REJ | PROTO_REJ => {
                // The gateway refused something optional we sent; nothing we send is
                // mandatory beyond LCP/IPCP/IP, so a rejection of IPCP or IP is fatal.
                if code == PROTO_REJ && body.len() >= 2 {
                    let p = u16::from_be_bytes([body[0], body[1]]);
                    if p == PROTO_IPCP || p == PROTO_IP {
                        self.down(DownReason::NegotiationFailed("gateway rejected IPv4"));
                    }
                }
            }
            _ => {
                let mut rej = Vec::with_capacity(data.len());
                rej.extend_from_slice(&data[..data.len().min(usize::from(self.peer_mru) - 8)]);
                self.lcp.id = self.lcp.id.wrapping_add(1);
                let rid = self.lcp.id;
                self.send_ctl(PROTO_LCP, CODE_REJ, rid, &rej);
            }
        }
    }

    fn lcp_maybe_open(&mut self, now: Instant) {
        if self.lcp.ours_acked && self.lcp.theirs_acked && self.phase == Phase::Establish {
            self.phase = Phase::Network;
            self.next_echo = self.cfg.echo_interval.map(|i| now + i);
            let mut want = vec![(IPCP_ADDR, vec![0, 0, 0, 0])];
            if self.cfg.request_dns {
                want.push((IPCP_DNS1, vec![0, 0, 0, 0]));
                want.push((IPCP_DNS2, vec![0, 0, 0, 0]));
            }
            self.ipcp.want = want;
            self.send_conf_req(PROTO_IPCP, now);
        }
    }

    fn ipcp_input(&mut self, data: &[u8], now: Instant) {
        let Some((code, id, body)) = parse_ctl(data) else {
            return;
        };
        match code {
            CONF_REQ => {
                let Some(opts) = parse_opts(body) else {
                    return;
                };
                let rej: Vec<_> = opts
                    .iter()
                    .filter(|(t, v)| !(*t == IPCP_ADDR && v.len() == 4))
                    .cloned()
                    .collect();
                if !rej.is_empty() {
                    self.send_ctl(PROTO_IPCP, CONF_REJ, id, &encode_opts(&rej));
                    return;
                }
                for (t, v) in &opts {
                    if *t == IPCP_ADDR && v.len() == 4 {
                        let ip = Ipv4Addr::new(v[0], v[1], v[2], v[3]);
                        self.peer_ip = (!ip.is_unspecified()).then_some(ip);
                    }
                }
                self.send_ctl(PROTO_IPCP, CONF_ACK, id, body);
                if self.phase == Phase::Open {
                    // A repeated request after we are up changes nothing we apply.
                    return;
                }
                self.ipcp.theirs_acked = true;
                self.ipcp_maybe_open();
            }
            CONF_ACK if id == self.ipcp.id && self.phase == Phase::Network => {
                let ok = self
                    .ipcp
                    .want
                    .iter()
                    .any(|(t, v)| *t == IPCP_ADDR && v.as_slice() != [0, 0, 0, 0]);
                if !ok {
                    // Acking 0.0.0.0 assigns nothing.
                    self.down(DownReason::NegotiationFailed("no IPv4 address assigned"));
                    return;
                }
                self.ipcp.ours_acked = true;
                self.ipcp.deadline = None;
                self.ipcp_maybe_open();
            }
            CONF_NAK if id == self.ipcp.id && self.phase == Phase::Network => {
                let Some(opts) = parse_opts(body) else {
                    return;
                };
                for (t, v) in opts {
                    if v.len() == 4 {
                        if let Some(w) = self.ipcp.want.iter_mut().find(|(w, _)| *w == t) {
                            w.1 = v;
                        }
                    }
                }
                self.send_conf_req(PROTO_IPCP, now);
            }
            CONF_REJ if id == self.ipcp.id && self.phase == Phase::Network => {
                let Some(opts) = parse_opts(body) else {
                    return;
                };
                for (t, _) in opts {
                    if t == IPCP_ADDR {
                        self.down(DownReason::NegotiationFailed("gateway refused IP-Address"));
                        return;
                    }
                    self.ipcp.want.retain(|(w, _)| *w != t);
                }
                self.send_conf_req(PROTO_IPCP, now);
            }
            TERM_REQ => {
                self.send_ctl(PROTO_IPCP, TERM_ACK, id, &[]);
                self.down(DownReason::PeerTerminated);
            }
            _ => {}
        }
    }

    fn ipcp_maybe_open(&mut self) {
        if !(self.ipcp.ours_acked && self.ipcp.theirs_acked) || self.phase != Phase::Network {
            return;
        }
        let get = |t: u8| {
            self.ipcp
                .want
                .iter()
                .find(|(w, _)| *w == t)
                .and_then(|(_, v)| <[u8; 4]>::try_from(v.as_slice()).ok())
                .map(Ipv4Addr::from)
                .filter(|a| !a.is_unspecified())
        };
        let Some(local) = get(IPCP_ADDR) else {
            self.down(DownReason::NegotiationFailed("no IPv4 address assigned"));
            return;
        };
        let dns = [get(IPCP_DNS1), get(IPCP_DNS2)]
            .into_iter()
            .flatten()
            .collect();
        self.phase = Phase::Open;
        self.events.push_back(PppEvent::Up(Ipv4Link {
            local,
            peer: self.peer_ip,
            dns,
            peer_mru: self.peer_mru,
        }));
    }
}

/// `code, id, body` of a control packet, honouring its length field.
fn parse_ctl(d: &[u8]) -> Option<(u8, u8, &[u8])> {
    if d.len() < 4 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([d[2], d[3]]));
    if len < 4 || len > d.len() {
        return None;
    }
    Some((d[0], d[1], &d[4..len]))
}

fn parse_opts(mut b: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 2 {
            return None;
        }
        let l = usize::from(b[1]);
        if l < 2 || l > b.len() || out.len() >= 64 {
            return None;
        }
        out.push((b[0], b[2..l].to_vec()));
        b = &b[l..];
    }
    Some(out)
}

fn encode_opts(o: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (t, v) in o {
        out.push(*t);
        out.push(u8::try_from(v.len() + 2).unwrap_or(u8::MAX));
        out.extend_from_slice(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted gateway: acks LCP magic, assigns 10.212.134.200 and DNS through IPCP Naks.
    struct Gw {
        lcp_id: u8,
        sent_ipcp_req: bool,
    }

    fn ctl(proto: u16, code: u8, id: u8, data: &[u8], ac: bool) -> Vec<u8> {
        let mut f = Vec::new();
        if ac {
            f.extend_from_slice(&[0xff, 0x03]);
        }
        f.extend_from_slice(&proto.to_be_bytes());
        f.push(code);
        f.push(id);
        f.extend_from_slice(&u16::try_from(data.len() + 4).unwrap().to_be_bytes());
        f.extend_from_slice(data);
        f
    }

    impl Gw {
        /// Answers one client frame like GATEWAY-2 (no ff03 on our side).
        fn answer(&mut self, f: &[u8]) -> Vec<Vec<u8>> {
            let f = f.strip_prefix(&[0xff, 0x03]).unwrap_or(f);
            let proto = u16::from_be_bytes([f[0], f[1]]);
            let (code, id, body) = parse_ctl(&f[2..]).unwrap();
            let mut out = Vec::new();
            match (proto, code) {
                (PROTO_LCP, CONF_REQ) => {
                    out.push(ctl(PROTO_LCP, CONF_ACK, id, body, false));
                    self.lcp_id += 1;
                    out.push(ctl(
                        PROTO_LCP,
                        CONF_REQ,
                        self.lcp_id,
                        &[5, 6, 1, 2, 3, 4],
                        false,
                    ));
                }
                (PROTO_IPCP, CONF_REQ) => {
                    if !self.sent_ipcp_req {
                        self.sent_ipcp_req = true;
                        // Gateway's own request: its address plus VJ compression (rejected).
                        out.push(ctl(
                            PROTO_IPCP,
                            CONF_REQ,
                            1,
                            &[3, 6, 203, 0, 113, 10, 2, 6, 0, 0x2d, 15, 1],
                            false,
                        ));
                    }
                    let opts = parse_opts(body).unwrap();
                    let want = |t| opts.iter().find(|(o, _)| *o == t).map(|(_, v)| v.clone());
                    if want(IPCP_ADDR) == Some(vec![0, 0, 0, 0]) {
                        let nak = encode_opts(&[
                            (IPCP_ADDR, vec![10, 212, 134, 200]),
                            (IPCP_DNS1, vec![10, 0, 0, 53]),
                            (IPCP_DNS2, vec![10, 0, 0, 54]),
                        ]);
                        out.push(ctl(PROTO_IPCP, CONF_NAK, id, &nak, false));
                    } else {
                        out.push(ctl(PROTO_IPCP, CONF_ACK, id, body, false));
                    }
                }
                (PROTO_IPCP, CONF_REJ) => {
                    out.push(ctl(
                        PROTO_IPCP,
                        CONF_REQ,
                        2,
                        &[3, 6, 203, 0, 113, 10],
                        false,
                    ));
                }
                _ => {}
            }
            out
        }
    }

    fn run(p: &mut Ppp, gw: &mut Gw, now: Instant) -> Vec<PppEvent> {
        let mut seen = Vec::new();
        for _ in 0..50 {
            let mut progressed = false;
            while let Some(e) = p.poll_event() {
                progressed = true;
                if let PppEvent::Send(f) = &e {
                    for r in gw.answer(f) {
                        p.input(&r, now);
                    }
                }
                seen.push(e);
            }
            if !progressed {
                break;
            }
        }
        seen
    }

    #[test]
    fn link_comes_up_like_tg2() {
        let t0 = Instant::now();
        let mut p = Ppp::new(PppConfig::new(0xdead_beef), t0);
        let mut gw = Gw {
            lcp_id: 0,
            sent_ipcp_req: false,
        };
        let ev = run(&mut p, &mut gw, t0);
        // First frame is our LCP Configure-Request with ff03 and Magic only.
        let PppEvent::Send(first) = &ev[0] else {
            panic!()
        };
        assert_eq!(
            first,
            &[
                0xff, 0x03, 0xc0, 0x21, 1, 1, 0, 10, 5, 6, 0xde, 0xad, 0xbe, 0xef
            ]
        );
        let up = ev.iter().find_map(|e| match e {
            PppEvent::Up(l) => Some(l.clone()),
            _ => None,
        });
        assert_eq!(
            up,
            Some(Ipv4Link {
                local: Ipv4Addr::new(10, 212, 134, 200),
                peer: Some(Ipv4Addr::new(203, 0, 113, 10)),
                dns: vec![Ipv4Addr::new(10, 0, 0, 53), Ipv4Addr::new(10, 0, 0, 54)],
                peer_mru: 1500,
            })
        );
        assert!(p.is_up());
        // IP both ways.
        p.send_ip(&[0x45, 0, 0, 20]).unwrap();
        assert_eq!(
            p.poll_event(),
            Some(PppEvent::Send(vec![0, 0x21, 0x45, 0, 0, 20]))
        );
        p.input(&[0, 0x21, 0x45, 1], t0);
        assert_eq!(p.poll_event(), Some(PppEvent::Packet(vec![0x45, 1])));
    }

    #[test]
    fn unknown_protocols_are_rejected_and_echo_answered() {
        let t0 = Instant::now();
        let mut p = Ppp::new(PppConfig::new(7), t0);
        let mut gw = Gw {
            lcp_id: 0,
            sent_ipcp_req: false,
        };
        run(&mut p, &mut gw, t0);
        // IPv6CP Configure-Request → Protocol-Reject.
        p.input(
            &ctl(0x8057, CONF_REQ, 1, &[1, 10, 0, 0, 0, 0, 0, 0, 0, 1], false),
            t0,
        );
        let Some(PppEvent::Send(f)) = p.poll_event() else {
            panic!()
        };
        assert_eq!(&f[2..4], &[0xc0, 0x21]);
        assert_eq!(f[4], PROTO_REJ);
        assert_eq!(&f[8..10], &[0x80, 0x57]);
        // Echo-Request → Echo-Reply with our magic.
        p.input(&ctl(PROTO_LCP, ECHO_REQ, 9, &[0, 0, 0, 1], false), t0);
        let Some(PppEvent::Send(f)) = p.poll_event() else {
            panic!()
        };
        assert_eq!(f[4], ECHO_REP);
        assert_eq!(f[5], 9);
        assert_eq!(&f[8..12], &7u32.to_be_bytes());
    }

    #[test]
    fn retransmits_then_gives_up() {
        let t0 = Instant::now();
        let mut cfg = PppConfig::new(1);
        cfg.max_configure = 3;
        let mut p = Ppp::new(cfg, t0);
        assert!(matches!(p.poll_event(), Some(PppEvent::Send(_))));
        let mut sends = 1;
        loop {
            let now = p.poll_timeout().unwrap();
            p.handle_timeout(now);
            match p.poll_event() {
                Some(PppEvent::Send(_)) => sends += 1,
                Some(PppEvent::Down(DownReason::NegotiationFailed(_))) => break,
                e => panic!("{e:?}"),
            }
        }
        assert_eq!(sends, 3);
        assert!(p.poll_timeout().is_none());
    }

    #[test]
    fn keepalive_and_termination() {
        let t0 = Instant::now();
        let mut cfg = PppConfig::new(1);
        cfg.echo_failures = 2;
        let mut p = Ppp::new(cfg, t0);
        let mut gw = Gw {
            lcp_id: 0,
            sent_ipcp_req: false,
        };
        run(&mut p, &mut gw, t0);
        // Gateway goes silent: two echoes, then down.
        let mut downs = 0;
        for _ in 0..5 {
            let Some(t) = p.poll_timeout() else { break };
            p.handle_timeout(t);
            while let Some(e) = p.poll_event() {
                if let PppEvent::Down(r) = e {
                    assert_eq!(r, DownReason::KeepaliveTimeout);
                    downs += 1;
                }
            }
        }
        assert_eq!(downs, 1);

        // Peer terminate.
        let mut p = Ppp::new(PppConfig::new(1), t0);
        let mut gw = Gw {
            lcp_id: 0,
            sent_ipcp_req: false,
        };
        run(&mut p, &mut gw, t0);
        p.input(&ctl(PROTO_LCP, TERM_REQ, 3, &[], false), t0);
        let evs: Vec<_> = std::iter::from_fn(|| p.poll_event()).collect();
        assert!(matches!(
            evs.last(),
            Some(PppEvent::Down(DownReason::PeerTerminated))
        ));

        // Our close: Terminate-Request, then Ack ends it.
        let mut p = Ppp::new(PppConfig::new(1), t0);
        run(
            &mut p,
            &mut Gw {
                lcp_id: 0,
                sent_ipcp_req: false,
            },
            t0,
        );
        p.close(t0);
        let Some(PppEvent::Send(f)) = p.poll_event() else {
            panic!()
        };
        assert_eq!(f[4], TERM_REQ);
        p.input(&ctl(PROTO_LCP, TERM_ACK, f[5], &[], false), t0);
        assert_eq!(p.poll_event(), Some(PppEvent::Down(DownReason::Closed)));
    }

    #[test]
    fn lcp_auth_request_is_rejected() {
        let t0 = Instant::now();
        let mut p = Ppp::new(PppConfig::new(1), t0);
        p.poll_event();
        // Gateway asks for PAP (option 3) and an MRU.
        p.input(
            &ctl(
                PROTO_LCP,
                CONF_REQ,
                1,
                &[3, 4, 0xc0, 0x23, 1, 4, 0x05, 0x4a],
                false,
            ),
            t0,
        );
        let Some(PppEvent::Send(f)) = p.poll_event() else {
            panic!()
        };
        assert_eq!(f[4], CONF_REJ);
        assert_eq!(&f[8..], &[3, 4, 0xc0, 0x23]);
    }

    proptest::proptest! {
        #[test]
        fn input_never_panics(frames: Vec<Vec<u8>>) {
            let t0 = Instant::now();
            let mut p = Ppp::new(PppConfig::new(1), t0);
            for f in frames {
                p.input(&f, t0);
                while p.poll_event().is_some() {}
            }
        }
    }
}
