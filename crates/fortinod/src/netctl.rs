//! Turns negotiated tunnel settings into journaled network changes.
//!
//! The settings come from the gateway via the worker and are untrusted: they are bounded and
//! validated here before anything is applied. The daemon is the only writer of routes, DNS and
//! the IPv6 policy.

use std::net::{IpAddr, Ipv4Addr};

use fortino_config::{DnsMode, IpPolicy};
use fortino_core::worker::TunnelConfig;
use fortino_platform::journal::Journaled;
use fortino_platform::{DnsConfig, IpNet, NetChange, NetPlatform, PlatformError, Route, RouteVia};

/// Maximum split routes accepted from a gateway.
pub const MAX_ROUTES: usize = 1024;
/// Maximum DNS servers accepted from a gateway.
pub const MAX_DNS_SERVERS: usize = 8;
/// Maximum DNS match domains accepted from a gateway.
pub const MAX_DNS_DOMAINS: usize = 64;

/// Why tunnel settings were refused or could not be applied.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    /// The gateway sent settings this client cannot or will not apply.
    #[error("unsupported tunnel settings: {0}")]
    Unsupported(&'static str),
    /// Settings were malformed.
    #[error("invalid tunnel settings: {0}")]
    Invalid(&'static str),
    /// Applying failed (already rolled back).
    #[error("network configuration failed: {0}")]
    Apply(String),
    /// Rollback failed; recovery is required.
    #[error("network cleanup failed: {0}")]
    Cleanup(String),
    /// This platform can't apply the settings; nothing was changed.
    #[error("{0}")]
    PlatformUnsupported(String),
}

/// Network controller used by the session manager.
pub trait NetController: Send {
    /// Restores anything an earlier run left behind. Returns the number of reverted entries.
    fn recover(&mut self) -> Result<usize, NetError>;
    /// Applies settings for a connected tunnel. On failure, nothing stays applied.
    fn apply(&mut self, tc: &TunnelConfig, policy: IpPolicy) -> Result<(), NetError>;
    /// Removes everything applied for the current tunnel.
    fn rollback(&mut self) -> Result<(), NetError>;
}

fn valid_ifname(n: &str) -> bool {
    let digits = n
        .strip_prefix("ppp")
        .or_else(|| n.strip_prefix("utun"))
        .or_else(|| n.strip_prefix("faketun"));
    matches!(digits, Some(d) if !d.is_empty() && d.len() <= 4 && d.bytes().all(|b| b.is_ascii_digit()))
}

fn valid_unicast(a: Ipv4Addr) -> bool {
    !(a.is_unspecified() || a.is_loopback() || a.is_multicast() || a.is_broadcast())
}

fn valid_domain(d: &str) -> bool {
    d.parse::<fortino_config::Host>()
        .is_ok_and(|h| matches!(h, fortino_config::Host::Dns(_)))
}

/// The tunnel settings to apply under a profile's DNS choice. With [`DnsMode::Local`] the
/// gateway's resolvers and match domains are dropped, so the Mac's own DNS answers every name;
/// routes are unchanged.
pub fn for_dns_mode(mut tc: TunnelConfig, mode: DnsMode) -> TunnelConfig {
    if mode == DnsMode::Local {
        if !tc.dns_servers.is_empty() || !tc.split_dns.is_empty() {
            tracing::info!(
                "profile keeps this Mac's DNS; the gateway's DNS settings are not applied"
            );
        }
        tc.dns_servers.clear();
        tc.dns_domains.clear();
        tc.split_dns.clear();
    }
    tc
}

/// Validates tunnel settings and builds the ordered change list.
pub fn plan(tc: &TunnelConfig, policy: IpPolicy) -> Result<Vec<NetChange>, NetError> {
    if !valid_ifname(&tc.interface) {
        return Err(NetError::Invalid("interface name"));
    }
    if !valid_unicast(tc.assigned_ip) {
        return Err(NetError::Invalid("assigned address"));
    }
    if !valid_unicast(tc.gateway_ip) {
        return Err(NetError::Invalid("gateway address"));
    }
    if tc.routes.len() > MAX_ROUTES {
        return Err(NetError::Invalid("too many routes"));
    }
    if tc.dns_servers.len() > MAX_DNS_SERVERS || tc.dns_domains.len() > MAX_DNS_DOMAINS {
        return Err(NetError::Invalid("too many resolver entries"));
    }
    if tc.dns_servers.iter().any(|a| !valid_unicast(*a)) {
        return Err(NetError::Invalid("DNS server address"));
    }
    if tc.dns_domains.iter().any(|d| !valid_domain(d)) {
        return Err(NetError::Invalid("DNS domain"));
    }
    let rule_domains: usize = tc.split_dns.iter().map(|r| r.domains.len()).sum();
    if tc.dns_domains.len() + rule_domains > MAX_DNS_DOMAINS {
        return Err(NetError::Invalid("too many resolver entries"));
    }
    for r in &tc.split_dns {
        if r.servers.is_empty() || r.servers.len() > MAX_DNS_SERVERS {
            return Err(NetError::Invalid("split DNS servers"));
        }
        if r.servers.iter().any(|a| !valid_unicast(*a)) {
            return Err(NetError::Invalid("DNS server address"));
        }
        if r.domains.is_empty() || r.domains.iter().any(|d| !valid_domain(d)) {
            return Err(NetError::Invalid("DNS domain"));
        }
    }
    // A domain may be routed to one resolver set only.
    let mut all: Vec<String> = tc
        .dns_domains
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .collect();
    all.extend(
        tc.split_dns
            .iter()
            .flat_map(|r| r.domains.iter().map(|d| d.to_ascii_lowercase())),
    );
    let n = all.len();
    all.sort();
    all.dedup();
    if all.len() != n {
        return Err(NetError::Invalid("DNS domain listed twice"));
    }
    for r in &tc.routes {
        if !r.is_ipv4() {
            return Err(NetError::Unsupported("IPv6 route on an IPv4-only tunnel"));
        }
        if r.prefix == 0 {
            return Err(NetError::Unsupported("default route in split mode"));
        }
    }
    if policy == IpPolicy::SplitIpv4 && tc.routes.is_empty() {
        return Err(NetError::Unsupported("split tunnel without routes"));
    }

    let ifname = tc.interface.clone();
    let tun = RouteVia::Interface(ifname.clone());
    // PPP assigns the address to its own interface; the daemon only adds routes, resolvers
    // and the IPv6 policy.
    let mut out = Vec::new();
    match policy {
        IpPolicy::SplitIpv4 => {
            for r in &tc.routes {
                out.push(NetChange::AddRoute(Route {
                    dest: *r,
                    via: tun.clone(),
                }));
            }
        }
        IpPolicy::FullIpv4 => {
            for (a, p) in [([0, 0, 0, 0], 1), ([128, 0, 0, 0], 1)] {
                out.push(NetChange::AddRoute(Route {
                    dest: IpNet {
                        addr: IpAddr::from(a),
                        prefix: p,
                    },
                    via: tun.clone(),
                }));
            }
        }
    }
    if !tc.dns_servers.is_empty() {
        let servers: Vec<IpAddr> = tc.dns_servers.iter().map(|a| IpAddr::V4(*a)).collect();
        if !tc.dns_domains.is_empty() {
            for d in &tc.dns_domains {
                out.push(NetChange::AddSplitDns {
                    domain: d.clone(),
                    servers: servers.clone(),
                });
            }
        } else if policy == IpPolicy::FullIpv4 {
            out.push(NetChange::SetDns {
                ifname,
                dns: DnsConfig {
                    servers,
                    search_domains: Vec::new(),
                },
            });
        }
        // Split mode without match domains: keep the original resolver.
    }
    for r in &tc.split_dns {
        let servers: Vec<IpAddr> = r.servers.iter().map(|a| IpAddr::V4(*a)).collect();
        for d in &r.domains {
            out.push(NetChange::AddSplitDns {
                domain: d.clone(),
                servers: servers.clone(),
            });
        }
    }
    if tc.block_ipv6 {
        out.push(NetChange::BlockIpv6);
    }
    Ok(out)
}

/// A [`NetController`] over a journaled platform.
#[derive(Debug)]
pub struct JournaledController<P: NetPlatform> {
    inner: Journaled<P>,
}

impl<P: NetPlatform> JournaledController<P> {
    /// Wraps a journaled platform.
    pub fn new(inner: Journaled<P>) -> Self {
        Self { inner }
    }
}

impl<P: NetPlatform> NetController for JournaledController<P> {
    fn recover(&mut self) -> Result<usize, NetError> {
        self.inner
            .recover()
            .map_err(|e| NetError::Cleanup(e.to_string()))
    }

    fn apply(&mut self, tc: &TunnelConfig, policy: IpPolicy) -> Result<(), NetError> {
        let mut changes = plan(tc, policy)?;
        // Pin the VPN server to the physical uplink before installing VPN routes. This is always
        // needed: besides a pushed prefix, the tunnel interface's own point-to-point peer can be
        // the server address, which would route the carrier into its own tunnel. route_to(gw) is
        // unreliable once the carrier is up (its live connection leaves a cached host route), so
        // read the uplink next-hop from a never-connected probe (TEST-NET-3, RFC 5737): before
        // VPN routes it resolves via the default route, giving the real uplink gateway.
        let gw = IpAddr::V4(tc.gateway_ip);
        const UPLINK_PROBE: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        let via = self
            .inner
            .platform()
            .route_to(UPLINK_PROBE)
            .map_err(|e| NetError::Apply(e.to_string()))?;
        tracing::info!(
            pin = match &via {
                Some(RouteVia::Gateway { .. }) => "gateway",
                Some(RouteVia::Interface(_)) => "interface",
                None => "none",
            },
            "pinning VPN server to the physical uplink"
        );
        if let Some(via @ RouteVia::Gateway { .. }) = via {
            // Only a gateway next-hop needs an explicit pin; a directly-connected server already
            // stays on its interface, and no default route means nothing to pin to.
            changes.insert(
                0,
                NetChange::AddRoute(Route {
                    dest: IpNet::host(gw),
                    via,
                }),
            );
        }
        self.inner.apply_all(&changes).map_err(|e| {
            if let PlatformError::Unsupported(m) = &e
                && self.inner.pending() == 0
            {
                NetError::PlatformUnsupported(m.clone())
            } else if self.inner.pending() > 0 {
                NetError::Cleanup(e.to_string())
            } else {
                NetError::Apply(e.to_string())
            }
        })
    }

    fn rollback(&mut self) -> Result<(), NetError> {
        self.inner
            .rollback_all()
            .map_err(|e| NetError::Cleanup(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use fortino_core::worker::SplitDnsRule;
    use fortino_platform::fake::{FakeNet, FakeState};

    fn tc() -> TunnelConfig {
        TunnelConfig {
            interface: "ppp0".into(),
            assigned_ip: Ipv4Addr::new(10, 212, 134, 200),
            routes: vec!["10.0.0.0/8".parse().unwrap()],
            dns_servers: vec![Ipv4Addr::new(10, 0, 0, 53)],
            dns_domains: vec!["corp.example".into()],
            split_dns: vec![],
            gateway_ip: Ipv4Addr::new(203, 0, 113, 10),
            block_ipv6: true,
        }
    }

    #[test]
    fn local_dns_applies_no_gateway_resolvers() {
        let dns =
            |c: &NetChange| matches!(c, NetChange::AddSplitDns { .. } | NetChange::SetDns { .. });
        let mut t = tc();
        t.split_dns = vec![SplitDnsRule {
            domains: vec!["other.example".into()],
            servers: vec![Ipv4Addr::new(10, 0, 0, 54)],
        }];
        let gateway = plan(
            &for_dns_mode(t.clone(), DnsMode::Gateway),
            IpPolicy::SplitIpv4,
        )
        .unwrap();
        assert_eq!(gateway.iter().filter(|c| dns(c)).count(), 2);

        for policy in [IpPolicy::SplitIpv4, IpPolicy::FullIpv4] {
            let local = plan(&for_dns_mode(t.clone(), DnsMode::Local), policy).unwrap();
            assert!(!local.iter().any(dns), "{policy:?}: {local:?}");
            // Routes and the IPv6 block are unchanged.
            let plain = plan(&t, policy).unwrap();
            let routes =
                |v: &[NetChange]| v.iter().filter(|c| !dns(c)).cloned().collect::<Vec<_>>();
            assert_eq!(routes(&local), routes(&plain));
        }

        // A full tunnel whose gateway sends DNS without domains needs full-tunnel DNS (not
        // available on macOS); keeping the Mac's DNS plans no DNS change at all.
        let mut t = tc();
        t.dns_domains.clear();
        let full = plan(&t, IpPolicy::FullIpv4).unwrap();
        assert!(full.iter().any(|c| matches!(c, NetChange::SetDns { .. })));
        let local = plan(&for_dns_mode(t, DnsMode::Local), IpPolicy::FullIpv4).unwrap();
        assert!(!local.iter().any(dns));
    }

    #[test]
    fn plan_rejects_bad_input() {
        let mut t = tc();
        t.interface = "en0".into();
        assert!(matches!(
            plan(&t, IpPolicy::SplitIpv4),
            Err(NetError::Invalid(_))
        ));
        let mut t = tc();
        t.routes = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(matches!(
            plan(&t, IpPolicy::SplitIpv4),
            Err(NetError::Unsupported(_))
        ));
        let mut t = tc();
        t.routes = vec!["fd00::/8".parse().unwrap()];
        assert!(plan(&t, IpPolicy::SplitIpv4).is_err());
        let mut t = tc();
        t.dns_domains = vec!["bad domain".into()];
        assert!(plan(&t, IpPolicy::SplitIpv4).is_err());
        let mut t = tc();
        t.split_dns = vec![SplitDnsRule {
            domains: vec!["corp.example".into()],
            servers: vec![Ipv4Addr::new(10, 1, 0, 53)],
        }];
        assert!(
            plan(&t, IpPolicy::SplitIpv4).is_err(),
            "same domain in two rules"
        );
    }

    #[test]
    fn split_rules_keep_their_own_servers() {
        let mut t = tc();
        t.dns_domains = vec![];
        t.split_dns = vec![
            SplitDnsRule {
                domains: vec!["a.example".into(), "b.example".into()],
                servers: vec![Ipv4Addr::new(10, 1, 0, 53)],
            },
            SplitDnsRule {
                domains: vec!["c.example".into()],
                servers: vec![Ipv4Addr::new(10, 2, 0, 53), Ipv4Addr::new(10, 2, 0, 54)],
            },
        ];
        let changes = plan(&t, IpPolicy::SplitIpv4).unwrap();
        let split: Vec<(String, usize, IpAddr)> = changes
            .iter()
            .filter_map(|c| match c {
                NetChange::AddSplitDns { domain, servers } => {
                    Some((domain.clone(), servers.len(), servers[0]))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            split,
            [
                ("a.example".to_owned(), 1, "10.1.0.53".parse().unwrap()),
                ("b.example".to_owned(), 1, "10.1.0.53".parse().unwrap()),
                ("c.example".to_owned(), 2, "10.2.0.53".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn apply_and_rollback_restore_host() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(FakeState::typical_host()));
        let before = state.lock().unwrap().net_only();
        let net = FakeNet::new(state.clone());
        let mut c =
            JournaledController::new(Journaled::open(net, dir.path().join("j.json")).unwrap());
        c.apply(&tc(), IpPolicy::SplitIpv4).unwrap();
        {
            let s = state.lock().unwrap();
            assert!(s.ipv6_blocked);
            assert!(s.split_dns.contains_key("corp.example"));
        }
        c.rollback().unwrap();
        assert_eq!(state.lock().unwrap().net_only(), before);

        c.apply(&tc(), IpPolicy::FullIpv4).unwrap();
        c.rollback().unwrap();
        assert_eq!(state.lock().unwrap().net_only(), before);
    }

    #[test]
    fn pins_server_via_the_uplink_gateway() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(FakeState::typical_host()));
        let net = FakeNet::new(state.clone());
        let mut c =
            JournaledController::new(Journaled::open(net, dir.path().join("j.json")).unwrap());
        // The server is pinned to the uplink's next-hop regardless of the pushed routes, because
        // the tunnel interface itself can otherwise capture the carrier.
        for policy in [IpPolicy::SplitIpv4, IpPolicy::FullIpv4] {
            c.apply(&tc(), policy).unwrap();
            assert!(
                state
                    .lock()
                    .unwrap()
                    .routes
                    .iter()
                    .any(|fortino_platform::fake::RouteKey(r)| r
                        == "203.0.113.10/32 via 192.0.2.1 dev en0"),
                "{policy:?}: server pinned via the uplink gateway"
            );
            c.rollback().unwrap();
        }
    }

    #[test]
    fn failed_apply_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(FakeState::typical_host()));
        // tc() split tunnel plans four changes (server pin, route, split DNS, IPv6 block);
        // fail the last one.
        state.lock().unwrap().fail_apply_at = Some(3);
        let before = state.lock().unwrap().net_only();
        let mut c = JournaledController::new(
            Journaled::open(FakeNet::new(state.clone()), dir.path().join("j.json")).unwrap(),
        );
        assert!(matches!(
            c.apply(&tc(), IpPolicy::SplitIpv4),
            Err(NetError::Apply(_))
        ));
        assert_eq!(state.lock().unwrap().net_only(), before);
    }
}
