//! Turns negotiated tunnel settings into journaled network changes.
//!
//! The settings come from the gateway via the worker and are untrusted: they are bounded and
//! validated here before anything is applied. The daemon is the only writer of routes, DNS and
//! the IPv6 policy.

use std::net::{IpAddr, Ipv4Addr};

use ofc_config::IpPolicy;
use ofc_core::worker::TunnelConfig;
use ofc_platform::journal::Journaled;
use ofc_platform::{DnsConfig, IpNet, NetChange, NetPlatform, Route, RouteVia};

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
    d.parse::<ofc_config::Host>()
        .is_ok_and(|h| matches!(h, ofc_config::Host::Dns(_)))
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
        // Keep the gateway on the physical uplink before any VPN route is installed.
        let gw = IpAddr::V4(tc.gateway_ip);
        let pin = self
            .inner
            .platform()
            .route_to(gw)
            .map_err(|e| NetError::Apply(e.to_string()))?;
        match pin {
            Some(via @ RouteVia::Gateway { .. }) => changes.insert(
                0,
                NetChange::AddRoute(Route {
                    dest: IpNet::host(gw),
                    via,
                }),
            ),
            Some(RouteVia::Interface(_)) => {}
            None => return Err(NetError::Apply("no route to gateway".into())),
        }
        self.inner.apply_all(&changes).map_err(|e| {
            if self.inner.pending() > 0 {
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

    use ofc_platform::fake::{FakeNet, FakeState};

    fn tc() -> TunnelConfig {
        TunnelConfig {
            interface: "ppp0".into(),
            assigned_ip: Ipv4Addr::new(10, 212, 134, 200),
            routes: vec!["10.0.0.0/8".parse().unwrap()],
            dns_servers: vec![Ipv4Addr::new(10, 0, 0, 53)],
            dns_domains: vec!["corp.example".into()],
            gateway_ip: Ipv4Addr::new(203, 0, 113, 10),
            block_ipv6: true,
        }
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
    fn failed_apply_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(Mutex::new(FakeState::typical_host()));
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
