//! Network value types shared by all platform implementations.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// An IP prefix (address + prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IpNet {
    /// Network address. Host bits are kept as given.
    pub addr: IpAddr,
    /// Prefix length (0..=32 for IPv4, 0..=128 for IPv6).
    pub prefix: u8,
}

impl IpNet {
    /// Builds a prefix, rejecting a prefix length that is too long for the family.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        (prefix <= max).then_some(Self { addr, prefix })
    }

    /// A host prefix (/32 or /128).
    pub fn host(addr: IpAddr) -> Self {
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        Self { addr, prefix }
    }

    /// Builds an IPv4 prefix from a dotted netmask. Returns `None` for a non-contiguous mask.
    pub fn from_v4_mask(addr: std::net::Ipv4Addr, mask: std::net::Ipv4Addr) -> Option<Self> {
        let m = u32::from(mask);
        let prefix = m.leading_ones();
        if m.checked_shl(prefix).unwrap_or(0) != 0 {
            return None;
        }
        u8::try_from(prefix)
            .ok()
            .and_then(|p| Self::new(IpAddr::V4(addr), p))
    }

    /// The IPv4 netmask, if this is an IPv4 prefix.
    pub fn v4_mask(&self) -> Option<std::net::Ipv4Addr> {
        match self.addr {
            IpAddr::V4(_) => {
                let m = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                Some(m.into())
            }
            IpAddr::V6(_) => None,
        }
    }

    /// True for an IPv4 prefix.
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// True when `ip` is inside this prefix.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let m = self.v4_mask().map(u32::from).unwrap_or(0);
                u32::from(n) & m == u32::from(a) & m
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let m = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                u128::from(n) & m == u128::from(a) & m
            }
            _ => false,
        }
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// Error parsing an [`IpNet`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid IP prefix: {0}")]
pub struct IpNetParseError(pub String);

impl FromStr for IpNet {
    type Err = IpNetParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let err = || IpNetParseError(s.to_owned());
        match s.split_once('/') {
            Some((a, p)) => {
                let addr: IpAddr = a.parse().map_err(|_| err())?;
                let prefix: u8 = p.parse().map_err(|_| err())?;
                Self::new(addr, prefix).ok_or_else(err)
            }
            None => s.parse().map(Self::host).map_err(|_| err()),
        }
    }
}

/// Where a route sends traffic.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RouteVia {
    /// Out of a (point-to-point) interface.
    Interface(String),
    /// Through a gateway, optionally pinned to an interface.
    Gateway {
        /// Next hop.
        gateway: IpAddr,
        /// Outgoing interface, when known.
        ifname: Option<String>,
    },
}

/// A route.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Route {
    /// Destination prefix.
    pub dest: IpNet,
    /// Next hop.
    pub via: RouteVia,
}

/// Resolver settings.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Name servers, in order.
    pub servers: Vec<IpAddr>,
    /// Search domains.
    pub search_domains: Vec<String>,
}

/// One network change the daemon makes. Every change has an [`Undo`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetChange {
    /// Assign an address to an interface.
    AddAddress {
        /// Interface.
        ifname: String,
        /// Local address and prefix.
        addr: IpNet,
        /// Point-to-point peer address, if any.
        peer: Option<IpAddr>,
    },
    /// Set the interface MTU.
    SetMtu {
        /// Interface.
        ifname: String,
        /// MTU in bytes.
        mtu: u32,
    },
    /// Bring the interface up.
    LinkUp {
        /// Interface.
        ifname: String,
    },
    /// Add a route.
    AddRoute(Route),
    /// Install resolvers for all names (full-tunnel DNS).
    SetDns {
        /// Interface the resolvers belong to.
        ifname: String,
        /// Resolver settings.
        dns: DnsConfig,
    },
    /// Install resolvers for one domain only (split DNS).
    AddSplitDns {
        /// Domain (without leading dot).
        domain: String,
        /// Resolvers for that domain.
        servers: Vec<IpAddr>,
    },
    /// Drop all IPv6 traffic except on loopback, for IPv4-only tunnels.
    BlockIpv6,
}

/// How to reverse one [`NetChange`]. Persisted in the journal, so it must be self-contained:
/// it carries any previous state needed to restore. Reverting must be idempotent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Undo {
    /// Nothing to reverse (e.g. the change dies with the tun device).
    Nothing,
    /// Remove an address.
    DelAddress {
        /// Interface.
        ifname: String,
        /// Address that was added.
        addr: IpNet,
    },
    /// Restore an interface MTU.
    RestoreMtu {
        /// Interface.
        ifname: String,
        /// MTU before the change.
        mtu: u32,
    },
    /// Remove a route.
    DelRoute(Route),
    /// Restore the previous resolver state. `previous` is a platform-specific snapshot.
    RestoreDns {
        /// Interface whose resolvers were set.
        ifname: String,
        /// Platform-defined snapshot of the state before the change.
        previous: String,
    },
    /// Remove (or restore) the resolvers of a split-DNS domain.
    DelSplitDns {
        /// Domain.
        domain: String,
        /// Platform-defined snapshot of what was there before, if anything.
        previous: Option<String>,
    },
    /// Remove the IPv6 block.
    UnblockIpv6,
    /// Remove the IPv6 block installed as a pf anchor; disable pf again if this change
    /// enabled it.
    UnblockIpv6Pf {
        /// pf was disabled before the block and must be disabled again.
        disable_pf: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ipnet_parse_and_mask() {
        let n: IpNet = "10.1.0.0/16".parse().unwrap();
        assert_eq!(n.v4_mask(), Some(Ipv4Addr::new(255, 255, 0, 0)));
        assert!(n.contains("10.1.200.3".parse().unwrap()));
        assert!(!n.contains("10.2.0.1".parse().unwrap()));
        assert_eq!(
            IpNet::from_v4_mask(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0)),
            Some("10.0.0.0/8".parse().unwrap())
        );
        assert_eq!(
            IpNet::from_v4_mask(Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 0, 255, 0)),
            None
        );
        assert!("1.2.3.4/33".parse::<IpNet>().is_err());
        assert_eq!("::1".parse::<IpNet>().unwrap().prefix, 128);
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
    }
}
