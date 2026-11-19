//! Facts about this machine that the EMS agent reports. Everything here is read
//! from the system and reported as is: nothing is invented or defaulted to look healthier.
//!
//! Collection is read-only. On macOS it runs `ioreg`, `sysctl`, `sw_vers`, `route`, `ifconfig`,
//! `stat` and `df`; on other systems it currently returns [`PlatformError::Unsupported`].

use std::net::Ipv4Addr;

use crate::PlatformError;

/// One network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Name (`en0`).
    pub name: String,
    /// IPv4 address.
    pub ip: Ipv4Addr,
    /// Hardware address.
    pub mac: [u8; 6],
    /// Default gateway, if this interface holds the default route.
    pub gateway: Option<Ipv4Addr>,
    /// Link is up.
    pub up: bool,
    /// Tunnel interface (`utun*`, `ppp*`, `tun*`).
    pub is_vpn: bool,
}

/// What the agent knows about the machine.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Platform UUID (IOPlatformUUID or `/etc/machine-id`).
    pub platform_uuid: Option<String>,
    /// Short host name.
    pub hostname: String,
    /// Logged-in console user, if any.
    pub user: Option<String>,
    /// OS name and version (`macOS 15.6.1`).
    pub os_version: String,
    /// Hardware vendor.
    pub manufacturer: Option<String>,
    /// Hardware model identifier.
    pub model: Option<String>,
    /// Hardware serial number.
    pub serial: Option<String>,
    /// CPU description.
    pub cpu: Option<String>,
    /// Memory in MiB.
    pub memory_mib: Option<u64>,
    /// Size of the system volume in GiB.
    pub disk_gib: Option<u64>,
    /// `ARM` or `X86`.
    pub arch: &'static str,
    /// Interfaces with an IPv4 address, the default-route interface first.
    pub interfaces: Vec<Interface>,
}

/// Parses `aa:bb:cc:dd:ee:ff`.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.trim().split([':', '-']);
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Reads `"Key" = "value"` from `ioreg -rd1 -c IOPlatformExpertDevice` output.
pub fn ioreg_value(text: &str, key: &str) -> Option<String> {
    // Strings print as `"v"`, data properties holding text as `<"v">`.
    ["\" = \"", "\" = <\""].iter().find_map(|sep| {
        let needle = format!("\"{key}{sep}");
        let start = text.find(&needle)? + needle.len();
        let rest = text.get(start..)?;
        let end = rest.find('"')?;
        Some(rest.get(..end)?.to_owned())
    })
}

/// Parses `route -n get default`: `(interface, gateway)`.
pub fn parse_default_route(text: &str) -> Option<(String, Option<Ipv4Addr>)> {
    let mut iface = None;
    let mut gw = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(v) = line.strip_prefix("interface:") {
            iface = Some(v.trim().to_owned());
        } else if let Some(v) = line.strip_prefix("gateway:") {
            gw = v.trim().parse().ok();
        }
    }
    iface.map(|i| (i, gw))
}

/// An interface while `ifconfig` output is being read: name, up, address, MAC.
type Partial = (String, bool, Option<Ipv4Addr>, Option<[u8; 6]>);

/// Parses `ifconfig` output into interfaces that have an IPv4 address and a MAC (or are tunnels).
pub fn parse_ifconfig(text: &str) -> Vec<Interface> {
    let mut out = Vec::new();
    let mut cur: Option<Partial> = None;
    let flush = |c: Option<Partial>, out: &mut Vec<Interface>| {
        if let Some((name, up, Some(ip), mac)) = c {
            let is_vpn = ["utun", "ppp", "tun", "ipsec"]
                .iter()
                .any(|p| name.starts_with(p));
            if ip.is_loopback() || (mac.is_none() && !is_vpn) {
                return;
            }
            out.push(Interface {
                name,
                ip,
                mac: mac.unwrap_or_default(),
                gateway: None,
                up,
                is_vpn,
            });
        }
    };
    for line in text.lines() {
        if !line.starts_with(['\t', ' ']) && line.contains(": flags=") {
            flush(cur.take(), &mut out);
            let name = line.split(':').next().unwrap_or_default().to_owned();
            let up = line
                .split_once('<')
                .and_then(|(_, r)| r.split_once('>'))
                .is_some_and(|(f, _)| f.split(',').any(|x| x == "UP"));
            cur = Some((name, up, None, None));
            continue;
        }
        let Some(c) = cur.as_mut() else { continue };
        let mut words = line.split_whitespace();
        match words.next() {
            Some("inet") if c.2.is_none() => c.2 = words.next().and_then(|w| w.parse().ok()),
            Some("ether") => c.3 = words.next().and_then(parse_mac),
            _ => {}
        }
    }
    flush(cur, &mut out);
    out
}

/// Collects the facts. Read-only.
pub fn collect() -> Result<Facts, PlatformError> {
    #[cfg(target_os = "macos")]
    {
        Ok(macos::collect())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err(PlatformError::Unsupported("host facts".into()))
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::process::Command;

    use super::*;

    fn out(program: &str, args: &[&str]) -> Option<String> {
        let o = Command::new(program).args(args).output().ok()?;
        o.status
            .success()
            .then(|| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .filter(|s| !s.is_empty())
    }

    fn sysctl(name: &str) -> Option<String> {
        out("/usr/sbin/sysctl", &["-n", name])
    }

    pub(super) fn collect() -> Facts {
        let ioreg =
            out("/usr/sbin/ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"]).unwrap_or_default();
        let mut interfaces = parse_ifconfig(&out("/sbin/ifconfig", &[]).unwrap_or_default());
        if let Some((iface, gw)) =
            out("/sbin/route", &["-n", "get", "default"]).and_then(|t| parse_default_route(&t))
        {
            if let Some(pos) = interfaces.iter().position(|i| i.name == iface) {
                let mut i = interfaces.remove(pos);
                i.gateway = gw;
                interfaces.insert(0, i);
            }
        }
        let disk_gib = out("/bin/df", &["-k", "/"]).and_then(|t| {
            let line = t.lines().nth(1)?;
            let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
            Some(kib / (1024 * 1024))
        });
        Facts {
            platform_uuid: ioreg_value(&ioreg, "IOPlatformUUID"),
            hostname: out("/bin/hostname", &["-s"]).unwrap_or_default(),
            user: out("/usr/bin/stat", &["-f%Su", "/dev/console"]).filter(|u| u != "root"),
            os_version: format!(
                "macOS {}",
                out("/usr/bin/sw_vers", &["-productVersion"]).unwrap_or_default()
            ),
            manufacturer: ioreg_value(&ioreg, "manufacturer"),
            model: sysctl("hw.model"),
            serial: ioreg_value(&ioreg, "IOPlatformSerialNumber"),
            cpu: sysctl("machdep.cpu.brand_string"),
            memory_mib: sysctl("hw.memsize")
                .and_then(|m| m.parse::<u64>().ok())
                .map(|b| b / (1024 * 1024)),
            disk_gib,
            arch: if cfg!(target_arch = "aarch64") {
                "ARM"
            } else {
                "X86"
            },
            interfaces,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioreg() {
        let t = r#"    "IOPlatformSerialNumber" = "C02XXXXXXX"
    "IOPlatformUUID" = "0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9"
    "manufacturer" = <"Apple Inc.">"#;
        assert_eq!(
            ioreg_value(t, "IOPlatformUUID").as_deref(),
            Some("0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9")
        );
        assert_eq!(
            ioreg_value(t, "manufacturer").as_deref(),
            Some("Apple Inc.")
        );
        assert_eq!(ioreg_value(t, "missing"), None);
    }

    #[test]
    fn route() {
        let t = "   route to: default\ndestination: default\n    gateway: 192.0.2.1\n  interface: en0\n";
        assert_eq!(
            parse_default_route(t),
            Some(("en0".into(), Some(Ipv4Addr::new(192, 0, 2, 1))))
        );
    }

    #[test]
    fn ifconfig() {
        let t = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tether aa:bb:cc:00:00:01\n\tinet6 fe80::1%en0 prefixlen 64\n\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n\
en1: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST> mtu 1500\n\tether aa:bb:cc:00:00:02\n\
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1300\n\tinet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff\n";
        let ifs = parse_ifconfig(t);
        assert_eq!(ifs.len(), 2);
        assert_eq!(ifs[0].name, "en0");
        assert_eq!(ifs[0].mac, [0xaa, 0xbb, 0xcc, 0, 0, 1]);
        assert!(ifs[0].up && !ifs[0].is_vpn);
        assert!(ifs[1].is_vpn);
    }

    #[test]
    fn mac() {
        assert_eq!(parse_mac("a:b:c:d:e:f"), Some([10, 11, 12, 13, 14, 15]));
        assert_eq!(parse_mac("a:b:c"), None);
        assert_eq!(parse_mac("a:b:c:d:e:f:0"), None);
    }
}
