//! macOS [`NetPlatform`] built on the system tools `route`, `scutil` and `pfctl`.
//!
//! **Status: unverified on a live tunnel.** The command lines below have been checked only by
//! unit tests and, for the read-only route lookup, against this Mac's output. Applying them
//! needs root and must be validated on a disposable host (milestone 3) before any release.
//!
//! - Routes: `route -n add -net CIDR -interface IF`, gateway pins as `-host IP GW`. Revert
//!   compares the installed route with ours before deleting it, so a route that the user or a
//!   network change replaced in the meantime is left alone.
//! - DNS: one SystemConfiguration dynamic-store key per change under
//!   `State:/Network/Service/org.fortino.*/DNS` (`ServerAddresses`,
//!   `SupplementalMatchDomains`). Revert removes only that key.
//! - IPv6 block: a pf anchor below `com.apple/` (evaluated by the stock `/etc/pf.conf`) with
//!   `block drop quick inet6`, loopback excepted. pf is enabled only if it was off, and disabled
//!   again on revert in that case.
//!
//! PPP creates its own interface and address, so [`NetPlatform::create_tun`] is unsupported.

use std::io;
use std::net::IpAddr;
use std::process::{Command, Stdio};

use crate::{
    IpNet, NetChange, NetPlatform, PlatformError, Result, Route, RouteVia, TunDevice, Undo,
};

/// pf anchor holding the IPv6 block.
pub const PF_ANCHOR: &str = "com.apple/250.Fortino";
/// Dynamic-store key prefix for resolver entries.
pub const DNS_KEY_PREFIX: &str = "State:/Network/Service/org.fortino";

/// Result of one command.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmdOutput {
    /// Exit status was zero.
    pub ok: bool,
    /// Standard output.
    pub stdout: String,
    /// Standard error.
    pub stderr: String,
}

/// Runs system tools. Replaced in tests.
pub trait Runner: Send {
    /// Runs `program` with `args`, feeding `stdin` if given.
    fn run(&mut self, program: &str, args: &[String], stdin: Option<&str>)
    -> io::Result<CmdOutput>;
}

/// Runs real commands with a minimal environment.
#[derive(Debug, Default)]
pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(
        &mut self,
        program: &str,
        args: &[String],
        stdin: Option<&str>,
    ) -> io::Result<CmdOutput> {
        use std::io::Write;
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        if let (Some(input), Some(mut w)) = (stdin, child.stdin.take()) {
            w.write_all(input.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        Ok(CmdOutput {
            ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

const ROUTE: &str = "/sbin/route";
const SCUTIL: &str = "/usr/sbin/scutil";
const PFCTL: &str = "/sbin/pfctl";

/// The macOS platform.
#[derive(Debug)]
pub struct MacNet<R: Runner = SystemRunner> {
    runner: R,
}

impl MacNet<SystemRunner> {
    /// Uses the real system tools.
    pub fn system() -> Self {
        Self {
            runner: SystemRunner,
        }
    }
}

impl<R: Runner> MacNet<R> {
    /// Uses `runner` for every command.
    pub fn with_runner(runner: R) -> Self {
        Self { runner }
    }

    /// The runner (for tests).
    pub fn runner(&mut self) -> &mut R {
        &mut self.runner
    }

    fn run(&mut self, program: &str, args: &[String], stdin: Option<&str>) -> Result<CmdOutput> {
        let out = self
            .runner
            .run(program, args, stdin)
            .map_err(|e| PlatformError::io(program.to_owned(), e))?;
        Ok(out)
    }

    fn must(&mut self, program: &str, args: &[String], stdin: Option<&str>) -> Result<()> {
        let out = self.run(program, args, stdin)?;
        if out.ok {
            Ok(())
        } else {
            Err(PlatformError::Other(format!(
                "{program} {} failed: {}",
                args.first().map(String::as_str).unwrap_or(""),
                out.stderr.trim()
            )))
        }
    }

    fn pf_enabled(&mut self) -> Result<bool> {
        let out = self.run(PFCTL, &["-s".into(), "info".into()], None)?;
        Ok(out
            .stdout
            .lines()
            .chain(out.stderr.lines())
            .any(|l| l.trim_start().starts_with("Status: Enabled")))
    }
}

fn s(x: impl ToString) -> String {
    x.to_string()
}

fn dest_args(dest: &IpNet) -> Vec<String> {
    if dest.prefix == if dest.is_ipv4() { 32 } else { 128 } {
        vec![s("-host"), s(dest.addr)]
    } else {
        vec![s("-net"), s(dest)]
    }
}

/// `route add` arguments for a route.
pub fn route_add_args(r: &Route) -> Vec<String> {
    let mut a = vec![s("-n"), s("add")];
    a.extend(dest_args(&r.dest));
    match &r.via {
        RouteVia::Interface(i) => {
            a.push(s("-interface"));
            a.push(i.clone());
        }
        RouteVia::Gateway { gateway, .. } => a.push(s(gateway)),
    }
    a
}

/// `route delete` arguments for a route.
pub fn route_delete_args(r: &Route) -> Vec<String> {
    let mut a = vec![s("-n"), s("delete")];
    a.extend(dest_args(&r.dest));
    if let RouteVia::Interface(i) = &r.via {
        a.push(s("-interface"));
        a.push(i.clone());
    }
    a
}

/// Parses `route -n get` output into the destination it matched and the next hop.
pub fn parse_route_get(out: &str) -> Option<(String, RouteVia)> {
    let mut dest = None;
    let mut gateway = None;
    let mut ifname = None;
    for line in out.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim().to_owned();
        match k.trim() {
            "destination" => dest = Some(v),
            "gateway" => gateway = Some(v),
            "interface" => ifname = Some(v),
            _ => {}
        }
    }
    let via = match (gateway.and_then(|g| g.parse::<IpAddr>().ok()), ifname) {
        (Some(gateway), ifname) => RouteVia::Gateway { gateway, ifname },
        (None, Some(i)) => RouteVia::Interface(i),
        (None, None) => return None,
    };
    Some((dest?, via))
}

fn dns_key(suffix: &str) -> String {
    format!("{DNS_KEY_PREFIX}.{suffix}/DNS")
}

/// `scutil` script that publishes a resolver entry.
pub fn scutil_set(
    key: &str,
    servers: &[IpAddr],
    match_domains: &[String],
    search: &[String],
) -> String {
    let mut out = String::from("d.init\n");
    let list = |v: Vec<String>| v.join(" ");
    out.push_str(&format!(
        "d.add ServerAddresses * {}\n",
        list(servers.iter().map(ToString::to_string).collect())
    ));
    if !match_domains.is_empty() {
        out.push_str(&format!(
            "d.add SupplementalMatchDomains * {}\n",
            list(match_domains.to_vec())
        ));
        // Without this, macOS also appends match domains to the default search list, so a
        // bare name such as `wiki` would be tried as `wiki.<vpn domain>` (seen in the VM).
        out.push_str("d.add SupplementalMatchDomainsNoSearch # 1\n");
    }
    if !search.is_empty() {
        out.push_str(&format!(
            "d.add SearchDomains * {}\n",
            list(search.to_vec())
        ));
    }
    out.push_str(&format!("set {key}\nquit\n"));
    out
}

/// pf rules for the IPv6 block.
pub const PF_RULES: &str = "pass quick on lo0 inet6 all\nblock drop quick inet6 all\n";

fn safe_token(t: &str) -> bool {
    !t.is_empty()
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

impl<R: Runner> NetPlatform for MacNet<R> {
    fn create_tun(&mut self) -> Result<TunDevice> {
        Err(PlatformError::Unsupported(
            "PPP creates its own interface".into(),
        ))
    }

    fn prepare(&mut self, change: &NetChange) -> Result<Undo> {
        Ok(match change {
            NetChange::AddRoute(r) => Undo::DelRoute(r.clone()),
            // A dynamic-store DNS entry without match domains is ignored by macOS (verified in
            // the VM), and scutil cannot express the empty match domain. Full-tunnel DNS needs
            // the primary service's resolvers overridden and restored; until that exists it is
            // refused here, before anything is journaled or changed.
            NetChange::SetDns { .. } => {
                return Err(PlatformError::Unsupported(
                    "full-tunnel DNS is not implemented on macOS yet".into(),
                ));
            }
            NetChange::AddSplitDns { domain, .. } => Undo::DelSplitDns {
                domain: domain.clone(),
                previous: None,
            },
            NetChange::BlockIpv6 => Undo::UnblockIpv6Pf {
                disable_pf: !self.pf_enabled()?,
            },
            NetChange::AddAddress { .. } | NetChange::SetMtu { .. } | NetChange::LinkUp { .. } => {
                return Err(PlatformError::Unsupported(
                    "PPP configures the interface itself".into(),
                ));
            }
        })
    }

    fn apply(&mut self, change: &NetChange) -> Result<()> {
        match change {
            NetChange::AddRoute(r) => self.must(ROUTE, &route_add_args(r), None),
            NetChange::SetDns { .. } => Err(PlatformError::Unsupported(
                "full-tunnel DNS is not implemented on macOS yet".into(),
            )),
            NetChange::AddSplitDns { domain, servers } => {
                if !safe_token(domain) {
                    return Err(PlatformError::Other("invalid DNS domain".into()));
                }
                let script = scutil_set(
                    &dns_key(&format!("split.{domain}")),
                    servers,
                    std::slice::from_ref(domain),
                    &[],
                );
                self.must(SCUTIL, &[], Some(&script))
            }
            NetChange::BlockIpv6 => {
                self.must(
                    PFCTL,
                    &[s("-a"), s(PF_ANCHOR), s("-f"), s("-")],
                    Some(PF_RULES),
                )?;
                if !self.pf_enabled()? {
                    self.must(PFCTL, &[s("-e")], None)?;
                }
                Ok(())
            }
            NetChange::AddAddress { .. } | NetChange::SetMtu { .. } | NetChange::LinkUp { .. } => {
                Err(PlatformError::Unsupported(
                    "PPP configures the interface itself".into(),
                ))
            }
        }
    }

    fn revert(&mut self, undo: &Undo) -> Result<()> {
        match undo {
            Undo::Nothing => Ok(()),
            Undo::DelRoute(r) => {
                // Compare before undo: only delete the route if it is still ours.
                let probe = r.dest.addr;
                let out = self.run(ROUTE, &[s("-n"), s("get"), s(probe)], None)?;
                let installed = parse_route_get(&out.stdout);
                let ours = match (&installed, &r.via) {
                    (Some((d, RouteVia::Interface(i))), RouteVia::Interface(want)) => {
                        i == want && d != "default"
                    }
                    (
                        Some((_, RouteVia::Gateway { gateway, .. })),
                        RouteVia::Gateway { gateway: want, .. },
                    ) => gateway == want,
                    _ => false,
                };
                if !ours {
                    tracing::info!(route = %r.dest, "route already gone or replaced; leaving it");
                    return Ok(());
                }
                self.must(ROUTE, &route_delete_args(r), None)
            }
            Undo::RestoreDns { previous, .. } => {
                if !previous.starts_with(DNS_KEY_PREFIX) {
                    return Err(PlatformError::Other("unexpected resolver key".into()));
                }
                self.must(SCUTIL, &[], Some(&format!("remove {previous}\nquit\n")))
            }
            Undo::DelSplitDns { domain, .. } => {
                if !safe_token(domain) {
                    return Err(PlatformError::Other("invalid DNS domain".into()));
                }
                let key = dns_key(&format!("split.{domain}"));
                self.must(SCUTIL, &[], Some(&format!("remove {key}\nquit\n")))
            }
            Undo::UnblockIpv6 | Undo::UnblockIpv6Pf { .. } => {
                self.must(PFCTL, &[s("-a"), s(PF_ANCHOR), s("-F"), s("rules")], None)?;
                if matches!(undo, Undo::UnblockIpv6Pf { disable_pf: true }) {
                    self.must(PFCTL, &[s("-d")], None)?;
                }
                Ok(())
            }
            Undo::DelAddress { .. } | Undo::RestoreMtu { .. } => Ok(()),
        }
    }

    fn route_to(&mut self, dst: IpAddr) -> Result<Option<RouteVia>> {
        let out = self.run(ROUTE, &[s("-n"), s("get"), s(dst)], None)?;
        if !out.ok {
            return Ok(None);
        }
        Ok(parse_route_get(&out.stdout).map(|(_, via)| via))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    /// Records commands and replays canned outputs (default: success, empty output).
    #[derive(Debug, Default)]
    struct Rec {
        calls: Vec<String>,
        replies: VecDeque<CmdOutput>,
    }

    impl Runner for Rec {
        fn run(&mut self, p: &str, a: &[String], stdin: Option<&str>) -> io::Result<CmdOutput> {
            let mut line = std::iter::once(p.to_owned())
                .chain(a.iter().cloned())
                .collect::<Vec<_>>()
                .join(" ");
            if let Some(i) = stdin {
                line.push_str(&format!(" <<< {}", i.replace('\n', "; ")));
            }
            self.calls.push(line.trim().to_owned());
            Ok(self.replies.pop_front().unwrap_or(CmdOutput {
                ok: true,
                ..Default::default()
            }))
        }
    }

    fn ok(stdout: &str) -> CmdOutput {
        CmdOutput {
            ok: true,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    const GET_EN0: &str = "   route to: 1.1.1.1\ndestination: 1.1.1.1\n    gateway: 192.168.0.1\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE>\n";

    #[test]
    fn parses_route_get() {
        let (d, via) = parse_route_get(GET_EN0).unwrap();
        assert_eq!(d, "1.1.1.1");
        assert_eq!(
            via,
            RouteVia::Gateway {
                gateway: "192.168.0.1".parse().unwrap(),
                ifname: Some("en0".into())
            }
        );
        let ppp = "   route to: 10.1.2.3\ndestination: 10.0.0.0\n       mask: 255.0.0.0\n  interface: ppp0\n";
        assert_eq!(
            parse_route_get(ppp).unwrap().1,
            RouteVia::Interface("ppp0".into())
        );
    }

    #[test]
    fn route_commands() {
        let r = Route {
            dest: "10.0.0.0/8".parse().unwrap(),
            via: RouteVia::Interface("ppp0".into()),
        };
        assert_eq!(
            route_add_args(&r).join(" "),
            "-n add -net 10.0.0.0/8 -interface ppp0"
        );
        let pin = Route {
            dest: IpNet::host("203.0.113.10".parse().unwrap()),
            via: RouteVia::Gateway {
                gateway: "192.168.0.1".parse().unwrap(),
                ifname: Some("en0".into()),
            },
        };
        assert_eq!(
            route_add_args(&pin).join(" "),
            "-n add -host 203.0.113.10 192.168.0.1"
        );
        assert_eq!(
            route_delete_args(&pin).join(" "),
            "-n delete -host 203.0.113.10"
        );
    }

    #[test]
    fn revert_leaves_replaced_route_alone() {
        let r = Route {
            dest: "10.0.0.0/8".parse().unwrap(),
            via: RouteVia::Interface("ppp0".into()),
        };
        let mut m = MacNet::with_runner(Rec::default());
        // Now served by en0's default route: ours is gone.
        m.runner().replies.push_back(ok(
            "destination: default\n    gateway: 192.168.0.1\n  interface: en0\n",
        ));
        m.revert(&Undo::DelRoute(r.clone())).unwrap();
        assert_eq!(m.runner().calls.len(), 1);

        // Still ours: deleted.
        m.runner()
            .replies
            .push_back(ok("destination: 10.0.0.0\n  interface: ppp0\n"));
        m.revert(&Undo::DelRoute(r)).unwrap();
        assert_eq!(
            m.runner().calls.last().unwrap(),
            "/sbin/route -n delete -net 10.0.0.0/8 -interface ppp0"
        );
    }

    #[test]
    fn split_dns_and_ipv6_block() {
        let mut m = MacNet::with_runner(Rec::default());
        let c = NetChange::AddSplitDns {
            domain: "corp.example".into(),
            servers: vec!["10.0.0.53".parse().unwrap()],
        };
        let undo = m.prepare(&c).unwrap();
        m.apply(&c).unwrap();
        m.revert(&undo).unwrap();
        assert_eq!(
            m.runner().calls,
            vec![
                "/usr/sbin/scutil <<< d.init; d.add ServerAddresses * 10.0.0.53; d.add SupplementalMatchDomains * corp.example; d.add SupplementalMatchDomainsNoSearch # 1; set State:/Network/Service/org.fortino.split.corp.example/DNS; quit;",
                "/usr/sbin/scutil <<< remove State:/Network/Service/org.fortino.split.corp.example/DNS; quit;",
            ]
        );

        let mut m = MacNet::with_runner(Rec::default());
        // pf disabled at prepare and at apply.
        m.runner().replies.push_back(ok("Status: Disabled"));
        let undo = m.prepare(&NetChange::BlockIpv6).unwrap();
        assert_eq!(undo, Undo::UnblockIpv6Pf { disable_pf: true });
        m.runner().replies.push_back(ok(""));
        m.runner().replies.push_back(ok("Status: Disabled"));
        m.apply(&NetChange::BlockIpv6).unwrap();
        m.revert(&undo).unwrap();
        let calls = &m.runner().calls;
        assert!(calls.contains(&"/sbin/pfctl -e".to_owned()));
        assert_eq!(
            calls[calls.len() - 2],
            "/sbin/pfctl -a com.apple/250.Fortino -F rules"
        );
        assert_eq!(calls[calls.len() - 1], "/sbin/pfctl -d");
    }

    #[test]
    fn rejects_interface_changes_and_bad_domains() {
        let mut m = MacNet::with_runner(Rec::default());
        assert!(
            m.prepare(&NetChange::LinkUp {
                ifname: "ppp0".into()
            })
            .is_err()
        );
        let bad = NetChange::AddSplitDns {
            domain: "x\nset Evil".into(),
            servers: vec![],
        };
        assert!(m.apply(&bad).is_err());
    }

    /// Read-only check against the real routing table.
    #[cfg(target_os = "macos")]
    #[test]
    fn live_route_lookup() {
        let mut m = MacNet::system();
        // Loopback always resolves to lo0.
        let via = m.route_to("127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(via, Some(RouteVia::Interface("lo0".into())));
    }
}
