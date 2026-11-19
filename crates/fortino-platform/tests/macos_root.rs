//! Live tests of the macOS controller (`route`, `scutil`, `pfctl`). They change the host's
//! network state, so they run only as root, inside a virtual machine, with
//! `FORTINO_VM_ROOT_TESTS=1`. Use `scripts/macos-vm-test.sh`, which runs them in a disposable
//! Tart clone. Elsewhere every test returns early without doing anything.
//!
//! Each test uses `feth` fake-ethernet interfaces in place of the PPP interface, and checks
//! that rollback (or crash recovery) restores the routing table, the resolver keys and pf.
#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::process::{Command, Stdio};

use fortino_platform::journal::Journaled;
use fortino_platform::macos::{DNS_KEY_PREFIX, MacNet, PF_ANCHOR};
use fortino_platform::{DnsConfig, NetChange, NetPlatform, Route, RouteVia};

const IF_A: &str = "feth4711";
const IF_B: &str = "feth4712";

fn enabled() -> bool {
    if std::env::var("FORTINO_VM_ROOT_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: set FORTINO_VM_ROOT_TESTS=1 (VM only)");
        return false;
    }
    assert!(nix_is_root(), "FORTINO_VM_ROOT_TESTS=1 needs root");
    let vm = sh("sysctl", &["-n", "kern.hv_vmm_present"]);
    assert_eq!(
        vm.trim(),
        "1",
        "refusing to change network state outside a VM"
    );
    true
}

fn nix_is_root() -> bool {
    sh("id", &["-u"]).trim() == "0"
}

fn run(program: &str, args: &[&str], stdin: Option<&str>) -> (bool, String) {
    let mut c = Command::new(program);
    c.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = c.spawn().unwrap();
    if let Some(input) = stdin {
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

fn sh(program: &str, args: &[&str]) -> String {
    run(program, args, None).1
}

fn must(program: &str, args: &[&str]) {
    let (ok, out) = run(program, args, None);
    assert!(ok, "{program} {args:?} failed: {out}");
}

/// Routing table without cloned and link-layer entries, which change on their own.
fn routes() -> Vec<String> {
    let mut v: Vec<String> = sh("netstat", &["-rn", "-f", "inet"])
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 4 || f[0] == "Destination" {
                return None;
            }
            let flags = f[2];
            if flags.contains('W') || flags.contains('L') || f[1].starts_with("link#") {
                return None;
            }
            Some(format!("{} {} {} {}", f[0], f[1], f[2], f[3]))
        })
        .collect();
    v.sort();
    v
}

fn dns_keys() -> Vec<String> {
    let (_, out) = run(
        "scutil",
        &[],
        Some("list State:/Network/Service/.*/DNS\nquit\n"),
    );
    let mut v: Vec<String> = out
        .lines()
        .filter_map(|l| l.split(" = ").nth(1).map(str::to_owned))
        .collect();
    v.sort();
    v
}

fn pf_enabled() -> bool {
    sh("pfctl", &["-s", "info"])
        .lines()
        .any(|l| l.trim_start().starts_with("Status: Enabled"))
}

fn anchor_rules() -> String {
    sh("pfctl", &["-a", PF_ANCHOR, "-s", "rules"])
        .lines()
        .filter(|l| !l.starts_with("No ALTQ") && !l.starts_with("ALTQ"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    routes: Vec<String>,
    dns: Vec<String>,
    pf: bool,
    anchor: String,
}

fn snapshot() -> Snapshot {
    Snapshot {
        routes: routes(),
        dns: dns_keys(),
        pf: pf_enabled(),
        anchor: anchor_rules(),
    }
}

/// Fake-ethernet interfaces standing in for the PPP link; destroyed on drop.
struct Feth;

impl Feth {
    fn create() -> Self {
        for (i, addr) in [(IF_A, "10.250.0.1"), (IF_B, "10.249.0.1")] {
            let _ = run("ifconfig", &[i, "destroy"], None);
            must("ifconfig", &[i, "create"]);
            must(
                "ifconfig",
                &[i, "inet", addr, "netmask", "255.255.255.0", "up"],
            );
        }
        Feth
    }
}

impl Drop for Feth {
    fn drop(&mut self) {
        for i in [IF_A, IF_B] {
            let _ = run("ifconfig", &[i, "destroy"], None);
        }
    }
}

fn route_if(dst: &str) -> Option<String> {
    let (_, out) = run("route", &["-n", "get", dst], None);
    fortino_platform::macos::parse_route_get(&out).map(|(_, via)| match via {
        RouteVia::Interface(i) => i,
        RouteVia::Gateway { gateway, ifname } => {
            format!("{gateway}@{}", ifname.unwrap_or_default())
        }
    })
}

fn default_gateway() -> IpAddr {
    let mut m = MacNet::system();
    match m.route_to("1.1.1.1".parse().unwrap()).unwrap() {
        Some(RouteVia::Gateway { gateway, .. }) => gateway,
        other => panic!("no default gateway: {other:?}"),
    }
}

/// The changes a split tunnel with DNS and the IPv6 block makes.
fn tunnel_changes() -> Vec<NetChange> {
    vec![
        NetChange::AddRoute(Route {
            dest: "198.51.100.77/32".parse().unwrap(),
            via: RouteVia::Gateway {
                gateway: default_gateway(),
                ifname: None,
            },
        }),
        NetChange::AddRoute(Route {
            dest: "10.251.0.0/16".parse().unwrap(),
            via: RouteVia::Interface(IF_A.into()),
        }),
        NetChange::AddRoute(Route {
            dest: "172.31.250.0/24".parse().unwrap(),
            via: RouteVia::Interface(IF_A.into()),
        }),
        NetChange::SetDns {
            ifname: IF_A.into(),
            dns: DnsConfig {
                servers: vec!["10.251.0.53".parse().unwrap()],
                search_domains: vec!["corp.example".into()],
            },
        },
        NetChange::AddSplitDns {
            domain: "intra.example".into(),
            servers: vec!["10.251.0.54".parse().unwrap()],
        },
        NetChange::BlockIpv6,
    ]
}

fn check_applied() {
    assert_eq!(route_if("10.251.3.4").as_deref(), Some(IF_A));
    assert_eq!(route_if("172.31.250.9").as_deref(), Some(IF_A));
    let pin = route_if("198.51.100.77").unwrap();
    assert!(
        pin.starts_with(&default_gateway().to_string()),
        "pin: {pin}"
    );

    let keys = dns_keys();
    assert!(
        keys.iter().any(|k| k.starts_with(DNS_KEY_PREFIX)),
        "keys: {keys:?}"
    );
    let resolvers = sh("scutil", &["--dns"]);
    assert!(resolvers.contains("10.251.0.53"), "{resolvers}");
    assert!(resolvers.contains("10.251.0.54"), "{resolvers}");
    assert!(resolvers.contains("intra.example"), "{resolvers}");

    assert!(pf_enabled());
    let rules = anchor_rules();
    assert!(rules.contains("block drop quick inet6 all"), "{rules}");
    // The stock ruleset must actually evaluate our anchor.
    let main = sh("pfctl", &["-s", "rules"]);
    assert!(main.contains("anchor \"com.apple/*\""), "{main}");
    // Loopback IPv6 still works; other IPv6 is dropped.
    assert!(run("ping6", &["-c", "1", "::1"], None).0);
    let (ok, out) = run("ping6", &["-c", "1", "-i", "1", "2001:db8::1"], None);
    assert!(!ok, "IPv6 left the host: {out}");
    eprintln!("ping6 2001:db8::1 while blocked: {}", out.trim());
}

#[test]
fn apply_then_rollback_restores_everything() {
    if !enabled() {
        return;
    }
    let _ifs = Feth::create();
    let before = snapshot();
    let dir = tempfile::tempdir().unwrap();
    let mut j = Journaled::open(MacNet::system(), dir.path().join("j.json")).unwrap();
    j.apply_all(&tunnel_changes()).unwrap();
    check_applied();
    j.rollback_all().unwrap();
    assert_eq!(j.pending(), 0);
    assert_eq!(snapshot(), before);
}

#[test]
fn crash_recovery_restores_everything() {
    if !enabled() {
        return;
    }
    let _ifs = Feth::create();
    let before = snapshot();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("j.json");
    {
        let mut j = Journaled::open(MacNet::system(), &path).unwrap();
        j.apply_all(&tunnel_changes()).unwrap();
        // Dropped without rollback, as if the daemon crashed.
    }
    check_applied();
    let mut j = Journaled::open(MacNet::system(), &path).unwrap();
    assert_eq!(j.recover().unwrap(), tunnel_changes().len());
    assert_eq!(snapshot(), before);
    // A second recovery has nothing left to do.
    assert_eq!(j.recover().unwrap(), 0);
}

#[test]
fn pf_left_enabled_when_it_was_enabled() {
    if !enabled() {
        return;
    }
    let was = pf_enabled();
    if !was {
        must("pfctl", &["-E"]);
    }
    let dir = tempfile::tempdir().unwrap();
    let mut j = Journaled::open(MacNet::system(), dir.path().join("j.json")).unwrap();
    j.apply(&NetChange::BlockIpv6).unwrap();
    j.rollback_all().unwrap();
    assert!(pf_enabled(), "pf was enabled before and must stay enabled");
    assert_eq!(anchor_rules(), "");
    if !was {
        must("pfctl", &["-d"]);
    }
}

#[test]
fn replaced_route_is_left_alone() {
    if !enabled() {
        return;
    }
    let _ifs = Feth::create();
    let dir = tempfile::tempdir().unwrap();
    let mut j = Journaled::open(MacNet::system(), dir.path().join("j.json")).unwrap();
    j.apply(&NetChange::AddRoute(Route {
        dest: "10.248.0.0/16".parse().unwrap(),
        via: RouteVia::Interface(IF_A.into()),
    }))
    .unwrap();
    // Someone else replaces the route while the tunnel is up.
    must(
        "route",
        &["-n", "change", "-net", "10.248.0.0/16", "-interface", IF_B],
    );
    j.rollback_all().unwrap();
    assert_eq!(route_if("10.248.1.1").as_deref(), Some(IF_B));
    must("route", &["-n", "delete", "-net", "10.248.0.0/16"]);
}

#[test]
fn failed_change_rolls_back_earlier_ones() {
    if !enabled() {
        return;
    }
    let _ifs = Feth::create();
    let before = snapshot();
    let dir = tempfile::tempdir().unwrap();
    let mut j = Journaled::open(MacNet::system(), dir.path().join("j.json")).unwrap();
    let mut changes = tunnel_changes();
    changes.insert(
        3,
        NetChange::AddRoute(Route {
            dest: "10.247.0.0/16".parse().unwrap(),
            via: RouteVia::Interface("feth9999".into()),
        }),
    );
    assert!(j.apply_all(&changes).is_err());
    assert_eq!(j.pending(), 0);
    assert_eq!(snapshot(), before);
}
