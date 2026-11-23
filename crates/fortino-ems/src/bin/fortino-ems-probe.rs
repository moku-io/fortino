//! Live EMS check. Development tool, not shipped.
//!
//! ```text
//! fortino-ems-probe HOST[:PORT] --print-pin
//! fortino-ems-probe HOST[:PORT] --pin SHA256 [--ca FILE] [--facts] [--sysinfo KEY=VAL]...
//! fortino-ems-probe HOST[:PORT] --pin SHA256 --state DIR --register [--key-file FILE] [--sysinfo KEY=VAL]... --yes
//! fortino-ems-probe HOST[:PORT] --pin SHA256 --state DIR --keepalive [--full] [--check-host] [--tag BITS|-] [--sysinfo KEY=VAL]...
//! fortino-ems-probe HOST[:PORT] --pin SHA256 --state DIR --deregister --yes
//! fortino-ems-probe HOST[:PORT] --forticlient
//! ```
//!
//! Without `--register`, `--keepalive` or `--deregister` it only sends PROBE, which creates
//! nothing on the server. `--register` creates a device record on the EMS and needs `--yes`;
//! get the administrator's approval first. `--uid` overrides the endpoint UID (default: the
//! platform UUID, which is also what an installed FortiClient uses). `--facts` prints what
//! would be reported, without contacting anything. `--forticlient` shows whether an installed
//! FortiClient manages this device on that EMS (values masked; contacts nothing). Secrets are
//! never printed. `--caps N` overrides the `CAPS` header for an experiment.
//!
//! `--sysinfo KEY=VAL` (repeatable) is the debug SYSINFO override: it replaces or adds a SYSINFO
//! key in what REGISTER and keepalives report, for testing how an EMS reacts (e.g.
//! `--sysinfo "OSVER=macOS 26.1.0"` for the golden_gate / Tahoe test). These values may not be
//! truthful; use only against an EMS you are authorised to test. See
//! the design notes.

use std::process::ExitCode;

use fortino_config::EmsServer;
use fortino_ems::report::{self, Compat};
use fortino_ems::{Agent, Connection, Keepalive, Store};
use fortino_proto_ems::ids::Uid;
use fortino_tls::Trust;
use fortino_tls::{fetch_leaf, fingerprint, parse_pin};

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// The value after every occurrence of `name` (for repeatable flags).
fn args_all<'a>(args: &'a [String], name: &str) -> Vec<&'a str> {
    args.iter()
        .enumerate()
        .filter(|(_, a)| a.as_str() == name)
        .filter_map(|(i, _)| args.get(i + 1))
        .map(String::as_str)
        .collect()
}

/// Debug SYSINFO overrides from `--sysinfo KEY=VAL` flags.
fn parse_overrides(args: &[String]) -> Result<std::collections::BTreeMap<String, String>, String> {
    let mut map = std::collections::BTreeMap::new();
    for item in args_all(args, "--sysinfo") {
        let (k, v) = item
            .split_once('=')
            .ok_or_else(|| format!("--sysinfo needs KEY=VALUE, got {item:?}"))?;
        map.insert(k.to_owned(), v.to_owned());
    }
    Ok(map)
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ems-probe: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let target = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .ok_or("usage: fortino-ems-probe HOST[:PORT] [options] (see source header)")?;
    let server: EmsServer = target.parse().map_err(|e| format!("EMS address: {e}"))?;

    let facts = fortino_platform::facts::collect().map_err(|e| e.to_string())?;
    let overrides = parse_overrides(&args)?;
    if has(&args, "--facts") {
        let s = report::full(&facts, &Compat::default(), None).map_err(|e| e.to_string())?;
        let s = fortino_ems::debug_override::apply(s, &overrides);
        for (k, v) in s.iter() {
            println!("{k}={v}");
        }
        return Ok(());
    }

    let fc = fortino_ems::forticlient::source(Some(fortino_ems::forticlient::MACOS_ROOT.into()))();
    if has(&args, "--forticlient") {
        let Some(fc) = fc else {
            println!("FortiClient: not installed");
            return Ok(());
        };
        let ours = facts
            .platform_uuid
            .as_deref()
            .and_then(|u| Uid::parse(u).ok());
        println!(
            "FortiClient: agent running={} registered={} same_uid={} ems_addresses={} this_ems={} tenant_known={}",
            fc.running,
            fc.serial.is_some(),
            ours.is_some() && fc.uid == ours,
            fc.addresses.len(),
            fc.uses_address(&server),
            fc.tenant.is_some(),
        );
        return Ok(());
    }

    if has(&args, "--print-pin") {
        let addr = tokio::net::lookup_host((server.host.to_string(), server.port))
            .await
            .map_err(|e| format!("resolve: {e}"))?
            .find(std::net::SocketAddr::is_ipv4)
            .ok_or("no IPv4 address")?;
        let leaf = fetch_leaf(addr, &server.host)
            .await
            .map_err(|e| e.to_string())?;
        println!("sha256:{}", fingerprint(&leaf));
        return Ok(());
    }

    let trust = match (arg(&args, "--pin"), arg(&args, "--ca")) {
        (Some(p), _) => Trust::Pinned(vec![
            parse_pin(p.trim_start_matches("sha256:")).ok_or("bad --pin")?,
        ]),
        (None, Some(ca)) => Trust::CaFile(ca.into()),
        (None, None) => return Err("give --pin (see --print-pin) or --ca".into()),
    };
    let conn = Connection::new(server, &trust).map_err(|e| e.to_string())?;
    let uid = match arg(&args, "--uid") {
        Some(u) => u.to_owned(),
        None => facts
            .platform_uuid
            .clone()
            .ok_or("no platform UUID; pass --uid")?,
    };
    let state = arg(&args, "--state").unwrap_or("target/ems-state");
    let mut compat = Compat::default();
    if let Some(c) = arg(&args, "--caps") {
        compat.caps = c.parse().map_err(|_| "bad --caps")?;
    }
    let agent = Agent {
        compat,
        facts,
        uid: Uid::parse(&uid).map_err(|e| e.to_string())?,
        store: Store::open(state).map_err(|e| e.to_string())?,
        overrides,
    };

    if has(&args, "--register") {
        if !has(&args, "--yes") {
            return Err("--register creates a device record on the EMS; add --yes".into());
        }
        let key = match arg(&args, "--key-file") {
            Some(f) => Some(
                std::fs::read_to_string(f)
                    .map_err(|e| format!("read key file: {e}"))?
                    .trim()
                    .to_owned(),
            ),
            None => None,
        };
        let r = agent
            .register(&conn, key.as_deref())
            .await
            .map_err(|e| e.to_string())?;
        println!(
            "registered serial={} vdom={} ka={}s rules={} conf={}",
            r.serial,
            r.vdom,
            r.ka_interval,
            r.host_rules.content.is_some(),
            r.conf.content.is_some()
        );
        return Ok(());
    }
    if has(&args, "--keepalive") {
        match agent
            .keepalive(&conn, has(&args, "--full"))
            .await
            .map_err(|e| e.to_string())?
        {
            Keepalive::Kept { tags, renew } => println!("kept tags={tags} renew={renew}"),
            Keepalive::Dropped => println!("dropped by the EMS; local registration removed"),
        }
        if let Some(r) = agent.registration(&conn).map_err(|e| e.to_string())? {
            println!(
                "received: conf={} host_rules={} server_list={} on_net={} off_net={}",
                r.conf.content.is_some(),
                r.host_rules.content.is_some(),
                r.server_list.content.is_some(),
                r.on_net.content.is_some(),
                r.off_net.content.is_some()
            );
        }
        if let Some(bits) = arg(&args, "--tag") {
            let bits = if bits == "-" {
                String::new()
            } else {
                bits.to_owned()
            };
            let rules = fortino_proto_ems::tags::Bits::parse(&bits).map_err(|_| "bad --tag")?;
            let tags = agent
                .report_rules(&conn, &rules)
                .await
                .map_err(|e| e.to_string())?;
            println!("tag message sent (rules={bits:?}); tags={tags}");
        }
        if has(&args, "--check-host") {
            match agent.check_host(&conn).await.map_err(|e| e.to_string())? {
                Some(tags) => println!("host verification reported; tags={tags}"),
                None => println!("host verification: nothing to report"),
            }
        }
        return Ok(());
    }
    if has(&args, "--deregister") {
        if !has(&args, "--yes") {
            return Err("--deregister removes the device record; add --yes".into());
        }
        // The device record may be FortiClient's too: never remove it from under FortiClient.
        if let (Some(fc), Some(reg)) = (&fc, agent.registration(&conn).map_err(|e| e.to_string())?)
        {
            if fc.active_with(&agent.uid)
                && fc.serial.as_ref().is_some_and(|s| s.as_str() == reg.serial)
            {
                return Err("FortiClient is registered to this EMS with the same device UID; deregistering would remove its registration too. Deregister from FortiClient, or delete Fortino's local record only.".into());
            }
        }
        agent.deregister(&conn).await.map_err(|e| e.to_string())?;
        println!("deregistered");
        return Ok(());
    }

    let p = agent.probe(&conn).await.map_err(|e| e.to_string())?;
    println!(
        "ems serial={} version={:?} proto={:?} features={:?} unknown_fields={:?}",
        p.serial, p.ems_version, p.proto_version, p.feature_bitmap, p.notes.unknown
    );
    Ok(())
}
