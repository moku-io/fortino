//! Live EMS check. Development tool, not shipped.
//!
//! ```text
//! fortino-ems-probe HOST[:PORT] --print-pin
//! fortino-ems-probe HOST[:PORT] --pin SHA256 [--ca FILE] [--facts]
//! fortino-ems-probe HOST[:PORT] --pin SHA256 --state DIR --register [--key-file FILE] --yes
//! fortino-ems-probe HOST[:PORT] --pin SHA256 --state DIR --keepalive [--full]
//! fortino-ems-probe HOST[:PORT] --pin SHA256 --state DIR --deregister --yes
//! ```
//!
//! Without `--register`, `--keepalive` or `--deregister` it only sends PROBE, which creates
//! nothing on the server. `--register` creates a device record on the EMS and needs `--yes`;
//! get the administrator's approval first. `--uid` overrides the endpoint UID (default: the
//! platform UUID, which is also what an installed FortiClient uses). `--facts` prints what
//! would be reported, without contacting anything. Secrets are never printed.

use std::process::ExitCode;

use fortino_config::EmsServer;
use fortino_ems::report::{self, Compat};
use fortino_ems::{Agent, Connection, Keepalive, Store};
use fortino_proto_ems::ids::Uid;
use fortino_sslvpn::Trust;
use fortino_sslvpn::transport::{fetch_leaf, fingerprint, parse_pin};

fn arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
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
    if has(&args, "--facts") {
        let s = report::full(&facts, &Compat::default(), None).map_err(|e| e.to_string())?;
        for (k, v) in s.iter() {
            println!("{k}={v}");
        }
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
            .map_err(|e| format!("{e:?}"))?;
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
    let agent = Agent {
        compat: Compat::default(),
        facts,
        uid: Uid::parse(&uid).map_err(|e| e.to_string())?,
        store: Store::open(state).map_err(|e| e.to_string())?,
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
        return Ok(());
    }
    if has(&args, "--deregister") {
        if !has(&args, "--yes") {
            return Err("--deregister removes the device record; add --yes".into());
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
