//! Human-readable output.

use std::time::{SystemTime, UNIX_EPOCH};

use fortino_config::import::Preview;
use fortino_config::{DEFAULT_EMS_PORT, Profile};
use fortino_core::proto::{State, Status};

pub fn profile_table(ps: &[Profile]) {
    println!("{:<24} {:<32} {:<8} EMS", "NAME", "GATEWAY", "SCOPE");
    for p in ps {
        let e = &p.spec.endpoint;
        let gw = match &e.realm {
            Some(r) => format!("{}:{}/{r}", e.host, e.port),
            None => format!("{}:{}", e.host, e.port),
        };
        let scope = match p.spec.ip_policy {
            fortino_config::IpPolicy::SplitIpv4 => "split",
            fortino_config::IpPolicy::FullIpv4 => "full",
        };
        let ems = e
            .ems
            .as_ref()
            .map_or_else(|| "-".into(), ToString::to_string);
        println!("{:<24} {:<32} {:<8} {ems}", p.spec.name, gw, scope);
    }
}

pub fn profile_details(p: &Profile) {
    let s = &p.spec;
    let e = &s.endpoint;
    println!("Name:        {}", s.name);
    println!("ID:          {}", p.id);
    println!("Revision:    {}", p.revision);
    if let Some(d) = &s.description {
        println!("Description: {d}");
    }
    println!("Gateway:     {}:{}", e.host, e.port);
    println!("Realm:       {}", e.realm.as_deref().unwrap_or("-"));
    match &e.ems {
        Some(x) => println!("EMS server:  {x}"),
        None => println!(
            "EMS server:  not set (set with: fortino profile edit {:?} --ems-server HOST[:PORT], default port {DEFAULT_EMS_PORT})",
            s.name
        ),
    }
    println!(
        "Username:    {}",
        s.username_hint.as_deref().unwrap_or("(ask)")
    );
    println!("Scope:       {}", s.ip_policy.describe());
    println!("DNS:         {}", s.dns_mode.describe());
    println!("Trust:       {} (strict certificate checks)", s.trust_id);
}

fn duration(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, (secs / 60) % 60, secs % 60);
    if h > 0 {
        format!("{h}h {m}m")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

pub fn status(s: &Status) {
    let label = match s.state {
        State::InUse => "VPN in use",
        other => other.as_str(),
    };
    println!("State:      {label}");
    if let Some(n) = &s.profile_name {
        match &s.gateway {
            Some(g) => println!("Profile:    {n} ({g})"),
            None => println!("Profile:    {n}"),
        }
    }
    if let Some(p) = s.ip_policy {
        println!("Scope:      {}", p.describe());
    }
    if let Some(i) = &s.interface {
        println!("Interface:  {i}");
    }
    if let Some(a) = &s.assigned_ip {
        println!("Address:    {a}");
    }
    if let Some(t) = s.connected_since {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(t, |d| d.as_secs());
        println!("Connected:  {}", duration(now.saturating_sub(t)));
    }
    if let Some(c) = &s.challenge {
        println!("Waiting for: {} ({}s left)", c.prompt, c.expires_in_secs);
    }
    if let Some(r) = &s.last_result
        && s.state == State::Idle
    {
        match r.code {
            Some(code) => println!("Last error: {} ({code})", r.message),
            None => println!("Last:       {}", r.message),
        }
    }
}

pub fn import_preview(p: &Preview) {
    for e in &p.entries {
        let status = if e.blocked.is_some() {
            "blocked"
        } else if e.skipped.is_some() {
            "skipped"
        } else {
            "eligible"
        };
        let ep = &e.spec.endpoint;
        println!(
            "{status:<9} #{:<3} {:<24} {}:{}{}",
            e.ordinal,
            e.spec.name,
            ep.host,
            ep.port,
            ep.realm
                .as_ref()
                .map(|r| format!("/{r}"))
                .unwrap_or_default()
        );
        if let Some(r) = e.blocked.as_ref().or(e.skipped.as_ref()) {
            println!("          reason: {r}");
        }
        for w in &e.warnings {
            println!("          warning: {w}");
        }
        for o in &e.omitted {
            println!("          omitted: {o}");
        }
    }
    for r in &p.rejected {
        println!("rejected  #{:<3} {r}", r.ordinal);
    }
    if p.excluded_ipsec > 0 {
        println!("{} IPsec connection(s) excluded", p.excluded_ipsec);
    }
    for n in &p.notes {
        println!("note: {n}");
    }
}
