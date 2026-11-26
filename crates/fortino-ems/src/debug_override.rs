//! Debug SYSINFO overrides for EMS protocol testing. Exposed in the app's profile editor for
//! maintainers; empty by default, and every non-empty use is logged as a warning.
//!
//! This module lets the maintainer inject arbitrary SYSINFO key/values into what the EMS agent
//! reports for one profile, to probe how an EMS reacts — for example an `OSVER` the deployment
//! does not list, or antivirus / feature-bitmap claims. It deliberately steps around the
//! "posture never lies" rule (AGENTS.md), so it is driven only by a per-profile map an operator
//! fills in by hand;
//! there is no friendly field picker, and it is empty in normal use.
//!
//! An `OSVER` override also applies to host verification ([`host_facts`]), so the rule results
//! describe the same OS the EMS was told about.
//!
//! Everything debug lives here and behind the `debug_ems_sysinfo` profile field, so removing the
//! feature is a clean delete: this module, that field, the two [`apply`] call sites and the
//! [`host_facts`] call site in [`crate::agent`].

use std::borrow::Cow;
use std::collections::BTreeMap;

use fortino_platform::facts::Facts;
use fortino_proto_ems::sysinfo::SysInfo;

/// The facts host verification evaluates: `facts` with an `OSVER` override as the OS version,
/// or `facts` unchanged when there is none. No other key feeds host verification.
pub fn host_facts<'a>(facts: &'a Facts, overrides: &BTreeMap<String, String>) -> Cow<'a, Facts> {
    let Some(os) = overrides.get("OSVER") else {
        return Cow::Borrowed(facts);
    };
    tracing::warn!(
        "DEBUG EMS overrides active: host verification evaluates the overridden OSVER, not this Mac's OS"
    );
    Cow::Owned(Facts {
        os_version: os.clone(),
        ..facts.clone()
    })
}

/// Returns `sysinfo` with `overrides` applied: an entry whose key already exists replaces that
/// value (keeping the original wire order); a new key is appended. Entries the SYSINFO framing
/// rejects (bad key or value) are skipped with a warning instead of failing registration. An
/// empty map is a no-op.
pub fn apply(sysinfo: SysInfo, overrides: &BTreeMap<String, String>) -> SysInfo {
    if overrides.is_empty() {
        return sysinfo;
    }
    tracing::warn!(
        keys = ?overrides.keys().collect::<Vec<_>>(),
        "DEBUG EMS overrides active: the SYSINFO sent to the EMS is deliberately not truthful for these keys"
    );
    let mut out = SysInfo::new();
    let mut present: Vec<String> = Vec::new();
    for (k, v) in sysinfo.iter() {
        present.push(k.to_owned());
        let value = overrides.get(k).map_or(v, String::as_str);
        if out.push(k, value).is_err() {
            tracing::warn!(
                key = k,
                "debug override rejected by SYSINFO framing; keeping original value"
            );
            let _ = out.push(k, v);
        }
    }
    for (k, v) in overrides {
        if present.iter().any(|p| p == k) {
            continue;
        }
        if out.push(k, v.as_str()).is_err() {
            tracing::warn!(key = %k, "debug override key/value rejected by SYSINFO framing; skipped");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn si(pairs: &[(&str, &str)]) -> SysInfo {
        let mut s = SysInfo::new();
        for (k, v) in pairs {
            s.push(k, *v).unwrap();
        }
        s
    }

    #[test]
    fn replaces_appends_preserves_order_and_skips_invalid() {
        let base = si(&[("OSVER", "macOS 15.7.7"), ("FCTOS", "OSX00")]);
        let mut ov = BTreeMap::new();
        ov.insert("OSVER".to_string(), "macOS 26.1.0".to_string()); // replace in place
        ov.insert("AVSIG_VER".to_string(), "9.9.9".to_string()); // appended
        ov.insert("bad key".to_string(), "x".to_string()); // invalid key: skipped
        let out = apply(base, &ov);
        assert_eq!(out.get("OSVER"), Some("macOS 26.1.0"));
        assert_eq!(out.get("FCTOS"), Some("OSX00"));
        assert_eq!(out.get("AVSIG_VER"), Some("9.9.9"));
        assert_eq!(out.get("bad key"), None);
        let keys: Vec<&str> = out.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["OSVER", "FCTOS", "AVSIG_VER"]);
    }

    #[test]
    fn invalid_value_keeps_original() {
        let base = si(&[("OSVER", "macOS 15.7.7")]);
        let mut ov = BTreeMap::new();
        ov.insert("OSVER".to_string(), "line\nbreak".to_string()); // value rejected by framing
        let out = apply(base, &ov);
        assert_eq!(out.get("OSVER"), Some("macOS 15.7.7"));
    }

    #[test]
    fn host_facts_take_only_the_osver_override() {
        let f = Facts {
            os_version: "macOS 26.1.0".into(),
            hostname: "h".into(),
            ..Facts::default()
        };
        assert!(matches!(host_facts(&f, &BTreeMap::new()), Cow::Borrowed(_)));
        let mut ov = BTreeMap::new();
        ov.insert("HOSTNAME".to_string(), "other".to_string());
        assert!(matches!(host_facts(&f, &ov), Cow::Borrowed(_)));
        ov.insert("OSVER".to_string(), "macOS 15.8.3".to_string());
        let h = host_facts(&f, &ov);
        assert_eq!(h.os_version, "macOS 15.8.3");
        assert_eq!(h.hostname, "h");
    }

    #[test]
    fn empty_is_noop() {
        let out = apply(si(&[("OSVER", "x")]), &BTreeMap::new());
        assert_eq!(out.get("OSVER"), Some("x"));
    }
}
