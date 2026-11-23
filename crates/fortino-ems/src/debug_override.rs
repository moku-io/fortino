//! Debug-only SYSINFO overrides for EMS protocol testing. **Not a shipping feature.**
//!
//! This module lets the maintainer inject arbitrary SYSINFO key/values into what the EMS agent
//! reports for one profile, to probe how an EMS reacts — for example an `OSVER` the deployment
//! does not list, or antivirus / feature-bitmap claims. It deliberately steps around the
//! "posture never lies" rule (AGENTS.md), so it is driven only by a per-profile map an operator
//! fills in by hand after reading [the design notes];
//! there is no friendly field picker, and it is empty in normal use.
//!
//! Everything debug lives here and behind the `debug_ems_sysinfo` profile field, so removing the
//! feature is a clean delete: this module, that field, and the two [`apply`] call sites in
//! [`crate::agent`].

use std::collections::BTreeMap;

use fortino_proto_ems::sysinfo::SysInfo;

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
    fn empty_is_noop() {
        let out = apply(si(&[("OSVER", "x")]), &BTreeMap::new());
        assert_eq!(out.get("OSVER"), Some("x"));
    }
}
