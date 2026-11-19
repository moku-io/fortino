//! Living alongside an installed FortiClient.
//!
//! Fortino uses the same endpoint UID as FortiClient (the platform UUID), so to an EMS both are
//! the same device. Two agents must never keep one device record alive at once: their reports
//! would alternate (different SYSINFO, host-check results and checksums), tags would flap, and
//! deregistering from one would remove the other's registration.
//!
//! So when FortiClient's own EMS agent is running and registered, with the same UID, to the
//! EMS a profile names, Fortino **defers** to it. It neither registers nor sends keepalives or
//! tag reports to that EMS. It presents FortiClient's registration (serial, tenant) to the
//! gateway, which is truthful because that registration belongs to this same device.
//! FortiClient's agent reports network changes, including the Fortino tunnel interface, on its
//! own.
//!
//! In every other case (not installed, agent not running, not registered, registered to
//! another EMS, or a different UID) Fortino acts as the agent for that EMS itself.
//!
//! State is read from FortiClient's world-readable files: `data/fct_uid.conf`,
//! `data/EMS_sn.conf` and `conf/epctrl.plist` (`EMS_ADDRESS`, `EMS_HOSTNAME`, `EMS_PORT`,
//! `EMS_TENANT_ID`). Nothing is written there.

use std::path::{Path, PathBuf};

use fortino_config::EmsServer;
use fortino_proto_ems::ids::{EmsSerial, Tenant, Uid};

/// FortiClient's install location on macOS.
pub const MACOS_ROOT: &str = "/Library/Application Support/Fortinet/FortiClient";

/// What FortiClient's EMS agent is doing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FortiClientState {
    /// Its endpoint UID.
    pub uid: Option<Uid>,
    /// Serial of the EMS it is registered to; `None` when not registered.
    pub serial: Option<EmsSerial>,
    /// The EMS address it uses (lower-case host or IP) and port.
    pub addresses: Vec<(String, u16)>,
    /// Its tenant, when stored in clear.
    pub tenant: Option<Tenant>,
    /// Its EMS agent process is running.
    pub running: bool,
}

impl FortiClientState {
    /// Registered and running, with this UID.
    pub fn active_with(&self, uid: &Uid) -> bool {
        self.running && self.serial.is_some() && self.uid.as_ref() == Some(uid)
    }

    /// Whether FortiClient's EMS address is `server`.
    pub fn uses_address(&self, server: &EmsServer) -> bool {
        let host = server.host.to_string().to_ascii_lowercase();
        self.addresses
            .iter()
            .any(|(h, p)| *h == host && *p == server.port)
    }
}

/// Reads the plist values that matter, from `plutil -convert json` output.
pub fn parse_epctrl_json(json: &str) -> (Vec<(String, u16)>, Option<Tenant>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return (Vec::new(), None);
    };
    let s = |k: &str| {
        v.get(k)
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|x| !x.is_empty() && !x.starts_with("Enc "))
            .map(str::to_ascii_lowercase)
    };
    let port = v
        .get("EMS_PORT")
        .and_then(serde_json::Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .filter(|p| *p != 0)
        .unwrap_or(8013);
    let mut addresses = Vec::new();
    for key in ["EMS_ADDRESS", "EMS_HOSTNAME"] {
        if let Some(a) = s(key) {
            // `host:port` or a bare host.
            let (h, p) = match a.rsplit_once(':') {
                Some((h, p)) if p.parse::<u16>().is_ok() => {
                    (h.to_owned(), p.parse().unwrap_or(port))
                }
                _ => (a, port),
            };
            if !addresses.contains(&(h.clone(), p)) {
                addresses.push((h, p));
            }
        }
    }
    let tenant = s("EMS_TENANT_ID").and_then(|t| Tenant::parse(&t).ok());
    (addresses, tenant)
}

fn read_trimmed(p: &Path) -> Option<String> {
    std::fs::read_to_string(p)
        .ok()
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Reads FortiClient's state from `root`. `None` when it is not installed.
pub fn read(root: &Path) -> Option<FortiClientState> {
    if !root.join("conf").is_dir() {
        return None;
    }
    let uid = read_trimmed(&root.join("data/fct_uid.conf")).and_then(|u| Uid::parse(&u).ok());
    let serial =
        read_trimmed(&root.join("data/EMS_sn.conf")).and_then(|s| EmsSerial::parse(&s).ok());
    let (addresses, tenant) = plist_json(&root.join("conf/epctrl.plist"))
        .map(|j| parse_epctrl_json(&j))
        .unwrap_or_default();
    Some(FortiClientState {
        uid,
        serial,
        addresses,
        tenant,
        running: agent_running(),
    })
}

#[cfg(target_os = "macos")]
fn plist_json(p: &Path) -> Option<String> {
    let o = std::process::Command::new("/usr/bin/plutil")
        .args(["-convert", "json", "-o", "-"])
        .arg(p)
        .output()
        .ok()?;
    o.status
        .success()
        .then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn plist_json(_: &Path) -> Option<String> {
    None
}

fn agent_running() -> bool {
    std::process::Command::new("/usr/bin/pgrep")
        .args(["-x", "epctrl"])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Reads FortiClient's state. Replaceable for tests.
pub type FortiClientSource = std::sync::Arc<dyn Fn() -> Option<FortiClientState> + Send + Sync>;

/// Reads from `root`, or never finds FortiClient when `root` is `None`.
pub fn source(root: Option<PathBuf>) -> FortiClientSource {
    std::sync::Arc::new(move || root.as_deref().and_then(read))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_values() {
        let (a, t) = parse_epctrl_json(
            r#"{"EMS_ADDRESS":"EMS.Example.org:9016","EMS_HOSTNAME":"ems.example.org","EMS_PORT":9016,
                "EMS_TENANT_ID":"00000000000000000000000000000000","FCT_ZTNA_TOKEN":"Enc xx"}"#,
        );
        assert_eq!(a, vec![("ems.example.org".to_owned(), 9016)]);
        assert_eq!(t, Some(Tenant::on_premises()));
        let (a, t) = parse_epctrl_json(r#"{"EMS_ADDRESS":"","EMS_PORT":8013,"EMS_TENANT_ID":""}"#);
        assert!(a.is_empty() && t.is_none());
        assert_eq!(parse_epctrl_json("not json"), (Vec::new(), None));
    }

    #[test]
    fn reads_files() {
        let d = tempfile::tempdir().unwrap();
        assert!(read(d.path()).is_none());
        std::fs::create_dir_all(d.path().join("conf")).unwrap();
        std::fs::create_dir_all(d.path().join("data")).unwrap();
        std::fs::write(
            d.path().join("data/fct_uid.conf"),
            "0A1B2C3D4E5F60718293A4B5C6D7E8F9\n",
        )
        .unwrap();
        std::fs::write(d.path().join("data/EMS_sn.conf"), "").unwrap();
        let s = read(d.path()).unwrap();
        assert!(s.uid.is_some());
        assert!(
            s.serial.is_none(),
            "an empty serial file means not registered"
        );
        std::fs::write(d.path().join("data/EMS_sn.conf"), "FCTEMS0000000001").unwrap();
        assert!(read(d.path()).unwrap().serial.is_some());
    }

    #[test]
    fn active_needs_running_registered_and_same_uid() {
        let uid = Uid::parse("0A1B2C3D4E5F60718293A4B5C6D7E8F9").unwrap();
        let mut s = FortiClientState {
            uid: Some(uid.clone()),
            serial: Some(EmsSerial::parse("FCTEMS0000000001").unwrap()),
            running: true,
            ..Default::default()
        };
        assert!(s.active_with(&uid));
        s.running = false;
        assert!(!s.active_with(&uid));
        s.running = true;
        assert!(!s.active_with(&Uid::parse("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF").unwrap()));
    }
}
