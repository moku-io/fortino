//! What the agent tells the EMS about this machine.
//!
//! Only facts read from the system go in. Fields for features Fortino does not have (antivirus,
//! sandbox, vulnerability scanning, signatures) are sent empty, never with made-up versions.

use fortino_platform::facts::Facts;
use fortino_proto_ems::ids::Mac;
use fortino_proto_ems::sysinfo::{NetIf, SysInfo, SysInfoError, nwifs};

use crate::store::Registration;

/// The declared compatibility profile: the client version and capability bitmap the
/// agent presents. Wire identity only; it does not claim posture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compat {
    /// `FCTVER`.
    pub version: String,
    /// Deployment identifier supplied by the package for this EMS.
    pub install_uid: Option<String>,
    /// `CAPS`.
    pub caps: u32,
}

impl Default for Compat {
    fn default() -> Self {
        Self {
            // UNVERIFIED: the oldest version EMS servers accept is not known; this is the
            // version known to be accepted.
            version: "7.4.4.1831".into(),
            // UNVERIFIED: CAPS bits are not decoded. Zero claims no optional capability.
            caps: 0,
            install_uid: None,
        }
    }
}

/// Feature bits Fortino has: 0x10 VPN, and
/// 0x8, which FortiClient always sets (UNVERIFIED). Antivirus (0x1), firewall (0x2), web
/// filter (0x4), vulnerability scan (0x20), sandbox, ZTNA (0x40000) and the rest stay clear.
pub const FEATURES: u32 = 0x8 | 0x10;

/// `FCTOS` for this platform.
pub fn fctos() -> &'static str {
    // UNVERIFIED: the Linux value is not observed.
    if cfg!(target_os = "macos") {
        "OSX00"
    } else {
        "LINUX"
    }
}

/// Interfaces in `NWIFS` form.
pub fn interfaces(f: &Facts) -> Vec<NetIf> {
    f.interfaces
        .iter()
        .map(|i| NetIf {
            name: i.name.clone(),
            ip: i.ip,
            mac: Mac(i.mac),
            gateway: i.gateway,
            gateway_mac: None,
            ssid: None,
            is_vpn: i.is_vpn,
        })
        .collect()
}

/// `FCT_SN`: `FCT800` and the CRC-32 of the hardware serial (or of the platform UUID when there
/// is no serial), as ten decimal digits.
// UNVERIFIED: the CRC-32 variant; zlib's is assumed.
pub fn fct_sn(f: &Facts) -> Option<String> {
    let source = f
        .serial
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| f.platform_uuid.clone().map(|u| u.to_ascii_uppercase()))?;
    let mut crc = flate2::Crc::new();
    crc.update(source.as_bytes());
    Some(format!("FCT800{:010}", crc.sum()))
}

/// A stable synthetic `USER_SID` for this user on this machine. macOS has no SIDs; FortiClient
/// fabricates an `S-1-5-21-…` value, and so does Fortino, derived from the platform UUID and the
/// user so it stays the same across runs. Identity only; it claims no posture.
// UNVERIFIED: FortiClient's exact derivation is not known; the shape and stability match.
pub fn user_sid(f: &Facts) -> Option<String> {
    let hex: String = f
        .platform_uuid
        .as_ref()?
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if hex.len() < 24 {
        return None;
    }
    let part = |i: usize| u32::from_str_radix(hex.get(i..i + 8).unwrap_or("0"), 16).unwrap_or(0);
    let rid = f.uid.filter(|u| *u != 0).unwrap_or_else(|| {
        let mut crc = flate2::Crc::new();
        crc.update(f.user.as_deref().unwrap_or("").as_bytes());
        1000 + (crc.sum() % 9000)
    });
    Some(format!(
        "S-1-5-21-{}-{}-{}-{rid}",
        part(0),
        part(8),
        part(16)
    ))
}

/// Checksums of the objects received so far, echoed so the server sends only what changed.
fn checksums(s: &mut SysInfo, reg: Option<&Registration>) -> Result<(), SysInfoError> {
    let sum = |pick: fn(&Registration) -> &str| {
        reg.map(pick)
            .filter(|v| !v.is_empty())
            .unwrap_or("0")
            .to_owned()
    };
    s.push("EP_CHKSUM", sum(|r| &r.conf.checksum))?;
    s.push("EP_RULECHKSUM", sum(|r| &r.host_rules.checksum))?;
    s.push("EP_OFFNETCHKSUM", sum(|r| &r.off_net.checksum))?;
    s.push("EP_ONNETCHKSUM", sum(|r| &r.on_net.checksum))?;
    s.push("EP_FGTCHKSUM", sum(|r| &r.server_list.checksum))?;
    s.push("WF_FILESCHKSUM", "0")?;
    Ok(())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Full SYSINFO, for REGISTER and full keepalives.
// Fortino reports no AV, web filter, firewall, sandbox or vulnerability scanning: those
// signature fields are empty and their feature bits clear.
pub fn full(
    f: &Facts,
    compat: &Compat,
    reg: Option<&Registration>,
) -> Result<SysInfo, SysInfoError> {
    let mut s = SysInfo::new();
    checksums(&mut s, reg)?;
    s.push("HOSTNAME", f.hostname.as_str())?;
    s.push("USER", f.user.clone().unwrap_or_default())?;
    s.push("USER_SID", user_sid(f).unwrap_or_default())?;
    s.push("DOMAIN", "")?;
    s.push("PC_DOMAIN", "")?;
    s.push("ADGUID", "")?;
    s.push(
        "INSTALLUID",
        reg.map_or(compat.install_uid.as_deref(), |r| r.install_uid.as_deref())
            .unwrap_or_default(),
    )?;
    for k in ["WORKGROUP", "GROUP_TAG", "FORTIEDR_VERSION"] {
        s.push(k, "")?;
    }
    // No software inventory and a hardware form-factor Fortino does not detect.
    s.push("INSTALLED_APPS", "0")?;
    s.push("ENABLED_APPS", "0")?;
    // UNVERIFIED: DESKTOP is a form-factor flag, not posture; FortiClient sent 0 here.
    s.push("DESKTOP", "0")?;
    s.push("COM_SN", f.serial.clone().unwrap_or_default())?;
    s.push("COM_MAN", f.manufacturer.clone().unwrap_or_default())?;
    s.push("COM_MODEL", f.model.clone().unwrap_or_default())?;
    s.push("CPU", f.cpu.clone().unwrap_or_default())?;
    s.push(
        "MEM",
        f.memory_mib.map(|m| m.to_string()).unwrap_or_default(),
    )?;
    s.push("HDD", f.disk_gib.map(|d| d.to_string()).unwrap_or_default())?;
    s.push("FCTARCH", f.arch)?;
    s.push("NWIFS", nwifs(&interfaces(f)))?;
    s.push("OSVER", f.os_version.as_str())?;
    s.push("FCTOS", fctos())?;
    s.push("FCTVER", compat.version.as_str())?;
    if let Some(sn) = fct_sn(f) {
        s.push("FCT_SN", sn)?;
    }
    for k in ["AVSIG_VER", "AVENG_VER", "VULSIG_VER", "VULENG_VER"] {
        s.push(k, "")?;
    }
    // UNVERIFIED: decimal is assumed for the value format.
    s.push("INSTALLED_FEATURE_BITMAP", FEATURES.to_string())?;
    s.push("ENABLED_FEATURE_BITMAP", FEATURES.to_string())?;
    s.push("HIDDEN_FEATURE_BITMAP", "0")?;
    s.push("UTC", now().to_string())?;
    Ok(s)
}

/// Mini SYSINFO, for the periodic keepalive.
pub fn mini(f: &Facts, reg: Option<&Registration>) -> Result<SysInfo, SysInfoError> {
    let mut s = SysInfo::new();
    checksums(&mut s, reg)?;
    s.push("USER", f.user.clone().unwrap_or_default())?;
    s.push("USER_SID", user_sid(f).unwrap_or_default())?;
    s.push("COM_SN", f.serial.clone().unwrap_or_default())?;
    s.push("CPU", f.cpu.clone().unwrap_or_default())?;
    s.push("COM_MODEL", f.model.clone().unwrap_or_default())?;
    s.push("NWIFS", nwifs(&interfaces(f)))?;
    s.push("FCTOS", fctos())?;
    s.push("UTC", now().to_string())?;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> Facts {
        Facts {
            platform_uuid: Some("0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9".into()),
            hostname: "mac-01".into(),
            user: Some("alice".into()),
            uid: Some(501),
            os_version: "macOS 15.6".into(),
            arch: "ARM",
            ..Facts::default()
        }
    }

    #[test]
    fn claims_nothing_it_does_not_have() {
        let s = full(&facts(), &Compat::default(), None).unwrap();
        for (k, v) in s.iter() {
            if k.starts_with("AV") || k.starts_with("VUL") {
                assert_eq!(v, "", "{k} must be empty");
            }
        }
        assert_eq!(s.get("ENABLED_FEATURE_BITMAP"), Some("24"));
        assert_eq!(s.get("INSTALLED_FEATURE_BITMAP"), Some("24"));
        assert_eq!(s.get("EP_CHKSUM"), Some("0"));
        // No inventory, no made-up app/EDR versions.
        assert_eq!(s.get("INSTALLED_APPS"), Some("0"));
        assert_eq!(s.get("FORTIEDR_VERSION"), Some(""));
    }

    #[test]
    fn user_sid_is_stable_and_shaped() {
        let f = facts();
        let sid = user_sid(&f).unwrap();
        assert!(sid.starts_with("S-1-5-21-") && sid.ends_with("-501"));
        assert_eq!(user_sid(&f), user_sid(&f), "must be deterministic");
        assert_eq!(
            full(&f, &Compat::default(), None).unwrap().get("USER_SID"),
            Some(sid.as_str())
        );
        // No platform UUID: no SID rather than a fake one.
        let mut bare = f.clone();
        bare.platform_uuid = None;
        assert_eq!(user_sid(&bare), None);
    }

    #[test]
    fn fct_sn_format() {
        let mut f = facts();
        f.platform_uuid = None;
        assert_eq!(fct_sn(&f), None, "no serial and no UUID: no FCT_SN");
        f.serial = Some("C02TEST0001".into());
        let sn = fct_sn(&f).unwrap();
        assert!(sn.starts_with("FCT800") && sn.len() == 16);
    }
}
