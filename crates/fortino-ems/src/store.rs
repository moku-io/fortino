//! Registrations, one per EMS server, side by side. Connecting a profile uses the registration of
//! that profile's EMS; nothing here ever moves one server's identity to another.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Error;

/// Profile objects received from the server, with the checksum the client echoes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Received {
    /// Checksum to echo (`CSUM`, `HVCS`, …). Empty until the object arrives.
    pub checksum: String,
    /// Decoded content.
    pub content: Option<String>,
}

/// One server's registration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// `host:port` as configured in the profile. The key of this record.
    pub server: String,
    /// Deployment identifier used during first enrollment, scoped to this EMS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub install_uid: Option<String>,
    /// Endpoint UID this registration was made with.
    pub uid: String,
    /// Server serial, from PROBE and REG.
    pub serial: String,
    /// Host the server names itself.
    pub host: String,
    /// Tenant from keepalives; all zero on premises.
    #[serde(default)]
    pub tenant: Option<String>,
    /// VDOM.
    pub vdom: String,
    /// Mini keepalive interval, seconds.
    pub ka_interval: u32,
    /// Full keepalive interval, seconds.
    pub full_ka_interval: u32,
    /// Latest `TAGS`.
    #[serde(default)]
    pub tags: String,
    /// Latest `RULES` sent.
    #[serde(default)]
    pub rules_sent: String,
    /// Quarantined by the server.
    #[serde(default)]
    pub quarantined: bool,
    /// Main profile (`ZCONF`).
    #[serde(default)]
    pub conf: Received,
    /// Host-verification rules (`ZHVR`).
    #[serde(default)]
    pub host_rules: Received,
    /// Server list (`ZFGTIP`).
    #[serde(default)]
    pub server_list: Received,
    /// On-fabric profile (`ONNET`).
    #[serde(default)]
    pub on_net: Received,
    /// Off-fabric profile (`OFFCONF`).
    #[serde(default)]
    pub off_net: Received,
    /// Unix time of registration.
    pub registered_at: u64,
    /// Unix time of the last accepted keepalive.
    #[serde(default)]
    pub last_keepalive: Option<u64>,
}

/// A connection key on disk, with the server it belongs to.
#[derive(Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
struct StoredKey {
    server: String,
    key: String,
}

/// A directory of registrations. Files are written atomically with mode 0600.
#[derive(Debug, Clone)]
pub struct Store {
    dir: PathBuf,
}

/// The normalized key for a server.
pub fn server_key(server: &fortino_config::EmsServer) -> String {
    server.to_string().to_ascii_lowercase()
}

impl Store {
    /// A store in `dir`, created if missing.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, Error> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).map_err(|e| Error::Store(format!("create store: {e}")))?;
        Ok(Self { dir })
    }

    fn path(&self, key: &str) -> PathBuf {
        let h = hex::encode(&Sha256::digest(key.as_bytes())[..12]);
        self.dir.join(format!("{h}.json"))
    }

    /// The registration for `key`, if any.
    pub fn load(&self, key: &str) -> Result<Option<Registration>, Error> {
        let p = self.path(key);
        let text = match std::fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Store(format!("read registration: {e}"))),
        };
        let r: Registration = serde_json::from_str(&text)
            .map_err(|e| Error::Store(format!("parse registration: {e}")))?;
        // A hash collision or a hand-edited file must not hand out another server's identity.
        Ok((r.server == key).then_some(r))
    }

    /// Writes a registration.
    pub fn save(&self, r: &Registration) -> Result<(), Error> {
        let p = self.path(&r.server);
        let text = serde_json::to_string_pretty(r)
            .map_err(|e| Error::Store(format!("encode registration: {e}")))?;
        write_private(&p, text.as_bytes())
    }

    /// Removes a registration. Only on explicit user request.
    pub fn remove(&self, key: &str) -> Result<bool, Error> {
        if self.load(key)?.is_none() {
            return Ok(false);
        }
        std::fs::remove_file(self.path(key))
            .map(|()| true)
            .map_err(|e| Error::Store(format!("remove registration: {e}")))
    }

    fn key_path(&self, server: &str) -> PathBuf {
        let h = hex::encode(&Sha256::digest(server.as_bytes())[..12]);
        self.dir.join("keys").join(format!("{h}.json"))
    }

    /// The connection key the user gave for `server`, if any.
    pub fn load_key(&self, server: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let text = match std::fs::read_to_string(self.key_path(server)) {
            Ok(t) => Zeroizing::new(t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Store(format!("read connection key: {e}"))),
        };
        let k: StoredKey = serde_json::from_str(&text)
            .map_err(|_| Error::Store("parse connection key file".into()))?;
        // As for registrations: never hand one server's key to another.
        Ok((k.server == server).then(|| Zeroizing::new(k.key.clone())))
    }

    /// Saves the connection key for `server`, replacing any earlier one.
    pub fn save_key(&self, server: &str, key: &str) -> Result<(), Error> {
        let dir = self.dir.join("keys");
        create_private_dir(&dir)?;
        let k = StoredKey {
            server: server.to_owned(),
            key: key.to_owned(),
        };
        let text = Zeroizing::new(
            serde_json::to_string(&k)
                .map_err(|e| Error::Store(format!("encode connection key: {e}")))?,
        );
        write_private(&self.key_path(server), text.as_bytes())
    }

    /// Removes the connection key for `server`. Returns whether there was one.
    pub fn remove_key(&self, server: &str) -> Result<bool, Error> {
        match std::fs::remove_file(self.key_path(server)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Store(format!("remove connection key: {e}"))),
        }
    }

    /// The servers that have a saved connection key.
    pub fn key_servers(&self) -> Result<Vec<String>, Error> {
        let rd = match std::fs::read_dir(self.dir.join("keys")) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(Error::Store(format!("list connection keys: {e}"))),
        };
        let mut out = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "json") {
                if let Ok(t) = std::fs::read_to_string(&p).map(Zeroizing::new) {
                    if let Ok(k) = serde_json::from_str::<StoredKey>(&t) {
                        out.push(k.server.clone());
                    }
                }
            }
        }
        out.sort();
        Ok(out)
    }

    /// Every registration.
    pub fn list(&self) -> Result<Vec<Registration>, Error> {
        let mut out = Vec::new();
        let rd = std::fs::read_dir(&self.dir).map_err(|e| Error::Store(format!("list: {e}")))?;
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "json") {
                if let Ok(t) = std::fs::read_to_string(&p) {
                    if let Ok(r) = serde_json::from_str::<Registration>(&t) {
                        out.push(r);
                    }
                }
            }
        }
        out.sort_by(|a, b| a.server.cmp(&b.server));
        Ok(out)
    }
}

fn create_private_dir(dir: &Path) -> Result<(), Error> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
        .map_err(|e| Error::Store(format!("create {}: {e}", dir.display())))
}

fn write_private(path: &Path, data: &[u8]) -> Result<(), Error> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(&tmp)
        .map_err(|e| Error::Store(format!("write {}: {e}", path.display())))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| Error::Store(format!("write {}: {e}", path.display())))?;
    std::fs::rename(&tmp, path).map_err(|e| Error::Store(format!("write {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg(server: &str) -> Registration {
        Registration {
            server: server.into(),
            uid: "0A1B2C3D4E5F60718293A4B5C6D7E8F9".into(),
            serial: "FCTEMS0000000001".into(),
            host: "ems.test".into(),
            tenant: None,
            vdom: "default".into(),
            ka_interval: 60,
            full_ka_interval: 43_230,
            tags: String::new(),
            rules_sent: String::new(),
            quarantined: false,
            conf: Received::default(),
            host_rules: Received::default(),
            server_list: Received::default(),
            on_net: Received::default(),
            off_net: Received::default(),
            install_uid: None,
            registered_at: 1,
            last_keepalive: None,
        }
    }

    #[test]
    fn registrations_live_side_by_side() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        s.save(&reg("ems-a.test:8013")).unwrap();
        let mut b = reg("ems-b.test:9016");
        b.serial = "FCTEMS0000000002".into();
        s.save(&b).unwrap();
        assert_eq!(
            s.load("ems-a.test:8013").unwrap().unwrap().serial,
            "FCTEMS0000000001"
        );
        assert_eq!(
            s.load("ems-b.test:9016").unwrap().unwrap().serial,
            "FCTEMS0000000002"
        );
        assert_eq!(s.list().unwrap().len(), 2);
        assert!(s.remove("ems-a.test:8013").unwrap());
        assert!(s.load("ems-a.test:8013").unwrap().is_none());
        assert!(s.load("ems-b.test:9016").unwrap().is_some());
    }

    #[test]
    fn keys_are_per_server() {
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        assert!(s.load_key("ems-a.test:8013").unwrap().is_none());
        s.save_key("ems-a.test:8013", "k3y").unwrap();
        s.save(&reg("ems-a.test:8013")).unwrap();
        assert_eq!(
            s.load_key("ems-a.test:8013").unwrap().unwrap().as_str(),
            "k3y"
        );
        assert!(s.load_key("ems-b.test:9016").unwrap().is_none());
        // A key file is not a registration.
        assert_eq!(s.list().unwrap().len(), 1);
        s.save_key("ems-a.test:8013", "other").unwrap();
        assert_eq!(
            s.load_key("ems-a.test:8013").unwrap().unwrap().as_str(),
            "other"
        );
        assert!(s.remove_key("ems-a.test:8013").unwrap());
        assert!(!s.remove_key("ems-a.test:8013").unwrap());
        assert!(s.load_key("ems-a.test:8013").unwrap().is_none());
        assert!(s.load("ems-a.test:8013").unwrap().is_some());
        assert!(s.key_servers().unwrap().is_empty());
        s.save_key("ems-b.test:9016", "k").unwrap();
        s.save_key("ems-a.test:8013", "k").unwrap();
        assert_eq!(
            s.key_servers().unwrap(),
            ["ems-a.test:8013", "ems-b.test:9016"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn key_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        s.save_key("ems-a.test:8013", "k3y").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&d.path().join("keys")), 0o700);
        assert_eq!(mode(&s.key_path("ems-a.test:8013")), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let s = Store::open(d.path()).unwrap();
        s.save(&reg("ems-a.test:8013")).unwrap();
        let p = s.path("ems-a.test:8013");
        assert_eq!(
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
