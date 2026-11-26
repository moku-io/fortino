//! Daemon-owned SQLite profile store.
//!
//! Every operation takes the owner UID (from peer credentials). A profile owned by another
//! UID is reported as not found, so the store never reveals its existence.

use std::collections::HashSet;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

use crate::model::{FieldError, Profile, ProfileId, ProfileSpec, name_key};

/// Current schema version.
pub const SCHEMA_VERSION: i64 = 1;
/// Maximum number of profiles one owner may store.
pub const MAX_PROFILES_PER_OWNER: usize = 256;

/// Store errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No such profile for this owner.
    #[error("profile not found")]
    NotFound,
    /// The expected revision does not match.
    #[error("stale revision (current {current})")]
    StaleRevision {
        /// The current revision.
        current: u64,
    },
    /// Another profile of this owner already has this name.
    #[error("a profile with this name already exists")]
    NameTaken,
    /// A field failed validation.
    #[error("invalid profile: {0}")]
    Invalid(#[from] FieldError),
    /// An import batch is ambiguous or conflicts with stored profiles.
    #[error("import conflict: {0}")]
    ImportConflict(String),
    /// Too many profiles.
    #[error("profile limit reached")]
    Limit,
    /// The database was written by a newer version.
    #[error("unsupported schema version {0}")]
    Schema(i64),
    /// SQLite failure.
    #[error("storage: {0}")]
    Sqlite(#[from] rusqlite::Error),
    /// Corrupt stored data.
    #[error("corrupt record: {0}")]
    Corrupt(String),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, StoreError>;

/// What import did with one entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ImportAction {
    /// A new profile was created.
    Created,
    /// An identical profile already existed.
    Unchanged,
    /// An existing profile was replaced (ID preserved).
    Replaced,
}

/// Result for one imported entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportResult {
    /// Normalized name.
    pub name: String,
    /// Profile ID.
    pub id: ProfileId,
    /// What happened.
    pub action: ImportAction,
}

/// The profile store.
#[derive(Debug)]
pub struct ProfileStore {
    conn: Connection,
}

impl ProfileStore {
    /// Opens (creating if needed) the store at `path` and migrates it.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Self::init(conn)
    }

    /// An in-memory store for tests.
    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self> {
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.pragma_update(None, "journal_mode", "DELETE")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        let tx = conn.transaction()?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(StoreError::Schema(version));
        }
        if version < 1 {
            tx.execute_batch(
                "CREATE TABLE profiles (
                    id TEXT PRIMARY KEY,
                    owner INTEGER NOT NULL,
                    name_key TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    spec TEXT NOT NULL,
                    UNIQUE (owner, name_key)
                 );
                 CREATE TABLE owner_revision (
                    owner INTEGER PRIMARY KEY,
                    revision INTEGER NOT NULL
                 );",
            )?;
        }
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        tx.commit()?;
        Ok(Self { conn })
    }

    /// The owner's store revision. Changes whenever any of the owner's profiles changes.
    pub fn store_revision(&self, owner: u32) -> Result<u64> {
        owner_rev(&self.conn, owner)
    }

    /// Lists the owner's profiles, sorted by name.
    pub fn list(&self, owner: u32) -> Result<Vec<Profile>> {
        let mut st = self.conn.prepare(
            "SELECT id, owner, revision, spec FROM profiles WHERE owner = ?1 ORDER BY name_key",
        )?;
        let rows = st.query_map([owner], row_raw)?;
        rows.map(|r| decode(r?)).collect()
    }

    /// The EMS servers named by any profile of any owner.
    pub fn ems_servers(&self) -> Result<Vec<crate::EmsServer>> {
        let mut st = self
            .conn
            .prepare("SELECT id, owner, revision, spec FROM profiles")?;
        let rows = st.query_map([], row_raw)?;
        let mut out = Vec::new();
        for r in rows {
            if let Some(ems) = decode(r?)?.spec.endpoint.ems {
                out.push(ems);
            }
        }
        Ok(out)
    }

    /// Fetches one profile by ID.
    pub fn get(&self, owner: u32, id: &ProfileId) -> Result<Profile> {
        get_tx(&self.conn, owner, id)?.ok_or(StoreError::NotFound)
    }

    /// Finds a profile by exact ID or by name (normalized, case-insensitive).
    pub fn find(&self, owner: u32, id_or_name: &str) -> Result<Profile> {
        if let Some(p) = get_tx(&self.conn, owner, &ProfileId(id_or_name.to_owned()))? {
            return Ok(p);
        }
        let Ok(n) = crate::model::normalize_name(id_or_name) else {
            return Err(StoreError::NotFound);
        };
        find_by_name(&self.conn, owner, &name_key(&n))?.ok_or(StoreError::NotFound)
    }

    /// Creates a profile.
    pub fn create(&mut self, owner: u32, spec: ProfileSpec) -> Result<Profile> {
        let spec = spec.validate()?;
        let tx = self.conn.transaction()?;
        let p = insert(&tx, owner, ProfileId::random(), spec)?;
        bump_owner(&tx, owner)?;
        tx.commit()?;
        Ok(p)
    }

    /// Replaces a profile's fields. `expected` must match the current revision.
    pub fn update(
        &mut self,
        owner: u32,
        id: &ProfileId,
        expected: u64,
        spec: ProfileSpec,
    ) -> Result<Profile> {
        let spec = spec.validate()?;
        let tx = self.conn.transaction()?;
        let cur = get_tx(&tx, owner, id)?.ok_or(StoreError::NotFound)?;
        if cur.revision != expected {
            return Err(StoreError::StaleRevision {
                current: cur.revision,
            });
        }
        let p = write(&tx, cur, spec)?;
        bump_owner(&tx, owner)?;
        tx.commit()?;
        Ok(p)
    }

    /// Deletes a profile. `expected` must match the current revision.
    pub fn delete(&mut self, owner: u32, id: &ProfileId, expected: u64) -> Result<()> {
        let tx = self.conn.transaction()?;
        let cur = get_tx(&tx, owner, id)?.ok_or(StoreError::NotFound)?;
        if cur.revision != expected {
            return Err(StoreError::StaleRevision {
                current: cur.revision,
            });
        }
        tx.execute(
            "DELETE FROM profiles WHERE id = ?1 AND owner = ?2",
            params![id.0, owner],
        )?;
        bump_owner(&tx, owner)?;
        tx.commit()?;
        Ok(())
    }

    /// Imports a batch atomically.
    ///
    /// - `expected_store_rev` must equal [`Self::store_revision`] or the batch is rejected.
    /// - Two entries sharing a normalized name make the batch ambiguous.
    /// - An identical entry is a no-op. An entry that only lacks the saved EMS server of the
    ///   same endpoint is also a no-op (the saved EMS setting is preserved).
    /// - A different entry under an existing name needs its name in `replace`. Replacement
    ///   keeps the ID. If the gateway host or port changes, the old EMS server is dropped.
    pub fn import(
        &mut self,
        owner: u32,
        expected_store_rev: u64,
        entries: Vec<ProfileSpec>,
        replace: &[String],
    ) -> Result<Vec<ImportResult>> {
        let mut specs = Vec::with_capacity(entries.len());
        let mut seen = HashSet::new();
        for (i, e) in entries.into_iter().enumerate() {
            let s = e.validate().map_err(|mut fe| {
                fe.field = format!("entries[{i}].{}", fe.field);
                fe
            })?;
            if !seen.insert(name_key(&s.name)) {
                return Err(StoreError::ImportConflict(format!(
                    "entries[{i}]: duplicate name in batch"
                )));
            }
            specs.push(s);
        }
        let replace: HashSet<String> = replace
            .iter()
            .filter_map(|n| crate::model::normalize_name(n).ok())
            .map(|n| name_key(&n))
            .collect();

        let tx = self.conn.transaction()?;
        let cur = owner_rev(&tx, owner)?;
        if cur != expected_store_rev {
            return Err(StoreError::StaleRevision { current: cur });
        }
        let mut out = Vec::with_capacity(specs.len());
        let mut changed = false;
        for (i, mut spec) in specs.into_iter().enumerate() {
            let key = name_key(&spec.name);
            match find_by_name(&tx, owner, &key)? {
                None => {
                    let p = insert(&tx, owner, ProfileId::random(), spec)?;
                    changed = true;
                    out.push(ImportResult {
                        name: p.spec.name,
                        id: p.id,
                        action: ImportAction::Created,
                    });
                }
                Some(existing) => {
                    keep_local_settings(&existing.spec, &mut spec);
                    if spec == existing.spec {
                        out.push(ImportResult {
                            name: existing.spec.name,
                            id: existing.id,
                            action: ImportAction::Unchanged,
                        });
                        continue;
                    }
                    if !replace.contains(&key) {
                        return Err(StoreError::ImportConflict(format!(
                            "entries[{i}]: name exists with different settings; select replacement"
                        )));
                    }
                    let p = write(&tx, existing, spec)?;
                    changed = true;
                    out.push(ImportResult {
                        name: p.spec.name,
                        id: p.id,
                        action: ImportAction::Replaced,
                    });
                }
            }
        }
        if changed {
            bump_owner(&tx, owner)?;
        }
        tx.commit()?;
        Ok(out)
    }
}

/// Carries settings an import entry doesn't describe over from the profile it matches by name.
///
/// A FortiClient file gives the name, the description and the gateway (host, port, realm);
/// the importer leaves everything else at its default. So a default here means "not in the
/// file": the username, routing, DNS, trust and debug settings stay as the user set them, and
/// re-importing an unchanged file stays a no-op. The EMS server stays while the gateway's host
/// and port do. Save password stays only while the gateway, the realm and the username all
/// stay: a saved password belongs to the account and the gateway it was given to, so a
/// replacement that moves the profile elsewhere turns it off (the client then removes the
/// password).
fn keep_local_settings(existing: &ProfileSpec, spec: &mut ProfileSpec) {
    let defaults = ProfileSpec::new(String::new(), spec.endpoint.host.clone());
    let (old, new) = (&existing.endpoint, &mut spec.endpoint);
    let same_gateway = old.host == new.host && old.port == new.port;
    if same_gateway && new.ems.is_none() {
        new.ems = old.ems.clone();
    }
    let same_realm = old.realm == new.realm;
    if spec.username_hint.is_none() {
        spec.username_hint = existing.username_hint.clone();
    }
    if spec.ip_policy == defaults.ip_policy {
        spec.ip_policy = existing.ip_policy;
    }
    if spec.dns_mode == defaults.dns_mode {
        spec.dns_mode = existing.dns_mode;
    }
    if spec.trust_id == defaults.trust_id {
        spec.trust_id = existing.trust_id.clone();
    }
    if spec.debug_ems_sysinfo.is_empty() {
        spec.debug_ems_sysinfo = existing.debug_ems_sysinfo.clone();
    }
    if !spec.save_password {
        spec.save_password = existing.save_password
            && same_gateway
            && same_realm
            && spec.username_hint == existing.username_hint;
    }
}

type RawRow = (String, u32, u64, String);

fn row_raw(r: &rusqlite::Row<'_>) -> rusqlite::Result<RawRow> {
    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
}

fn decode((id, owner, revision, spec): RawRow) -> Result<Profile> {
    let spec: ProfileSpec =
        serde_json::from_str(&spec).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    Ok(Profile {
        id: ProfileId(id),
        owner,
        revision,
        spec,
    })
}

fn get_tx(c: &Connection, owner: u32, id: &ProfileId) -> Result<Option<Profile>> {
    c.query_row(
        "SELECT id, owner, revision, spec FROM profiles WHERE id = ?1 AND owner = ?2",
        params![id.0, owner],
        row_raw,
    )
    .optional()?
    .map(decode)
    .transpose()
}

fn find_by_name(c: &Connection, owner: u32, key: &str) -> Result<Option<Profile>> {
    c.query_row(
        "SELECT id, owner, revision, spec FROM profiles WHERE owner = ?1 AND name_key = ?2",
        params![owner, key],
        row_raw,
    )
    .optional()?
    .map(decode)
    .transpose()
}

fn owner_rev(c: &Connection, owner: u32) -> Result<u64> {
    Ok(c.query_row(
        "SELECT revision FROM owner_revision WHERE owner = ?1",
        [owner],
        |r| r.get(0),
    )
    .optional()?
    .unwrap_or(0))
}

fn bump_owner(tx: &Transaction<'_>, owner: u32) -> Result<()> {
    tx.execute(
        "INSERT INTO owner_revision (owner, revision) VALUES (?1, 1)
         ON CONFLICT(owner) DO UPDATE SET revision = revision + 1",
        [owner],
    )?;
    Ok(())
}

fn encode(spec: &ProfileSpec) -> Result<String> {
    serde_json::to_string(spec).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn map_unique(e: rusqlite::Error) -> StoreError {
    match &e {
        rusqlite::Error::SqliteFailure(f, _)
            if f.code == rusqlite::ErrorCode::ConstraintViolation =>
        {
            StoreError::NameTaken
        }
        _ => StoreError::Sqlite(e),
    }
}

fn insert(tx: &Transaction<'_>, owner: u32, id: ProfileId, spec: ProfileSpec) -> Result<Profile> {
    let count: usize = tx.query_row(
        "SELECT COUNT(*) FROM profiles WHERE owner = ?1",
        [owner],
        |r| r.get(0),
    )?;
    if count >= MAX_PROFILES_PER_OWNER {
        return Err(StoreError::Limit);
    }
    tx.execute(
        "INSERT INTO profiles (id, owner, name_key, revision, spec) VALUES (?1, ?2, ?3, 1, ?4)",
        params![id.0, owner, name_key(&spec.name), encode(&spec)?],
    )
    .map_err(map_unique)?;
    Ok(Profile {
        id,
        owner,
        revision: 1,
        spec,
    })
}

fn write(tx: &Transaction<'_>, cur: Profile, spec: ProfileSpec) -> Result<Profile> {
    let revision = cur.revision + 1;
    tx.execute(
        "UPDATE profiles SET name_key = ?1, revision = ?2, spec = ?3 WHERE id = ?4 AND owner = ?5",
        params![
            name_key(&spec.name),
            revision,
            encode(&spec)?,
            cur.id.0,
            cur.owner
        ],
    )
    .map_err(map_unique)?;
    Ok(Profile {
        id: cur.id,
        owner: cur.owner,
        revision,
        spec,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::EmsServer;

    fn spec(name: &str, host: &str) -> ProfileSpec {
        ProfileSpec::new(name, host.parse().unwrap())
    }

    #[test]
    fn crud_and_ownership() {
        let mut s = ProfileStore::in_memory().unwrap();
        let p = s.create(501, spec("GATEWAY-2", "tg2.example.org")).unwrap();
        assert_eq!(p.revision, 1);
        assert!(matches!(
            s.create(501, spec("gateway-2", "x.example")),
            Err(StoreError::NameTaken)
        ));
        // Another user can use the same name and cannot see ours.
        s.create(502, spec("GATEWAY-2", "x.example")).unwrap();
        assert!(matches!(s.get(502, &p.id), Err(StoreError::NotFound)));
        assert!(matches!(s.delete(502, &p.id, 1), Err(StoreError::NotFound)));
        assert_eq!(s.list(501).unwrap().len(), 1);
        assert_eq!(s.find(501, "gateway-2").unwrap().id, p.id);
        assert_eq!(s.find(501, &p.id.0).unwrap().id, p.id);

        let mut sp = p.spec.clone();
        sp.name = "GATEWAY-2 renamed".into();
        sp.endpoint.ems = Some("ems.example.org:9016".parse().unwrap());
        let u = s.update(501, &p.id, 1, sp.clone()).unwrap();
        assert_eq!((u.id.clone(), u.revision), (p.id.clone(), 2));
        assert!(matches!(
            s.update(501, &p.id, 1, sp),
            Err(StoreError::StaleRevision { current: 2 })
        ));
        assert!(matches!(
            s.delete(501, &p.id, 1),
            Err(StoreError::StaleRevision { .. })
        ));
        s.delete(501, &p.id, 2).unwrap();
        assert!(s.list(501).unwrap().is_empty());
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("profiles.db");
        let id = {
            let mut s = ProfileStore::open(&path).unwrap();
            let mut sp = spec("GATEWAY-1", "tg1.example.org");
            sp.endpoint.ems = Some(EmsServer {
                host: "ems1.example.org".parse().unwrap(),
                port: 8013,
            });
            s.create(501, sp).unwrap().id
        };
        let s = ProfileStore::open(&path).unwrap();
        let p = s.get(501, &id).unwrap();
        assert_eq!(
            p.spec.endpoint.ems.unwrap().to_string(),
            "ems1.example.org:8013"
        );
    }

    #[test]
    fn import_semantics() {
        let mut s = ProfileStore::in_memory().unwrap();
        let rev = s.store_revision(501).unwrap();
        let r = s
            .import(
                501,
                rev,
                vec![spec("A", "a.example"), spec("B", "b.example")],
                &[],
            )
            .unwrap();
        assert!(r.iter().all(|x| x.action == ImportAction::Created));

        // Save an EMS server on A; reimport of the same endpoint preserves it.
        let a = s.find(501, "A").unwrap();
        let mut sp = a.spec.clone();
        sp.endpoint.ems = Some("ems.example".parse().unwrap());
        s.update(501, &a.id, a.revision, sp).unwrap();

        let rev = s.store_revision(501).unwrap();
        let r = s
            .import(501, rev, vec![spec("A", "a.example")], &[])
            .unwrap();
        assert_eq!(r[0].action, ImportAction::Unchanged);
        assert_eq!(s.store_revision(501).unwrap(), rev);

        // Stale store revision.
        assert!(matches!(
            s.import(501, rev + 5, vec![spec("C", "c.example")], &[]),
            Err(StoreError::StaleRevision { .. })
        ));
        // Duplicate names in one batch.
        assert!(matches!(
            s.import(
                501,
                rev,
                vec![spec("C", "c.example"), spec("c", "d.example")],
                &[]
            ),
            Err(StoreError::ImportConflict(_))
        ));
        // Changed gateway without replacement: conflict, and nothing written (atomic).
        assert!(matches!(
            s.import(
                501,
                rev,
                vec![spec("C", "c.example"), spec("A", "a2.example")],
                &[]
            ),
            Err(StoreError::ImportConflict(_))
        ));
        assert!(s.find(501, "C").is_err());
        // With replacement: ID kept, EMS dropped because the gateway changed.
        let r = s
            .import(501, rev, vec![spec("A", "a2.example")], &["a".into()])
            .unwrap();
        assert_eq!(r[0].action, ImportAction::Replaced);
        assert_eq!(r[0].id, a.id);
        let a2 = s.get(501, &a.id).unwrap();
        assert_eq!(a2.spec.endpoint.ems, None);
    }

    /// A FortiClient file can't express the username, Save password, routing or DNS, so
    /// re-importing it keeps what the user set; a replacement that moves the profile to another
    /// gateway keeps those settings but not Save password (the password was the old gateway's).
    #[test]
    fn reimport_keeps_settings_the_file_does_not_carry() {
        let mut s = ProfileStore::in_memory().unwrap();
        let rev = s.store_revision(501).unwrap();
        s.import(501, rev, vec![spec("A", "a.example")], &[])
            .unwrap();
        let a = s.find(501, "A").unwrap();
        let mut sp = a.spec.clone();
        sp.username_hint = Some("alice".into());
        sp.save_password = true;
        sp.ip_policy = crate::IpPolicy::FullIpv4;
        sp.dns_mode = crate::DnsMode::Local;
        let a = s.update(501, &a.id, a.revision, sp).unwrap();

        let rev = s.store_revision(501).unwrap();
        let r = s
            .import(501, rev, vec![spec("A", "a.example")], &[])
            .unwrap();
        assert_eq!(r[0].action, ImportAction::Unchanged);
        assert_eq!(s.get(501, &a.id).unwrap(), a);

        let r = s
            .import(501, rev, vec![spec("A", "b.example")], &["A".into()])
            .unwrap();
        assert_eq!(r[0].action, ImportAction::Replaced);
        let b = s.get(501, &a.id).unwrap().spec;
        assert_eq!(b.endpoint.host, "b.example".parse().unwrap());
        assert_eq!(b.username_hint.as_deref(), Some("alice"));
        assert_eq!(b.ip_policy, crate::IpPolicy::FullIpv4);
        assert_eq!(b.dns_mode, crate::DnsMode::Local);
        assert!(!b.save_password, "a saved password stays with its gateway");
    }
}
