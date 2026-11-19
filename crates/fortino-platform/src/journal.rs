//! Write-ahead rollback journal for network changes.
//!
//! Every change is recorded as its [`Undo`] on disk **before** it is applied. After a crash, the
//! next daemon start calls [`Journaled::recover`], which reverts every recorded entry in reverse
//! order. Because the entry is written first, a crash in the middle of an apply is covered too;
//! that is why [`NetPlatform::revert`] must tolerate changes that were never applied.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{NetChange, NetPlatform, PlatformError, Result, TunDevice, Undo};

/// Default journal location on Linux. macOS supplies its daemon-owned state directory.
pub const DEFAULT_PATH: &str = "/var/lib/fortino/journal.json";

const VERSION: u32 = 1;

#[derive(Debug, Default, Serialize, Deserialize)]
struct JournalFile {
    version: u32,
    entries: Vec<Undo>,
}

/// A platform whose changes are journaled.
#[derive(Debug)]
pub struct Journaled<P: NetPlatform> {
    platform: P,
    path: PathBuf,
    entries: Vec<Undo>,
}

impl<P: NetPlatform> Journaled<P> {
    /// Wraps `platform`, journaling to `path`. Entries left by an earlier process are loaded
    /// but not reverted; call [`Self::recover`] for that.
    pub fn open(platform: P, path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let entries = load(&path)?;
        Ok(Self {
            platform,
            path,
            entries,
        })
    }

    /// Number of changes currently recorded.
    pub fn pending(&self) -> usize {
        self.entries.len()
    }

    /// Access to the wrapped platform (read-only operations such as `route_to`).
    pub fn platform(&mut self) -> &mut P {
        &mut self.platform
    }

    /// Creates a tun device (not journaled: it is removed when dropped).
    pub fn create_tun(&mut self) -> Result<TunDevice> {
        self.platform.create_tun()
    }

    /// Reverts everything a previous process left in the journal. Returns how many entries
    /// were reverted. A failed step remains journaled for recovery.
    pub fn recover(&mut self) -> Result<usize> {
        let n = self.entries.len();
        if n > 0 {
            tracing::warn!(
                entries = n,
                "journal not empty at startup; restoring network state"
            );
        }
        self.rollback_all()?;
        Ok(n)
    }

    /// Records and applies one change. If the apply fails, the change is reverted and removed
    /// from the journal before the error is returned.
    pub fn apply(&mut self, change: &NetChange) -> Result<()> {
        let undo = self.platform.prepare(change)?;
        self.entries.push(undo.clone());
        if let Err(e) = self.save() {
            self.entries.pop();
            return Err(e);
        }
        tracing::debug!(?change, "applying network change");
        if let Err(e) = self.platform.apply(change) {
            tracing::warn!(error = %e, ?change, "network change failed; reverting it");
            if let Err(re) = self.platform.revert(&undo) {
                // Leave the entry so a later rollback retries it.
                tracing::error!(error = %re, "revert of failed change also failed");
                return Err(e);
            }
            self.finish_last_undo()?;
            return Err(e);
        }
        Ok(())
    }

    /// Applies changes in order; on the first failure, reverts all of them.
    pub fn apply_all(&mut self, changes: &[NetChange]) -> Result<()> {
        let mark = self.entries.len();
        for c in changes {
            if let Err(e) = self.apply(c) {
                self.rollback_to(mark)?;
                return Err(e);
            }
        }
        Ok(())
    }

    /// Reverts recorded changes newest first. A failed step and its predecessors stay pending.
    pub fn rollback_all(&mut self) -> Result<()> {
        self.rollback_to(0)
    }

    fn rollback_to(&mut self, mark: usize) -> Result<()> {
        while self.entries.len() > mark {
            if let Some(undo) = self.entries.last() {
                self.platform.revert(undo)?;
            }
            self.finish_last_undo()?;
        }
        Ok(())
    }

    // Keep the in-memory and on-disk retry point if persisting completion fails.
    // Platform revert is idempotent, so repeating the last successful undo is safe.
    fn finish_last_undo(&mut self) -> Result<()> {
        let remaining = self.entries.len() - 1;
        save(&self.path, &self.entries[..remaining])?;
        self.entries.truncate(remaining);
        Ok(())
    }

    fn save(&self) -> Result<()> {
        save(&self.path, &self.entries)
    }
}

fn load(path: &Path) -> Result<Vec<Undo>> {
    match fs::read(path) {
        Ok(b) => {
            let f: JournalFile = serde_json::from_slice(&b).map_err(|e| {
                PlatformError::Other(format!("corrupt journal {}: {e}", path.display()))
            })?;
            if f.version != VERSION {
                return Err(PlatformError::Other(format!(
                    "journal {} has unknown version {}",
                    path.display(),
                    f.version
                )));
            }
            Ok(f.entries)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(PlatformError::io(format!("read {}", path.display()), e)),
    }
}

fn save(path: &Path, entries: &[Undo]) -> Result<()> {
    let io = |op: &str, e| PlatformError::io(format!("{op} {}", path.display()), e);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| io("create dir for", e))?;
    }
    let f = JournalFile {
        version: VERSION,
        entries: entries.to_vec(),
    };
    let data = serde_json::to_vec_pretty(&f)
        .map_err(|e| PlatformError::Other(format!("serialize journal: {e}")))?;
    let tmp = path.with_extension("json.tmp");
    {
        let mut file = fs::File::create(&tmp).map_err(|e| io("create", e))?;
        file.write_all(&data).map_err(|e| io("write", e))?;
        file.sync_all().map_err(|e| io("sync", e))?;
    }
    fs::rename(&tmp, path).map_err(|e| io("rename", e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeNet, FakeState};
    use crate::{DnsConfig, Route, RouteVia};
    use std::sync::{Arc, Mutex};

    fn changes(ifname: &str) -> Vec<NetChange> {
        vec![
            NetChange::AddAddress {
                ifname: ifname.into(),
                addr: "10.212.134.5/32".parse().unwrap(),
                peer: None,
            },
            NetChange::AddRoute(Route {
                dest: "10.0.0.0/8".parse().unwrap(),
                via: RouteVia::Interface(ifname.into()),
            }),
            NetChange::SetDns {
                ifname: ifname.into(),
                dns: DnsConfig {
                    servers: vec!["10.0.0.53".parse().unwrap()],
                    search_domains: vec!["corp.example".into()],
                },
            },
            NetChange::AddSplitDns {
                domain: "corp.example".into(),
                servers: vec!["10.0.0.53".parse().unwrap()],
            },
            NetChange::BlockIpv6,
        ]
    }

    #[test]
    fn crash_mid_apply_then_restart_restores() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let st = Arc::new(Mutex::new(FakeState::typical_host()));
        let before = st.lock().unwrap().net_only();

        // Process 1: applies some changes, then "crashes" (dropped without rollback).
        {
            let mut j = Journaled::open(FakeNet::new(st.clone()), &path).unwrap();
            // The interface exists in the fake even though the tun handle is gone.
            st.lock().unwrap().links.insert("utun9".into(), 1500);
            for c in changes("utun9").iter().take(4) {
                j.apply(c).unwrap();
            }
            assert_eq!(j.pending(), 4);
            // Simulate a crash after the journal write of the 5th change but before its apply.
            let undo = j.platform.prepare(&NetChange::BlockIpv6).unwrap();
            j.entries.push(undo);
            j.save().unwrap();
            std::mem::forget(j);
        }
        assert_ne!(st.lock().unwrap().net_only().routes, before.routes);

        // Process 2: starts, finds the journal, restores.
        let mut j = Journaled::open(FakeNet::new(st.clone()), &path).unwrap();
        assert_eq!(j.recover().unwrap(), 5);
        assert_eq!(j.pending(), 0);
        let mut after = st.lock().unwrap().net_only();
        after.links.remove("utun9");
        assert_eq!(after, before);

        // Journal on disk is empty, so a third start has nothing to do.
        let mut j3 = Journaled::open(FakeNet::new(st), &path).unwrap();
        assert_eq!(j3.recover().unwrap(), 0);
    }

    #[test]
    fn failure_in_apply_all_reverts_everything() {
        let dir = tempfile::tempdir().unwrap();
        let st = Arc::new(Mutex::new(FakeState::typical_host()));
        let before = st.lock().unwrap().net_only();
        let mut j = Journaled::open(FakeNet::new(st.clone()), dir.path().join("j.json")).unwrap();
        let tun = j.create_tun().unwrap();
        st.lock().unwrap().fail_apply_at = Some(3);
        assert!(j.apply_all(&changes(&tun.name)).is_err());
        assert_eq!(j.pending(), 0);
        let mut after = st.lock().unwrap().net_only();
        after.links.remove(&tun.name);
        assert_eq!(after, before);
    }

    #[test]
    fn rollback_all_after_connect() {
        let dir = tempfile::tempdir().unwrap();
        let st = Arc::new(Mutex::new(FakeState::typical_host()));
        let before = st.lock().unwrap().net_only();
        let mut j = Journaled::open(FakeNet::new(st.clone()), dir.path().join("j.json")).unwrap();
        let tun = j.create_tun().unwrap();
        j.apply_all(&changes(&tun.name)).unwrap();
        assert!(st.lock().unwrap().ipv6_blocked);
        j.rollback_all().unwrap();
        let mut after = st.lock().unwrap().net_only();
        after.links.remove(&tun.name);
        assert_eq!(after, before);
    }

    #[test]
    fn failed_undo_remains_pending_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.json");
        let state = Arc::new(Mutex::new(FakeState::typical_host()));
        let mut journal = Journaled::open(FakeNet::new(state.clone()), &path).unwrap();
        journal.apply(&NetChange::BlockIpv6).unwrap();
        journal.entries.push(Undo::RestoreDns {
            ifname: "utun9".into(),
            previous: "invalid fake DNS snapshot".into(),
        });
        journal.save().unwrap();
        assert!(journal.rollback_all().is_err());
        assert_eq!(journal.pending(), 2);
        drop(journal);

        let mut reopened = Journaled::open(FakeNet::new(state.clone()), path).unwrap();
        assert!(reopened.recover().is_err());
        assert_eq!(reopened.pending(), 2);
        assert!(state.lock().unwrap().ipv6_blocked);
    }

    #[test]
    fn corrupt_journal_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("j.json");
        std::fs::write(&p, b"{not json").unwrap();
        assert!(Journaled::open(FakeNet::new(Arc::default()), &p).is_err());
    }
}
