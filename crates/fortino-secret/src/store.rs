//! Saved VPN passwords in the user's own secret store.
//!
//! Only a client running in the user's session uses this; the root daemon never does. A store
//! keeps at most one password per profile, keyed by the profile's opaque ID (so a rename keeps
//! it) and the username (so a different account never gets another account's password).
//!
//! A store can also remember that the gateway rejected the saved password. A rejected password
//! is never sent again: the client asks the user instead, and saving a new password clears the
//! mark.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Mutex;

use crate::Secret;

/// What a store knows about a profile's saved password, without reading the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedPassword {
    /// The account the password belongs to.
    pub username: String,
    /// The gateway rejected this password the last time it was sent.
    pub rejected: bool,
}

/// A store failure. Callers treat every failure as "no saved password" and ask the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// This system has no secret store for this session (no Keychain, a headless Linux session).
    NoStore,
    /// The store exists but can't be used now: locked, access refused, or the user cancelled
    /// the system's access prompt. The text is the store's own explanation.
    Unavailable(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NoStore => f.write_str("no secret store is available in this session"),
            StoreError::Unavailable(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for StoreError {}

/// The user's secret store.
pub trait CredentialStore: Send + Sync {
    /// Where passwords are kept, for messages ("the login keychain").
    fn location(&self) -> &'static str;

    /// The saved password's account and state, without reading the secret (no access prompt).
    fn info(&self, profile_id: &str) -> Result<Option<SavedPassword>, StoreError>;

    /// Reads the password saved for `profile_id` and `username`. `Ok(None)` when there is none.
    /// The system may ask the user to allow access.
    fn read(&self, profile_id: &str, username: &str) -> Result<Option<Secret>, StoreError>;

    /// Saves `password` as the profile's only saved password, replacing any other (also one for
    /// another username) and clearing a rejected mark. `label` is the profile's display name,
    /// shown by the system's password manager.
    fn save(
        &self,
        profile_id: &str,
        label: &str,
        username: &str,
        password: &Secret,
    ) -> Result<(), StoreError>;

    /// Records that the gateway rejected the saved password for `username`, keeping it.
    fn mark_rejected(&self, profile_id: &str, username: &str) -> Result<(), StoreError>;

    /// Removes the profile's saved password. True when one existed.
    fn remove(&self, profile_id: &str) -> Result<bool, StoreError>;
}

/// No store: every read finds nothing and every write fails with [`StoreError::NoStore`].
#[derive(Debug, Default, Clone, Copy)]
pub struct NoStore;

impl CredentialStore for NoStore {
    fn location(&self) -> &'static str {
        "no secret store"
    }
    fn info(&self, _: &str) -> Result<Option<SavedPassword>, StoreError> {
        Ok(None)
    }
    fn read(&self, _: &str, _: &str) -> Result<Option<Secret>, StoreError> {
        Ok(None)
    }
    fn save(&self, _: &str, _: &str, _: &str, _: &Secret) -> Result<(), StoreError> {
        Err(StoreError::NoStore)
    }
    fn mark_rejected(&self, _: &str, _: &str) -> Result<(), StoreError> {
        Err(StoreError::NoStore)
    }
    fn remove(&self, _: &str) -> Result<bool, StoreError> {
        Ok(false)
    }
}

/// An in-memory store, for tests.
#[derive(Debug, Default)]
pub struct MemoryStore {
    items: Mutex<BTreeMap<String, (SavedPassword, Secret)>>,
}

impl MemoryStore {
    fn items(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, (SavedPassword, Secret)>> {
        self.items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl CredentialStore for MemoryStore {
    fn location(&self) -> &'static str {
        "memory"
    }
    fn info(&self, profile_id: &str) -> Result<Option<SavedPassword>, StoreError> {
        Ok(self.items().get(profile_id).map(|(i, _)| i.clone()))
    }
    fn read(&self, profile_id: &str, username: &str) -> Result<Option<Secret>, StoreError> {
        Ok(self
            .items()
            .get(profile_id)
            .filter(|(i, _)| i.username == username)
            .map(|(_, s)| s.clone()))
    }
    fn save(
        &self,
        profile_id: &str,
        _label: &str,
        username: &str,
        password: &Secret,
    ) -> Result<(), StoreError> {
        let info = SavedPassword {
            username: username.to_owned(),
            rejected: false,
        };
        self.items()
            .insert(profile_id.to_owned(), (info, password.clone()));
        Ok(())
    }
    fn mark_rejected(&self, profile_id: &str, username: &str) -> Result<(), StoreError> {
        if let Some((i, _)) = self.items().get_mut(profile_id)
            && i.username == username
        {
            i.rejected = true;
        }
        Ok(())
    }
    fn remove(&self, profile_id: &str) -> Result<bool, StoreError> {
        Ok(self.items().remove(profile_id).is_some())
    }
}

/// The platform's store: the login Keychain on macOS, none elsewhere yet (or without the
/// `platform-store` feature).
pub fn platform_store() -> Box<dyn CredentialStore> {
    #[cfg(all(target_os = "macos", feature = "platform-store"))]
    {
        Box::new(crate::keychain::Keychain)
    }
    #[cfg(not(all(target_os = "macos", feature = "platform-store")))]
    {
        Box::new(NoStore)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_keeps_one_password_per_profile_and_username() {
        let s = MemoryStore::default();
        assert_eq!(s.info("p1").unwrap(), None);
        s.save("p1", "Office", "alice", &Secret::new("one"))
            .unwrap();
        assert_eq!(s.read("p1", "alice").unwrap().unwrap().expose(), "one");
        assert_eq!(s.read("p1", "bob").unwrap(), None);
        assert_eq!(s.read("p2", "alice").unwrap(), None);

        s.mark_rejected("p1", "bob").unwrap();
        assert!(!s.info("p1").unwrap().unwrap().rejected);
        s.mark_rejected("p1", "alice").unwrap();
        assert!(s.info("p1").unwrap().unwrap().rejected);

        // Saving again replaces the account and clears the mark.
        s.save("p1", "Office", "bob", &Secret::new("two")).unwrap();
        let i = s.info("p1").unwrap().unwrap();
        assert_eq!((i.username.as_str(), i.rejected), ("bob", false));
        assert_eq!(s.read("p1", "alice").unwrap(), None);

        assert!(s.remove("p1").unwrap());
        assert!(!s.remove("p1").unwrap());
    }

    #[test]
    fn no_store_reads_nothing_and_refuses_writes() {
        let s = NoStore;
        assert_eq!(s.info("p").unwrap(), None);
        assert_eq!(s.read("p", "u").unwrap(), None);
        assert_eq!(
            s.save("p", "P", "u", &Secret::new("x")),
            Err(StoreError::NoStore)
        );
        assert!(!s.remove("p").unwrap());
    }
}
