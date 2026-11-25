//! Which secret store the CLI uses for saved passwords.
//!
//! The platform store (the login Keychain on macOS). `FORTINO_CREDENTIAL_STORE=none` turns saved
//! passwords off for one run. Development builds also accept `file:<path>`, a plain JSON file,
//! so tests never touch the developer's own keychain; release builds ignore it.

use fortino_secret::store::{NoStore, platform_store};
use fortino_secret::{CredentialStore, SavedPassword, Secret, StoreError};

/// The store for this run.
pub fn open() -> Box<dyn CredentialStore> {
    let choice = std::env::var("FORTINO_CREDENTIAL_STORE").unwrap_or_default();
    if choice == "none" {
        return Box::new(NoStore);
    }
    #[cfg(debug_assertions)]
    if let Some(path) = choice.strip_prefix("file:") {
        return Box::new(file::FileStore::new(path.into()));
    }
    platform_store()
}

/// Debug-only plain-file store for tests. Never compiled into release builds.
#[cfg(debug_assertions)]
mod file {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde::{Deserialize, Serialize};

    use super::{CredentialStore, SavedPassword, Secret, StoreError};

    #[derive(Debug, Default, Serialize, Deserialize)]
    struct Item {
        label: String,
        username: String,
        password: String,
        rejected: bool,
    }

    #[derive(Debug)]
    pub struct FileStore {
        path: PathBuf,
    }

    impl FileStore {
        pub fn new(path: PathBuf) -> Self {
            Self { path }
        }

        fn load(&self) -> Result<BTreeMap<String, Item>, StoreError> {
            match std::fs::read(&self.path) {
                Ok(b) => serde_json::from_slice(&b)
                    .map_err(|e| StoreError::Unavailable(format!("test store: {e}"))),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
                Err(e) => Err(StoreError::Unavailable(format!("test store: {e}"))),
            }
        }

        fn store(&self, m: &BTreeMap<String, Item>) -> Result<(), StoreError> {
            let b = serde_json::to_vec_pretty(m)
                .map_err(|e| StoreError::Unavailable(format!("test store: {e}")))?;
            std::fs::write(&self.path, b)
                .map_err(|e| StoreError::Unavailable(format!("test store: {e}")))
        }
    }

    impl CredentialStore for FileStore {
        fn location(&self) -> &'static str {
            "the test store"
        }
        fn info(&self, profile_id: &str) -> Result<Option<SavedPassword>, StoreError> {
            Ok(self.load()?.get(profile_id).map(|i| SavedPassword {
                username: i.username.clone(),
                rejected: i.rejected,
            }))
        }
        fn read(&self, profile_id: &str, username: &str) -> Result<Option<Secret>, StoreError> {
            Ok(self
                .load()?
                .get(profile_id)
                .filter(|i| i.username == username)
                .map(|i| Secret::new(i.password.as_str())))
        }
        fn save(
            &self,
            profile_id: &str,
            label: &str,
            username: &str,
            password: &Secret,
        ) -> Result<(), StoreError> {
            let mut m = self.load()?;
            m.insert(
                profile_id.to_owned(),
                Item {
                    label: label.to_owned(),
                    username: username.to_owned(),
                    password: password.expose().to_owned(),
                    rejected: false,
                },
            );
            self.store(&m)
        }
        fn mark_rejected(&self, profile_id: &str, username: &str) -> Result<(), StoreError> {
            let mut m = self.load()?;
            if let Some(i) = m.get_mut(profile_id)
                && i.username == username
            {
                i.rejected = true;
            }
            self.store(&m)
        }
        fn remove(&self, profile_id: &str) -> Result<bool, StoreError> {
            let mut m = self.load()?;
            let had = m.remove(profile_id).is_some();
            self.store(&m)?;
            Ok(had)
        }
    }
}
