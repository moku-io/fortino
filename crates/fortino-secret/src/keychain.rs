//! [`CredentialStore`] in the user's login Keychain (macOS).
//!
//! One generic password per profile: service `org.fortino.vpn.<profile ID>`, account the
//! username, label "Fortino: <profile name>" (what Keychain Access shows), description ("Kind"
//! in Keychain Access) naming the gateway it was saved for. The item's comment records that the
//! gateway rejected the password. Keychain Access lets the user see, change or
//! delete the item like any other.
//!
//! The item belongs to the program that created it: macOS lets that program (the `fortino`
//! command, also bundled in the app) read it without asking, and asks the user before any other
//! program can.

use security_framework::base::Error;
use security_framework::item::{
    ItemClass, ItemSearchOptions, ItemUpdateOptions, Limit, update_item,
};
use security_framework::passwords::{
    PasswordOptions, delete_generic_password, generic_password, set_generic_password_options,
};
use zeroize::Zeroizing;

use crate::Secret;
use crate::store::{CredentialStore, SavedPassword, StoreError};

/// `errSecItemNotFound`.
const NOT_FOUND: i32 = -25300;

/// Start of the description; the gateway follows.
const DESCRIPTION: &str = "Fortino VPN password for ";

/// The comment that marks a rejected password.
const REJECTED: &str = "The VPN gateway rejected this password. Fortino asks for it again.";

/// The login Keychain.
#[derive(Debug, Default, Clone, Copy)]
pub struct Keychain;

fn service(profile_id: &str) -> String {
    format!("org.fortino.vpn.{profile_id}")
}

fn unavailable(e: &Error) -> StoreError {
    StoreError::Unavailable(format!("the login keychain: {e}"))
}

/// One saved item's attributes.
struct Attrs {
    account: String,
    comment: Option<String>,
    description: Option<String>,
}

/// The accounts saved for a profile, with their comments and descriptions.
fn items(profile_id: &str) -> Result<Vec<Attrs>, StoreError> {
    let found = ItemSearchOptions::new()
        .class(ItemClass::generic_password())
        .service(&service(profile_id))
        .load_attributes(true)
        .limit(Limit::All)
        .search();
    let found = match found {
        Ok(v) => v,
        Err(e) if e.code() == NOT_FOUND => return Ok(Vec::new()),
        Err(e) => return Err(unavailable(&e)),
    };
    Ok(found
        .iter()
        .filter_map(|r| r.simplify_dict())
        .filter_map(|d| {
            Some(Attrs {
                account: d.get("acct")?.clone(),
                comment: d.get("icmt").cloned(),
                description: d.get("desc").cloned(),
            })
        })
        .collect())
}

impl CredentialStore for Keychain {
    fn location(&self) -> &'static str {
        "the login keychain"
    }

    fn info(&self, profile_id: &str) -> Result<Option<SavedPassword>, StoreError> {
        Ok(items(profile_id)?
            .into_iter()
            .next()
            .map(|a| SavedPassword {
                gateway: a
                    .description
                    .as_deref()
                    .and_then(|d| d.strip_prefix(DESCRIPTION))
                    .map(str::to_owned),
                username: a.account,
                rejected: a.comment.as_deref() == Some(REJECTED),
            }))
    }

    fn read(&self, profile_id: &str, username: &str) -> Result<Option<Secret>, StoreError> {
        match generic_password(PasswordOptions::new_generic_password(
            &service(profile_id),
            username,
        )) {
            Ok(bytes) => {
                let bytes = Zeroizing::new(bytes);
                match std::str::from_utf8(&bytes) {
                    Ok(s) => Ok(Some(Secret::new(s))),
                    Err(_) => Err(StoreError::Unavailable(
                        "the saved password is not text".into(),
                    )),
                }
            }
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(unavailable(&e)),
        }
    }

    fn save(
        &self,
        profile_id: &str,
        label: &str,
        username: &str,
        gateway: &str,
        password: &Secret,
    ) -> Result<(), StoreError> {
        // Start from a fresh item: this drops another account's password and a rejected mark.
        self.remove(profile_id)?;
        let mut o = PasswordOptions::new_generic_password(&service(profile_id), username);
        o.set_label(&format!("Fortino: {label}"));
        o.set_description(&format!("{DESCRIPTION}{gateway}"));
        set_generic_password_options(password.expose().as_bytes(), o).map_err(|e| unavailable(&e))
    }

    fn mark_rejected(&self, profile_id: &str, username: &str) -> Result<(), StoreError> {
        let mut search = ItemSearchOptions::new();
        search
            .class(ItemClass::generic_password())
            .service(&service(profile_id))
            .account(username);
        let mut update = ItemUpdateOptions::new();
        update.set_comment(REJECTED);
        match update_item(&search, &update) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == NOT_FOUND => Ok(()),
            Err(e) => Err(unavailable(&e)),
        }
    }

    fn remove(&self, profile_id: &str) -> Result<bool, StoreError> {
        let svc = service(profile_id);
        let accounts = items(profile_id)?;
        for a in &accounts {
            match delete_generic_password(&svc, &a.account) {
                Ok(()) => {}
                Err(e) if e.code() == NOT_FOUND => {}
                Err(e) => return Err(unavailable(&e)),
            }
        }
        Ok(!accounts.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes to the real login keychain of whoever runs it, so it runs only on request:
    /// `cargo test -p fortino-secret --features platform-store -- --ignored keychain` in a logged-in session.
    #[test]
    #[ignore = "uses the login keychain"]
    fn keychain_round_trip() {
        let k = Keychain;
        let id = format!("test-{}", std::process::id());
        let _ = k.remove(&id);
        assert_eq!(k.info(&id).unwrap(), None);
        k.save(
            &id,
            "Test",
            "alice",
            "vpn.example.org:443",
            &Secret::new("p@ss wörd"),
        )
        .unwrap();
        assert_eq!(
            k.info(&id).unwrap(),
            Some(SavedPassword {
                username: "alice".into(),
                gateway: Some("vpn.example.org:443".into()),
                rejected: false
            })
        );
        assert_eq!(k.read(&id, "alice").unwrap().unwrap().expose(), "p@ss wörd");
        assert_eq!(k.read(&id, "bob").unwrap(), None);
        k.mark_rejected(&id, "alice").unwrap();
        assert!(k.info(&id).unwrap().unwrap().rejected);
        k.save(
            &id,
            "Test",
            "bob",
            "vpn.example.org:443",
            &Secret::new("other"),
        )
        .unwrap();
        let i = k.info(&id).unwrap().unwrap();
        assert_eq!((i.username.as_str(), i.rejected), ("bob", false));
        assert_eq!(k.read(&id, "alice").unwrap(), None);
        assert!(k.remove(&id).unwrap());
        assert_eq!(k.info(&id).unwrap(), None);
    }
}
