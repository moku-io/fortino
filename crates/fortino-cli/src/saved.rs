//! Saved passwords during a connection attempt.
//!
//! The password prompt is answered from the user's secret store when the profile has
//! **Save password** on. The daemon can't tell the difference: it gets the same answer as a
//! typed one. A password the user types is saved once the tunnel is up, so only a password the
//! gateway accepted is kept. When the gateway rejects a saved password it is marked and never
//! sent again; the next attempt asks the user.

use fortino_core::ErrorCode;
use fortino_core::proto::ChallengeKind;
use fortino_secret::{CredentialStore, SavedPassword, Secret, StoreError};

/// What the store has for a profile and username.
#[derive(Debug)]
pub enum Lookup {
    /// A password the gateway has not rejected.
    Found(Secret),
    /// Nothing saved for this username.
    Missing,
    /// The saved password was rejected by the gateway last time.
    Rejected,
    /// The store couldn't be read (locked, access refused).
    Unavailable(StoreError),
}

impl Lookup {
    /// Short reason, for the app: `missing`, `rejected` or `unavailable`.
    pub fn reason(&self) -> &'static str {
        match self {
            Lookup::Found(_) => "found",
            Lookup::Missing => "missing",
            Lookup::Rejected => "rejected",
            Lookup::Unavailable(_) => "unavailable",
        }
    }
}

/// Looks up the saved password for `profile_id` and `username`. Reads the secret only when the
/// item is for this username and not marked rejected.
pub fn lookup(store: &dyn CredentialStore, profile_id: &str, username: &str) -> Lookup {
    match store.info(profile_id) {
        Ok(Some(i)) if i.username == username && i.rejected => Lookup::Rejected,
        Ok(Some(i)) if i.username == username => match store.read(profile_id, username) {
            Ok(Some(s)) => Lookup::Found(s),
            Ok(None) => Lookup::Missing,
            Err(e) => Lookup::Unavailable(e),
        },
        Ok(_) => Lookup::Missing,
        Err(e) => Lookup::Unavailable(e),
    }
}

/// What to do with a typed password once connected.
#[derive(Debug, PartialEq, Eq)]
pub enum AfterConnect {
    /// Nothing to save.
    Nothing,
    /// Save it: nothing was saved for this username.
    Save,
    /// The saved one was rejected: ask before replacing it.
    AskToReplace,
}

/// Tracks one attempt's password: whether it came from the store, whether the gateway took it,
/// and a typed one to save.
#[derive(Debug)]
pub struct Keeper {
    profile_id: String,
    label: String,
    enabled: bool,
    /// The store's item when the attempt started.
    initial: Option<SavedPassword>,
    /// The username whose saved password was sent in this attempt.
    sent_saved: Option<String>,
    /// A password the user typed in this attempt, with its username.
    typed: Option<(String, Secret)>,
    /// Why the store wasn't used for the typed password.
    typed_because: Option<&'static str>,
    /// The gateway got past the password (a code was asked for, or the tunnel came up).
    accepted: bool,
}

impl Keeper {
    /// A keeper for `profile_id`. `enabled` is the profile's **Save password** choice.
    pub fn new(store: &dyn CredentialStore, profile_id: &str, label: &str, enabled: bool) -> Self {
        let initial = if enabled {
            store.info(profile_id).ok().flatten()
        } else {
            None
        };
        Self {
            profile_id: profile_id.to_owned(),
            label: label.to_owned(),
            enabled,
            initial,
            sent_saved: None,
            typed: None,
            typed_because: None,
            accepted: false,
        }
    }

    /// The saved password to answer this prompt with, if there is one and it hasn't been sent in
    /// this attempt yet. `note` receives a line for the user when the store isn't used.
    pub fn saved_answer(
        &mut self,
        store: &dyn CredentialStore,
        username: Option<&str>,
        note: &mut dyn FnMut(String),
    ) -> Option<Secret> {
        if !self.enabled || self.sent_saved.is_some() {
            return None;
        }
        let username = username?;
        let l = lookup(store, &self.profile_id, username);
        self.typed_because = Some(l.reason());
        match l {
            Lookup::Found(s) => {
                note(format!("Using the password saved in {}.", store.location()));
                self.sent_saved = Some(username.to_owned());
                Some(s)
            }
            Lookup::Missing => None,
            Lookup::Rejected => {
                note("The gateway rejected the saved password last time; type it again.".into());
                None
            }
            Lookup::Unavailable(e) => {
                note(format!("Could not read the saved password: {e}."));
                None
            }
        }
    }

    /// Remembers a password the user typed, to save once connected.
    pub fn typed(&mut self, username: Option<&str>, password: &str) {
        if self.enabled
            && let Some(u) = username
        {
            self.typed = Some((u.to_owned(), Secret::new(password)));
        }
    }

    /// A new prompt appeared: a prompt after the password means the gateway accepted it.
    pub fn saw_challenge(&mut self, kind: ChallengeKind) {
        if kind == ChallengeKind::Otp {
            self.accepted = true;
        }
    }

    /// The tunnel is up. Returns what to do with a typed password.
    pub fn connected(&mut self) -> AfterConnect {
        self.accepted = true;
        let Some((user, _)) = &self.typed else {
            return AfterConnect::Nothing;
        };
        match (&self.initial, self.typed_because) {
            // The store was there but couldn't be read: writing would fail the same way.
            (_, Some("unavailable")) => AfterConnect::Nothing,
            (Some(i), _) if &i.username == user && i.rejected => AfterConnect::AskToReplace,
            _ => AfterConnect::Save,
        }
    }

    /// Saves the typed password.
    pub fn save_typed(&self, store: &dyn CredentialStore) -> Result<(), StoreError> {
        match &self.typed {
            Some((u, p)) => store.save(&self.profile_id, &self.label, u, p),
            None => Ok(()),
        }
    }

    /// The attempt ended with `code`. If a saved password was sent and the gateway refused the
    /// login before asking for anything else, marks it rejected and returns true.
    pub fn finished(&self, store: &dyn CredentialStore, code: Option<ErrorCode>) -> bool {
        let Some(user) = &self.sent_saved else {
            return false;
        };
        if self.accepted || code != Some(ErrorCode::AuthDenied) {
            return false;
        }
        store.mark_rejected(&self.profile_id, user).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fortino_secret::store::MemoryStore;

    fn quiet() -> impl FnMut(String) {
        |_| {}
    }

    #[test]
    fn disabled_profile_never_reads_or_saves() {
        let s = MemoryStore::default();
        s.save("p", "P", "alice", &Secret::new("pw")).unwrap();
        let mut k = Keeper::new(&s, "p", "P", false);
        assert!(k.saved_answer(&s, Some("alice"), &mut quiet()).is_none());
        k.typed(Some("alice"), "typed");
        assert_eq!(k.connected(), AfterConnect::Nothing);
    }

    #[test]
    fn first_connection_saves_the_typed_password_once_connected() {
        let s = MemoryStore::default();
        let mut k = Keeper::new(&s, "p", "P", true);
        assert!(k.saved_answer(&s, Some("alice"), &mut quiet()).is_none());
        k.typed(Some("alice"), "secret");
        k.saw_challenge(ChallengeKind::Otp);
        assert_eq!(k.connected(), AfterConnect::Save);
        k.save_typed(&s).unwrap();
        assert_eq!(s.read("p", "alice").unwrap().unwrap().expose(), "secret");
    }

    #[test]
    fn saved_password_answers_once_per_attempt() {
        let s = MemoryStore::default();
        s.save("p", "P", "alice", &Secret::new("pw")).unwrap();
        let mut k = Keeper::new(&s, "p", "P", true);
        let mut notes = Vec::new();
        let a = k.saved_answer(&s, Some("alice"), &mut |n| notes.push(n));
        assert_eq!(a.unwrap().expose(), "pw");
        assert!(notes[0].starts_with("Using the password saved in"));
        assert!(k.saved_answer(&s, Some("alice"), &mut quiet()).is_none());
        assert_eq!(k.connected(), AfterConnect::Nothing);
    }

    #[test]
    fn another_username_is_not_given_the_saved_password() {
        let s = MemoryStore::default();
        s.save("p", "P", "alice", &Secret::new("pw")).unwrap();
        let mut k = Keeper::new(&s, "p", "P", true);
        assert!(k.saved_answer(&s, Some("bob"), &mut quiet()).is_none());
        k.typed(Some("bob"), "bobs");
        assert_eq!(k.connected(), AfterConnect::Save);
    }

    #[test]
    fn rejected_saved_password_is_marked_and_not_sent_again() {
        let s = MemoryStore::default();
        s.save("p", "P", "alice", &Secret::new("old")).unwrap();
        let mut k = Keeper::new(&s, "p", "P", true);
        assert!(k.saved_answer(&s, Some("alice"), &mut quiet()).is_some());
        assert!(k.finished(&s, Some(ErrorCode::AuthDenied)));
        assert!(s.info("p").unwrap().unwrap().rejected);

        // Next attempt: not sent, the user types it and is asked before it replaces the old one.
        let mut k = Keeper::new(&s, "p", "P", true);
        let mut notes = Vec::new();
        assert!(
            k.saved_answer(&s, Some("alice"), &mut |n| notes.push(n))
                .is_none()
        );
        assert!(notes[0].contains("rejected"));
        k.typed(Some("alice"), "new");
        assert_eq!(k.connected(), AfterConnect::AskToReplace);
        k.save_typed(&s).unwrap();
        assert!(!s.info("p").unwrap().unwrap().rejected);
    }

    #[test]
    fn a_refusal_after_the_code_prompt_is_not_blamed_on_the_password() {
        let s = MemoryStore::default();
        s.save("p", "P", "alice", &Secret::new("pw")).unwrap();
        let mut k = Keeper::new(&s, "p", "P", true);
        assert!(k.saved_answer(&s, Some("alice"), &mut quiet()).is_some());
        k.saw_challenge(ChallengeKind::Otp);
        assert!(!k.finished(&s, Some(ErrorCode::AuthDenied)));
        assert!(!s.info("p").unwrap().unwrap().rejected);
    }

    #[test]
    fn other_failures_do_not_mark_the_password() {
        let s = MemoryStore::default();
        s.save("p", "P", "alice", &Secret::new("pw")).unwrap();
        let mut k = Keeper::new(&s, "p", "P", true);
        assert!(k.saved_answer(&s, Some("alice"), &mut quiet()).is_some());
        assert!(!k.finished(&s, Some(ErrorCode::TransportFailure)));
        assert!(!k.finished(&s, None));
        assert!(!s.info("p").unwrap().unwrap().rejected);
    }
}
