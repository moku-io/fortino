//! Peer authorization: kernel peer credentials, socket group membership, and the UID and group
//! allowlists.
//!
//! A UID in a message is never trusted; only the credentials of the connected socket count.

use nix::unistd::{Gid, Group, Uid, User};

/// Who may use the daemon.
#[derive(Debug, Clone, Default)]
pub struct Authorizer {
    /// Allowed UIDs (root is implicit).
    pub allowed: Vec<u32>,
    /// Groups whose members are allowed, checked at each connection.
    pub allowed_groups: Vec<Gid>,
    /// Administrator UIDs (root is implicit).
    pub admins: Vec<u32>,
    /// Required group, by GID, if any.
    pub group: Option<Gid>,
}

/// The authenticated caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// Kernel-reported UID.
    pub uid: u32,
    /// May act on other users' attempts.
    pub admin: bool,
}

impl Authorizer {
    /// Builds an authorizer, resolving the group name.
    pub fn new(allowed: Vec<u32>, admins: Vec<u32>, group: Option<&str>) -> Result<Self, String> {
        let group = match group {
            None => None,
            Some(name) => Some(
                Group::from_name(name)
                    .map_err(|e| format!("group {name}: {e}"))?
                    .ok_or_else(|| format!("group {name} does not exist"))?
                    .gid,
            ),
        };
        Ok(Self {
            allowed,
            allowed_groups: Vec::new(),
            admins,
            group,
        })
    }

    /// Checks a peer UID. Returns `None` when access is denied.
    pub fn authorize(&self, uid: u32) -> Option<Peer> {
        if uid == 0 {
            return Some(Peer { uid, admin: true });
        }
        if !self.allowed.contains(&uid) && !self.allowed_groups.iter().any(|g| in_group(uid, *g)) {
            return None;
        }
        if let Some(gid) = self.group
            && !in_group(uid, gid)
        {
            return None;
        }
        Some(Peer {
            uid,
            admin: self.admins.contains(&uid),
        })
    }
}

/// Resolves group names, skipping (with a warning) groups that do not exist on this host.
pub fn resolve_groups(names: &[String]) -> Vec<Gid> {
    names
        .iter()
        .filter_map(|name| match Group::from_name(name) {
            Ok(Some(g)) => Some(g.gid),
            _ => {
                tracing::warn!(group = %name, "allowed group not found; ignored");
                None
            }
        })
        .collect()
}

/// True when `uid` has `gid` as primary group or is listed as a member.
fn in_group(uid: u32, gid: Gid) -> bool {
    let Ok(Some(user)) = User::from_uid(Uid::from_raw(uid)) else {
        return false;
    };
    if user.gid == gid {
        return true;
    }
    matches!(Group::from_gid(gid), Ok(Some(g)) if g.mem.contains(&user.name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist() {
        let a = Authorizer::new(vec![501], vec![], None).unwrap();
        assert_eq!(
            a.authorize(501),
            Some(Peer {
                uid: 501,
                admin: false
            })
        );
        assert_eq!(a.authorize(502), None);
        assert!(a.authorize(0).unwrap().admin);
    }

    #[test]
    fn allowed_groups() {
        let me = nix::unistd::getuid();
        if me.as_raw() == 0 {
            return;
        }
        let user = User::from_uid(me).unwrap().unwrap();
        let mut a = Authorizer::new(vec![], vec![], None).unwrap();
        assert!(a.authorize(me.as_raw()).is_none());
        a.allowed_groups = vec![Gid::from_raw(4_000_000_000), user.gid];
        assert!(!a.authorize(me.as_raw()).unwrap().admin);
        a.allowed_groups = vec![Gid::from_raw(4_000_000_000)];
        assert!(a.authorize(me.as_raw()).is_none());
        assert!(resolve_groups(&["no-such-group-fortino".into()]).is_empty());
    }

    #[test]
    fn group_membership_uses_primary_group() {
        let me = nix::unistd::getuid();
        let user = User::from_uid(me).unwrap().unwrap();
        let mut a = Authorizer::new(vec![me.as_raw()], vec![], None).unwrap();
        a.group = Some(user.gid);
        assert!(a.authorize(me.as_raw()).is_some());
        // A GID nobody has.
        a.group = Some(Gid::from_raw(4_000_000_000));
        if me.as_raw() != 0 {
            assert!(a.authorize(me.as_raw()).is_none());
        }
    }
}
