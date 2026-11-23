//! Approval markers: small files an administrator creates as root (through the app's
//! administrator prompt) to record a decision the unprivileged user cannot make alone, such as
//! trusting one specific certificate. A marker is named by the SHA-256 of a normalized key
//! (`host:port`) and is honoured only when it and its directory are owned by the expected user
//! (root in production) and writable by nobody else.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Largest marker accepted.
pub const MAX_MARKER_LEN: u64 = 256;

/// The marker file name for `key`: lower-case hex SHA-256 of its bytes.
pub fn marker_name(key: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(key.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The path and content of the marker for `key` in `dir`, or `None` when there is none or it
/// is not protected: the directory and the file (a regular file, not a symlink, at most
/// [`MAX_MARKER_LEN`] bytes) must be owned by `owner` and not group- or world-writable.
pub fn read_protected(dir: &Path, key: &str, owner: u32) -> Option<(PathBuf, String)> {
    let protected = |m: &std::fs::Metadata| m.uid() == owner && m.mode() & 0o022 == 0;
    if !std::fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir() && protected(&m)) {
        return None;
    }
    let path = dir.join(marker_name(key));
    if !std::fs::symlink_metadata(&path)
        .is_ok_and(|m| m.is_file() && protected(&m) && m.len() <= MAX_MARKER_LEN)
    {
        return None;
    }
    let content = std::fs::read_to_string(&path).ok()?;
    Some((path, content))
}

/// The SHA-256 pin in a gateway pin marker: one `sha256:<64 hex>` line.
pub fn gateway_pin(content: &str) -> Option<[u8; 32]> {
    crate::parse_pin(content.trim().strip_prefix("sha256:")?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn me(dir: &Path) -> u32 {
        std::fs::metadata(dir).unwrap().uid()
    }

    #[test]
    fn only_protected_markers_are_read() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("pins");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let owner = me(&dir);
        let key = "vpn.example.com:443";
        let file = dir.join(marker_name(key));

        assert!(read_protected(&dir, key, owner).is_none());
        std::fs::write(&file, "sha256:abc\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_protected(&dir, key, owner),
            Some((file.clone(), "sha256:abc\n".into()))
        );
        // Another owner (root, in production, when the test does not run as root).
        assert!(read_protected(&dir, key, owner.wrapping_add(1)).is_none());
        // Writable by others.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o622)).unwrap();
        assert!(read_protected(&dir, key, owner).is_none());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(read_protected(&dir, key, owner).is_none());
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // Oversized.
        std::fs::write(&file, "x".repeat(300)).unwrap();
        assert!(read_protected(&dir, key, owner).is_none());
        // A symlink is not a marker.
        std::fs::remove_file(&file).unwrap();
        let target = d.path().join("elsewhere");
        std::fs::write(&target, "sha256:abc").unwrap();
        std::os::unix::fs::symlink(&target, &file).unwrap();
        assert!(read_protected(&dir, key, owner).is_none());
    }

    #[test]
    fn gateway_pins_parse() {
        let hex = "ab".repeat(32);
        assert_eq!(gateway_pin(&format!("sha256:{hex}\n")), Some([0xab; 32]));
        assert_eq!(gateway_pin(&hex), None);
        assert_eq!(gateway_pin("sha256:zz"), None);
        assert_eq!(gateway_pin(""), None);
    }
}
