//! Secret types and log redaction.
//!
//! - [`Secret`] holds a password, OTP, cookie or key. It zeroizes on drop and its `Debug` and
//!   `Display` print `[REDACTED]`, so a secret can't end up in a log by accident.
//! - [`redact`] scrubs known secret-bearing patterns (`SVPNCOOKIE=…`, `credential=…`, …) from
//!   free text. [`RedactingWriter`] applies it to every line a logger writes.
//! - [`store`] keeps saved VPN passwords in the user's own secret store ([`CredentialStore`]).

use std::fmt;
use std::io;

use zeroize::{Zeroize, Zeroizing};

#[cfg(all(target_os = "macos", feature = "platform-store"))]
pub mod keychain;
pub mod store;

pub use store::{CredentialStore, SavedPassword, StoreError};

/// Replacement text for redacted values.
pub const REDACTED: &str = "[REDACTED]";

/// A secret string. Zeroized on drop; never printed.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a string as a secret.
    pub fn new(s: impl Into<String>) -> Self {
        Self(Zeroizing::new(s.into()))
    }

    /// Returns the secret value. Callers must not log it.
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// True when the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

/// Secret byte buffer (keys, raw cookies). Zeroized on drop; never printed.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    /// Wraps bytes as a secret.
    pub fn new(b: Vec<u8>) -> Self {
        Self(Zeroizing::new(b))
    }

    /// Returns the bytes. Callers must not log them.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{REDACTED}({} bytes)", self.0.len())
    }
}

/// Keys whose value is redacted when they appear as `key=value` or `key: value`.
/// Matching is case-insensitive.
const SECRET_KEYS: &[&str] = &[
    "svpncookie",
    "svpntmpcookie",
    "svpnnetworkcookie",
    "credential",
    "credential2",
    "password",
    "passwd",
    "code",
    "code2",
    "magic",
    "cookie",
    "authorization",
    "x-fos-auth",
    "sysinfo",
    "cert_req",
    "private_key",
    "token",
];

fn is_key_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Bytes that end a redacted value.
fn ends_value(b: u8) -> bool {
    matches!(
        b,
        b'&' | b';' | b'|' | b',' | b'"' | b'\'' | b'\r' | b'\n' | b' ' | b'\t'
    )
}

/// Redacts the values of known secret keys in `text`.
///
/// Handles `key=value` (form bodies, cookies, query strings) and `key: value` (HTTP headers,
/// EMS replies). The value runs until `&`, `;`, `|`, `,`, quote, whitespace or end of text;
/// for header form (`key: value`) it runs to end of line.
pub fn redact(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < bytes.len() {
        // Start of a key: previous byte is not a key byte.
        if is_key_byte(bytes[i]) && (i == 0 || !is_key_byte(bytes[i - 1])) {
            let start = i;
            let mut j = i;
            while j < bytes.len() && is_key_byte(bytes[j]) {
                j += 1;
            }
            let key = &text[start..j];
            let is_secret = SECRET_KEYS.iter().any(|k| k.eq_ignore_ascii_case(key));
            if is_secret && j < bytes.len() {
                let (sep_end, header) = match bytes[j] {
                    b'=' => (j + 1, false),
                    b':' => {
                        let mut k = j + 1;
                        while k < bytes.len() && bytes[k] == b' ' {
                            k += 1;
                        }
                        (k, true)
                    }
                    _ => (j, false),
                };
                if sep_end > j {
                    let mut v = sep_end;
                    while v < bytes.len() {
                        let b = bytes[v];
                        let stop = if header {
                            b == b'\r' || b == b'\n'
                        } else {
                            ends_value(b)
                        };
                        if stop {
                            break;
                        }
                        v += 1;
                    }
                    if v > sep_end {
                        out.push_str(&text[copied..sep_end]);
                        out.push_str(REDACTED);
                        copied = v;
                        i = v;
                        continue;
                    }
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out.push_str(&text[copied..]);
    out
}

/// An `io::Write` adapter that redacts each write before passing it on.
///
/// Use it as the writer of the log subscriber so that a secret that reaches a log line through
/// a formatted string (not a [`Secret`]) is still scrubbed. Each `write` call is redacted as a
/// unit; `tracing-subscriber`'s fmt layer writes one whole event per call.
#[derive(Debug)]
pub struct RedactingWriter<W: io::Write> {
    inner: W,
}

impl<W: io::Write> RedactingWriter<W> {
    /// Wraps `inner`.
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: io::Write> io::Write for RedactingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let text = String::from_utf8_lossy(buf);
        let mut red = redact(&text);
        self.inner.write_all(red.as_bytes())?;
        red.zeroize();
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn secret_debug_and_display_are_redacted() {
        let s = Secret::new("hunter2");
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(format!("{s}"), REDACTED);
        assert_eq!(s.expose(), "hunter2");
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Login {
            user: String,
            pw: Secret,
        }
        let l = Login {
            user: "alice".into(),
            pw: s,
        };
        let d = format!("{l:?}");
        assert!(!d.contains("hunter2"), "{d}");
    }

    #[test]
    fn redacts_form_body() {
        let body = "username=alice&credential=s3cr%26et&realm=&code=123456&ajax=1";
        let r = redact(body);
        assert_eq!(
            r,
            "username=alice&credential=[REDACTED]&realm=&code=[REDACTED]&ajax=1"
        );
    }

    #[test]
    fn redacts_cookie_header_and_set_cookie() {
        let h = "GET / HTTP/1.1\r\nCookie: SVPNCOOKIE=abcDEF123==; path=/\r\nHost: gw\r\n";
        let r = redact(h);
        assert!(!r.contains("abcDEF123"), "{r}");
        assert!(r.contains("Host: gw"));
        for name in ["SVPNCOOKIE", "SVPNTMPCOOKIE", "SVPNNETWORKCOOKIE"] {
            let header = format!("Set-Cookie: {name}=synthetic-secret; path=/; secure");
            assert_eq!(
                redact(&header),
                format!("Set-Cookie: {name}={REDACTED}; path=/; secure")
            );
        }
    }

    #[test]
    fn keeps_unrelated_keys() {
        let t = "ret=1,reqid=42,polid=1-1-2,grp=g";
        assert_eq!(redact(t), t);
        // "encode" contains "code" but is a different key.
        assert_eq!(redact("encode=abc"), "encode=abc");
    }

    #[test]
    fn redacts_ems_kv() {
        let t = "X-FCCK-REGISTER: SYSINFO|aGVsbG8=|FCTUID|ABC|";
        // `SYSINFO|value|` is pipe form; covered by the key=value rule only when "=" is used,
        // so EMS bodies are redacted by the EMS codec itself. Header-style is covered here:
        let h = "SYSINFO: aGVsbG8=";
        assert_eq!(redact(h), "SYSINFO: [REDACTED]");
        assert!(redact(t).contains("FCTUID"));
    }

    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn cookie_and_password_never_appear_in_formatted_logs() {
        let buf = Buf::default();
        let b2 = buf.clone();
        let sub = tracing_subscriber::fmt()
            .with_writer(move || RedactingWriter::new(b2.clone()))
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(sub, || {
            let pw = Secret::new("p@ssw0rd!");
            tracing::info!(?pw, "login");
            tracing::info!("response header Set-Cookie: SVPNCOOKIE=Q0ZGRUU=; path=/");
            tracing::info!(body = "username=bob&credential=p@ssw0rd!", "post");
        });
        let out = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(!out.contains("p@ssw0rd!"), "{out}");
        assert!(!out.contains("Q0ZGRUU"), "{out}");
        assert!(out.contains("login"));
    }
}
