//! `KEY|value|KEY|value|…|` bodies.
//!
//! Requests carry them after `X-FCCK-<TYPE>: `; replies carry them after `<REPLYTYPE>: `. The
//! trailing `|` is always present. Values may be empty or span lines (PEM), but never contain
//! `|`: no escaping has been observed, so the encoder refuses such values rather than invent one.

use zeroize::Zeroize;

/// Longest key accepted in either direction.
pub const MAX_KEY_LEN: usize = 64;
/// Most fields accepted in one reply.
pub const MAX_FIELDS: usize = 1024;

/// Errors building a body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FieldError {
    /// The key is empty, too long or not `[A-Z0-9_]`.
    #[error("invalid field key {0:?}")]
    Key(String),
    /// The value contains `|` or NUL.
    #[error("value of {0} contains a separator")]
    Value(String),
}

/// An ordered list of fields. Order is kept because FortiClient's order is part of the wire
/// identity. Values are wiped on drop: a body may carry a registration key.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Fields(Vec<(String, String)>);

impl std::fmt::Debug for Fields {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Names only: values may be secret or large.
        f.debug_list()
            .entries(self.0.iter().map(|(k, _)| k))
            .finish()
    }
}

impl Drop for Fields {
    fn drop(&mut self) {
        for (_, v) in &mut self.0 {
            v.zeroize();
        }
    }
}

pub(crate) fn valid_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= MAX_KEY_LEN
        && key
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

impl Fields {
    /// An empty body.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a field.
    pub fn push(&mut self, key: &str, value: impl Into<String>) -> Result<(), FieldError> {
        if !valid_key(key) {
            return Err(FieldError::Key(key.to_owned()));
        }
        let value = value.into();
        if value.contains(['|', '\0']) {
            let mut value = value;
            value.zeroize();
            return Err(FieldError::Value(key.to_owned()));
        }
        self.0.push((key.to_owned(), value));
        Ok(())
    }

    /// The first value for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// Fields in wire order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of fields.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// No fields.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Appends `KEY|value|` for every field.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        for (k, v) in &self.0 {
            out.extend_from_slice(k.as_bytes());
            out.push(b'|');
            out.extend_from_slice(v.as_bytes());
            out.push(b'|');
        }
    }

    /// Parses `KEY|value|…|` followed only by whitespace or NULs.
    pub(crate) fn parse(text: &str) -> Result<Self, ParseError> {
        let mut parts = text.split('|');
        let mut fields = Vec::new();
        loop {
            let Some(key) = parts.next() else {
                return Err(ParseError::Truncated);
            };
            let Some(value) = parts.next() else {
                // `key` is what followed the final `|`: only padding is allowed there.
                if !key
                    .trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0')
                    .is_empty()
                {
                    return Err(ParseError::Truncated);
                }
                break;
            };
            if !valid_key(key) {
                return Err(ParseError::Key);
            }
            if fields.len() == MAX_FIELDS {
                return Err(ParseError::TooManyFields);
            }
            fields.push((key.to_owned(), value.to_owned()));
        }
        Ok(Self(fields))
    }
}

/// Errors parsing a reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Larger than [`crate::reply::MAX_REPLY`].
    #[error("reply too large")]
    TooLarge,
    /// No `<TYPE>: ` prefix.
    #[error("reply has no type")]
    NoType,
    /// Not UTF-8.
    #[error("reply is not text")]
    NotText,
    /// A key that is not `[A-Z0-9_]`.
    #[error("malformed field key")]
    Key,
    /// A key without a value, or text after the final `|`.
    #[error("truncated field list")]
    Truncated,
    /// More than [`MAX_FIELDS`] fields.
    #[error("too many fields")]
    TooManyFields,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_order_and_empty_values() {
        let mut f = Fields::new();
        f.push("USR_NAME", "").unwrap();
        f.push("CERT", "-----BEGIN X-----\nAAAA\n-----END X-----\n")
            .unwrap();
        f.push("A1", "x").unwrap();
        let mut out = Vec::new();
        f.encode_into(&mut out);
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("USR_NAME||CERT|-----BEGIN"));
        assert!(text.ends_with("A1|x|"));
        assert_eq!(Fields::parse(&text).unwrap(), f);
    }

    #[test]
    fn refuses_separators_and_bad_keys() {
        let mut f = Fields::new();
        assert!(f.push("K", "a|b").is_err());
        assert!(f.push("K", "a\0").is_err());
        assert!(f.push("lower", "a").is_err());
        assert!(f.push("", "a").is_err());
        assert!(f.is_empty());
    }

    #[test]
    fn parse_rejects_dangling_text() {
        assert_eq!(Fields::parse("A|1|B"), Err(ParseError::Truncated));
        assert_eq!(Fields::parse("A|1|junk|"), Err(ParseError::Key));
        assert!(Fields::parse("A|1|\n\0").is_ok());
        assert!(Fields::parse("").unwrap().is_empty());
    }

    #[test]
    fn debug_hides_values() {
        let mut f = Fields::new();
        f.push("REG_KEY", "s3cret").unwrap();
        assert!(!format!("{f:?}").contains("s3cret"));
    }
}
