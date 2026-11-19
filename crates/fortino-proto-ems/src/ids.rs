//! Endpoint and server identifiers.

use std::fmt;

/// Errors validating an identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdError {
    /// Not 32 hex digits once dashes are removed.
    #[error("endpoint UID must be 32 hex digits")]
    Uid,
    /// Not an EMS serial (`FCTEMS…` or `FEMS…`, alphanumeric).
    #[error("not an EMS serial number")]
    EmsSerial,
    /// Not 32 decimal digits.
    #[error("tenant ID must be 32 digits")]
    Tenant,
}

/// The endpoint's `FCTUID`: the platform UUID with dashes removed, upper-case. FortiClient
/// derives it from IOPlatformUUID on macOS (verified); Linux uses `/etc/machine-id`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Uid(String);

impl Uid {
    /// Accepts a UUID with or without dashes, in either case.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let hex: String = text.trim().chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(IdError::Uid);
        }
        Ok(Self(hex.to_ascii_uppercase()))
    }

    /// The wire form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Uid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uid({})", self.0)
    }
}

/// Longest serial accepted.
const MAX_SERIAL: usize = 32;

/// An EMS server's serial number, learned from PROBE and pinned per server. FortiClient refuses
/// a server whose serial does not start with `FCTEMS` or `FEMS`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EmsSerial(String);

impl EmsSerial {
    /// Validates a serial.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        let ok = (text.starts_with("FCTEMS") || text.starts_with("FEMS"))
            && text.len() <= MAX_SERIAL
            && text.bytes().all(|b| b.is_ascii_alphanumeric());
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(IdError::EmsSerial)
        }
    }

    /// The wire form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EmsSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for EmsSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EmsSerial({})", self.0)
    }
}

/// The EMS tenant (`TENANT` in keepalive replies): 32 digits, all zero on premises.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Tenant(String);

impl Tenant {
    /// The on-premises tenant.
    pub fn on_premises() -> Self {
        Self("0".repeat(32))
    }

    /// Validates a tenant.
    pub fn parse(text: &str) -> Result<Self, IdError> {
        if text.len() == 32 && text.bytes().all(|b| b.is_ascii_digit()) {
            Ok(Self(text.to_owned()))
        } else {
            Err(IdError::Tenant)
        }
    }

    /// The wire form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A MAC address. EMS headers write it lower-case and dash-separated.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Mac(pub [u8; 6]);

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}-{b:02x}-{c:02x}-{d:02x}-{e:02x}-{g:02x}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_from_platform_uuid() {
        let u = Uid::parse("0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9").unwrap();
        assert_eq!(u.as_str(), "0A1B2C3D4E5F60718293A4B5C6D7E8F9");
        assert!(Uid::parse("0a1b").is_err());
        assert!(Uid::parse("ZZ1B2C3D4E5F60718293A4B5C6D7E8F9").is_err());
    }

    #[test]
    fn serial_prefixes() {
        assert!(EmsSerial::parse("FCTEMS0000000001").is_ok());
        assert!(EmsSerial::parse("FEMS000001").is_ok());
        assert!(EmsSerial::parse("FGT60F0000000001").is_err());
        assert!(EmsSerial::parse("FCTEMS0000:1").is_err());
    }

    #[test]
    fn mac_format() {
        assert_eq!(
            Mac([0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03]).to_string(),
            "aa-bb-cc-01-02-03"
        );
    }
}
