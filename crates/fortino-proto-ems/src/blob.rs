//! `Z*` reply fields (`ZCONF`, `ZHVR`, `ZFGTIP`): zlib, then base64 (observed
//! sizes match the files they become).

use std::io::Read;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Largest inflated blob accepted by default. Observed profiles are tens of kilobytes.
pub const DEFAULT_MAX_INFLATED: usize = 4 << 20;

/// Errors decoding a blob.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BlobError {
    /// Not base64.
    #[error("blob is not base64")]
    Base64,
    /// Not a zlib stream.
    #[error("blob is not zlib data")]
    Zlib,
    /// Inflates past the limit.
    #[error("blob inflates past {0} bytes")]
    TooLarge(usize),
}

/// Decodes a `Z*` value, refusing anything that inflates past `max` bytes.
pub fn decode(value: &str, max: usize) -> Result<Vec<u8>, BlobError> {
    let compact: String = value.split_ascii_whitespace().collect();
    let raw = STANDARD.decode(compact).map_err(|_| BlobError::Base64)?;
    let mut out = Vec::new();
    flate2::read::ZlibDecoder::new(raw.as_slice())
        .take(max as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| BlobError::Zlib)?;
    if out.len() > max {
        return Err(BlobError::TooLarge(max));
    }
    Ok(out)
}

/// Encodes a blob the way EMS does. Used by the mock EMS and tests.
pub fn encode(data: &[u8]) -> String {
    use std::io::Write;
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    // Writing into a Vec cannot fail.
    let _ = z.write_all(data);
    let raw = z.finish().unwrap_or_default();
    STANDARD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_starts_like_ems() {
        let v = encode(b"<forticlient_configuration/>");
        // zlib with default compression base64-encodes to "eJ…", as observed.
        assert!(v.starts_with("eJ"));
        assert_eq!(
            decode(&v, 1024).unwrap(),
            b"<forticlient_configuration/>".to_vec()
        );
    }

    #[test]
    fn bounded() {
        let v = encode(&vec![b'a'; 10_000]);
        assert_eq!(decode(&v, 100), Err(BlobError::TooLarge(100)));
        assert_eq!(decode("not base64!", 100), Err(BlobError::Base64));
        assert_eq!(decode("AAAA", 100), Err(BlobError::Zlib));
    }
}
