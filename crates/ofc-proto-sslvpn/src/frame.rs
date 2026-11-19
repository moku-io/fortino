//! The `0x5050` ("PP") frame that carries PPP over the TLS connection:
//!
//! ```text
//! | total length (u16 BE) | 0x5050 | payload length (u16 BE) | payload |
//! ```
//!
//! `total length = payload length + 6`. GATEWAY-2 used exactly this layout.

/// Frame magic.
pub const MAGIC: u16 = 0x5050;
/// Header size.
pub const HEADER: usize = 6;
/// Largest payload a frame can carry.
pub const MAX_PAYLOAD: usize = u16::MAX as usize - HEADER;

/// Frame errors. Any of them ends the tunnel: the stream cannot be resynchronized.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    /// The magic was not `0x5050`. `head` holds the first bytes, which may be an HTTP error.
    #[error("unexpected bytes on the tunnel (not a 0x5050 frame)")]
    BadMagic {
        /// Up to 16 leading bytes, for diagnostics.
        head: Vec<u8>,
    },
    /// Lengths disagree.
    #[error("inconsistent frame lengths")]
    BadLength,
    /// Payload too large to send.
    #[error("payload too large")]
    TooLarge,
}

/// Appends a frame carrying `payload` to `out`.
pub fn encode(payload: &[u8], out: &mut Vec<u8>) -> Result<(), FrameError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(FrameError::TooLarge);
    }
    let len = u16::try_from(payload.len()).map_err(|_| FrameError::TooLarge)?;
    out.extend_from_slice(&(len + HEADER as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// Incremental decoder.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    /// Adds received bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// The next complete payload, if any.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        if self.buf.len() < HEADER {
            return Ok(None);
        }
        let total = usize::from(u16::from_be_bytes([self.buf[0], self.buf[1]]));
        let magic = u16::from_be_bytes([self.buf[2], self.buf[3]]);
        let plen = usize::from(u16::from_be_bytes([self.buf[4], self.buf[5]]));
        if magic != MAGIC {
            return Err(FrameError::BadMagic {
                head: self.buf.iter().take(16).copied().collect(),
            });
        }
        if total != plen + HEADER {
            return Err(FrameError::BadLength);
        }
        if self.buf.len() < total {
            return Ok(None);
        }
        let payload = self.buf[HEADER..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(payload))
    }

    /// Bytes buffered but not yet returned.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_split_arbitrarily() {
        let mut wire = Vec::new();
        encode(b"\xc0\x21\x01\x01\x00\x04", &mut wire).unwrap();
        encode(b"", &mut wire).unwrap();
        encode(&[7u8; 1500], &mut wire).unwrap();
        assert_eq!(&wire[..6], &[0, 12, 0x50, 0x50, 0, 6]);
        for split in 1..wire.len() {
            let mut d = Decoder::default();
            let mut got = Vec::new();
            for chunk in [&wire[..split], &wire[split..]] {
                d.push(chunk);
                while let Some(f) = d.next_frame().unwrap() {
                    got.push(f);
                }
            }
            assert_eq!(got.len(), 3);
            assert_eq!(got[2].len(), 1500);
            assert_eq!(d.pending(), 0);
        }
    }

    #[test]
    fn rejects_http_and_bad_lengths() {
        let mut d = Decoder::default();
        d.push(b"HTTP/1.1 403 Forbidden\r\n");
        assert!(matches!(d.next_frame(), Err(FrameError::BadMagic { .. })));
        let mut d = Decoder::default();
        d.push(&[0, 10, 0x50, 0x50, 0, 6]);
        assert_eq!(d.next_frame(), Err(FrameError::BadLength));
        assert_eq!(
            encode(&vec![0; MAX_PAYLOAD + 1], &mut Vec::new()),
            Err(FrameError::TooLarge)
        );
    }

    proptest::proptest! {
        #[test]
        fn never_panics(data: Vec<u8>) {
            let mut d = Decoder::default();
            d.push(&data);
            while let Ok(Some(_)) = d.next_frame() {}
        }
    }
}
