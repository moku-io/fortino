//! Length-prefixed frames: a 4-byte big-endian byte count followed by the payload.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::Zeroizing;

/// Maximum control-protocol message size (256 KiB).
pub const MAX_CONTROL_FRAME: usize = 256 * 1024;

/// Reads one frame. Returns `Ok(None)` on a clean EOF before the length prefix.
///
/// The buffer is zeroized on drop because control messages can carry secrets.
pub async fn read_frame<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds size limit",
        ));
    }
    let mut buf = Zeroizing::new(vec![0u8; n]);
    r.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

/// Reads frames through a buffer of its own, so [`FrameReader::next`] may be cancelled (a
/// `select!` branch that loses) without losing the bytes of a half-read frame, which
/// [`read_frame`] would: its next call would read payload bytes as a length.
#[derive(Debug)]
pub struct FrameReader {
    buf: Zeroizing<Vec<u8>>,
    max: usize,
}

impl FrameReader {
    /// A reader for frames up to `max` bytes.
    pub fn new(max: usize) -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            max,
        }
    }

    /// The next frame, or `Ok(None)` on a clean EOF between frames. Cancel-safe.
    pub async fn next<R: AsyncRead + Unpin>(
        &mut self,
        r: &mut R,
    ) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
        loop {
            if self.buf.len() >= 4 {
                let n = u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                    as usize;
                if n > self.max {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "frame exceeds size limit",
                    ));
                }
                if self.buf.len() >= 4 + n {
                    let frame = Zeroizing::new(self.buf[4..4 + n].to_vec());
                    self.buf.drain(..4 + n);
                    return Ok(Some(frame));
                }
            }
            let mut chunk = Zeroizing::new([0u8; 8192]);
            // `read` is cancel-safe: when it doesn't complete, nothing was consumed.
            let got = r.read(&mut chunk[..]).await?;
            if got == 0 {
                return if self.buf.is_empty() {
                    Ok(None)
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed inside a frame",
                    ))
                };
            }
            self.buf.extend_from_slice(&chunk[..got]);
        }
    }
}

/// Writes one frame and flushes.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    payload: &[u8],
    max: usize,
) -> io::Result<()> {
    if payload.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame exceeds size limit",
        ));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "frame too large"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(payload).await?;
    w.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A frame read in pieces, with the read abandoned between them, comes out whole.
    #[tokio::test]
    async fn reader_survives_cancelled_reads() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let mut r = FrameReader::new(1024);
        let payload = b"hello frames";
        a.write_all(&(payload.len() as u32).to_be_bytes())
            .await
            .unwrap();
        a.write_all(&payload[..5]).await.unwrap();
        // A select! that loses: the pending read is dropped.
        tokio::select! {
            _ = r.next(&mut b) => panic!("the frame isn't complete yet"),
            () = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }
        a.write_all(&payload[5..]).await.unwrap();
        assert_eq!(r.next(&mut b).await.unwrap().unwrap().as_slice(), payload);
        drop(a);
        assert!(r.next(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn roundtrip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"hello", 16).await.unwrap();
        let f = read_frame(&mut b, 16).await.unwrap().unwrap();
        assert_eq!(&f[..], b"hello");

        assert!(write_frame(&mut a, &[0; 17], 16).await.is_err());
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        assert!(read_frame(&mut b, 16).await.is_err());

        drop(a);
        assert!(read_frame(&mut b, 16).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn truncated_frame_is_error() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        a.write_all(&10u32.to_be_bytes()).await.unwrap();
        a.write_all(b"abc").await.unwrap();
        drop(a);
        assert!(read_frame(&mut b, 16).await.is_err());
    }
}
