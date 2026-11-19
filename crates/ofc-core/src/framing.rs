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
