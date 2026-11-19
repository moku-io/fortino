//! Minimal HTTP/1.1 request reader and response writer for the mock servers.

use std::fmt::Write as _;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Maximum header block the mock accepts.
const MAX_HEADER: usize = 64 * 1024;
/// Maximum body the mock accepts.
const MAX_BODY: usize = 1024 * 1024;

/// A parsed HTTP request.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Method (`GET`, `POST`, …).
    pub method: String,
    /// Path without the query string.
    pub path: String,
    /// Raw query string (without `?`), empty if none.
    pub query: String,
    /// Headers in the order received (names as sent).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Request {
    /// First header with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Value of a cookie from the `Cookie` header.
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.header("cookie")?.split(';').find_map(|kv| {
            let (k, v) = kv.trim().split_once('=')?;
            (k == name).then_some(v)
        })
    }

    /// Decoded `application/x-www-form-urlencoded` body field.
    pub fn form(&self, name: &str) -> Option<String> {
        form_get(&String::from_utf8_lossy(&self.body), name)
    }

    /// Decoded query parameter.
    pub fn query_param(&self, name: &str) -> Option<String> {
        form_get(&self.query, name)
    }
}

/// Looks up and percent-decodes a field in a urlencoded string.
pub fn form_get(s: &str, name: &str) -> Option<String> {
    s.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
        (pct_decode(k) == name).then(|| pct_decode(v))
    })
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3])
                    .ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match h {
                    Some(v) => {
                        out.push(v);
                        i += 2;
                    }
                    None => out.push(b'%'),
                }
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Mock errors.
#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    /// Socket error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Bad request.
    #[error("bad request: {0}")]
    Bad(&'static str),
}

/// Reads one request. Returns `Ok(None)` on a clean EOF before any byte.
pub async fn read_request<R: AsyncRead + Unpin>(
    r: &mut BufReader<R>,
) -> Result<Option<Request>, HttpError> {
    let mut line = String::new();
    if r.read_line(&mut line).await? == 0 {
        return Ok(None);
    }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next().ok_or(HttpError::Bad("no method"))?.to_owned();
    let target = parts.next().ok_or(HttpError::Bad("no target"))?;
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut req = Request {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        ..Default::default()
    };
    let mut total = line.len();
    loop {
        line.clear();
        let n = r.read_line(&mut line).await?;
        if n == 0 {
            return Err(HttpError::Bad("eof in headers"));
        }
        total += n;
        if total > MAX_HEADER {
            return Err(HttpError::Bad("headers too large"));
        }
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':').ok_or(HttpError::Bad("bad header"))?;
        req.headers.push((k.trim().to_owned(), v.trim().to_owned()));
    }
    if let Some(len) = req.header("content-length") {
        let len: usize = len.parse().map_err(|_| HttpError::Bad("content-length"))?;
        if len > MAX_BODY {
            return Err(HttpError::Bad("body too large"));
        }
        req.body = vec![0; len];
        r.read_exact(&mut req.body).await?;
    }
    Ok(Some(req))
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers (Content-Length is added automatically).
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    /// 200 with a body and content type.
    pub fn ok(content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), content_type.into())],
            body: body.into(),
        }
    }

    /// Empty response with this status.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            headers: vec![],
            body: vec![],
        }
    }

    /// Adds a header.
    pub fn with_header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }

    /// Serializes the response.
    pub fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            302 => "Found",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            _ => "Status",
        };
        let mut h = format!("HTTP/1.1 {} {reason}\r\n", self.status);
        for (k, v) in &self.headers {
            let _ = write!(h, "{k}: {v}\r\n");
        }
        let _ = write!(h, "Content-Length: {}\r\n\r\n", self.body.len());
        let mut out = h.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }

    /// Writes the response.
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, w: &mut W) -> std::io::Result<()> {
        w.write_all(&self.to_bytes()).await?;
        w.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_form() {
        assert_eq!(
            form_get("username=a%40b.c&credential=x+y%26z", "credential").as_deref(),
            Some("x y&z")
        );
        assert_eq!(form_get("a=1&b=", "b").as_deref(), Some(""));
        assert_eq!(form_get("a=%4", "a").as_deref(), Some("%4"));
    }

    #[tokio::test]
    async fn parse_request() {
        let raw = b"POST /remote/logincheck?x=1 HTTP/1.1\r\nHost: gw\r\nCookie: A=1; SVPNCOOKIE=abc\r\nContent-Length: 5\r\n\r\nu=bob";
        let mut r = BufReader::new(&raw[..]);
        let req = read_request(&mut r).await.unwrap().unwrap();
        assert_eq!(req.path, "/remote/logincheck");
        assert_eq!(req.query, "x=1");
        assert_eq!(req.cookie("SVPNCOOKIE"), Some("abc"));
        assert_eq!(req.form("u").as_deref(), Some("bob"));
    }
}
