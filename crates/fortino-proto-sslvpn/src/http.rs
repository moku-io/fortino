//! HTTP/1.1 for the login phase. Requests keep headers in exactly the order given, because the
//! gateway may fingerprint them. Responses are parsed incrementally with hard limits,
//! since everything a gateway sends is untrusted.

use std::fmt::Write as _;

use zeroize::Zeroizing;

/// Largest header block accepted from a gateway.
pub const MAX_HEADER: usize = 32 * 1024;
/// Largest response body accepted from a gateway.
pub const MAX_BODY: usize = 1024 * 1024;
/// Most headers accepted in one response.
pub const MAX_HEADERS: usize = 128;

/// Response parsing errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HttpError {
    /// The response violated HTTP/1.1 framing.
    #[error("malformed HTTP response: {0}")]
    Malformed(&'static str),
    /// The response exceeded a limit.
    #[error("HTTP response too large: {0}")]
    TooLarge(&'static str),
    /// The connection closed before the response was complete.
    #[error("connection closed mid-response")]
    Truncated,
}

/// An HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `GET` or `POST`.
    pub method: &'static str,
    /// Request target (path and query).
    pub target: String,
    /// Headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Body (empty for GET). Wiped on drop: login forms carry credentials.
    pub body: Zeroizing<Vec<u8>>,
}

impl Request {
    /// Serializes the request. The result may carry credentials and is wiped on drop.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut head = String::with_capacity(256);
        let _ = write!(head, "{} {} HTTP/1.1\r\n", self.method, self.target);
        for (k, v) in &self.headers {
            let _ = write!(head, "{k}: {v}\r\n");
        }
        head.push_str("\r\n");
        let mut out = Zeroizing::new(Vec::with_capacity(head.len() + self.body.len()));
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(&self.body);
        out
    }

    /// The first header with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }
}

/// A parsed HTTP response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Decoded body (chunked encoding removed).
    pub body: Vec<u8>,
}

impl Response {
    /// The first header with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        find_header(&self.headers, name)
    }

    /// Cookies set by this response, as `(name, value)`, in order. Attributes are dropped.
    pub fn set_cookies(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
            .filter_map(|(_, v)| {
                let pair = v.split(';').next()?;
                let (n, val) = pair.split_once('=')?;
                Some((n.trim(), val.trim()))
            })
    }

    /// The last value this response set for cookie `name` (possibly empty, which clears it).
    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.set_cookies()
            .filter(|(n, _)| *n == name)
            .map(|(_, v)| v)
            .last()
    }

    /// The body as text (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

fn find_header<'a>(h: &'a [(String, String)], name: &str) -> Option<&'a str> {
    h.iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Result of feeding bytes to [`parse_response`].
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// More bytes are needed.
    Incomplete,
    /// A complete response, and how many input bytes it used.
    Done(Response, usize),
}

/// Parses one response from `buf`. `eof` says the peer has closed the connection, which ends a
/// body that has neither `Content-Length` nor chunked encoding. Interim answers (`1xx`, such as
/// a `100 Continue` a front end sends unasked) are skipped: the final answer follows them.
pub fn parse_response(buf: &[u8], eof: bool) -> Result<Parsed, HttpError> {
    let mut skipped = 0;
    loop {
        match parse_one(&buf[skipped..], eof)? {
            Parsed::Done(r, used) if (100..200).contains(&r.status) && r.status != 101 => {
                skipped += used;
            }
            Parsed::Done(r, used) => return Ok(Parsed::Done(r, skipped + used)),
            Parsed::Incomplete => return Ok(Parsed::Incomplete),
        }
    }
}

fn parse_one(buf: &[u8], eof: bool) -> Result<Parsed, HttpError> {
    let Some(head_end) = find(buf, b"\r\n\r\n") else {
        if buf.len() > MAX_HEADER {
            return Err(HttpError::TooLarge("header"));
        }
        return if eof {
            Err(HttpError::Truncated)
        } else {
            Ok(Parsed::Incomplete)
        };
    };
    if head_end > MAX_HEADER {
        return Err(HttpError::TooLarge("header"));
    }
    let head = std::str::from_utf8(&buf[..head_end])
        .map_err(|_| HttpError::Malformed("non-UTF-8 header"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or(HttpError::Malformed("empty"))?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(HttpError::Malformed("status line"));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .filter(|s| (100..=999).contains(s))
        .ok_or(HttpError::Malformed("status code"))?;
    let mut headers = Vec::new();
    for l in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(HttpError::TooLarge("header count"));
        }
        let (k, v) = l.split_once(':').ok_or(HttpError::Malformed("header"))?;
        if k.is_empty() || k.bytes().any(|b| b == b' ' || b == b'\t') {
            return Err(HttpError::Malformed("header name"));
        }
        headers.push((k.to_owned(), v.trim().to_owned()));
    }
    let body_start = head_end + 4;
    let rest = &buf[body_start..];
    let mut resp = Response {
        status,
        headers,
        body: Vec::new(),
    };

    let chunked = resp
        .header("transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
    if chunked {
        return match dechunk(rest)? {
            Some((body, used)) => {
                resp.body = body;
                Ok(Parsed::Done(resp, body_start + used))
            }
            None if eof => Err(HttpError::Truncated),
            None => Ok(Parsed::Incomplete),
        };
    }
    let no_body = status == 204 || status == 304 || (100..200).contains(&status);
    if no_body {
        return Ok(Parsed::Done(resp, body_start));
    }
    if let Some(cl) = resp.header("content-length") {
        let n: usize = cl
            .parse()
            .map_err(|_| HttpError::Malformed("content-length"))?;
        if n > MAX_BODY {
            return Err(HttpError::TooLarge("body"));
        }
        if rest.len() < n {
            return if eof {
                Err(HttpError::Truncated)
            } else {
                Ok(Parsed::Incomplete)
            };
        }
        resp.body = rest[..n].to_vec();
        return Ok(Parsed::Done(resp, body_start + n));
    }
    if rest.len() > MAX_BODY {
        return Err(HttpError::TooLarge("body"));
    }
    if eof {
        resp.body = rest.to_vec();
        Ok(Parsed::Done(resp, buf.len()))
    } else {
        Ok(Parsed::Incomplete)
    }
}

/// Decodes a chunked body. Returns `None` while incomplete.
fn dechunk(mut b: &[u8]) -> Result<Option<(Vec<u8>, usize)>, HttpError> {
    let start = b.len();
    let mut body = Vec::new();
    loop {
        let Some(eol) = find(b, b"\r\n") else {
            if b.len() > 1024 {
                return Err(HttpError::Malformed("chunk size line"));
            }
            return Ok(None);
        };
        let line = std::str::from_utf8(&b[..eol]).map_err(|_| HttpError::Malformed("chunk"))?;
        let size_hex = line.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_hex, 16).map_err(|_| HttpError::Malformed("chunk size"))?;
        b = &b[eol + 2..];
        if size == 0 {
            // Skip trailers up to the blank line; they are headers and get the same limit.
            let trailers = b.len();
            loop {
                if trailers - b.len() > MAX_HEADER {
                    return Err(HttpError::TooLarge("trailer"));
                }
                let Some(e) = find(b, b"\r\n") else {
                    if b.len() > MAX_HEADER {
                        return Err(HttpError::TooLarge("trailer"));
                    }
                    return Ok(None);
                };
                let blank = e == 0;
                b = &b[e + 2..];
                if blank {
                    return Ok(Some((body, start - b.len())));
                }
            }
        }
        if body.len().saturating_add(size) > MAX_BODY {
            return Err(HttpError::TooLarge("body"));
        }
        if b.len() < size + 2 {
            return Ok(None);
        }
        body.extend_from_slice(&b[..size]);
        if &b[size..size + 2] != b"\r\n" {
            return Err(HttpError::Malformed("chunk terminator"));
        }
        b = &b[size + 2..];
    }
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(b: &[u8], eof: bool) -> (Response, usize) {
        match parse_response(b, eof).unwrap() {
            Parsed::Done(r, n) => (r, n),
            Parsed::Incomplete => panic!("incomplete"),
        }
    }

    #[test]
    fn content_length_and_cookies() {
        let raw = b"HTTP/1.1 200 OK\r\nSet-Cookie: SVPNCOOKIE=; path=/\r\nSet-Cookie: SVPNCOOKIE=abc; secure\r\nContent-Length: 5\r\n\r\nhelloEXTRA";
        let (r, n) = done(raw, false);
        assert_eq!(r.status, 200);
        assert_eq!(r.body, b"hello");
        assert_eq!(n, raw.len() - 5);
        assert_eq!(r.cookie("SVPNCOOKIE"), Some("abc"));
        assert_eq!(r.cookie("missing"), None);
    }

    #[test]
    fn incremental() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        for i in 0..raw.len() {
            assert_eq!(
                parse_response(&raw[..i], false).unwrap(),
                Parsed::Incomplete
            );
        }
        assert!(parse_response(&raw[..raw.len() - 1], true).is_err());
    }

    #[test]
    fn interim_answers_are_skipped() {
        let raw = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        let (r, n) = done(raw, false);
        assert_eq!(
            (r.status, r.body.as_slice(), n),
            (200, &b"ok"[..], raw.len())
        );
        assert_eq!(
            parse_response(b"HTTP/1.1 100 Continue\r\n\r\n", false),
            Ok(Parsed::Incomplete)
        );
    }

    #[test]
    fn endless_trailers_are_refused() {
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        for _ in 0..4096 {
            raw.extend_from_slice(b"X-Trailer: aaaaaaaaaaaaaaaa\r\n");
        }
        assert!(matches!(
            parse_response(&raw, false),
            Err(HttpError::TooLarge(_))
        ));
        let mut open = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        open.extend(std::iter::repeat_n(b'a', MAX_HEADER + 1));
        assert!(matches!(
            parse_response(&open, false),
            Err(HttpError::TooLarge(_))
        ));
    }

    #[test]
    fn chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\n\r\n";
        let (r, n) = done(raw, false);
        assert_eq!(r.body, b"abcde");
        assert_eq!(n, raw.len());
        assert_eq!(
            parse_response(&raw[..raw.len() - 2], false).unwrap(),
            Parsed::Incomplete
        );
    }

    #[test]
    fn read_to_close() {
        let raw = b"HTTP/1.0 403 Forbidden\r\n\r\n<html>no</html>";
        assert_eq!(parse_response(raw, false).unwrap(), Parsed::Incomplete);
        let (r, _) = done(raw, true);
        assert_eq!(r.status, 403);
        assert_eq!(r.text(), "<html>no</html>");
    }

    #[test]
    fn rejects_garbage_and_oversize() {
        assert!(parse_response(b"SSH-2.0-x\r\n\r\n", false).is_err());
        assert!(parse_response(b"HTTP/1.1 abc OK\r\n\r\n", false).is_err());
        let big = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(parse_response(big.as_bytes(), false).is_err());
        let long = vec![b'a'; MAX_HEADER + 1];
        assert!(parse_response(&long, false).is_err());
    }

    #[test]
    fn request_keeps_header_order() {
        let r = Request {
            method: "GET",
            target: "/remote/info".into(),
            headers: vec![("B".into(), "1".into()), ("A".into(), "2".into())],
            body: Zeroizing::default(),
        };
        assert_eq!(
            *r.encode(),
            b"GET /remote/info HTTP/1.1\r\nB: 1\r\nA: 2\r\n\r\n".to_vec()
        );
    }

    proptest::proptest! {
        #[test]
        fn never_panics(data: Vec<u8>, eof: bool) {
            let _ = parse_response(&data, eof);
        }

        /// Shaped like a real answer, so the header, length, chunk and trailer handling run;
        /// cut anywhere, as reads arrive.
        #[test]
        fn never_panics_on_shaped_answers(
            status in 100u16..600,
            headers in proptest::collection::vec(
                ("(Content-Length|Transfer-Encoding|Set-Cookie|Location|[A-Za-z-]{1,12})",
                 "(chunked|[0-9]{1,6}|[ -~]{0,20})"),
                0..6,
            ),
            chunks in proptest::collection::vec(("[0-9a-fA-F]{1,4}", "[ -~]{0,40}"), 0..4),
            trailer in "[ -~]{0,30}",
            cut in 0usize..400,
            eof: bool,
        ) {
            let mut raw = format!("HTTP/1.1 {status} X\r\n");
            for (k, v) in &headers {
                raw.push_str(&format!("{k}: {v}\r\n"));
            }
            raw.push_str("\r\n");
            for (size, data) in &chunks {
                raw.push_str(&format!("{size}\r\n{data}\r\n"));
            }
            raw.push_str(&format!("0\r\n{trailer}\r\n\r\n"));
            let b = raw.as_bytes();
            let _ = parse_response(&b[..cut.min(b.len())], eof);
            let _ = parse_response(b, eof);
        }
    }
}
