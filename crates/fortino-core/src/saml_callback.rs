//! The local listener a single sign-on ends at.
//!
//! After the sign-in the gateway redirects the user's browser to
//! `http://127.0.0.1:<port>/?id=…`. A client listens there while the challenge is outstanding,
//! answers the browser with a fixed page and hands the request's query string to the attempt.
//! It binds the loopback address only, never echoes what it receives and keeps nothing but the
//! first valid callback.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use fortino_proto_sslvpn::saml::{self, Callback, MAX_REQUEST_HEAD};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use zeroize::Zeroizing;

/// How long one connection may take to send its request and read the answer.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// Connections served at once; more are closed unanswered.
const MAX_CONNECTIONS: usize = 16;

/// What the browser shows once the callback has arrived.
const DONE_PAGE: &str = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width\"><title>Fortino</title></head>\
<body style=\"font: 15px -apple-system, system-ui, sans-serif; margin: 3em; line-height: 1.4\">\
<h1 style=\"font-size: 1.3em\">Signed in</h1>\
<p>Fortino is finishing the connection. You can close this tab.</p></body></html>";

/// A listener on `127.0.0.1` for one single sign-on.
#[derive(Debug)]
pub struct CallbackListener {
    listener: TcpListener,
    port: u16,
}

impl CallbackListener {
    /// Listens on `127.0.0.1:port`. Port 0 picks a free port (tests).
    pub async fn bind(port: u16) -> io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
        let port = listener.local_addr()?.port();
        Ok(Self { listener, port })
    }

    /// The port listened on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Waits for the gateway's redirect and returns its query string (`id=…`). Other requests
    /// are answered with 404 or 400 and ignored. Connections are served concurrently, so an idle
    /// one can't hold up the callback.
    pub async fn next_login(&self) -> io::Result<Zeroizing<String>> {
        let (tx, mut rx) = mpsc::channel::<Zeroizing<String>>(1);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                accepted = self.listener.accept() => {
                    let (stream, _) = accepted?;
                    if tasks.len() >= MAX_CONNECTIONS {
                        continue;
                    }
                    let (tx, port) = (tx.clone(), self.port);
                    tasks.spawn(async move {
                        if let Ok(Some(q)) =
                            tokio::time::timeout(CONNECTION_TIMEOUT, serve(stream, port)).await
                        {
                            let _ = tx.try_send(q);
                        }
                    });
                }
                Some(q) = rx.recv() => return Ok(q),
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
    }
}

/// Reads one request head and answers it. Returns the query string of a login.
async fn serve(mut s: TcpStream, port: u16) -> Option<Zeroizing<String>> {
    let Ok(Some(head)) = read_head(&mut s).await else {
        let _ = respond(&mut s, "400 Bad Request", "").await;
        return None;
    };
    match saml::callback_request(&head, port) {
        Callback::Login(q) => {
            let _ = respond(&mut s, "200 OK", DONE_PAGE).await;
            Some(q)
        }
        Callback::NotFound => {
            let _ = respond(&mut s, "404 Not Found", "").await;
            None
        }
        Callback::Bad => {
            let _ = respond(&mut s, "400 Bad Request", "").await;
            None
        }
    }
}

/// Reads up to the blank line ending a request head, without it. `None` when the head doesn't
/// end within [`MAX_REQUEST_HEAD`] bytes or the peer closes first.
async fn read_head(s: &mut TcpStream) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_HEAD + 1024));
    let mut chunk = Zeroizing::new([0u8; 1024]);
    loop {
        let n = s.read(&mut chunk[..]).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = head_end(&buf) {
            buf.truncate(end);
            return Ok(Some(buf));
        }
        if buf.len() > MAX_REQUEST_HEAD {
            return Ok(None);
        }
    }
}

/// Where the blank line ending a request head starts.
fn head_end(b: &[u8]) -> Option<usize> {
    let crlf = b.windows(4).position(|w| w == b"\r\n\r\n");
    let lf = b.windows(2).position(|w| w == b"\n\n");
    match (crlf, lf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

async fn respond(s: &mut TcpStream, status: &str, body: &str) -> io::Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n\
         X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body.as_bytes()).await?;
    s.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn send(port: u16, request: &str) -> String {
        let mut s = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        out
    }

    #[tokio::test]
    async fn returns_the_first_login_and_answers_everything_else() {
        let l = CallbackListener::bind(0).await.unwrap();
        let port = l.port();
        let client = tokio::spawn(async move {
            // An idle connection must not hold up the others.
            let _idle = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .unwrap();
            let favicon = send(
                port,
                &format!("GET /favicon.ico HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
            )
            .await;
            assert!(favicon.starts_with("HTTP/1.1 404"), "{favicon}");
            let rebound = send(
                port,
                &format!("GET /?id=x1 HTTP/1.1\r\nHost: evil.example:{port}\r\n\r\n"),
            )
            .await;
            assert!(rebound.starts_with("HTTP/1.1 400"), "{rebound}");
            let page = send(
                port,
                &format!("GET /?id=s3cret-1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"),
            )
            .await;
            assert!(page.starts_with("HTTP/1.1 200"), "{page}");
            assert!(page.contains("Signed in"));
            assert!(!page.contains("s3cret"), "the page must not echo the id");
        });
        let q = tokio::time::timeout(Duration::from_secs(5), l.next_login())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(q.as_str(), "id=s3cret-1");
        client.await.unwrap();
    }

    #[test]
    fn head_end_takes_the_first_blank_line() {
        assert_eq!(head_end(b"GET / HTTP/1.1\r\nA: b\r\n\r\nrest"), Some(20));
        assert_eq!(head_end(b"GET / HTTP/1.1\nA: b\n\nrest"), Some(19));
        assert_eq!(head_end(b"GET / HTTP/1.1\r\n"), None);
    }
}
