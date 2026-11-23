//! TLS to the gateway and one-request-per-connection HTTP, as FortiClient's login does
//! (each request on a new connection).

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use fortino_config::Host;
use fortino_proto_sslvpn::http::{self, Parsed, Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::Failure;

pub use fortino_tls::{
    TlsClient, Trust, client_config, fetch_leaf, fingerprint, parse_pin, server_name,
};

/// Where and how to connect.
pub struct Gateway {
    /// Configured host (SNI and certificate name).
    pub host: Host,
    /// Port.
    pub port: u16,
    /// Connect here instead of resolving `host` (tests).
    pub connect_override: Option<SocketAddr>,
    /// TLS client; completes a chain the gateway sent without its intermediates.
    pub tls: TlsClient,
    /// Address actually connected to, once known.
    pub resolved: Option<SocketAddr>,
    /// Per-request timeout.
    pub timeout: Duration,
    /// Reuse one TLS connection for the HTTP phase (`Connection: keep-alive`), as
    /// openfortivpn does. Some gateways sit behind a front end that does not share sessions
    /// across connections.
    pub keep_alive: bool,
    conn: Option<TlsStream<TcpStream>>,
}

impl std::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gateway")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("resolved", &self.resolved)
            .finish_non_exhaustive()
    }
}

impl Gateway {
    /// Builds the TLS client. The trust store must load before anything is sent.
    pub fn new(host: Host, port: u16, trust: &Trust) -> Result<Self, Failure> {
        Ok(Self {
            host,
            port,
            connect_override: None,
            keep_alive: false,
            conn: None,
            tls: TlsClient::new(trust)?,
            resolved: None,
            timeout: Duration::from_secs(30),
        })
    }

    async fn exchange_once(&mut self, req: &Request) -> Result<Response, Failure> {
        let mut s = match self.conn.take() {
            Some(s) => s,
            None => self.connect().await?,
        };
        let deadline = self.timeout;
        let fut = async {
            s.write_all(&req.encode())
                .await
                .map_err(|e| Failure::Transport(format!("send: {e}")))?;
            read_response(&mut s).await
        };
        let r = tokio::time::timeout(deadline, fut)
            .await
            .map_err(|_| Failure::Transport("gateway did not answer".into()))??;
        let server_closes = r
            .header("connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"));
        if self.keep_alive && !server_closes {
            self.conn = Some(s);
        }
        Ok(r)
    }

    /// Drops the kept-alive connection.
    pub fn close(&mut self) {
        self.conn = None;
    }

    /// The `Host` header value.
    // UNVERIFIED: whether FortiClient includes a non-default port.
    pub fn host_header(&self) -> String {
        if self.port == 443 {
            self.host.to_string()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    async fn resolve(&mut self) -> Result<SocketAddr, Failure> {
        if let Some(a) = self.connect_override.or(self.resolved) {
            return Ok(a);
        }
        let a = match &self.host {
            Host::Ipv4(ip) => SocketAddr::new(IpAddr::V4(*ip), self.port),
            Host::Dns(name) => tokio::net::lookup_host((name.as_str(), self.port))
                .await
                .map_err(|e| Failure::Transport(format!("resolve: {e}")))?
                .find(SocketAddr::is_ipv4)
                .ok_or_else(|| Failure::Transport("no IPv4 address for gateway".into()))?,
        };
        // Pin the address for the whole attempt, so the route the daemon keeps on the uplink
        // matches every later connection.
        self.resolved = Some(a);
        Ok(a)
    }

    /// Opens a verified TLS connection.
    pub async fn connect(&mut self) -> Result<TlsStream<TcpStream>, Failure> {
        let addr = self.resolve().await?;
        let name = server_name(&self.host)?;
        let s = self
            .tls
            .connect(addr, &name, self.timeout, "gateway certificate")
            .await?;
        if self.resolved.is_none() {
            self.resolved = s.get_ref().0.peer_addr().ok();
        }
        Ok(s)
    }

    /// Sends one request and reads the response: on a fresh connection, or on the kept-alive
    /// one (reconnecting once if the gateway closed it).
    pub async fn exchange(&mut self, req: &Request) -> Result<Response, Failure> {
        let mut req = req.clone();
        if self.keep_alive {
            for (k, v) in &mut req.headers {
                if k.eq_ignore_ascii_case("connection") {
                    *v = "keep-alive".into();
                }
            }
        }
        if tracing::enabled!(tracing::Level::TRACE) && req.method == "GET" {
            let head: Vec<String> = req
                .headers
                .iter()
                .map(|(k, v)| {
                    let secret = k.eq_ignore_ascii_case("cookie")
                        || k.to_ascii_uppercase().starts_with("FSV_")
                        || k.starts_with("EMSSN");
                    format!(
                        "{k}: {}",
                        if secret {
                            format!("<{} bytes>", v.len())
                        } else {
                            v.clone()
                        }
                    )
                })
                .collect();
            let path = req.target.split('?').next().unwrap_or("");
            tracing::trace!("request: {} {} | {}", req.method, path, head.join(" | "));
        }
        let reused = self.keep_alive && self.conn.is_some();
        let r = match self.exchange_once(&req).await {
            Err(Failure::Transport(_)) if reused => {
                self.conn = None;
                self.exchange_once(&req).await?
            }
            r => r?,
        };
        if tracing::enabled!(tracing::Level::DEBUG) {
            // Names only: cookie values, bodies and query strings can carry secrets.
            let cookies: Vec<String> = r
                .set_cookies()
                .map(|(n, v)| format!("{n}{}", if v.is_empty() { "=<cleared>" } else { "" }))
                .collect();
            let path = req.target.split('?').next().unwrap_or("");
            let body = r.text();
            let keys: Vec<&str> = if body.trim_start().starts_with("ret=") {
                body.split(',')
                    .filter_map(|p| p.split_once('=').map(|(k, _)| k))
                    .take(16)
                    .collect()
            } else {
                Vec::new()
            };
            let ret = body
                .trim_start()
                .strip_prefix("ret=")
                .and_then(|r| r.split(',').next())
                .unwrap_or("");
            let redir = body
                .split(',')
                .find_map(|p| p.strip_prefix("redir="))
                .map(|r| r.split('?').next().unwrap_or(""))
                .unwrap_or("");
            let loc = r
                .header("location")
                .map(|l| l.split('?').next().unwrap_or(""))
                .unwrap_or("");
            tracing::debug!(
                "{} {} -> {} set-cookie={:?} ret={} keys={:?} redir={} location={} body={}B",
                req.method,
                path,
                r.status,
                cookies,
                ret,
                keys,
                redir,
                loc,
                r.body.len()
            );
        }
        if tracing::enabled!(tracing::Level::TRACE) && r.body.len() <= 1024 {
            tracing::trace!("body: {}", mask_tokens(&r.text()));
        }
        Ok(r)
    }
}

/// Masks every run of 6+ token characters (cookies, IDs), for diagnostics.
fn mask_tokens(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut run = String::new();
    let flush = |run: &mut String, out: &mut String| {
        if run.len() >= 6 {
            out.push_str("<…>");
        } else {
            out.push_str(run);
        }
        run.clear();
    };
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '%' | '+' | '/' | '=') {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(if c.is_control() { ' ' } else { c });
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Reads one HTTP response from `s`.
pub async fn read_response<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
) -> Result<Response, Failure> {
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let n = match s.read(&mut chunk).await {
            Ok(n) => n,
            // A peer closing TLS without close_notify still ends the response.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(Failure::Transport(format!("receive: {e}"))),
        };
        buf.extend_from_slice(&chunk[..n]);
        match http::parse_response(&buf, n == 0) {
            Ok(Parsed::Done(r, _)) => return Ok(r),
            Ok(Parsed::Incomplete) if n == 0 => {
                return Err(Failure::Transport("connection closed".into()));
            }
            Ok(Parsed::Incomplete) => {}
            Err(e) => return Err(Failure::Backend(format!("gateway HTTP: {e}"))),
        }
    }
}
