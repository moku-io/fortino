//! TLS to the gateway and one-request-per-connection HTTP, as FortiClient's login does
//!.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fortino_config::Host;
use fortino_proto_sslvpn::http::{self, Parsed, Request, Response};
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::Failure;

/// How to verify the gateway.
#[derive(Debug, Clone)]
pub enum Trust {
    /// An administrator-provisioned PEM bundle.
    CaFile(std::path::PathBuf),
    /// DER certificates (tests).
    Roots(Vec<Vec<u8>>),
    /// Explicit SHA-256 pins of the gateway's leaf certificate. The
    /// chain and name are not checked, but the handshake signature still is. Set only by an
    /// administrator for a gateway whose certificate does not match its configured address.
    Pinned(Vec<[u8; 32]>),
}

/// Parses a SHA-256 pin written as hex, with or without `:` separators.
pub fn parse_pin(s: &str) -> Option<[u8; 32]> {
    let hex: String = s.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// SHA-256 of a certificate, as lower-case hex.
pub fn fingerprint(der: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Accepts exactly the pinned leaf certificates.
#[derive(Debug)]
struct PinVerifier {
    pins: Vec<[u8; 32]>,
    algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        use sha2::Digest;
        let got: [u8; 32] = sha2::Sha256::digest(end_entity.as_ref()).into();
        if self.pins.contains(&got) {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Fetches the gateway's leaf certificate without trusting it, so an administrator can
/// decide whether to pin it. Sends nothing but the TLS handshake.
pub async fn fetch_leaf(addr: SocketAddr, name: &Host) -> Result<Vec<u8>, Failure> {
    #[derive(Debug)]
    struct Grab(
        std::sync::Mutex<Option<Vec<u8>>>,
        rustls::crypto::WebPkiSupportedAlgorithms,
    );
    impl rustls::client::danger::ServerCertVerifier for Grab {
        fn verify_server_cert(
            &self,
            ee: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls_pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            if let Ok(mut g) = self.0.lock() {
                *g = Some(ee.to_vec());
            }
            // Never complete the handshake.
            Err(rustls::Error::General("certificate captured".into()))
        }
        fn verify_tls12_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(m, c, d, &self.1)
        }
        fn verify_tls13_signature(
            &self,
            m: &[u8],
            c: &CertificateDer<'_>,
            d: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(m, c, d, &self.1)
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.1.supported_schemes()
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let grab = Arc::new(Grab(
        std::sync::Mutex::new(None),
        provider.signature_verification_algorithms,
    ));
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Failure::Backend(format!("tls config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(grab.clone())
        .with_no_client_auth();
    let tcp = TcpStream::connect(addr)
        .await
        .map_err(|e| Failure::Transport(format!("connect: {e}")))?;
    let sn = server_name(name)?;
    let _ = TlsConnector::from(Arc::new(cfg)).connect(sn, tcp).await;
    let got = grab.0.lock().ok().and_then(|g| g.clone());
    got.ok_or_else(|| Failure::Transport("no certificate received".into()))
}

/// The TLS server name for a configured host.
pub fn server_name(host: &Host) -> Result<ServerName<'static>, Failure> {
    match host {
        Host::Dns(n) => ServerName::try_from(n.clone())
            .map_err(|_| Failure::Trust("invalid gateway name".into())),
        Host::Ipv4(ip) => Ok(ServerName::IpAddress(IpAddr::V4(*ip).into())),
    }
}

/// A TLS client configuration for `trust`. Also used for the EMS connection.
pub fn client_config(trust: &Trust) -> Result<rustls::ClientConfig, Failure> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let algs = provider.signature_verification_algorithms;
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Failure::Backend(format!("tls config: {e}")))?;
    Ok(match trust {
        Trust::Pinned(pins) if pins.is_empty() => {
            return Err(Failure::Trust("no certificate pins configured".into()));
        }
        Trust::Pinned(pins) => builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinVerifier {
                pins: pins.clone(),
                algs,
            }))
            .with_no_client_auth(),
        _ => builder
            .with_root_certificates(load_roots(trust)?)
            .with_no_client_auth(),
    })
}

/// Where and how to connect.
pub struct Gateway {
    /// Configured host (SNI and certificate name).
    pub host: Host,
    /// Port.
    pub port: u16,
    /// Connect here instead of resolving `host` (tests).
    pub connect_override: Option<SocketAddr>,
    tls: TlsConnector,
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

fn load_roots(trust: &Trust) -> Result<RootCertStore, Failure> {
    let mut roots = RootCertStore::empty();
    let certs: Vec<CertificateDer<'static>> = match trust {
        Trust::CaFile(p) => read_pem(p)?,
        Trust::Roots(v) => v.iter().map(|d| CertificateDer::from(d.clone())).collect(),
        Trust::Pinned(_) => return Ok(roots),
    };
    let (added, _ignored) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err(Failure::Trust("no usable CA certificates".into()));
    }
    Ok(roots)
}

fn read_pem(p: &Path) -> Result<Vec<CertificateDer<'static>>, Failure> {
    CertificateDer::pem_file_iter(p)
        .map_err(|e| Failure::Trust(format!("CA bundle: {e}")))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Failure::Trust(format!("CA bundle: {e}")))
}

impl Gateway {
    /// Builds the TLS client. The trust store must load before anything is sent.
    pub fn new(host: Host, port: u16, trust: &Trust) -> Result<Self, Failure> {
        let cfg = client_config(trust)?;
        Ok(Self {
            host,
            port,
            connect_override: None,
            keep_alive: false,
            conn: None,
            tls: TlsConnector::from(Arc::new(cfg)),
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
        let tcp = tokio::time::timeout(self.timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| Failure::Transport("connect timed out".into()))?
            .map_err(|e| Failure::Transport(format!("connect: {e}")))?;
        let _ = tcp.set_nodelay(true);
        if self.resolved.is_none() {
            self.resolved = tcp.peer_addr().ok();
        }
        let name = server_name(&self.host)?;
        tokio::time::timeout(self.timeout, self.tls.connect(name, tcp))
            .await
            .map_err(|_| Failure::Transport("TLS handshake timed out".into()))?
            .map_err(classify_tls)
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

fn classify_tls(e: std::io::Error) -> Failure {
    let cert = e
        .get_ref()
        .and_then(|i| i.downcast_ref::<rustls::Error>())
        .is_some_and(|r| {
            matches!(
                r,
                rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
            )
        });
    if cert {
        Failure::Trust(format!("gateway certificate: {e}"))
    } else {
        Failure::Transport(format!("TLS: {e}"))
    }
}
