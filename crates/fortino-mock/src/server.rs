//! Generic TLS server with pluggable route handlers.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use rustls::server::WebPkiClientVerifier;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;

use crate::http::{Request, Response, read_request};

/// The TLS stream handed to a takeover handler.
pub type MockStream = BufReader<tokio_rustls::server::TlsStream<TcpStream>>;

/// Boxed future.
pub type BoxFut = Pin<Box<dyn Future<Output = ()> + Send>>;

/// What a route returns.
pub enum Reply {
    /// Send this response and keep reading requests (unless the client closes).
    Http(Response),
    /// Hand the raw stream to a function (used for tunnel endpoints).
    Takeover(Box<dyn FnOnce(MockStream, Request) -> BoxFut + Send>),
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http(r) => f.debug_tuple("Http").field(r).finish(),
            Self::Takeover(_) => f.write_str("Takeover"),
        }
    }
}

impl From<Response> for Reply {
    fn from(r: Response) -> Self {
        Self::Http(r)
    }
}

/// A route handler.
pub type Handler = Arc<dyn Fn(&Request) -> Reply + Send + Sync>;

/// Maps `(method, path)` to handlers.
#[derive(Clone, Default)]
pub struct Router {
    routes: Vec<(String, String, Handler)>,
}

impl std::fmt::Debug for Router {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r: Vec<_> = self
            .routes
            .iter()
            .map(|(m, p, _)| format!("{m} {p}"))
            .collect();
        f.debug_struct("Router").field("routes", &r).finish()
    }
}

impl Router {
    /// Empty router.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a route. Later routes with the same method and path win.
    pub fn route<F>(mut self, method: &str, path: &str, f: F) -> Self
    where
        F: Fn(&Request) -> Reply + Send + Sync + 'static,
    {
        self.routes
            .insert(0, (method.into(), path.into(), Arc::new(f)));
        self
    }

    fn dispatch(&self, req: &Request) -> Reply {
        let mut path_matched = false;
        for (m, p, h) in &self.routes {
            if *p == req.path {
                path_matched = true;
                if m.eq_ignore_ascii_case(&req.method) {
                    return h(req);
                }
            }
        }
        Reply::Http(Response::status(if path_matched { 405 } else { 404 }))
    }
}

/// TLS options for a mock server.
#[derive(Debug, Clone, Default)]
pub struct TlsOptions {
    /// Send a CertificateRequest with no CA names and accept clients without a certificate
    /// (what GATEWAY-2 does).
    pub request_optional_client_cert: bool,
    /// Only offer TLS 1.3.
    pub tls13_only: bool,
}

/// A running mock server.
#[derive(Debug)]
pub struct MockHandle {
    /// Listening address.
    pub addr: SocketAddr,
    /// SHA-256 of the server leaf certificate (DER), lower-case hex.
    pub cert_sha256: String,
    /// DER of the server leaf certificate (to add as a trusted root in tests).
    pub cert_der: Vec<u8>,
    shutdown: watch::Sender<bool>,
}

impl MockHandle {
    /// Stops accepting connections.
    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }
}

impl Drop for MockHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Mock setup errors.
#[derive(Debug, thiserror::Error)]
pub enum MockError {
    /// I/O.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// TLS config.
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    /// Certificate generation.
    #[error("cert: {0}")]
    Cert(#[from] rcgen::Error),
    /// Other.
    #[error("{0}")]
    Other(String),
}

fn tls_config(
    opts: &TlsOptions,
    names: Vec<String>,
) -> Result<(rustls::ServerConfig, Vec<u8>), MockError> {
    let ck = rcgen::generate_simple_self_signed(names)?;
    let cert_der = ck.cert.der().to_vec();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if opts.tls13_only {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)?;
    let builder = if opts.request_optional_client_cert {
        // A throwaway CA nobody holds a cert for; with no CA hints sent, like GATEWAY-2.
        let ca = rcgen::generate_simple_self_signed(vec!["mock-client-ca".into()])?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(ca.cert.der().to_vec()))?;
        let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .allow_unauthenticated()
            .clear_root_hint_subjects()
            .build()
            .map_err(|e| MockError::Other(e.to_string()))?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let cfg = builder.with_single_cert(vec![CertificateDer::from(cert_der.clone())], key)?;
    Ok((cfg, cert_der))
}

/// Starts a TLS server on 127.0.0.1 (random port) serving `router`. The certificate is
/// self-signed for `localhost` and `sslvpn.test`.
pub async fn start(router: Router, opts: TlsOptions) -> Result<MockHandle, MockError> {
    start_on(
        router,
        opts,
        "127.0.0.1:0"
            .parse()
            .map_err(|_| MockError::Other("addr".into()))?,
    )
    .await
}

/// Like [`start`], listening on `bind` (port 0 picks one).
pub async fn start_on(
    router: Router,
    opts: TlsOptions,
    bind: std::net::SocketAddr,
) -> Result<MockHandle, MockError> {
    let router = Arc::new(router);
    let names = vec!["localhost".into(), "sslvpn.test".into()];
    start_raw(opts, names, bind, move |tls| {
        let router = router.clone();
        Box::pin(async move { serve(BufReader::new(tls), &router).await })
    })
    .await
}

/// The TLS stream handed to a raw handler.
pub type RawStream = tokio_rustls::server::TlsStream<TcpStream>;

/// Starts a TLS server whose connections go straight to `handler`, for protocols that are not
/// HTTP (the mock EMS). The certificate is self-signed for `names`.
pub async fn start_raw<F>(
    opts: TlsOptions,
    names: Vec<String>,
    bind: std::net::SocketAddr,
    handler: F,
) -> Result<MockHandle, MockError>
where
    F: Fn(RawStream) -> BoxFut + Send + Sync + 'static,
{
    let (cfg, cert_der) = tls_config(&opts, names)?;
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind(bind).await?;
    let addr = listener.local_addr()?;
    let (tx, mut rx) = watch::channel(false);
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = rx.changed() => break,
                acc = listener.accept() => {
                    let Ok((sock, peer)) = acc else { continue };
                    let acceptor = acceptor.clone();
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        match acceptor.accept(sock).await {
                            Ok(tls) => handler(tls).await,
                            Err(e) => tracing::debug!(%peer, error = %e, "mock tls accept failed"),
                        }
                    });
                }
            }
        }
    });
    Ok(MockHandle {
        addr,
        cert_sha256: hex::encode(Sha256::digest(&cert_der)),
        cert_der,
        shutdown: tx,
    })
}

async fn serve(mut s: MockStream, router: &Router) {
    loop {
        let req = match read_request(&mut s).await {
            Ok(Some(r)) => r,
            Ok(None) => return,
            Err(e) => {
                tracing::debug!(error = %e, "mock: bad request");
                let _ = Response::status(400).write_to(&mut s).await;
                return;
            }
        };
        let close = req
            .header("connection")
            .is_some_and(|c| c.eq_ignore_ascii_case("close"));
        match router.dispatch(&req) {
            Reply::Http(resp) => {
                if resp.write_to(&mut s).await.is_err() {
                    return;
                }
                if close {
                    let _ = s.get_mut().shutdown().await;
                    return;
                }
            }
            Reply::Takeover(f) => {
                f(s, req).await;
                return;
            }
        }
    }
}

/// Keeps the generic bound helpers in one place.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}
