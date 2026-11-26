//! TLS trust shared by the SSL VPN worker and the EMS agent: CA bundles, explicit SHA-256
//! leaf pins, and the rustls client configuration built from them.

pub mod issuers;
#[cfg(unix)]
pub mod markers;

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fortino_config::Host;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

/// TLS setup errors.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    /// Certificate or trust configuration.
    #[error("{0}")]
    Trust(String),
    /// Network or TLS.
    #[error("{0}")]
    Transport(String),
    /// Local TLS configuration.
    #[error("{0}")]
    Backend(String),
    /// The gateway wants something this client doesn't do (a client certificate).
    #[error("{0}")]
    Unsupported(String),
}

/// How to verify the gateway.
#[derive(Debug, Clone)]
pub enum Trust {
    /// An administrator-provisioned PEM bundle.
    CaFile(std::path::PathBuf),
    /// DER certificates (tests).
    Roots(Vec<Vec<u8>>),
    /// Explicit SHA-256 pins of the gateway's leaf certificate (`trusted-cert`). The
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

/// Issuer certificates fetched per [`TlsClient`], at most.
const MAX_FETCHED: usize = 16;
/// Issuer URLs tried per [`TlsClient`], at most.
const MAX_TRIED: usize = 8;
/// Handshake retries after fetching issuers, per connection.
const MAX_FETCH_ROUNDS: usize = 3;
/// Longest wait for one missing intermediate certificate.
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest wait for all of them in one connect: a CA host that never answers must still end
/// the attempt as a trust failure, well before the daemon's progress deadline would end it as
/// a timeout.
const FETCH_BUDGET: Duration = Duration::from_secs(12);

/// The CA-bundle verifier, plus intermediate certificates fetched because the server left
/// them out (see [`issuers`]).
#[derive(Debug)]
struct CompletingVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    /// Fetched intermediates, offered alongside the ones the server sent.
    fetched: Mutex<Vec<CertificateDer<'static>>>,
    /// The chain of the last handshake that failed with an unknown issuer.
    unknown_issuer_chain: Mutex<Option<Vec<CertificateDer<'static>>>>,
    /// Issuer URLs already tried.
    tried: Mutex<Vec<String>>,
}

impl CompletingVerifier {
    /// After a handshake failed with an unknown issuer, fetches the issuer certificates named by
    /// that chain and by earlier fetched ones. True when a new certificate was added, so a retry
    /// can succeed.
    async fn fetch_missing(&self, timeout: Duration, connect_override: Option<SocketAddr>) -> bool {
        let Some(chain) = self
            .unknown_issuer_chain
            .lock()
            .ok()
            .and_then(|mut c| c.take())
        else {
            return false;
        };
        let fetched = self.fetched.lock().map(|f| f.clone()).unwrap_or_default();
        let mut urls: Vec<String> = Vec::new();
        for cert in chain.iter().chain(fetched.iter()) {
            for u in issuers::ca_issuer_urls(cert) {
                if !urls.contains(&u) {
                    urls.push(u);
                }
            }
        }
        let mut added = false;
        for url in urls {
            {
                let Ok(mut tried) = self.tried.lock() else {
                    return added;
                };
                if tried.contains(&url) || tried.len() >= MAX_TRIED {
                    continue;
                }
                tried.push(url.clone());
            }
            match issuers::fetch(&url, timeout, connect_override).await {
                Ok(certs) => {
                    let Ok(mut f) = self.fetched.lock() else {
                        return added;
                    };
                    let before = f.len();
                    for cert in certs {
                        if f.len() < MAX_FETCHED && !f.contains(&cert) && !chain.contains(&cert) {
                            f.push(cert);
                        }
                    }
                    let new = f.len().saturating_sub(before);
                    if new > 0 {
                        tracing::info!(
                            "server sent an incomplete certificate chain; fetched {new} issuing \
                             CA certificate(s) it names"
                        );
                        added = true;
                    }
                }
                Err(e) => {
                    tracing::info!("could not fetch the server's issuing CA certificate: {e}")
                }
            }
        }
        added
    }
}

impl rustls::client::danger::ServerCertVerifier for CompletingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: rustls_pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let fetched = self.fetched.lock().map(|f| f.clone()).unwrap_or_default();
        let result = if fetched.is_empty() {
            self.inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)
        } else {
            let mut all: Vec<CertificateDer<'_>> = intermediates.to_vec();
            all.extend(fetched);
            self.inner
                .verify_server_cert(end_entity, &all, server_name, ocsp, now)
        };
        if matches!(
            result,
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            ))
        ) && let Ok(mut c) = self.unknown_issuer_chain.lock()
        {
            *c = Some(
                std::iter::once(end_entity)
                    .chain(intermediates)
                    .map(|d| d.clone().into_owned())
                    .collect(),
            );
        }
        result
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// A TLS client for one server. With a CA trust it completes a chain the server sent without
/// its intermediate CA certificates, fetching them from the URL the certificates name
/// (Authority Information Access), as macOS and browsers do. Fetched certificates are kept for
/// later connections from the same client.
pub struct TlsClient {
    connector: TlsConnector,
    completer: Option<Arc<CompletingVerifier>>,
    /// Fetch issuer certificates from this address instead of the URL's host (tests).
    pub issuer_fetch_override: Option<SocketAddr>,
}

impl std::fmt::Debug for TlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsClient")
            .field("completes_chains", &self.completer.is_some())
            .finish_non_exhaustive()
    }
}

impl TlsClient {
    /// Builds the client; the trust store must load before anything is sent.
    pub fn new(trust: &Trust) -> Result<Self, Failure> {
        if let Trust::Pinned(_) = trust {
            return Ok(Self {
                connector: TlsConnector::from(Arc::new(client_config(trust)?)),
                completer: None,
                issuer_fetch_override: None,
            });
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(load_roots(trust)?),
            provider.clone(),
        )
        .build()
        .map_err(|e| Failure::Backend(format!("tls verifier: {e}")))?;
        let completer = Arc::new(CompletingVerifier {
            inner,
            fetched: Mutex::new(Vec::new()),
            unknown_issuer_chain: Mutex::new(None),
            tried: Mutex::new(Vec::new()),
        });
        let cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| Failure::Backend(format!("tls config: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(completer.clone())
            .with_no_client_auth();
        Ok(Self {
            connector: TlsConnector::from(Arc::new(cfg)),
            completer: Some(completer),
            issuer_fetch_override: None,
        })
    }

    /// Connects to `addr` and completes the handshake for `name`, each step within `timeout`.
    /// A certificate failure is reported as `Trust("<what>: …")`.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        name: &ServerName<'static>,
        timeout: Duration,
        what: &str,
    ) -> Result<TlsStream<TcpStream>, Failure> {
        let mut rounds = 0;
        let fetch_until = tokio::time::Instant::now() + FETCH_BUDGET;
        loop {
            let tcp = tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .map_err(|_| Failure::Transport("connect timed out".into()))?
                .map_err(|e| Failure::Transport(format!("connect: {e}")))?;
            let _ = tcp.set_nodelay(true);
            let e = match tokio::time::timeout(timeout, self.connector.connect(name.clone(), tcp))
                .await
                .map_err(|_| Failure::Transport("TLS handshake timed out".into()))?
            {
                Ok(s) => return Ok(s),
                Err(e) => classify(e, what),
            };
            let retry = match (&e, &self.completer) {
                (Failure::Trust(_), Some(c)) if rounds < MAX_FETCH_ROUNDS => {
                    let left = fetch_until.saturating_duration_since(tokio::time::Instant::now());
                    let fetch =
                        c.fetch_missing(left.min(FETCH_TIMEOUT), self.issuer_fetch_override);
                    tokio::time::timeout(left, fetch).await.unwrap_or(false)
                }
                _ => false,
            };
            if !retry {
                return Err(e);
            }
            rounds += 1;
        }
    }
}

/// Maps a handshake error: certificate problems to `Trust("<what>: …")`, the rest to
/// `Transport`.
pub fn classify(e: std::io::Error, what: &str) -> Failure {
    let cert = e
        .get_ref()
        .and_then(|i| i.downcast_ref::<rustls::Error>())
        .is_some_and(|r| {
            matches!(
                r,
                rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
            )
        });
    let client_cert = e
        .get_ref()
        .and_then(|i| i.downcast_ref::<rustls::Error>())
        .is_some_and(|r| {
            matches!(
                r,
                rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired)
            )
        });
    if cert {
        Failure::Trust(format!("{what}: {e}"))
    } else if client_cert {
        Failure::Unsupported("the gateway requires a client certificate".into())
    } else {
        Failure::Transport(format!("TLS: {e}"))
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
