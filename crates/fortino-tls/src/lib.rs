//! TLS trust shared by the SSL VPN worker and the EMS agent: CA bundles, explicit SHA-256
//! leaf pins, and the rustls client configuration built from them.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use fortino_config::Host;
use rustls::RootCertStore;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

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
}

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
