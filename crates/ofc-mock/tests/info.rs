use std::sync::Arc;

use ofc_mock::fortigate::{self, Scenario};
use rustls_pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;

#[tokio::test]
async fn serves_remote_info() {
    let sc = Scenario::from_yaml(include_str!("../../../fixtures/mock/basic.yaml")).unwrap();
    let h = fortigate::start(&sc).await.unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(h.cert_der.clone())).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let mut tls = TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("sslvpn.test").unwrap(), tcp)
        .await
        .unwrap();
    tls.write_all(b"GET /remote/info HTTP/1.1\r\nHost: sslvpn.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    tls.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("remoteauthtimeout=\"600\""), "{out}");
}
