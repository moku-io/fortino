//! A server that sends only its leaf certificate: the client fetches the missing intermediate
//! from the leaf's CA Issuers URL and verifies the completed chain against its roots.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fortino_tls::{Failure, TlsClient, Trust};
use rcgen::{BasicConstraints, CertificateParams, CustomExtension, IsCa, KeyPair};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const NAME: &str = "vpn.example.test";
const ISSUER_URL: &str = "http://ca.example.test/intermediate.crt";

/// DER TLV with a short or two-byte length.
fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
    let n = body.len();
    let mut v = vec![tag];
    if n < 0x80 {
        v.push(n as u8);
    } else {
        v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
    }
    v.extend_from_slice(body);
    v
}

fn aia(url: &str) -> CustomExtension {
    let ca_issuers = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];
    let mut desc = wrap(0x06, &ca_issuers);
    desc.extend(wrap(0x86, url.as_bytes()));
    CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], wrap(0x30, &wrap(0x30, &desc)))
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p
}

struct Pki {
    root: Vec<u8>,
    intermediate: Vec<u8>,
    leaf: Vec<u8>,
    leaf_key: Vec<u8>,
}

/// Root → intermediate → leaf; the leaf names `issuer_url` as its CA Issuers location.
fn pki(issuer_url: &str) -> Pki {
    let root_key = KeyPair::generate().unwrap();
    let root = ca_params("Example Root").self_signed(&root_key).unwrap();
    let int_key = KeyPair::generate().unwrap();
    let int = ca_params("Example Intermediate")
        .signed_by(&int_key, &root, &root_key)
        .unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut lp = CertificateParams::new(vec![NAME.into()]).unwrap();
    lp.custom_extensions.push(aia(issuer_url));
    let leaf = lp.signed_by(&leaf_key, &int, &int_key).unwrap();
    Pki {
        root: root.der().to_vec(),
        intermediate: int.der().to_vec(),
        leaf: leaf.der().to_vec(),
        leaf_key: leaf_key.serialize_der(),
    }
}

/// A TLS server presenting `chain`, answering every connection until dropped.
async fn tls_server(chain: Vec<Vec<u8>>, key: Vec<u8>) -> SocketAddr {
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        chain.into_iter().map(CertificateDer::from).collect(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let a = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut t) = a.accept(s).await {
                    let _ = t.write_all(b"ok").await;
                    let _ = t.shutdown().await;
                }
            });
        }
    });
    addr
}

/// An HTTP server answering every request with `status` and `body`; counts requests.
async fn http_server(
    status: &'static str,
    body: Vec<u8>,
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            log.lock().unwrap().push(req);
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/pkix-cert\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
        }
    });
    (addr, seen)
}

async fn connect(client: &TlsClient, addr: SocketAddr) -> Result<(), Failure> {
    let name = ServerName::try_from(NAME.to_owned()).unwrap();
    let mut s = client
        .connect(addr, &name, Duration::from_secs(5), "gateway certificate")
        .await?;
    let mut got = Vec::new();
    let _ = s.read_to_end(&mut got).await;
    assert_eq!(got, b"ok");
    Ok(())
}

#[tokio::test]
async fn fetches_the_missing_intermediate_once() {
    let p = pki(ISSUER_URL);
    let gw = tls_server(vec![p.leaf.clone()], p.leaf_key.clone()).await;
    let (http, seen) = http_server("200 OK", p.intermediate.clone()).await;

    let mut client = TlsClient::new(&Trust::Roots(vec![p.root.clone()])).unwrap();
    client.issuer_fetch_override = Some(http);
    connect(&client, gw).await.unwrap();
    // Later connections reuse the fetched certificate.
    connect(&client, gw).await.unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].starts_with("GET /intermediate.crt HTTP/1.0\r\n"));
    assert!(seen[0].contains("\r\nHost: ca.example.test\r\n"));
}

#[tokio::test]
async fn a_complete_chain_needs_no_fetch() {
    let p = pki(ISSUER_URL);
    let gw = tls_server(
        vec![p.leaf.clone(), p.intermediate.clone()],
        p.leaf_key.clone(),
    )
    .await;
    let (http, seen) = http_server("200 OK", p.intermediate.clone()).await;
    let mut client = TlsClient::new(&Trust::Roots(vec![p.root.clone()])).unwrap();
    client.issuer_fetch_override = Some(http);
    connect(&client, gw).await.unwrap();
    assert!(seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_failed_fetch_reports_the_trust_error() {
    let p = pki(ISSUER_URL);
    let gw = tls_server(vec![p.leaf.clone()], p.leaf_key.clone()).await;
    let (http, _) = http_server("404 Not Found", Vec::new()).await;
    let mut client = TlsClient::new(&Trust::Roots(vec![p.root.clone()])).unwrap();
    client.issuer_fetch_override = Some(http);
    match connect(&client, gw).await {
        Err(Failure::Trust(m)) => assert!(m.contains("UnknownIssuer"), "{m}"),
        other => panic!("expected a trust failure, got {other:?}"),
    }
}

#[tokio::test]
async fn a_fetched_certificate_is_never_a_trust_anchor() {
    // The client trusts an unrelated root; the fetched intermediate chains to a root it does
    // not know, so the server stays untrusted.
    let p = pki(ISSUER_URL);
    let other = pki(ISSUER_URL);
    let gw = tls_server(vec![p.leaf.clone()], p.leaf_key.clone()).await;
    let (http, seen) = http_server("200 OK", p.intermediate.clone()).await;
    let mut client = TlsClient::new(&Trust::Roots(vec![other.root.clone()])).unwrap();
    client.issuer_fetch_override = Some(http);
    assert!(matches!(connect(&client, gw).await, Err(Failure::Trust(_))));
    // Each URL is tried once, not on every retry.
    assert_eq!(seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn pinned_trust_never_fetches() {
    let p = pki(ISSUER_URL);
    let gw = tls_server(vec![p.leaf.clone()], p.leaf_key.clone()).await;
    let (http, seen) = http_server("200 OK", p.intermediate.clone()).await;
    let pin: [u8; 32] = fortino_tls::parse_pin(&fortino_tls::fingerprint(&p.leaf)).unwrap();
    let mut client = TlsClient::new(&Trust::Pinned(vec![pin])).unwrap();
    client.issuer_fetch_override = Some(http);
    connect(&client, gw).await.unwrap();
    assert!(seen.lock().unwrap().is_empty());
}
