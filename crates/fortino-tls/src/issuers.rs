//! Completing a certificate chain the server sent without its intermediate CA certificates.
//!
//! Some gateways present only their own certificate. macOS and browsers still verify them: they
//! download the missing issuer from the "CA Issuers" URL in the certificate's Authority
//! Information Access extension (RFC 5280 4.2.2.1). This module does the same: it reads that URL,
//! fetches the certificate over plain HTTP and hands it to the verifier as an extra
//! *intermediate*. Fetched certificates are never trust anchors; the chain must still end at a
//! configured root, so this cannot make an untrusted certificate trusted.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// id-pe-authorityInfoAccess (1.3.6.1.5.5.7.1.1), DER contents of the OID.
const AIA_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];
/// id-ad-caIssuers (1.3.6.1.5.5.7.48.2).
const CA_ISSUERS_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];

/// At most this many CA Issuers URLs are read from one certificate.
const MAX_URLS_PER_CERT: usize = 4;
/// Longest URL accepted.
const MAX_URL_LEN: usize = 512;
/// Largest HTTP response read (an intermediate certificate is about 2 KiB).
const MAX_RESPONSE: usize = 64 * 1024;
/// Longest HTTP response head.
const MAX_HEAD: usize = 8 * 1024;

/// One DER TLV: `(tag, contents, rest)`. Single-byte tags and definite lengths only.
fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    if tag & 0x1f == 0x1f {
        return None;
    }
    let (&first, mut rest) = rest.split_first()?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let (bytes, r) = rest.split_at_checked(n)?;
        rest = r;
        bytes.iter().try_fold(0usize, |a, b| {
            a.checked_mul(256)?.checked_add(usize::from(*b))
        })?
    };
    let (contents, rest) = rest.split_at_checked(len)?;
    Some((tag, contents, rest))
}

/// The first TLV of `input` if it has `tag`.
fn take_tlv(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    match tlv(input)? {
        (t, c, r) if t == tag => Some((c, r)),
        _ => None,
    }
}

/// The CA Issuers URLs in a DER certificate's Authority Information Access extension, in
/// order. Empty when the certificate has none or does not parse.
pub fn ca_issuer_urls(cert: &[u8]) -> Vec<String> {
    ca_issuer_urls_opt(cert).unwrap_or_default()
}

fn ca_issuer_urls_opt(cert: &[u8]) -> Option<Vec<String>> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE { ..., [3] EXPLICIT Extensions } ... }
    let (cert, _) = take_tlv(cert, 0x30)?;
    let (tbs, _) = take_tlv(cert, 0x30)?;
    let mut fields = tbs;
    let exts = loop {
        let (tag, contents, rest) = tlv(fields)?;
        if tag == 0xa3 {
            break contents;
        }
        fields = rest;
    };
    let (mut exts, _) = take_tlv(exts, 0x30)?;
    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
    while let Some((ext, rest)) = take_tlv(exts, 0x30) {
        exts = rest;
        let (oid, after) = take_tlv(ext, 0x06)?;
        if oid != AIA_OID {
            continue;
        }
        let after = match take_tlv(after, 0x01) {
            Some((_, r)) => r,
            None => after,
        };
        let (value, _) = take_tlv(after, 0x04)?;
        // AuthorityInfoAccessSyntax ::= SEQUENCE OF SEQUENCE { accessMethod OID, accessLocation GeneralName }
        let (mut descs, _) = take_tlv(value, 0x30)?;
        let mut urls = Vec::new();
        while let Some((desc, rest)) = take_tlv(descs, 0x30) {
            descs = rest;
            let Some((method, location)) = take_tlv(desc, 0x06) else {
                continue;
            };
            // uniformResourceIdentifier [6] IMPLICIT IA5String
            if method == CA_ISSUERS_OID
                && let Some((uri, _)) = take_tlv(location, 0x86)
                && uri.len() <= MAX_URL_LEN
                && let Ok(s) = std::str::from_utf8(uri)
                && urls.len() < MAX_URLS_PER_CERT
            {
                urls.push(s.to_owned());
            }
        }
        return Some(urls);
    }
    Some(Vec::new())
}

/// Whether `der` is shaped like an X.509 certificate (and not, say, a PKCS#7 bundle):
/// SEQUENCE { SEQUENCE, SEQUENCE, BIT STRING } filling the input exactly.
fn looks_like_certificate(der: &[u8]) -> bool {
    let shape = || -> Option<bool> {
        let (cert, rest) = take_tlv(der, 0x30)?;
        let (_, r) = take_tlv(cert, 0x30)?;
        let (_, r) = take_tlv(r, 0x30)?;
        let (_, r) = take_tlv(r, 0x03)?;
        Some(rest.is_empty() && r.is_empty())
    };
    shape().unwrap_or(false)
}

/// A host and path from an `http://` URL. Only port 80 is accepted, so a certificate cannot
/// point the client at arbitrary local services.
fn parse_http_url(url: &str) -> Option<(String, String)> {
    let scheme = url.get(..7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let rest = url.get(7..)?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest.get(..i)?, rest.get(i..)?),
        None => (rest, "/"),
    };
    let host = match authority.rsplit_once(':') {
        Some((h, "80")) => h,
        Some(_) => return None,
        None => authority,
    };
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let path_ok = path.bytes().all(|b| b.is_ascii_graphic());
    (host_ok && path_ok).then(|| (host.to_ascii_lowercase(), path.to_owned()))
}

/// Addresses an issuer fetch must not reach: this machine and link-local networks.
fn forbidden(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unicast_link_local()
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| forbidden(IpAddr::V4(v4)))
        }
    }
}

/// The body of a complete `200` HTTP/1.x response, or `None`. Chunked responses are refused
/// (the request is HTTP/1.0, so a server should not send one).
pub fn http_body(response: &[u8]) -> Option<&[u8]> {
    let head_end = response
        .get(..response.len().min(MAX_HEAD))?
        .windows(4)
        .position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(response.get(..head_end)?).ok()?;
    let body = response.get(head_end.checked_add(4)?..)?;
    let mut lines = head.split("\r\n");
    let mut status = lines.next()?.split(' ');
    if !status.next()?.starts_with("HTTP/1.") || status.next()? != "200" {
        return None;
    }
    let mut length = None;
    for line in lines {
        let (k, v) = line.split_once(':')?;
        let v = v.trim();
        if k.eq_ignore_ascii_case("transfer-encoding") && !v.eq_ignore_ascii_case("identity") {
            return None;
        }
        if k.eq_ignore_ascii_case("content-length") {
            length = Some(v.parse::<usize>().ok()?);
        }
    }
    match length {
        Some(n) => body.get(..n),
        None => Some(body),
    }
}

/// id-signedData (1.2.840.113549.1.7.2).
const SIGNED_DATA_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// At most this many certificates are taken from one download.
const MAX_CERTS_PER_DOWNLOAD: usize = 8;

/// The certificates in a PKCS#7 `SignedData` "certs-only" bundle (`.p7c`), as CAs publish for
/// a root with cross-signed variants.
fn pkcs7_certificates(der: &[u8]) -> Option<Vec<CertificateDer<'static>>> {
    // ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
    let (info, _) = take_tlv(der, 0x30)?;
    let (oid, rest) = take_tlv(info, 0x06)?;
    if oid != SIGNED_DATA_OID {
        return None;
    }
    let (content, _) = take_tlv(rest, 0xa0)?;
    // SignedData ::= SEQUENCE { version INTEGER, digestAlgorithms SET, encapContentInfo
    //   SEQUENCE, certificates [0] IMPLICIT SET OF Certificate OPTIONAL, ... }
    let (sd, _) = take_tlv(content, 0x30)?;
    let (_, r) = take_tlv(sd, 0x02)?;
    let (_, r) = take_tlv(r, 0x31)?;
    let (_, r) = take_tlv(r, 0x30)?;
    let (mut certs, _) = take_tlv(r, 0xa0)?;
    let mut out = Vec::new();
    while let Some((tag, _, rest)) = tlv(certs) {
        let whole = certs.get(..certs.len().checked_sub(rest.len())?)?;
        certs = rest;
        if tag == 0x30 && looks_like_certificate(whole) && out.len() < MAX_CERTS_PER_DOWNLOAD {
            out.push(CertificateDer::from(whole.to_vec()));
        }
    }
    Some(out)
}

/// The certificates from an issuer download: DER (`application/pkix-cert`), PEM, or a PKCS#7
/// bundle (`application/pkcs7-mime`). Empty when the body is none of these.
pub fn certificates_from_body(body: &[u8]) -> Vec<CertificateDer<'static>> {
    if body.starts_with(b"-----BEGIN") {
        return CertificateDer::pem_slice_iter(body)
            .filter_map(Result::ok)
            .map(CertificateDer::into_owned)
            .filter(|c| looks_like_certificate(c.as_ref()))
            .take(MAX_CERTS_PER_DOWNLOAD)
            .collect();
    }
    if looks_like_certificate(body) {
        return vec![CertificateDer::from(body.to_vec())];
    }
    pkcs7_certificates(body).unwrap_or_default()
}

/// Downloads the issuer certificates at `url`. `connect_override` replaces the URL's address
/// (tests). Errors are short descriptions without the URL.
pub(crate) async fn fetch(
    url: &str,
    timeout: Duration,
    connect_override: Option<SocketAddr>,
) -> Result<Vec<CertificateDer<'static>>, String> {
    let (host, path) = parse_http_url(url).ok_or("not a plain http URL on port 80")?;
    let work = async {
        let addr = match connect_override {
            Some(a) => a,
            None => tokio::net::lookup_host((host.as_str(), 80))
                .await
                .map_err(|e| format!("resolve: {e}"))?
                .find(|a| !forbidden(a.ip()))
                .ok_or("no usable address")?,
        };
        let mut s = TcpStream::connect(addr)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        let req = format!(
            "GET {path} HTTP/1.0\r\nHost: {host}\r\nAccept: application/pkix-cert, */*\r\nConnection: close\r\n\r\n"
        );
        s.write_all(req.as_bytes())
            .await
            .map_err(|e| format!("send: {e}"))?;
        let mut buf = Vec::new();
        (&mut s)
            .take(u64::try_from(MAX_RESPONSE).unwrap_or(u64::MAX))
            .read_to_end(&mut buf)
            .await
            .map_err(|e| format!("receive: {e}"))?;
        let body = http_body(&buf).ok_or("unexpected HTTP response")?;
        let certs = certificates_from_body(body);
        if certs.is_empty() {
            return Err("response holds no certificate".to_owned());
        }
        Ok(certs)
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| "timed out".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn urls_are_restricted_to_http_port_80() {
        assert_eq!(
            parse_http_url("http://crt.example.com/Some%20CA.crt"),
            Some(("crt.example.com".into(), "/Some%20CA.crt".into()))
        );
        assert_eq!(
            parse_http_url("HTTP://CA.example.com:80"),
            Some(("ca.example.com".into(), "/".into()))
        );
        for bad in [
            "https://ca.example.com/x.crt",
            "ldap://ca.example.com/x",
            "http://ca.example.com:8080/x.crt",
            "http://user@ca.example.com/x.crt",
            "http://[::1]/x.crt",
            "http:///x.crt",
            "http://ca.example.com/a b",
            "http://ca.example.com/a\r\nX: y",
        ] {
            assert_eq!(parse_http_url(bad), None, "{bad}");
        }
    }

    #[test]
    fn local_addresses_are_forbidden() {
        for ip in [
            "127.0.0.1",
            "0.0.0.0",
            "169.254.169.254",
            "::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(forbidden(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["192.0.2.10", "10.1.2.3", "2001:db8::1"] {
            assert!(!forbidden(ip.parse().unwrap()), "{ip}");
        }
    }

    #[tokio::test]
    async fn loopback_is_refused_without_an_override() {
        let e = fetch("http://127.0.0.1/ca.crt", Duration::from_secs(2), None).await;
        assert!(e.is_err());
    }

    #[test]
    fn http_bodies() {
        assert_eq!(
            http_body(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef"),
            Some(&b"abc"[..])
        );
        assert_eq!(http_body(b"HTTP/1.0 200 OK\r\n\r\nabc"), Some(&b"abc"[..]));
        assert_eq!(http_body(b"HTTP/1.1 404 Not Found\r\n\r\nabc"), None);
        assert_eq!(
            http_body(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc"),
            None
        );
        assert_eq!(
            http_body(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n"
            ),
            None
        );
        assert_eq!(http_body(b"HTTP/1.1 200 OK\r\n"), None);
    }

    #[test]
    fn reads_ca_issuers_from_a_certificate() {
        let mut p = rcgen::CertificateParams::new(vec!["vpn.example.test".into()]).unwrap();
        p.custom_extensions.push(aia_extension(&[
            ("1.3.6.1.5.5.7.48.1", "http://ocsp.example.test"),
            ("1.3.6.1.5.5.7.48.2", "http://ca.example.test/int.crt"),
        ]));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = p.self_signed(&key).unwrap();
        assert_eq!(
            ca_issuer_urls(cert.der()),
            vec!["http://ca.example.test/int.crt".to_owned()]
        );
        assert!(looks_like_certificate(cert.der()));
        assert_eq!(
            certificates_from_body(cert.pem().as_bytes()),
            vec![cert.der().clone()]
        );
        assert_eq!(certificates_from_body(cert.der()), vec![cert.der().clone()]);
        let p7 = pkcs7(&[cert.der(), cert.der()]);
        assert_eq!(certificates_from_body(&p7).len(), 2);
        assert!(certificates_from_body(b"HTTP junk").is_empty());

        let plain = rcgen::CertificateParams::new(vec!["x.example.test".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert!(ca_issuer_urls(plain.der()).is_empty());
    }

    fn wrap(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = body.len();
        if n < 0x80 {
            v.push(n as u8);
        } else {
            v.extend_from_slice(&[0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(body);
        v
    }

    /// A PKCS#7 certs-only bundle.
    fn pkcs7(certs: &[&[u8]]) -> Vec<u8> {
        let mut sd = wrap(0x02, &[1]);
        sd.extend(wrap(0x31, &[]));
        sd.extend(wrap(
            0x30,
            &wrap(
                0x06,
                &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01],
            ),
        ));
        sd.extend(wrap(0xa0, &certs.concat()));
        sd.extend(wrap(0x31, &[]));
        let mut info = wrap(0x06, SIGNED_DATA_OID);
        info.extend(wrap(0xa0, &wrap(0x30, &sd)));
        wrap(0x30, &info)
    }

    /// An Authority Information Access extension with `(method OID, URI)` pairs.
    fn aia_extension(entries: &[(&str, &str)]) -> rcgen::CustomExtension {
        let mut descs = Vec::new();
        for (oid, uri) in entries {
            let method = if *oid == "1.3.6.1.5.5.7.48.2" {
                CA_ISSUERS_OID
            } else {
                &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01][..]
            };
            let mut d = wrap(0x06, method);
            d.extend(wrap(0x86, uri.as_bytes()));
            descs.extend(wrap(0x30, &d));
        }
        rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 5, 5, 7, 1, 1], wrap(0x30, &descs))
    }

    proptest! {
        #[test]
        fn certificate_parsing_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = ca_issuer_urls(&data);
            let _ = looks_like_certificate(&data);
            let _ = certificates_from_body(&data);
        }

        #[test]
        fn http_parsing_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = http_body(&data);
        }

        #[test]
        fn url_parsing_never_panics(s in ".{0,200}") {
            let _ = parse_http_url(&s);
        }

        #[test]
        fn parsing_framed_garbage_never_panics(body in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut v = vec![0x30, 0x82, (body.len() >> 8) as u8, body.len() as u8];
            v.extend(body);
            let _ = ca_issuer_urls(&v);
        }
    }
}
