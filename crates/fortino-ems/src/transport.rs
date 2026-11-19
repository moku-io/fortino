//! TLS to the EMS: one connection per exchange (`PERCON|0` in every reply); the reply is one
//! line ending in CRLF.
//!
//! FortiClient also presents a client certificate built into its binary. Fortino has no such
//! certificate and presents none; an EMS that insists on it is unsupported.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fortino_config::EmsServer;
use fortino_proto_ems::message::BuildError;
use fortino_proto_ems::reply::{self, MAX_REPLY, Reply};
use fortino_sslvpn::Trust;
use fortino_sslvpn::transport::{client_config, server_name};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use crate::Error;

/// A configured EMS endpoint.
pub struct Connection {
    server: EmsServer,
    tls: TlsConnector,
    connect_override: Option<SocketAddr>,
    timeout: Duration,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("server", &self.server.to_string())
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Builds the TLS client. `trust` is a CA bundle or a pinned leaf; EMS servers often use
    /// self-signed certificates, so a pin confirmed by the user is the usual case.
    pub fn new(server: EmsServer, trust: &Trust) -> Result<Self, Error> {
        let cfg = client_config(trust).map_err(|e| Error::Trust(format!("{e:?}")))?;
        Ok(Self {
            server,
            tls: TlsConnector::from(Arc::new(cfg)),
            connect_override: None,
            timeout: Duration::from_secs(30),
        })
    }

    /// Connects to `addr` instead of resolving the host (tests).
    pub fn connect_to(mut self, addr: SocketAddr) -> Self {
        self.connect_override = Some(addr);
        self
    }

    /// The server.
    pub fn server(&self) -> &EmsServer {
        &self.server
    }

    async fn resolve(&self) -> Result<SocketAddr, Error> {
        if let Some(a) = self.connect_override {
            return Ok(a);
        }
        let target = (self.server.host.to_string(), self.server.port);
        tokio::net::lookup_host(target)
            .await
            .map_err(|e| Error::Transport(format!("resolve: {e}")))?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| Error::Transport("no IPv4 address for the EMS".into()))
    }

    /// Sends one request and reads the reply. `build` receives the local address used to reach
    /// the server, for when the default-route address is not known.
    pub async fn exchange<F>(&self, build: F) -> Result<Reply, Error>
    where
        F: FnOnce(Ipv4Addr) -> Result<Zeroizing<Vec<u8>>, BuildError>,
    {
        let addr = self.resolve().await?;
        let fut = async {
            let tcp = TcpStream::connect(addr)
                .await
                .map_err(|e| Error::Transport(format!("connect: {e}")))?;
            let local = match tcp.local_addr().map(|a| a.ip()) {
                Ok(IpAddr::V4(ip)) => ip,
                _ => Ipv4Addr::UNSPECIFIED,
            };
            let name = server_name(&self.server.host)
                .map_err(|_| Error::Trust("invalid EMS name".into()))?;
            let mut tls = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|e| Error::Trust(format!("tls: {e}")))?;
            let msg = build(local)?;
            tls.write_all(&msg)
                .await
                .map_err(|e| Error::Transport(format!("send: {e}")))?;
            let mut buf = Vec::new();
            let mut chunk = [0u8; 8192];
            loop {
                match tls.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if buf.len() + n > MAX_REPLY {
                            return Err(Error::Protocol("reply too large".into()));
                        }
                        let from = buf.len().saturating_sub(1);
                        buf.extend_from_slice(&chunk[..n]);
                        // The reply ends at the first CRLF; values may hold bare LF (PEM).
                        if let Some(at) = buf[from..].windows(2).position(|w| w == b"\r\n") {
                            buf.truncate(from + at);
                            break;
                        }
                    }
                    // Servers often close without close_notify; take what arrived.
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(Error::Transport(format!("receive: {e}"))),
                }
            }
            reply::parse(&buf).map_err(|e| Error::Protocol(e.to_string()))
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| Error::Transport("EMS did not answer".into()))?
    }
}
