//! Mock FortiGate SSL VPN, built from the design notes.
//!
//! Every behaviour that is inferred rather than observed
//! carries an `UNVERIFIED` comment and must match the client's assumption.

use serde::Deserialize;

use crate::http::Response;
use crate::server::{self, MockError, MockHandle, Router, TlsOptions};

/// `/remote/info` values.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct InfoCfg {
    /// `encmethod`; anything but 0 means encrypted credentials.
    pub encmethod: u32,
    /// `salt`.
    pub salt: String,
    /// `remoteauthtimeout` in seconds.
    pub remoteauthtimeout: u32,
    /// `f` flag field.
    pub flag: String,
}

impl Default for InfoCfg {
    fn default() -> Self {
        Self {
            encmethod: 0,
            salt: "5a1t5a1t".into(),
            remoteauthtimeout: 600,
            flag: "0".into(),
        }
    }
}

/// A mock gateway scenario. Loaded from YAML (see `fixtures/mock/*.yaml`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Scenario {
    /// `/remote/info`.
    pub info: InfoCfg,
    /// TLS behaviour.
    pub tls: TlsCfg,
}

/// TLS behaviour of the mock.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct TlsCfg {
    /// Send an optional CertificateRequest with no CA names.
    pub request_optional_client_cert: bool,
    /// Only offer TLS 1.3.
    pub tls13_only: bool,
}

impl Scenario {
    /// Parses a YAML scenario.
    pub fn from_yaml(s: &str) -> Result<Self, MockError> {
        serde_yaml::from_str(s).map_err(|e| MockError::Other(format!("scenario: {e}")))
    }
}

/// Body of `/remote/info`.
///
/// Both gateways returned these values as attributes on an `api` element.
/// The envelope and values here are synthetic. Only the fields exercised by this mock are emitted.
pub fn info_body(i: &InfoCfg) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><info><api encmethod=\"{}\" salt=\"{}\" \
         remoteauthtimeout=\"{}\" f=\"{}\"/></info>",
        i.encmethod, i.salt, i.remoteauthtimeout, i.flag
    )
}

/// Builds the router for a scenario.
pub fn router(sc: &Scenario) -> Router {
    let info = info_body(&sc.info);
    Router::new().route("GET", "/remote/info", move |_| {
        Response::ok("application/xml", info.clone()).into()
    })
}

/// Starts a mock FortiGate for `sc`.
pub async fn start(sc: &Scenario) -> Result<MockHandle, MockError> {
    let opts = TlsOptions {
        request_optional_client_cert: sc.tls.request_optional_client_cert,
        tls13_only: sc.tls.tls13_only,
    };
    server::start(router(sc), opts).await
}
