//! Sans-IO codecs for the FortiGate SSL VPN. Nothing here performs I/O, so every codec is
//! unit-testable.
//!
//! - [`http`]: HTTP/1.1 request encoding with an exact header order, and an incremental
//!   response parser.
//! - [`identity`]: the client's wire identity (header profile, `FSV_*` headers).
//! - [`info`]: the `/remote/info` pre-flight.
//! - [`login`]: `/remote/logincheck` forms and response classification.
//! - [`saml`]: single sign-on through the system browser (`/remote/saml/…`).
//! - [`config`]: `/remote/fortisslvpn_xml` tunnel settings.
//! - [`frame`]: the `0x5050` PPP-over-TLS frame codec.
//! - [`ppp`]: a PPP client (LCP and IPCP) that brings the link up and carries IPv4.
//!
//! Behaviour that is inferred rather than observed on a gateway carries an `UNVERIFIED` comment.

pub mod config;
pub mod frame;
pub mod http;
pub mod identity;
pub mod info;
pub mod login;
pub mod ppp;
pub mod saml;

mod urlenc;
