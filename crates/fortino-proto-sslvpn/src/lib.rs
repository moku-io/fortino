//! Sans-IO codecs for the FortiGate SSL VPN, written from the design notes and the
//! observations. Nothing here performs I/O, so every codec is unit-testable.
//!
//! - [`http`]: HTTP/1.1 request encoding with an exact header order, and an incremental
//!   response parser.
//! - [`identity`]: the client's wire identity (header profile, `FSV_*` headers).
//! - [`info`]: the `/remote/info` pre-flight.
//! - [`login`]: `/remote/logincheck` forms and response classification.
//! - [`config`]: `/remote/fortisslvpn_xml` tunnel settings.
//! - [`frame`]: the `0x5050` PPP-over-TLS frame codec.
//! - [`ppp`]: a PPP client (LCP and IPCP) that brings the link up and carries IPv4.
//!
//! Behaviour that is inferred rather than observed carries an `UNVERIFIED` comment.

pub mod config;
pub mod frame;
pub mod http;
pub mod identity;
pub mod info;
pub mod login;
pub mod ppp;

mod urlenc;
