//! Shared model for the daemon and its clients: control protocol, framing, stable error codes,
//! the worker interface with a fake worker, an async client library, and the local listener a
//! single sign-on in the browser ends at.

pub mod client;
pub mod error;
pub mod framing;
pub mod proto;
pub mod saml_callback;
pub mod worker;
pub mod worker_wire;

pub use error::{ErrorCode, ProtoError};
