//! Shared model for the daemon and its clients: control protocol, framing, stable error codes,
//! the worker interface with a fake worker, and an async client library.

pub mod client;
pub mod error;
pub mod framing;
pub mod proto;
pub mod worker;
pub mod worker_wire;

pub use error::{ErrorCode, ProtoError};
