//! Mock FortiGate and EMS servers used by tests.
//!
//! The binary `fortino-mock` runs a scenario file: `fortino-mock fortigate fixtures/mock/basic.yaml`.

pub mod ems;
pub mod fortigate;
pub mod http;
pub mod server;

pub use server::{MockHandle, Router, TlsOptions};
