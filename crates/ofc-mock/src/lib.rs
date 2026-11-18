//! Mock FortiGate and EMS servers used by tests. Built only from the design notes.
//!
//! The binary `ofc-mock` runs a scenario file: `ofc-mock fortigate fixtures/mock/basic.yaml`.

pub mod fortigate;
pub mod http;
pub mod server;

pub use server::{MockHandle, Router, TlsOptions};
