//! Sans-IO codecs for the FortiClient EMS protocol. Nothing here performs I/O.
//!
//! - [`message`]: requests (`MSG_HEADER`, `X-FCCK-<TYPE>` bodies, `SIZE`).
//! - [`reply`]: replies (`<TYPE>: KEY|value|…|`) and typed views of them.
//! - [`fields`]: the `KEY|value|` body format both directions share.
//! - [`sysinfo`]: `SYSINFO` and `NWIFS`.
//! - [`blob`]: `Z*` fields (zlib, then base64).
//! - [`tags`]: `RULES` and `TAGS` bitstrings.
//! - [`hv`]: host-verification rules (`hv.conf`).
//! - [`ids`]: endpoint UID, EMS serial, tenant, MAC.
//!
//! Behaviour that is inferred rather than observed carries an `UNVERIFIED` comment.

pub mod blob;
pub mod fields;
pub mod hv;
pub mod ids;
pub mod message;
pub mod reply;
pub mod sysinfo;
pub mod tags;
