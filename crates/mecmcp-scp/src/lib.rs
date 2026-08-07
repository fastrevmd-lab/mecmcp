//! SCP1 file transfer client for legacy SSH-based devices.
//!
//! This crate provides an SCP1 (legacy SCP protocol) client for uploading and
//! downloading files over SSH exec channels. It targets devices like Junos that
//! disable SFTP-over-SSH.
//!
//! ## Platform Support
//!
//! The SCP client is **Unix-only** (Linux, macOS, BSD). Non-Unix platforms
//! cannot build code that imports this crate's public API.

#[cfg(unix)]
pub mod config;
#[cfg(unix)]
pub mod error;
#[cfg(unix)]
pub mod scp;

#[cfg(unix)]
pub use config::{HostKeyVerification, SshAuth, SshConfig};
#[cfg(unix)]
pub use error::ScpError;
#[cfg(unix)]
pub use scp::{ScpClient, ScpOutcome};
