//! Caller-attributed audit events for vendor-neutral MCP servers.
//!
//! This crate is deliberately free of vendor concepts. It knows about
//! principals, attribution, and audit outcomes; it does not know what
//! a device is or what configuration it holds.

mod attribution;
mod init;
mod redact;
mod schema;
mod scope;
pub mod testutil;

pub use attribution::{ActorType, AgentIdentity, Attribution, Principal, Tier};
pub use init::{AuditConfig, AuditFormat, init_tracing};
pub use redact::{
    AuditRedaction, FieldTransform, REDACTABLE_FIELDS, RedactError, active, install, render,
};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::{
    AuditScope, DEFAULT_DURATION_METRIC, duration_metric_name, install_duration_metric_name,
};
