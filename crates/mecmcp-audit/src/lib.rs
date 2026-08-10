//! Caller-attributed audit events for vendor-neutral MCP servers.
//!
//! This crate is deliberately free of vendor concepts. It knows about
//! principals, attribution, and audit outcomes; it does not know what
//! a device is or what configuration it holds.

mod attribution;
pub mod canonical;
pub mod evidence;
mod init;
mod redact;
mod schema;
mod scope;
pub mod signing;
pub mod sinks;
pub mod testutil;

pub use attribution::{
    ActorType, AgentIdentity, Attribution, Principal, Tier, TokenVerifiedFields,
};
pub use evidence::{
    ApplyIntentRecord, ApprovalRecord, ChainSegment, ClosedSegment, EvidenceError, EvidenceRecord,
    GENESIS_PREV_HASH, ProposalRecord, ResultReceipt, SegmentArchive, append, close,
};
pub use init::{AuditConfig, AuditFileSink, AuditFormat, FileHandle, init_tracing};
pub use redact::{
    AuditRedaction, FieldTransform, REDACTABLE_FIELDS, RedactError, active, install, render,
};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::{
    AuditScope, DEFAULT_DURATION_METRIC, duration_metric_name, install_duration_metric_name,
};
pub use sinks::{DeliveryLedger, DeliveryStatus, SsdfSink, SsdfSinkConfig, SsdfSinkError};
