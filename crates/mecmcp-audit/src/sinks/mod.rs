//! Evidence sinks for closed segments.

pub mod delivery_ledger;
pub mod ssdf;

pub use delivery_ledger::{DeliveryLedger, DeliveryStatus};
pub use ssdf::{ProducedHead, SsdfSink, SsdfSinkConfig, SsdfSinkError};
