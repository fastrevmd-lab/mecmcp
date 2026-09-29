//! Evidence sinks for closed segments.

pub mod delivery_ledger;
pub mod forward;
pub mod ssdf;

pub use delivery_ledger::{DeliveryLedger, DeliveryStatus};
pub use forward::{ForwardSink, ForwardSinkConfig, ForwardSinkError};
pub use ssdf::{DeliveryReport, ProducedHead, SsdfSink, SsdfSinkConfig, SsdfSinkError};
