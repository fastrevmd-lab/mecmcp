//! Vendor-neutral adapters between `rmcp` handlers and the mecmcp foundations.

mod caller;

pub use caller::caller_from_extensions;
