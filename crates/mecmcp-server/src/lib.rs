//! Vendor-neutral adapters between `rmcp` handlers and the mecmcp foundations.

mod authorize;
mod caller;
mod tools;

pub use authorize::{
    AuthorizationError, authorize_call, authorize_target, authorize_tool,
};
pub use caller::caller_from_extensions;
pub use tools::filter_tools_for_scope;
