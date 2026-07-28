//! Vendor-neutral adapters between `rmcp` handlers and the mecmcp foundations.

mod audit;
mod authorize;
mod caller;
mod result;
mod tools;

pub use audit::audit_scope;
pub use authorize::{
    AuthorizationError, authorize_call, authorize_target, authorize_tool,
};
pub use caller::caller_from_extensions;
pub use result::{
    BoundedText, ResultFormat, ResultLimits, bounded_text, tool_error, tool_result,
};
pub use tools::filter_tools_for_scope;
