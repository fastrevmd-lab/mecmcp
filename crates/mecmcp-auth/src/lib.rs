//! Vendor-neutral bearer-token authentication, scopes, and grants.
//!
//! This crate is deliberately free of vendor concepts. It knows about tokens,
//! names, and opaque authorization subjects; it does not know what a subject
//! means to any particular device family.

pub mod token;
pub mod scope;
pub mod grant;

pub use token::{TokenDigest, TokenError, TokenSecret};
pub use scope::{MAX_SCOPE_NAMES, ScopeError, ScopeSet};
pub use grant::{Grant, GrantError, NoAction, NoGrant};
