//! Runtime utilities for MCP servers.
//!
//! This crate provides common runtime infrastructure for MCP servers, including
//! CLI parsing, validation, TLS bootstrap, and privilege management.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cli;
pub mod cli_validate;
