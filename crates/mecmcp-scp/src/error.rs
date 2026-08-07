//! Error types for SCP operations.

use std::io;

/// Errors that can occur during SCP file transfers.
#[derive(Debug, thiserror::Error)]
pub enum ScpError {
    /// SSH connection failed.
    #[error("SSH connection failed: {0}")]
    Connect(String),

    /// SSH channel operation failed.
    #[error("SSH channel error: {0}")]
    Channel(String),

    /// SSH channel closed unexpectedly.
    #[error("SSH channel closed: {0}")]
    ChannelClosed(String),

    /// I/O error during file or network operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Authentication failed.
    #[error("Authentication failed: {0}")]
    Auth(String),

    /// Host key verification failed.
    #[error("Host key verification failed: {0}")]
    HostKeyVerification(String),

    /// SCP client is poisoned due to cancelled channel open.
    ///
    /// When a transfer is cancelled during channel open, the client becomes
    /// poisoned and must be reconnected. This prevents unpredictable behavior
    /// from leaked channels.
    #[error("SCP client poisoned: a previous transfer was cancelled during channel open")]
    ScpClientPoisoned,
}
