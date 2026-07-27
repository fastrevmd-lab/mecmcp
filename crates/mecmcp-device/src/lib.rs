//! Cross-process device locking and cancellation primitives.
//!
//! This crate provides two independent facilities used by MCP servers managing
//! network devices:
//!
//! - **Device locking** ([`DeviceLock`], [`FlockDeviceLock`]) — cross-process
//!   mutual exclusion using kernel file locks, so long-running destructive
//!   workflows (upgrades, reboots, configuration replacements) cannot be raced
//!   by a second caller. The lock is held by an open file descriptor and
//!   released by the kernel on process death, so there is no stale-lock cleanup
//!   path to get wrong.
//!
//! - **Cancellation plumbing** ([`cancel`]) — helpers for racing a future
//!   against a [`tokio_util::sync::CancellationToken`], used by long-running
//!   tools to respect client-side cancellation or request timeouts.
//!
//! ## Cross-process exclusion
//!
//! Unlike in-process concurrency limiting (tokio `Semaphore`, HTTP connection
//! pooling), [`DeviceLock`] provides true mutual exclusion across multiple
//! processes. The kernel is the authority: file locks are released on process
//! death, so no cleanup daemon is needed.
//!
//! The [`FlockDeviceLock`] implementation uses POSIX advisory locks via
//! [`rustix::fs::flock`]. A lock that cannot be acquired immediately enters a
//! polling loop with a configurable timeout. Once acquired, the lock is held
//! until the [`DeviceLockGuard`] drops.
//!
//! ## Example
//!
//! ```no_run
//! use mecmcp_device::{DeviceLock, FlockDeviceLock};
//! use std::time::Duration;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let lock = FlockDeviceLock::with_timing(
//!     "/var/lib/device-locks",
//!     Duration::from_secs(30),
//!     Duration::from_millis(100),
//! )?;
//!
//! let _guard = lock.acquire("device-01", "upgrade", "correlation-123").await?;
//! // The lock is held until _guard drops.
//! # Ok(())
//! # }
//! ```

pub mod cancel;
mod flock;

pub use flock::{DeviceLockGuard, FlockDeviceLock};

use async_trait::async_trait;
use std::fmt;

/// Cross-process mutual exclusion for device operations.
///
/// Implementors provide a mechanism to acquire an exclusive lock on a named
/// device, blocking until the lock is available or a timeout elapses. The lock
/// is released when the returned [`DeviceLockGuard`] drops.
///
/// The trait is generic over the guard type to allow different implementations
/// (file locks, distributed locks, etc.) to return different guards with
/// different lifetimes and resource ownership.
#[async_trait]
pub trait DeviceLock: Send + Sync {
    /// The RAII guard type that releases the lock on drop.
    type Guard;

    /// Acquire an exclusive lock on the named device for the given operation.
    ///
    /// # Parameters
    ///
    /// - `device` — device name or identifier (implementation-defined format)
    /// - `operation` — human-readable operation name for diagnostics
    /// - `correlation_id` — request correlation ID for diagnostics
    ///
    /// # Returns
    ///
    /// - `Ok(guard)` — the lock was acquired; it is released when the guard drops.
    /// - `Err(DeviceLockError::Busy)` — the lock was held by another process
    ///   and the timeout elapsed.
    /// - `Err(DeviceLockError::Cancelled)` — the operation was cancelled before
    ///   the lock was acquired.
    /// - `Err(DeviceLockError::Other)` — a filesystem or I/O error occurred.
    async fn acquire(
        &self,
        device: &str,
        operation: &str,
        correlation_id: &str,
    ) -> Result<Self::Guard, DeviceLockError>;

    /// Acquire an exclusive lock with cancellation support.
    ///
    /// Like [`acquire`](DeviceLock::acquire), but the wait can be cancelled by
    /// firing the provided [`tokio_util::sync::CancellationToken`].
    async fn acquire_cancellable(
        &self,
        device: &str,
        operation: &str,
        correlation_id: &str,
        cancellation: &tokio_util::sync::CancellationToken,
    ) -> Result<Self::Guard, DeviceLockError>;
}

/// Errors returned by [`DeviceLock`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum DeviceLockError {
    /// The lock was held by another process and the timeout elapsed.
    #[error("device {device:?} lock held by another process (waited {waited_secs}s)")]
    Busy {
        /// The device name that was locked.
        device: String,
        /// The number of seconds the caller waited.
        waited_secs: u64,
    },

    /// The operation was cancelled before the lock was acquired.
    #[error("device lock acquisition cancelled")]
    Cancelled,

    /// A filesystem or I/O error occurred.
    #[error("device {device:?} lock error: {detail}")]
    Other {
        /// The device name that was being locked.
        device: String,
        /// A human-readable error detail.
        detail: String,
    },
}

impl DeviceLockError {
    /// Construct an `Other` error with the given device and detail.
    pub(crate) fn other(device: impl Into<String>, detail: impl fmt::Display) -> Self {
        Self::Other {
            device: device.into(),
            detail: detail.to_string(),
        }
    }
}
