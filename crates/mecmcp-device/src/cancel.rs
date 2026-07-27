//! Cooperative cancellation primitives for long-running device operations.
//!
//! MCP servers typically expose a [`tokio_util::sync::CancellationToken`] on
//! every request context that fires when the client sends a
//! `notifications/cancelled` JSON-RPC message or when the server-side request
//! timeout elapses. This module provides two helpers that wrap an inner future
//! in a `tokio::select!` against the token, so every await site in
//! long-running tools can short-circuit on cancel without hand-rolling the
//! select form.
//!
//! ## `biased;` ordering
//!
//! Both helpers use `biased;` in the select, so on every poll the
//! `token.cancelled()` branch is checked before the inner future. A token
//! that was cancelled before the helper was even reached therefore returns
//! `Cancelled` on the first poll instead of letting the inner future run.
//!
//! ## Example
//!
//! ```
//! use mecmcp_device::cancel::{select_cancel, Cancellable};
//! use tokio_util::sync::CancellationToken;
//!
//! #[derive(Debug, thiserror::Error)]
//! enum MyError {
//!     #[error("operation cancelled")]
//!     Cancelled,
//!     #[error("device error: {0}")]
//!     Device(String),
//! }
//!
//! impl Cancellable for MyError {
//!     fn cancelled() -> Self {
//!         Self::Cancelled
//!     }
//! }
//!
//! async fn long_operation(token: &CancellationToken) -> Result<u32, MyError> {
//!     select_cancel(token, async {
//!         tokio::time::sleep(std::time::Duration::from_secs(1)).await;
//!         Ok(42)
//!     }).await
//! }
//! ```

use std::future::Future;
use tokio_util::sync::CancellationToken;

/// An error type that can represent cancellation.
///
/// Implement this trait for your error enum to use [`select_cancel`] and
/// [`select_cancel_raw`].
pub trait Cancellable: Sized {
    /// Construct a cancellation error.
    fn cancelled() -> Self;
}

/// Race `fut` against `token.cancelled()`. If the token fires first, drop
/// `fut` and return `E::cancelled()`. Otherwise return whatever `fut` produced.
///
/// Use this when the inner future's `Output` is already `Result<_, E>` where
/// `E: Cancellable` — the common case for inter-tool calls.
///
/// # Example
///
/// ```
/// use mecmcp_device::cancel::{select_cancel, Cancellable};
/// use tokio_util::sync::CancellationToken;
///
/// #[derive(Debug, thiserror::Error)]
/// enum MyError {
///     #[error("cancelled")]
///     Cancelled,
/// }
///
/// impl Cancellable for MyError {
///     fn cancelled() -> Self {
///         Self::Cancelled
///     }
/// }
///
/// # async fn example() -> Result<(), MyError> {
/// let token = CancellationToken::new();
/// let result: Result<u32, MyError> = select_cancel(&token, async { Ok(42) }).await;
/// # Ok(())
/// # }
/// ```
pub async fn select_cancel<F, T, E>(token: &CancellationToken, fut: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
    E: Cancellable,
{
    tokio::select! {
        biased;
        _ = token.cancelled() => Err(E::cancelled()),
        r = fut => r,
    }
}

/// Race `fut` against `token.cancelled()`. If the token fires first, drop
/// `fut` and return `E::cancelled()`. Otherwise return `Ok(value)`.
///
/// Use this for futures whose `Output` is NOT already `Result<_, E>` — e.g.
/// `tokio::time::sleep`, `tokio::time::timeout`, or a device client call that
/// returns `Result<String, OtherError>` and needs caller-side mapping.
///
/// # Example
///
/// ```
/// use mecmcp_device::cancel::{select_cancel_raw, Cancellable};
/// use tokio_util::sync::CancellationToken;
/// use std::time::Duration;
///
/// #[derive(Debug, thiserror::Error)]
/// enum MyError {
///     #[error("cancelled")]
///     Cancelled,
/// }
///
/// impl Cancellable for MyError {
///     fn cancelled() -> Self {
///         Self::Cancelled
///     }
/// }
///
/// # async fn example() -> Result<(), MyError> {
/// let token = CancellationToken::new();
/// select_cancel_raw(&token, tokio::time::sleep(Duration::from_secs(1))).await?;
/// # Ok(())
/// # }
/// ```
pub async fn select_cancel_raw<F, T, E>(token: &CancellationToken, fut: F) -> Result<T, E>
where
    F: Future<Output = T>,
    E: Cancellable,
{
    tokio::select! {
        biased;
        _ = token.cancelled() => Err(E::cancelled()),
        v = fut => Ok(v),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error, PartialEq)]
    enum TestError {
        #[error("cancelled")]
        Cancelled,
    }

    impl Cancellable for TestError {
        fn cancelled() -> Self {
            Self::Cancelled
        }
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn select_cancel_returns_inner_when_not_cancelled() {
        let token = CancellationToken::new();
        let r: Result<u32, TestError> = select_cancel(&token, async { Ok(42u32) }).await;
        assert_eq!(r, Ok(42));
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn select_cancel_returns_cancelled_when_pre_cancelled() {
        let token = CancellationToken::new();
        token.cancel();

        // Inner future would sleep 10s if it ran; assert the helper
        // returns within 50ms.
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(50),
            select_cancel::<_, u32, TestError>(&token, async {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                Ok(0)
            }),
        )
        .await;

        assert_eq!(r, Ok(Err(TestError::Cancelled)));
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn select_cancel_raw_returns_value_when_not_cancelled() {
        let token = CancellationToken::new();
        let r: Result<&'static str, TestError> = select_cancel_raw(&token, async { "ok" }).await;
        assert_eq!(r, Ok("ok"));
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn select_cancel_raw_returns_cancelled_when_cancelled_mid_flight() {
        let token = CancellationToken::new();
        let token2 = token.clone();

        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            token2.cancel();
        });

        let r = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            select_cancel_raw::<_, (), TestError>(&token, async {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }),
        )
        .await;

        assert_eq!(r, Ok(Err(TestError::Cancelled)));
    }
}
