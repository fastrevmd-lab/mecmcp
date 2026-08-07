//! Graceful shutdown coordination.
//!
//! Provides a `GracefulShutdown` coordinator that aggregates multiple shutdown
//! sources (Ctrl-C/SIGINT, Unix SIGTERM, manual trigger) into a single
//! awaitable signal.

use tokio_util::sync::CancellationToken;

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

/// Graceful shutdown coordinator.
///
/// Aggregates multiple shutdown triggers into a single awaitable future:
/// - Ctrl-C (SIGINT on Unix, Ctrl-C event on Windows)
/// - SIGTERM (Unix only; systemd and Docker default signal)
/// - Manual shutdown via `trigger()`
///
/// On Unix platforms, both SIGINT and SIGTERM are handled. On non-Unix
/// platforms, only Ctrl-C is handled (SIGTERM does not exist).
///
/// # Example
///
/// ```ignore
/// use mecmcp_runtime::shutdown::GracefulShutdown;
///
/// #[tokio::main]
/// async fn main() {
///     let shutdown = GracefulShutdown::new();
///     let shutdown_signal = shutdown.subscribe();
///
///     // Start server...
///
///     shutdown_signal.await;
///     // Clean up...
/// }
/// ```
pub struct GracefulShutdown {
    token: CancellationToken,
}

impl GracefulShutdown {
    /// Create a new shutdown coordinator.
    ///
    /// Automatically installs handlers for Ctrl-C and (on Unix) SIGTERM.
    ///
    /// Shutdown state is latched: once triggered, all current and future
    /// subscribers observe it immediately. This ensures SIGTERM arriving
    /// during startup (before any subscriber exists) is not lost (#156).
    ///
    /// # Errors
    ///
    /// Returns an error if signal handler installation fails. This is a
    /// configuration error (e.g., signal already handled elsewhere) and should
    /// be treated as fatal.
    pub fn new() -> Result<Self, std::io::Error> {
        let token = CancellationToken::new();

        // Install SIGINT handler (Unix) - constructing the listener can fail
        #[cfg(unix)]
        {
            let mut int_signal = signal(SignalKind::interrupt())?;
            let token_clone = token.clone();
            tokio::spawn(async move {
                if int_signal.recv().await.is_some() {
                    tracing::info!("received SIGINT (Ctrl-C), shutting down");
                    token_clone.cancel();
                }
            });
        }

        // Install SIGTERM handler (Unix only)
        #[cfg(unix)]
        {
            let mut term_signal = signal(SignalKind::terminate())?;
            let token_clone = token.clone();
            tokio::spawn(async move {
                if term_signal.recv().await.is_some() {
                    tracing::info!("received SIGTERM, shutting down");
                    token_clone.cancel();
                }
            });
        }

        // Install Ctrl-C handler (Windows and non-Unix fallback)
        // tokio::signal::ctrl_c() has no way to fail synchronously on non-Unix
        // platforms, so we spawn it and document the limitation.
        #[cfg(not(unix))]
        {
            let token_clone = token.clone();
            tokio::spawn(async move {
                if let Err(e) = tokio::signal::ctrl_c().await {
                    tracing::error!(error = %e, "failed to listen for Ctrl-C");
                    return;
                }
                tracing::info!("received Ctrl-C, shutting down");
                token_clone.cancel();
            });
        }

        Ok(Self { token })
    }

    /// Subscribe to the shutdown signal.
    ///
    /// Returns a future that completes when shutdown is triggered. If shutdown
    /// was already triggered before this call, the future completes immediately.
    #[must_use]
    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            inner: Box::pin(self.token.clone().cancelled_owned()),
        }
    }

    /// Manually trigger shutdown.
    ///
    /// This can be called from application code to initiate a graceful shutdown.
    pub fn trigger(&self) {
        tracing::info!("manual shutdown triggered");
        self.token.cancel();
    }
}

// No Default impl because `new()` now returns Result

/// A future that completes when shutdown is triggered.
///
/// If shutdown was already triggered before this signal was created,
/// it completes immediately (latched behavior).
///
/// The wait future is constructed **once**, in `subscribe`, and held across
/// polls. It must not be recreated per poll: `CancellationToken::cancelled()`
/// registers its waker with the token on first poll and *deregisters it on
/// drop*, so a fresh future built inside `poll` unregisters the waker it just
/// installed, and nothing ever wakes the task again. That is not a theoretical
/// concern — it shipped in 0.7.0 and stopped SIGTERM from ever reaching
/// `serve_router`, so no server drained.
pub struct ShutdownSignal {
    inner: std::pin::Pin<Box<tokio_util::sync::WaitForCancellationFutureOwned>>,
}

impl ShutdownSignal {
    /// Wait for the shutdown signal.
    pub async fn wait(self) {
        self.await;
    }
}

impl std::future::Future for ShutdownSignal {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn manual_trigger() {
        let shutdown = GracefulShutdown::new().expect("shutdown coordinator");
        let signal = shutdown.subscribe();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown.trigger();
        });

        tokio::time::timeout(Duration::from_millis(200), signal)
            .await
            .expect("shutdown signal should have fired");
    }

    #[tokio::test]
    async fn multiple_subscribers() {
        let shutdown = GracefulShutdown::new().expect("shutdown coordinator");
        let signal1 = shutdown.subscribe();
        let signal2 = shutdown.subscribe();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown.trigger();
        });

        let result = tokio::join!(
            tokio::time::timeout(Duration::from_millis(200), signal1),
            tokio::time::timeout(Duration::from_millis(200), signal2),
        );

        assert!(result.0.is_ok(), "first subscriber should receive signal");
        assert!(result.1.is_ok(), "second subscriber should receive signal");
    }

    #[tokio::test]
    async fn trigger_before_subscribe_is_latched() {
        // Regression test for #156: SIGTERM arriving before subscribe() must not be lost.
        // systemd sends SIGTERM on restart; if it arrives during startup before any
        // subscriber exists, the process must still observe it and begin draining.
        let shutdown = GracefulShutdown::new().expect("shutdown coordinator");

        // Trigger BEFORE subscribing
        shutdown.trigger();

        // Now subscribe and verify we immediately see the shutdown state
        let signal = shutdown.subscribe();
        tokio::time::timeout(Duration::from_millis(100), signal)
            .await
            .expect("late subscriber must see shutdown state immediately (latched)");
    }

    #[tokio::test]
    async fn signal_as_future() {
        let shutdown = GracefulShutdown::new().expect("shutdown coordinator");
        let signal = shutdown.subscribe();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            shutdown.trigger();
        });

        // Use .await directly to test Future implementation
        tokio::time::timeout(Duration::from_millis(200), signal)
            .await
            .expect("shutdown signal should complete as future");
    }

    /// The signal must wake a task that is *parked on it*, with nothing else
    /// scheduled to wake that task.
    ///
    /// Every other test here wraps the signal in `tokio::time::timeout`, whose
    /// own timer re-polls the task at the deadline — so they pass even when the
    /// signal's waker was never registered. That is exactly how 0.7.0 shipped a
    /// `Future` impl that could never complete: it rebuilt `cancelled()` inside
    /// `poll` and dropped it, deregistering the waker each time. Live servers
    /// then hung on SIGTERM instead of draining.
    ///
    /// Here the waiter task's only wake source is the token, and the timeout
    /// applies to the *oneshot*, so it cannot substitute for a missing waker.
    #[tokio::test]
    async fn signal_wakes_a_parked_task_without_another_timer() {
        let shutdown = GracefulShutdown::new().expect("shutdown coordinator");
        let signal = shutdown.subscribe();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            signal.await;
            let _ = tx.send(());
        });

        // Let the waiter reach its await point and park.
        tokio::time::sleep(Duration::from_millis(50)).await;
        shutdown.trigger();

        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .expect("a parked waiter must be woken by the signal itself")
            .expect("waiter task must not be dropped");
    }

    // SIGTERM handler installation is verified by successful construction.
    // Actually sending SIGTERM to the test process would require unsafe FFI
    // (libc::kill or rustix raw signal number) and is not worth the complexity
    // for a handler that uses the same tokio::signal infrastructure as the
    // manually-tested SIGHUP handler above. The handler is verified in
    // integration tests with systemd/Docker.

    // Note: Ctrl-C test is not feasible in this test environment because
    // sending SIGINT via kill_process() would terminate the test runner itself.
    // The Ctrl-C handler is manually verified to work in integration tests.
}
