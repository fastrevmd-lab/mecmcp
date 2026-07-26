//! Graceful shutdown coordination.
//!
//! Provides a `GracefulShutdown` coordinator that aggregates multiple shutdown
//! sources (Ctrl-C, manual trigger) into a single awaitable signal.

use tokio::sync::watch;

/// Graceful shutdown coordinator.
///
/// Aggregates multiple shutdown triggers into a single awaitable future:
/// - Ctrl-C (SIGINT)
/// - Manual shutdown via `trigger()`
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
    tx: watch::Sender<bool>,
}

impl GracefulShutdown {
    /// Create a new shutdown coordinator.
    ///
    /// Automatically installs a handler for Ctrl-C.
    #[must_use]
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        let tx_clone = tx.clone();

        // Install Ctrl-C handler
        tokio::spawn(async move {
            if let Err(e) = tokio::signal::ctrl_c().await {
                tracing::error!(error = %e, "failed to listen for Ctrl-C");
                return;
            }
            tracing::info!("received Ctrl-C, shutting down");
            let _ = tx_clone.send(true);
        });

        Self { tx }
    }

    /// Subscribe to the shutdown signal.
    ///
    /// Returns a future that completes when shutdown is triggered.
    #[must_use]
    pub fn subscribe(&self) -> ShutdownSignal {
        ShutdownSignal {
            rx: self.tx.subscribe(),
        }
    }

    /// Manually trigger shutdown.
    ///
    /// This can be called from application code to initiate a graceful shutdown.
    pub fn trigger(&self) {
        tracing::info!("manual shutdown triggered");
        let _ = self.tx.send(true);
    }
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// A future that completes when shutdown is triggered.
pub struct ShutdownSignal {
    rx: watch::Receiver<bool>,
}

impl ShutdownSignal {
    /// Wait for the shutdown signal.
    pub async fn wait(mut self) {
        let _ = self.rx.wait_for(|&v| v).await;
    }
}

impl std::future::Future for ShutdownSignal {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Use wait_for which properly integrates with watch receiver's waker mechanism
        let wait_fut = self.rx.wait_for(|&v| v);
        tokio::pin!(wait_fut);

        match wait_fut.poll(cx) {
            std::task::Poll::Ready(Ok(_)) => std::task::Poll::Ready(()),
            std::task::Poll::Ready(Err(_)) => {
                // Sender dropped, treat as shutdown
                std::task::Poll::Ready(())
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn manual_trigger() {
        let shutdown = GracefulShutdown::new();
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
        let shutdown = GracefulShutdown::new();
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
    async fn signal_as_future() {
        let shutdown = GracefulShutdown::new();
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

    // Note: Ctrl-C test is not feasible in this test environment because
    // sending SIGINT via kill_process() would terminate the test runner itself.
    // The Ctrl-C handler is manually verified to work in integration tests.
}
