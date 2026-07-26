//! Unix signal handling for hot-reload.
//!
//! Provides SIGHUP listening on Unix platforms, invoking a callback when the
//! signal is received. On non-Unix platforms, this module is a no-op.

#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};

/// SIGHUP signal handler (Unix only).
///
/// Spawns a background task that listens for SIGHUP and invokes the provided
/// callback each time the signal is received.
///
/// # Arguments
///
/// * `callback` - Function to invoke on each SIGHUP
///
/// # Returns
///
/// Returns `Ok(())` if the handler was installed successfully, or an error if
/// signal registration failed.
///
/// # Errors
///
/// Returns error if the SIGHUP handler cannot be registered with the runtime.
#[cfg(unix)]
pub fn install_hup_handler<F>(callback: F) -> std::io::Result<()>
where
    F: Fn() + Send + 'static,
{
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            callback();
        }
    });
    Ok(())
}

/// No-op on non-Unix platforms.
///
/// # Errors
///
/// Always returns `Ok(())` on non-Unix platforms.
#[cfg(not(unix))]
pub fn install_hup_handler<F>(_callback: F) -> std::io::Result<()>
where
    F: Fn() + Send + 'static,
{
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn hup_handler_invokes_callback() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;

        let counter = Arc::new(AtomicUsize::new(0));
        let counter_clone = counter.clone();

        install_hup_handler(move || {
            counter_clone.fetch_add(1, Ordering::SeqCst);
        })
        .expect("failed to install SIGHUP handler");

        // Give the handler time to register
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Send SIGHUP to ourselves
        let pid = rustix::process::Pid::from_raw(std::process::id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::HUP)
            .expect("failed to send SIGHUP");

        // Wait for signal delivery and callback execution
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "callback should have been invoked once"
        );

        // Send another SIGHUP
        rustix::process::kill_process(pid, rustix::process::Signal::HUP)
            .expect("failed to send SIGHUP");
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "callback should have been invoked twice"
        );
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_is_noop() {
        let result = install_hup_handler(|| {});
        assert!(result.is_ok());
    }
}
