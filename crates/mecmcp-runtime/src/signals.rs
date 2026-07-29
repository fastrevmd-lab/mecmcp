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

/// SIGHUP handler that awaits each callback before receiving the next signal.
///
/// This is appropriate for atomic reload workflows whose individual steps
/// must not overlap.
///
/// # Errors
///
/// Returns an error if the SIGHUP listener cannot be registered.
#[cfg(unix)]
pub fn install_hup_handler_async<F, Fut>(callback: F) -> std::io::Result<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut hup = signal(SignalKind::hangup())?;
    tokio::spawn(async move {
        while hup.recv().await.is_some() {
            callback().await;
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

/// No-op async SIGHUP handler on non-Unix platforms.
///
/// # Errors
///
/// Always returns `Ok(())` on non-Unix platforms.
#[cfg(not(unix))]
pub fn install_hup_handler_async<F, Fut>(_callback: F) -> std::io::Result<()>
where
    F: Fn() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(unix)]
    static SIGNAL_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[cfg(unix)]
    #[tokio::test]
    async fn hup_handler_invokes_callback() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;

        let _signal_test_guard = SIGNAL_TEST_LOCK.lock().await;
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

    #[cfg(unix)]
    #[tokio::test]
    async fn async_hup_callbacks_are_awaited_serially() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::time::Duration;

        let _signal_test_guard = SIGNAL_TEST_LOCK.lock().await;
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        install_hup_handler_async({
            let active = active.clone();
            let maximum = maximum.clone();
            let completed = completed.clone();
            move || {
                let active = active.clone();
                let maximum = maximum.clone();
                let completed = completed.clone();
                async move {
                    let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                    maximum.fetch_max(now, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    active.fetch_sub(1, Ordering::SeqCst);
                    completed.fetch_add(1, Ordering::SeqCst);
                }
            }
        })
        .expect("async handler");

        let pid = rustix::process::Pid::from_raw(std::process::id() as i32).unwrap();
        rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("first HUP");
        tokio::time::sleep(Duration::from_millis(5)).await;
        rustix::process::kill_process(pid, rustix::process::Signal::HUP).expect("second HUP");
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert_eq!(completed.load(Ordering::SeqCst), 2);
        assert_eq!(maximum.load(Ordering::SeqCst), 1);
    }

    #[cfg(not(unix))]
    #[test]
    fn non_unix_is_noop() {
        let result = install_hup_handler(|| {});
        assert!(result.is_ok());
    }
}
