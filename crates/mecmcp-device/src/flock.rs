//! File-lock based device locking implementation.

use crate::{DeviceLock, DeviceLockError};
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::sync::CancellationToken;

/// Default directory for device lock files.
///
/// Consumers can use this as a standard location for lock files, or provide
/// their own path to [`FlockDeviceLock::for_directory`].
#[allow(dead_code)] // Public API constant, not used internally
pub const DEFAULT_DEVICE_LOCK_DIR: &str = "/var/lib/mecmcp/device-locks";

/// Default timeout for acquiring a lock.
const DEFAULT_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default poll interval when waiting for a lock.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Cross-process device locking using kernel file locks.
///
/// Uses POSIX advisory locks ([`rustix::fs::flock`]) to provide mutual
/// exclusion across multiple processes. The lock is held by an open file
/// descriptor and released by the kernel on process death, so no cleanup
/// daemon is needed.
///
/// Lock files are named by the SHA-256 hash of the device name, avoiding
/// filesystem escaping issues and limiting filename length.
#[derive(Clone, Debug)]
pub struct FlockDeviceLock {
    directory: Arc<PathBuf>,
    wait_timeout: Duration,
    poll_interval: Duration,
}

impl FlockDeviceLock {
    /// Create a new lock manager for the given directory.
    ///
    /// The directory is created with mode `0o700` if it does not exist.
    /// Symlinks are rejected.
    ///
    /// Uses default timing: 30s wait timeout, 100ms poll interval.
    pub fn for_directory(directory: impl Into<PathBuf>) -> Result<Self, DeviceLockError> {
        Self::with_timing(directory, DEFAULT_WAIT_TIMEOUT, DEFAULT_POLL_INTERVAL)
    }

    /// Create a new lock manager with custom timing.
    ///
    /// # Parameters
    ///
    /// - `directory` — where lock files are stored
    /// - `wait_timeout` — how long to wait for a busy lock before giving up
    /// - `poll_interval` — how often to retry acquiring a busy lock
    pub fn with_timing(
        directory: impl Into<PathBuf>,
        wait_timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, DeviceLockError> {
        let directory = directory.into();
        prepare_directory(&directory)?;
        Ok(Self {
            directory: Arc::new(directory),
            wait_timeout,
            poll_interval: poll_interval.max(Duration::from_millis(1)),
        })
    }

    /// The directory where lock files are stored.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    fn lock_path(&self, device: &str) -> PathBuf {
        let digest: [u8; 32] = Sha256::digest(device.as_bytes()).into();
        let mut filename = String::with_capacity(64 + ".lock".len());
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut filename, "{byte:02x}").expect("writing to String cannot fail");
        }
        filename.push_str(".lock");
        self.directory.join(filename)
    }
}

#[async_trait]
impl DeviceLock for FlockDeviceLock {
    type Guard = DeviceLockGuard;

    async fn acquire(
        &self,
        device: &str,
        operation: &str,
        correlation_id: &str,
    ) -> Result<Self::Guard, DeviceLockError> {
        self.acquire_cancellable(device, operation, correlation_id, &CancellationToken::new())
            .await
    }

    async fn acquire_cancellable(
        &self,
        device: &str,
        operation: &str,
        correlation_id: &str,
        cancellation: &CancellationToken,
    ) -> Result<Self::Guard, DeviceLockError> {
        let path = self.lock_path(device);
        let mut file = open_lock_file(&path, device)?;
        let started = Instant::now();
        let deadline = started
            .checked_add(self.wait_timeout)
            .ok_or_else(|| DeviceLockError::other(device, "lock wait deadline overflow"))?;
        let mut wait_logged = false;

        loop {
            if cancellation.is_cancelled() {
                return Err(DeviceLockError::Cancelled);
            }

            match try_lock(&file) {
                Ok(()) => {
                    let waited = started.elapsed();
                    write_metadata(&mut file, device, operation, correlation_id, "held").map_err(
                        |error| {
                            DeviceLockError::other(
                                device,
                                format!("writing lock metadata: {error}"),
                            )
                        },
                    )?;
                    tracing::info!(
                        event = "device_lock_acquired",
                        device,
                        operation,
                        correlation_id,
                        waited_ms = waited.as_millis() as u64,
                        lock_path = %path.display(),
                        "acquired cross-process device lock"
                    );
                    return Ok(DeviceLockGuard {
                        file: Some(file),
                        path,
                        device: device.to_string(),
                        operation: operation.to_string(),
                        correlation_id: correlation_id.to_string(),
                        acquired_at: Instant::now(),
                    });
                }
                Err(LockError::WouldBlock) => {
                    if !wait_logged {
                        tracing::info!(
                            event = "device_lock_wait",
                            device,
                            operation,
                            correlation_id,
                            wait_timeout_ms = self.wait_timeout.as_millis() as u64,
                            "waiting for cross-process device lock"
                        );
                        wait_logged = true;
                    }
                    if Instant::now() >= deadline {
                        tracing::warn!(
                            event = "device_lock_busy",
                            device,
                            operation,
                            correlation_id,
                            waited_ms = started.elapsed().as_millis() as u64,
                            "cross-process device lock remained busy"
                        );
                        return Err(DeviceLockError::Busy {
                            device: device.to_string(),
                            waited_secs: self.wait_timeout.as_secs(),
                        });
                    }
                }
                Err(LockError::Other(msg)) => {
                    return Err(DeviceLockError::other(
                        device,
                        format!("locking {}: {msg}", path.display()),
                    ));
                }
            }

            tokio::select! {
                _ = cancellation.cancelled() => return Err(DeviceLockError::Cancelled),
                _ = tokio::time::sleep(self.poll_interval) => {}
            }
        }
    }
}

/// RAII guard for a device lock.
///
/// The lock is released when the guard drops. The underlying file descriptor
/// is closed and the kernel releases the lock automatically.
#[derive(Debug)]
pub struct DeviceLockGuard {
    file: Option<File>,
    path: PathBuf,
    device: String,
    operation: String,
    correlation_id: String,
    acquired_at: Instant,
}

impl Drop for DeviceLockGuard {
    fn drop(&mut self) {
        let Some(mut file) = self.file.take() else {
            return;
        };
        if let Err(error) = write_metadata(
            &mut file,
            &self.device,
            &self.operation,
            &self.correlation_id,
            "released",
        ) {
            tracing::warn!(
                event = "device_lock_metadata_failed",
                device = %self.device,
                operation = %self.operation,
                correlation_id = %self.correlation_id,
                error = %error,
                "failed to update device lock release metadata"
            );
        }
        if let Err(error) = unlock(&file) {
            tracing::error!(
                event = "device_lock_release_failed",
                device = %self.device,
                operation = %self.operation,
                correlation_id = %self.correlation_id,
                error = %error,
                lock_path = %self.path.display(),
                "failed to release cross-process device lock"
            );
            return;
        }
        tracing::info!(
            event = "device_lock_released",
            device = %self.device,
            operation = %self.operation,
            correlation_id = %self.correlation_id,
            held_ms = self.acquired_at.elapsed().as_millis() as u64,
            "released cross-process device lock"
        );
    }
}

#[derive(Debug)]
enum LockError {
    WouldBlock,
    Other(String),
}

fn try_lock(file: &File) -> Result<(), LockError> {
    use rustix::fs::{FlockOperation, flock};

    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Err(LockError::WouldBlock),
        Err(e) => Err(LockError::Other(e.to_string())),
    }
}

fn unlock(file: &File) -> Result<(), std::io::Error> {
    use rustix::fs::{FlockOperation, flock};

    flock(file, FlockOperation::Unlock).map_err(std::io::Error::from)
}

fn prepare_directory(directory: &Path) -> Result<(), DeviceLockError> {
    if let Ok(metadata) = std::fs::symlink_metadata(directory) {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(DeviceLockError::other(
                "startup",
                format!(
                    "lock directory {} must be a real directory",
                    directory.display()
                ),
            ));
        }
        secure_directory_permissions(directory)?;
        return Ok(());
    }

    std::fs::create_dir_all(directory).map_err(|error| {
        DeviceLockError::other(
            "startup",
            format!("creating lock directory {}: {error}", directory.display()),
        )
    })?;

    let metadata = std::fs::symlink_metadata(directory).map_err(|error| {
        DeviceLockError::other(
            "startup",
            format!("checking lock directory {}: {error}", directory.display()),
        )
    })?;

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(DeviceLockError::other(
            "startup",
            format!(
                "lock directory {} must be a real directory",
                directory.display()
            ),
        ));
    }

    secure_directory_permissions(directory)?;
    Ok(())
}

fn secure_directory_permissions(directory: &Path) -> Result<(), DeviceLockError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                DeviceLockError::other(
                    "startup",
                    format!(
                        "setting lock directory permissions on {}: {error}",
                        directory.display()
                    ),
                )
            },
        )?;
    }
    Ok(())
}

fn open_lock_file(path: &Path, device: &str) -> Result<File, DeviceLockError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);

    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);

        // Use rustix constants instead of libc
        let flags = OFlags::CLOEXEC.bits() | OFlags::NOFOLLOW.bits();
        options.custom_flags(flags as i32);
    }

    let file = options.open(path).map_err(|error| {
        DeviceLockError::other(
            device,
            format!("opening lock file {}: {error}", path.display()),
        )
    })?;

    let metadata = file.metadata().map_err(|error| {
        DeviceLockError::other(
            device,
            format!("checking lock file {}: {error}", path.display()),
        )
    })?;

    if !metadata.is_file() {
        return Err(DeviceLockError::other(
            device,
            format!("lock path {} is not a regular file", path.display()),
        ));
    }

    Ok(file)
}

fn write_metadata(
    file: &mut File,
    device: &str,
    operation: &str,
    correlation_id: &str,
    state: &str,
) -> Result<(), std::io::Error> {
    let timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();

    let metadata = serde_json::json!({
        "state": state,
        "device": device,
        "operation": operation,
        "correlation_id": correlation_id,
        "pid": std::process::id(),
        "timestamp_unix_ms": timestamp_ms,
    });

    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    serde_json::to_writer(&mut *file, &metadata)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn separate_managers_serialize_operations() {
        let directory = tempfile::tempdir().unwrap();
        let first_mgr = FlockDeviceLock::with_timing(
            directory.path(),
            Duration::from_millis(50),
            Duration::from_millis(5),
        )
        .unwrap();
        let second_mgr = first_mgr.clone();

        let guard = first_mgr
            .acquire("device-01", "upgrade", "op-1")
            .await
            .unwrap();

        let error = second_mgr
            .acquire("device-01", "config-change", "op-2")
            .await
            .unwrap_err();

        assert!(matches!(error, DeviceLockError::Busy { .. }));
        drop(guard);

        second_mgr
            .acquire("device-01", "config-change", "op-2")
            .await
            .unwrap();
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn different_devices_do_not_block_each_other() {
        let directory = tempfile::tempdir().unwrap();
        let lock = FlockDeviceLock::with_timing(
            directory.path(),
            Duration::from_millis(50),
            Duration::from_millis(5),
        )
        .unwrap();

        let _first = lock.acquire("device-01", "op1", "corr-1").await.unwrap();
        let _second = lock.acquire("device-02", "op2", "corr-2").await.unwrap();
    }

    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn cancellation_stops_lock_wait() {
        let directory = tempfile::tempdir().unwrap();
        let lock = FlockDeviceLock::with_timing(
            directory.path(),
            Duration::from_secs(10),
            Duration::from_millis(5),
        )
        .unwrap();

        let _guard = lock.acquire("device-01", "op1", "corr-1").await.unwrap();

        let cancellation = CancellationToken::new();
        cancellation.cancel();

        let error = lock
            .acquire_cancellable("device-01", "op2", "corr-2", &cancellation)
            .await
            .unwrap_err();

        assert!(matches!(error, DeviceLockError::Cancelled));
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn symlink_directory_is_rejected() {
        #[cfg(unix)]
        {
            let root = tempfile::tempdir().unwrap();
            let target = root.path().join("target");
            let link = root.path().join("link");
            std::fs::create_dir(&target).unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(FlockDeviceLock::for_directory(link).is_err());
        }
    }

    /// Cross-process exclusion test using separate file descriptors.
    ///
    /// This test opens the same lock file with two independent file descriptors,
    /// simulating what happens when two processes open the file. The kernel's
    /// file-lock mechanism ensures mutual exclusion even across these separate
    /// file handles, proving that the lock survives beyond a single file descriptor
    /// and provides true cross-process semantics.
    #[allow(clippy::unwrap_used)]
    #[tokio::test]
    async fn cross_process_exclusion_with_separate_file_descriptors() {
        let directory = tempfile::tempdir().unwrap();
        let device = "device-xproc";

        // Compute the lock path the same way FlockDeviceLock does.
        let digest: [u8; 32] = Sha256::digest(device.as_bytes()).into();
        let mut filename = String::with_capacity(64 + ".lock".len());
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut filename, "{byte:02x}").unwrap();
        }
        filename.push_str(".lock");
        let lock_path = directory.path().join(filename);

        // Open and lock via the first file descriptor.
        let mut opts1 = OpenOptions::new();
        opts1.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts1.mode(0o600);
        }
        let file1 = opts1.open(&lock_path).unwrap();
        try_lock(&file1).unwrap();

        // Open a second, independent file descriptor to the same lock file.
        // This simulates a second process opening the file.
        let mut opts2 = OpenOptions::new();
        opts2.read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts2.mode(0o600);
        }
        let file2 = opts2.open(&lock_path).unwrap();

        // The second FD cannot acquire the lock while the first holds it.
        let result = try_lock(&file2);
        assert!(matches!(result, Err(LockError::WouldBlock)));

        // Release the lock on file1.
        unlock(&file1).unwrap();

        // Now file2 can acquire it.
        try_lock(&file2).unwrap();
    }
}
