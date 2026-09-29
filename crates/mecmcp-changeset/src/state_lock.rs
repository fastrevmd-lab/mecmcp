//! Cross-process advisory lock guarding a read-modify-write cycle against the
//! changeset state file (MEC-540).
//!
//! `write_state` already replaces the state file with an atomic rename, so a
//! reader never observes a half-written file. What it does not prevent is two
//! processes each doing read → mutate → write against the same path: the
//! second writer's snapshot was taken before the first writer's change
//! landed, so its write silently reverts that change once both renames have
//! happened. [`StateFileLock`] closes that window by serializing the whole
//! cycle, not just the write, across processes.

use crate::persistence::PersistenceError;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// Holds an exclusive, cross-process lock for the lifetime of a
/// read-modify-write cycle against a changeset state file.
///
/// Backed by a sibling `<state file>.lock` file rather than the state file
/// itself: `write_state` replaces the state file by renaming a new inode
/// into place, and a lock held against the old inode would not apply to the
/// replacement, silently stopping being effective the moment the first
/// writer under the lock committed. The lock file's identity never changes,
/// so every acquirer locks the same inode.
///
/// The lock is released when this value drops; the kernel also releases it
/// if the holding process dies, so a crash cannot wedge every future
/// acquirer.
#[derive(Debug)]
pub(crate) struct StateFileLock {
    file: File,
}

impl StateFileLock {
    /// Blocks until the lock on `state_path`'s sibling lock file is
    /// acquired.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file cannot be opened (for example, its
    /// parent directory does not exist or is not writable) or the `flock`
    /// syscall itself fails.
    pub(crate) fn acquire(state_path: &Path) -> Result<Self, PersistenceError> {
        let lock_path = lock_path_for(state_path);
        let file = open_lock_file(&lock_path)?;
        lock_exclusive(&file).map_err(|error| {
            PersistenceError::new(format!(
                "locking changeset state '{}': {error}",
                lock_path.display()
            ))
        })?;
        Ok(Self { file })
    }
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        // Best-effort: the kernel releases the lock when the fd closes at
        // the end of this drop regardless, so a failed explicit unlock does
        // not wedge the next acquirer.
        let _ = unlock(&self.file);
    }
}

fn lock_path_for(state_path: &Path) -> PathBuf {
    let mut name = state_path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".lock");
    state_path.with_file_name(name)
}

fn open_lock_file(path: &Path) -> Result<File, PersistenceError> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);

    #[cfg(unix)]
    {
        use rustix::fs::OFlags;
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
        let flags = (OFlags::CLOEXEC | OFlags::NOFOLLOW).bits();
        options.custom_flags(flags as i32);
    }

    options.open(path).map_err(|error| {
        PersistenceError::new(format!(
            "opening changeset state lock file '{}': {error}",
            path.display()
        ))
    })
}

fn lock_exclusive(file: &File) -> std::io::Result<()> {
    use rustix::fs::{FlockOperation, flock};

    // Blocking: the whole point is for a second RMW cycle to wait for the
    // first to finish rather than racing it. Callers hold this for the
    // short duration of a read-modify-write, not across long-lived server
    // operation.
    flock(file, FlockOperation::LockExclusive).map_err(std::io::Error::from)
}

fn unlock(file: &File) -> std::io::Result<()> {
    use rustix::fs::{FlockOperation, flock};

    flock(file, FlockOperation::Unlock).map_err(std::io::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn second_acquirer_blocks_until_first_releases() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");

        let first = StateFileLock::acquire(&state_path).unwrap();

        let (tx, rx) = mpsc::channel();
        let second_path = state_path.clone();
        let handle = std::thread::spawn(move || {
            let _second = StateFileLock::acquire(&second_path).unwrap();
            tx.send(()).unwrap();
        });

        // The second acquirer must still be blocked shortly after the first
        // took the lock.
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "second acquirer should not have progressed while the first held the lock"
        );

        drop(first);

        rx.recv_timeout(Duration::from_secs(5))
            .expect("second acquirer should proceed once the first releases");
        handle.join().unwrap();
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn lock_path_is_a_sibling_of_the_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let _lock = StateFileLock::acquire(&state_path).unwrap();
        assert!(dir.path().join("state.json.lock").exists());
    }
}
