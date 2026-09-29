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
    /// Blocks until the lock on `state_path`'s sibling `.lock` file is
    /// acquired.
    ///
    /// This is the read-modify-write lock: short-lived, held only for the
    /// duration of a single read-modify-write cycle against the state file.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file cannot be opened (for example, its
    /// parent directory does not exist or is not writable) or the `flock`
    /// syscall itself fails.
    pub(crate) fn acquire(state_path: &Path) -> Result<Self, PersistenceError> {
        let lock_path = lock_path_with_suffix(state_path, "lock");
        let file = open_lock_file(&lock_path)?;
        lock_exclusive(&file).map_err(|error| {
            PersistenceError::new(format!(
                "locking changeset state '{}': {error}",
                lock_path.display()
            ))
        })?;
        Ok(Self { file })
    }

    /// Tries, without blocking, to take the lock on `state_path`'s sibling
    /// `.owner` file.
    ///
    /// This is the single-writer lock: a live server holds it for the whole
    /// time it has `state_path` loaded, distinct from and never taken at the
    /// same time in the same process as the short-lived `.lock` file above.
    /// Offline resolution (`resolve_persisted_operation`) uses this to refuse
    /// to run while a server is up, rather than serializing behind it and
    /// silently reverting whatever the server persists next (MEC-540 review,
    /// finding 2).
    ///
    /// Returns `Ok(None)` rather than blocking when another process already
    /// holds the lock — offline resolution and server startup both need to
    /// fail fast and say so, not hang waiting for the other side to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file cannot be opened, or the `flock`
    /// syscall itself fails for a reason other than the lock being held.
    pub(crate) fn try_acquire_owner(state_path: &Path) -> Result<Option<Self>, PersistenceError> {
        let lock_path = lock_path_with_suffix(state_path, "owner");
        let file = open_lock_file(&lock_path)?;
        match try_lock_exclusive(&file) {
            Ok(true) => Ok(Some(Self { file })),
            Ok(false) => Ok(None),
            Err(error) => Err(PersistenceError::new(format!(
                "locking changeset state owner '{}': {error}",
                lock_path.display()
            ))),
        }
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

fn lock_path_with_suffix(state_path: &Path, suffix: &str) -> PathBuf {
    let mut name = state_path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".");
    name.push(suffix);
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

/// Returns `Ok(true)` if the lock was taken, `Ok(false)` if another holder
/// already has it, and `Err` for any other failure.
fn try_lock_exclusive(file: &File) -> std::io::Result<bool> {
    use rustix::fs::{FlockOperation, flock};

    match flock(file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(error) => Err(std::io::Error::from(error)),
    }
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

    #[allow(clippy::unwrap_used)]
    #[test]
    fn owner_lock_path_is_a_sibling_of_the_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let _owner = StateFileLock::try_acquire_owner(&state_path)
            .unwrap()
            .unwrap();
        assert!(dir.path().join("state.json.owner").exists());
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn try_acquire_owner_refuses_while_another_holder_has_it() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");

        let first = StateFileLock::try_acquire_owner(&state_path)
            .unwrap()
            .expect("first acquirer should get the owner lock");

        assert!(
            StateFileLock::try_acquire_owner(&state_path)
                .unwrap()
                .is_none(),
            "a second acquirer must not get the owner lock while the first holds it"
        );

        drop(first);

        assert!(
            StateFileLock::try_acquire_owner(&state_path)
                .unwrap()
                .is_some(),
            "the owner lock must become available once the first holder releases it"
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn owner_lock_and_rmw_lock_are_independent() {
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");

        let _owner = StateFileLock::try_acquire_owner(&state_path)
            .unwrap()
            .unwrap();
        // The short-lived RMW lock must still be acquirable while the
        // long-lived owner lock is held by the same or another process --
        // they guard different things and must not contend with each other.
        let _rmw = StateFileLock::acquire(&state_path).unwrap();
    }
}
