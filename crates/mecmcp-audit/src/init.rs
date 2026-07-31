//! Configurable tracing/audit sinks: stderr (text or JSON), an optional
//! dedicated JSON audit file, and an optional native journald target.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// stderr output format for logs and audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFormat {
    /// Emit logs and audit events as human-readable text.
    Text,
    /// Emit logs and audit events as JSON lines.
    Json,
}

impl AuditFormat {
    /// Parse from a CLI/env string; unknown → Text.
    pub fn parse(s: &str) -> Self {
        if s.eq_ignore_ascii_case("json") {
            AuditFormat::Json
        } else {
            AuditFormat::Text
        }
    }
}

/// Audit / logging configuration.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Output format for stderr.
    pub format: AuditFormat,
    /// When set, `target="audit"` events are also appended as JSON lines here.
    pub audit_log_file: Option<PathBuf>,
    /// When set, per-field redaction is applied to emitted audit events.
    pub redaction: Option<crate::redact::AuditRedaction>,
    /// When true, `target="audit"` events are also sent to journald natively.
    pub journald: bool,
}

/// A cloneable append writer over a shared file handle.
///
/// The path is kept alongside the descriptor so the sink can be reopened in
/// place — see [`FileHandle::reopen`]. It is behind an `Arc` because
/// `MakeWriter` clones this per event, and a `PathBuf` clone on that path would
/// be an allocation per audit record.
#[derive(Clone)]
pub struct FileHandle {
    file: Arc<Mutex<File>>,
    path: Arc<Path>,
}

impl FileHandle {
    /// Open `path` for append, creating it if absent.
    ///
    /// # Errors
    /// Returns the underlying I/O error if the file cannot be opened.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileHandle {
            file: Arc::new(Mutex::new(f)),
            path: Arc::from(path),
        })
    }

    /// Reopen the same path, replacing the descriptor in place.
    ///
    /// This is the lossless half of log rotation: rename the file, signal the
    /// process, and every clone of this handle — including the one the
    /// subscriber holds — starts writing to the new inode. `copytruncate` is the
    /// alternative, and it drops whatever is written between the copy finishing
    /// and the truncate executing. On an audit log the point is that the record
    /// is complete (#198).
    ///
    /// The new file is opened *before* the lock is taken, so a bad path fails
    /// without disturbing the sink that is currently working.
    ///
    /// # Errors
    /// Returns the underlying I/O error if the path cannot be reopened.
    pub fn reopen(&self) -> std::io::Result<()> {
        let fresh = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&*self.path)?;

        let mut guard = self.file.lock().expect("audit file mutex not poisoned");
        // `File` is unbuffered, so a write that already returned is in the
        // kernel and nothing is stranded in userspace by the swap. Writes
        // themselves take this same lock, so none can straddle it.
        *guard = fresh;
        Ok(())
    }

    /// The path this handle writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Write for FileHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file
            .lock()
            .expect("audit file mutex not poisoned")
            .write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .lock()
            .expect("audit file mutex not poisoned")
            .flush()
    }
}

impl<'a> MakeWriter<'a> for FileHandle {
    type Writer = FileHandle;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn is_audit(meta: &tracing::Metadata<'_>) -> bool {
    meta.target() == "audit"
}

/// A JSON fmt layer filtered to `target == "audit"`, writing to `handle`.
pub fn audit_file_layer<S>(handle: FileHandle) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .json()
        .with_writer(handle)
        .with_filter(filter_fn(is_audit))
}

fn audit_journald_layer<S>(layer: tracing_journald::Layer) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    layer
        .with_field_prefix(Some("AUDIT".to_owned()))
        .with_filter(filter_fn(is_audit))
}

fn make_journald_layer_with<F>(
    enabled: bool,
    factory: F,
) -> io::Result<Option<tracing_journald::Layer>>
where
    F: FnOnce() -> io::Result<tracing_journald::Layer>,
{
    if enabled {
        factory().map(Some)
    } else {
        Ok(None)
    }
}

/// A live audit-file sink that can be reopened for log rotation.
///
/// Returned only when a file sink was configured *and* this call installed the
/// subscriber. That second condition matters: `init_tracing` is idempotent, so a
/// later call builds layers that are then discarded, and a handle from such a
/// call would reopen a file nothing is writing to. Rather than hand back a
/// plausible no-op, those calls return `None`.
///
/// `Debug` prints the path only — there is nothing sensitive in it, and a
/// caller logging its own audit configuration should be able to.
#[derive(Clone)]
pub struct AuditFileSink {
    handle: FileHandle,
}

impl std::fmt::Debug for AuditFileSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditFileSink")
            .field("path", &self.handle.path())
            .finish()
    }
}

impl AuditFileSink {
    /// Reopen the audit file in place, for lossless rotation on SIGHUP.
    ///
    /// # Errors
    /// Returns the underlying I/O error if the path cannot be reopened. The
    /// existing sink keeps working when this fails.
    pub fn reopen(&self) -> io::Result<()> {
        self.handle.reopen()
    }

    /// The path being written to.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.handle.path()
    }
}

/// Initialize the global subscriber. Idempotent (`try_init`).
///
/// Returns [`AuditFileSink`] when an audit file was configured and this call
/// installed the subscriber, so the caller can reopen it on SIGHUP.
///
/// # Errors
///
/// Returns an error when the explicitly enabled journald layer cannot be
/// constructed, **or when a configured audit file cannot be opened**.
///
/// That second case used to be swallowed with `.ok()`: startup succeeded
/// without the requested audit file and without a warning, so an operator could
/// believe durable audit evidence was being appended when the sink was absent
/// because of a bad path or permissions. Silent loss is not an acceptable
/// default for a destination someone explicitly asked for (#158). A caller that
/// genuinely wants best-effort behaviour can leave `audit_log_file` unset, or
/// catch this error itself and decide.
pub fn init_tracing(cfg: &AuditConfig) -> io::Result<Option<AuditFileSink>> {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let stderr = match cfg.format {
        AuditFormat::Text => stderr.boxed(),
        AuditFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .boxed(),
    };
    // `?`, not `.ok()`. See the note on this function.
    let file_handle = cfg
        .audit_log_file
        .as_ref()
        .map(|path| FileHandle::open(path))
        .transpose()?;
    let file_layer = file_handle.clone().map(audit_file_layer);
    let journald_layer =
        make_journald_layer_with(cfg.journald, tracing_journald::layer)?.map(audit_journald_layer);

    let installed = tracing_subscriber::registry()
        .with(env)
        .with(stderr)
        .with(file_layer)
        .with(journald_layer)
        .try_init()
        .is_ok();

    if let Some(redaction) = cfg.redaction.clone() {
        crate::redact::install(redaction);
    }

    // Only hand back a sink that is actually wired to the installed subscriber.
    Ok(file_handle
        .filter(|_| installed)
        .map(|handle| AuditFileSink { handle }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A configured audit file that cannot be opened must fail startup.
    ///
    /// The old `.ok()` returned success with no sink and no warning, so an
    /// operator could believe durable audit evidence was being written when it
    /// was not (#158).
    #[test]
    fn a_configured_audit_file_that_cannot_be_opened_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        // A path whose parent does not exist: open fails, and no amount of
        // create(true) fixes it.
        let unusable = dir.path().join("no-such-dir").join("audit.log");

        let cfg = AuditConfig {
            format: AuditFormat::Json,
            audit_log_file: Some(unusable.clone()),
            redaction: None,
            journald: false,
        };
        let error = init_tracing(&cfg).unwrap_err();
        assert!(
            !unusable.exists(),
            "the file must not have been created behind the error"
        );
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied
            ),
            "expected the underlying open error, got {error:?}"
        );
    }

    /// No configured file means no error and no sink — best effort stays
    /// available by simply not asking for a file.
    #[test]
    fn no_configured_audit_file_is_not_an_error() {
        let cfg = AuditConfig {
            format: AuditFormat::Json,
            audit_log_file: None,
            redaction: None,
            journald: false,
        };
        assert!(init_tracing(&cfg).unwrap().is_none());
    }

    /// Reopen must follow the path, not the inode — that is what makes
    /// rename-then-signal rotation lossless (#198).
    #[test]
    fn reopen_follows_the_path_to_a_new_inode() {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut handle = FileHandle::open(&path).unwrap();

        handle.write_all(b"before-rotation\n").unwrap();
        handle.flush().unwrap();

        // Rotate the way logrotate's default mode does: move the file aside.
        let rotated = dir.path().join("audit.log.1");
        std::fs::rename(&path, &rotated).unwrap();

        // Without a reopen, this write would follow the moved inode.
        handle.reopen().unwrap();
        handle.write_all(b"after-rotation\n").unwrap();
        handle.flush().unwrap();

        let mut fresh = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut fresh)
            .unwrap();
        let mut old = String::new();
        std::fs::File::open(&rotated)
            .unwrap()
            .read_to_string(&mut old)
            .unwrap();

        assert_eq!(
            fresh, "after-rotation\n",
            "new writes must go to the new file"
        );
        assert_eq!(
            old, "before-rotation\n",
            "the rotated file must keep everything written before, losing nothing"
        );
    }

    /// Every clone follows the reopen, including the one the subscriber holds.
    #[test]
    fn reopen_is_visible_to_existing_clones() {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let handle = FileHandle::open(&path).unwrap();
        // `MakeWriter` hands out clones per event; this stands in for one that
        // was already created before the rotation.
        let mut clone = handle.clone();

        std::fs::rename(&path, dir.path().join("audit.log.1")).unwrap();
        handle.reopen().unwrap();

        clone.write_all(b"via-clone\n").unwrap();
        clone.flush().unwrap();

        let mut fresh = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut fresh)
            .unwrap();
        assert_eq!(
            fresh, "via-clone\n",
            "a clone kept writing to the old inode after reopen"
        );
    }

    /// A failed reopen must leave the working sink alone.
    #[test]
    fn a_failed_reopen_keeps_the_existing_sink() {
        use std::io::Read;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut handle = FileHandle::open(&path).unwrap();
        handle.write_all(b"first\n").unwrap();

        // Replace the path with a directory so reopen cannot succeed.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(handle.reopen().is_err(), "reopening a directory must fail");

        // The original descriptor still works.
        handle.write_all(b"second\n").unwrap();
        handle.flush().unwrap();
        std::fs::remove_dir(&path).unwrap();
        // The unlinked original is still readable through the live descriptor's
        // data, which is the point: the sink was not broken by the failure.
        let mut buffer = String::new();
        let _ = std::fs::File::open(dir.path().join("audit.log"))
            .map(|mut f| f.read_to_string(&mut buffer));
    }

    #[test]
    fn json_line_written_to_audit_file_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Build only the file layer + a temporary subscriber (not the global one,
        // which other tests may have set). Verify a target="audit" event lands as JSON.
        let handle = FileHandle::open(&path).unwrap();
        let layer = audit_file_layer(handle.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "audit", tool = "t", result = "ok", "audit");
            tracing::info!(target: "not_audit", "ignored");
        });
        drop(handle); // flush
        let body = std::fs::read_to_string(&path).unwrap();
        let line = body.lines().next().expect("one audit line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["fields"]["tool"], "t");
        assert!(
            !body.contains("ignored"),
            "non-audit events must not hit the audit file"
        );
    }

    #[test]
    fn disabled_journald_does_not_call_factory() {
        let layer =
            make_journald_layer_with(false, || -> std::io::Result<tracing_journald::Layer> {
                panic!("disabled journald must not construct a socket")
            })
            .expect("disabled journald is infallible");

        assert!(layer.is_none());
    }

    #[test]
    fn enabled_journald_propagates_factory_error() {
        let result = make_journald_layer_with(true, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "journal unavailable",
            ))
        });

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("enabled journald must propagate construction failure"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "journal unavailable");
    }
}
