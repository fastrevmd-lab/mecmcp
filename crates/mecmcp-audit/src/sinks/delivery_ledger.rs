//! Delivery status tracking for evidence segments.
//!
//! The ledger records delivery attempts and outcomes in a separate file from the
//! hashed evidence records, ensuring that delivery metadata never mutates the
//! immutable chain.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Unique identifier for a segment: (server_id, run_id, segment_seq).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SegmentId {
    /// Originating audit server identifier.
    pub server_id: String,
    /// Audit run identifier.
    pub run_id: String,
    /// Sequence number within this run (0-based).
    pub segment_seq: u64,
}

/// Delivery status for a segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum DeliveryStatus {
    /// Segment is spooled but not yet delivered.
    Pending,
    /// Segment was successfully delivered to SSDF.
    Delivered {
        /// Timestamp of successful delivery (RFC3339).
        delivered_at: String,
    },
    /// Delivery failed and will be retried.
    Failed {
        /// Last failure timestamp (RFC3339).
        failed_at: String,
        /// Error message from the last attempt.
        error: String,
        /// Number of attempts made so far.
        attempts: u64,
    },
}

/// Ledger entry for a segment delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LedgerEntry {
    server_id: String,
    run_id: String,
    segment_seq: u64,
    #[serde(flatten)]
    status: DeliveryStatus,
}

/// Errors that can occur when working with the delivery ledger.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// I/O error reading or writing the ledger.
    #[error("ledger I/O error: {0}")]
    Io(#[from] io::Error),
    /// Invalid ledger entry format.
    #[error("invalid ledger entry: {0}")]
    InvalidEntry(String),
}

/// Delivery ledger: tracks delivery status for evidence segments.
///
/// The ledger is an append-only file of JSON lines. Each line is a status
/// update for a segment. The latest status for each segment is kept in memory.
pub struct DeliveryLedger {
    path: PathBuf,
    file: File,
    /// In-memory index of the latest status for each segment.
    index: HashMap<SegmentId, DeliveryStatus>,
}

impl DeliveryLedger {
    /// Open or create a delivery ledger at the given path.
    ///
    /// The ledger file is opened in append mode. Existing entries are loaded
    /// into the in-memory index.
    pub fn open(path: &Path) -> Result<Self, LedgerError> {
        // Anchor the path before storing it (same reasoning as FileHandle).
        let path = std::path::absolute(path)?;

        // Open for append, create if absent.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)?;

        // A crash or a full disk partway through `write_entry` leaves a final
        // line with no terminating newline. That is an interrupted append, not
        // corruption, and it must not be fatal: the sink treats a ledger failure
        // as survivable *because* the segment is already safe in the outbox, and
        // that reasoning collapses if the next start cannot open the ledger to
        // replay it. Drop the stump and truncate, so the next append does not
        // weld itself onto a partial record.
        //
        // Only the last line gets this benefit. A malformed line anywhere else
        // cannot be explained by an interrupted append, and rewritten history is
        // the one thing this subsystem exists to notice.
        let mut contents = String::new();
        {
            let mut reader = BufReader::new(&file);
            reader.read_to_string(&mut contents)?;
        }
        let torn_tail = match contents.rfind('\n') {
            Some(index) if index + 1 < contents.len() => contents.len() - (index + 1),
            None if !contents.is_empty() => contents.len(),
            _ => 0,
        };
        if torn_tail > 0 {
            let keep = contents.len() - torn_tail;
            tracing::warn!(
                bytes = torn_tail,
                path = %path.display(),
                "discarding an unterminated final ledger entry left by an interrupted write"
            );
            file.set_len(keep as u64)?;
            file.sync_all()?;
            contents.truncate(keep);
        }

        // Load existing entries into the index.
        let mut index = HashMap::new();
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry: LedgerEntry = serde_json::from_str(line).map_err(|e| {
                LedgerError::InvalidEntry(format!("failed to parse ledger entry: {}", e))
            })?;
            let id = SegmentId {
                server_id: entry.server_id,
                run_id: entry.run_id,
                segment_seq: entry.segment_seq,
            };
            index.insert(id, entry.status);
        }

        // Reopen for append-only writing (the read handle above is consumed).
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self { path, file, index })
    }

    /// Get the current delivery status for a segment.
    pub fn status(&self, id: &SegmentId) -> Option<&DeliveryStatus> {
        self.index.get(id)
    }

    /// Mark a segment as pending delivery.
    pub fn mark_pending(&mut self, id: SegmentId) -> Result<(), LedgerError> {
        self.write_entry(&id, DeliveryStatus::Pending)
    }

    /// Mark a segment as successfully delivered.
    pub fn mark_delivered(
        &mut self,
        id: SegmentId,
        delivered_at: String,
    ) -> Result<(), LedgerError> {
        self.write_entry(&id, DeliveryStatus::Delivered { delivered_at })
    }

    /// Mark a segment delivery as failed.
    pub fn mark_failed(
        &mut self,
        id: SegmentId,
        failed_at: String,
        error: String,
        attempts: u64,
    ) -> Result<(), LedgerError> {
        self.write_entry(
            &id,
            DeliveryStatus::Failed {
                failed_at,
                error,
                attempts,
            },
        )
    }

    /// Get all segments with pending delivery.
    pub fn pending(&self) -> Vec<SegmentId> {
        self.index
            .iter()
            .filter_map(|(id, status)| {
                if matches!(
                    status,
                    DeliveryStatus::Pending | DeliveryStatus::Failed { .. }
                ) {
                    Some(id.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// The path to the ledger file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Write an entry to the ledger and update the index.
    fn write_entry(&mut self, id: &SegmentId, status: DeliveryStatus) -> Result<(), LedgerError> {
        let entry = LedgerEntry {
            server_id: id.server_id.clone(),
            run_id: id.run_id.clone(),
            segment_seq: id.segment_seq,
            status: status.clone(),
        };
        let mut line = serde_json::to_string(&entry)
            .map_err(|e| LedgerError::InvalidEntry(format!("failed to serialize entry: {}", e)))?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.index.insert(id.clone(), status);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_id(seq: u64) -> SegmentId {
        SegmentId {
            server_id: "server_test".to_string(),
            run_id: "run_test".to_string(),
            segment_seq: seq,
        }
    }

    #[test]
    fn new_ledger_is_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let ledger = DeliveryLedger::open(&path).unwrap();
        assert!(ledger.pending().is_empty());
    }

    #[test]
    fn mark_pending_records_and_retrieves_status() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let mut ledger = DeliveryLedger::open(&path).unwrap();

        let id = make_id(0);
        ledger.mark_pending(id.clone()).unwrap();

        assert_eq!(ledger.status(&id), Some(&DeliveryStatus::Pending));
        assert_eq!(ledger.pending(), vec![id]);
    }

    #[test]
    fn mark_delivered_updates_status() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let mut ledger = DeliveryLedger::open(&path).unwrap();

        let id = make_id(0);
        ledger.mark_pending(id.clone()).unwrap();
        ledger
            .mark_delivered(id.clone(), "2026-08-09T12:00:00Z".to_string())
            .unwrap();

        assert!(matches!(
            ledger.status(&id),
            Some(DeliveryStatus::Delivered { .. })
        ));
        assert!(ledger.pending().is_empty());
    }

    #[test]
    fn mark_failed_keeps_segment_pending() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.jsonl");
        let mut ledger = DeliveryLedger::open(&path).unwrap();

        let id = make_id(0);
        ledger.mark_pending(id.clone()).unwrap();
        ledger
            .mark_failed(
                id.clone(),
                "2026-08-09T12:00:00Z".to_string(),
                "connection refused".to_string(),
                1,
            )
            .unwrap();

        assert!(matches!(
            ledger.status(&id),
            Some(DeliveryStatus::Failed { .. })
        ));
        assert_eq!(ledger.pending(), vec![id]);
    }

    #[test]
    fn ledger_survives_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.jsonl");

        let id = make_id(0);
        {
            let mut ledger = DeliveryLedger::open(&path).unwrap();
            ledger.mark_pending(id.clone()).unwrap();
        }

        // Reopen and verify the status persisted.
        let ledger = DeliveryLedger::open(&path).unwrap();
        assert_eq!(ledger.status(&id), Some(&DeliveryStatus::Pending));
        assert_eq!(ledger.pending(), vec![id]);
    }

    #[test]
    fn latest_status_wins_after_reopen() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("ledger.jsonl");

        let id = make_id(0);
        {
            let mut ledger = DeliveryLedger::open(&path).unwrap();
            ledger.mark_pending(id.clone()).unwrap();
            ledger
                .mark_delivered(id.clone(), "2026-08-09T12:00:00Z".to_string())
                .unwrap();
        }

        // Reopen and verify only the latest status is active.
        let ledger = DeliveryLedger::open(&path).unwrap();
        assert!(matches!(
            ledger.status(&id),
            Some(DeliveryStatus::Delivered { .. })
        ));
        assert!(ledger.pending().is_empty());
    }
}
