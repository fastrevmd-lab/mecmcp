//! Produces evidence records at the change-set lifecycle points.
//!
//! Everything else in this crate could already describe a change: the four
//! record types, the per-record hash chain, segment closing and archiving, and
//! a sink that delivers closed segments. Nothing created a record. `ssdf.audit`
//! held 20,193 `sovereign` rows and **zero** `evidence` rows, and would have
//! kept holding zero with credentials on every host, because no code path built
//! a segment to spool (mecmcp#292).
//!
//! This is that path. One recorder owns one run's chain; a caller appends at
//! each lifecycle point and takes closed segments to ship.
//!
//! # What the caller must guarantee
//!
//! **One recorder per `(server_id, run_id)`.** `prev_hash` is the previous
//! record's hash, so two recorders on the same run fork the chain — and a fork
//! verifies as two valid chains rather than as an error. The recorder
//! serialises its own appends behind a mutex; it cannot detect a second
//! recorder, and nothing downstream can either.

use crate::ProducedHead;
use crate::evidence::{
    ApplyIntentRecord, ApprovalRecord, ChainSegment, ClosedSegment, EvidenceRecord, ProposalRecord,
    ResultReceipt, append, close,
};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

/// `prev_hash` of the first record in an SSDF evidence chain.
///
/// **Not** [`crate::evidence::GENESIS_PREV_HASH`], which is 64 zeroes for
/// entsafe-audit compatibility. The SSDF contract says the first evidence
/// record per tier carries `prev_hash = ""`, and its verifier reads any other
/// unreachable predecessor as `missing_predecessor` — so seeding with the
/// zero hash would make every chain this produces fail verification at the
/// destination while looking correct here.
const SSDF_CHAIN_START: &str = "";

/// Changes whose context is held awaiting their later lifecycle records.
///
/// Bounds a long-lived server: proposals that never reach a receipt or a
/// rejection would otherwise accumulate for the life of the process.
const MAX_TRACKED_CHANGES: usize = 1024;

/// The head a new run must continue from.
///
/// `local_newest` is what this writer last **produced**, which only
/// [`SsdfSink::produced_head`](crate::SsdfSink::produced_head) can answer — it
/// reads the append-only outbox, so it covers delivered and undelivered
/// segments alike. `remote` is the newest `row_hash` SSDF holds for this
/// writer.
///
/// Local wins whenever it exists, and "produced" rather than "pending" is the
/// whole point. Preferring the newest *unacknowledged* segment forks the chain
/// in a state the sink reaches on its own: `attempt_delivery` blocks only the
/// failed `(server_id, run_id)`, so a later run can overtake a stalled one.
/// The remote head is then a **descendant** of the pending tail, and resuming
/// from the tail makes the next segment a sibling of one that already landed.
///
/// The argument is a [`ProducedHead`] rather than a `String` so that mistake
/// cannot be made again: a pending tail and a remote head are both strings, and
/// an earlier version of this function took whichever the caller had to hand.
///
/// Remote is the fallback only when this writer has produced nothing locally —
/// a fresh spool after a host rebuild — and `None` from both means a genuinely
/// new writer, which starts a root.
///
/// This assumes one writer per `server_id`. Two processes sharing one would
/// make even "newest produced" wrong, and nothing here can detect that; see
/// [`EvidenceRecorder`].
#[must_use]
pub fn resume_head(remote: Option<String>, local_newest: Option<ProducedHead>) -> Option<String> {
    local_newest.map(Into::into).or(remote)
}

/// The durable spool refused a segment.
///
/// Carries the underlying reason as text rather than wrapping the sink's error
/// type: the recorder is deliberately ignorant of which sink it feeds, and a
/// generic parameter here would spread through every caller for no gain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolError(String);

impl SpoolError {
    /// Build one from whatever the spool reported.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }

    /// Why the spool refused.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SpoolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "evidence spool refused the segment: {}", self.0)
    }
}

impl std::error::Error for SpoolError {}

/// The durable persist step a recorder calls before it lets an apply proceed.
type Spool = Box<dyn Fn(ClosedSegment) -> Result<(), SpoolError> + Send + Sync>;

/// How a recorder identifies itself and when it rolls a segment.
#[derive(Debug, Clone)]
pub struct RecorderConfig {
    /// Originating audit server identifier.
    pub server_id: String,
    /// Audit run identifier — one per process lifetime.
    pub run_id: String,
    /// Head hash this run's chain continues from.
    ///
    /// SSDF groups verification by **tier**, and reads an empty `prev_hash` as
    /// a chain root. A recorder that always starts empty therefore mints a new
    /// accepted root on every process start — and once there are many roots,
    /// deleting a whole run leaves no missing predecessor for the verifier to
    /// notice. Pass the tier's current head (the `row_hash` of its newest row,
    /// read as `ssdf_audit_verify`); `None` only when the tier is genuinely
    /// empty.
    pub resume_from: Option<String>,
    /// Records per segment before it closes itself.
    ///
    /// A segment is the unit of delivery, so this trades latency against
    /// request count. Left unbounded, a long-lived server would hold every
    /// record until shutdown and lose them all to a crash.
    pub records_per_segment: usize,
}

impl std::fmt::Debug for EvidenceRecorder {
    /// Deliberately opaque: the state is a live chain behind a mutex, and the
    /// spool is a closure. Printing the config identifies the writer, which is
    /// what a reader of a `Debug` line actually wants.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceRecorder")
            .field("server_id", &self.config.server_id)
            .field("run_id", &self.config.run_id)
            .field("has_spool", &self.spool.is_some())
            .finish()
    }
}

/// Appends evidence records to a run's chain and rolls segments.
pub struct EvidenceRecorder {
    config: RecorderConfig,
    state: Mutex<RecorderState>,
    /// Durable sink for a segment that must survive the next instruction.
    ///
    /// Without one, [`apply_intent`](Self::apply_intent) can only reach memory,
    /// and a crash during the device call it precedes loses the very record
    /// that was supposed to prove the attempt happened.
    spool: Option<Spool>,
}

struct RecorderState {
    current: ChainSegment,
    next_seq: u64,
    /// Head hash of the last closed segment, linking the next one to it.
    prev_head: String,
    closed: Vec<ClosedSegment>,
    /// What the proposal said, keyed by **changeset**, so later records
    /// describe the same change rather than blanks.
    ///
    /// Not by `request_id`: that identifies one MCP call, and proposal,
    /// approval and apply are three separate calls with three different values.
    /// Keying on it looks right and misses every time in production, which is
    /// the failure this map exists to prevent.
    context: HashMap<String, ChangeContext>,
    /// Insertion order of `context` keys, oldest first.
    ///
    /// `HashMap` iteration order is randomised, so evicting `keys().next()`
    /// drops an arbitrary entry — quite possibly a change still mid-lifecycle,
    /// whose approval and receipt would then emit the blank fields this map
    /// exists to prevent. The oldest is the only defensible victim.
    context_order: VecDeque<String>,
}

/// The identifying facts of one change, carried across its lifecycle.
///
/// Without this, `approval` lands with no `device_id` and no `diff_hash`, and a
/// receipt lands with no `principal` — rows that cannot establish that the
/// approval and the result concern the change that was proposed, which is the
/// only thing the evidence tier is for.
#[derive(Debug, Clone, Default)]
struct ChangeContext {
    device_id: String,
    principal: String,
    diff_hash: String,
}

impl EvidenceRecorder {
    /// Start a run's chain.
    #[must_use]
    pub fn new(config: RecorderConfig) -> Self {
        let start = config
            .resume_from
            .clone()
            .unwrap_or_else(|| SSDF_CHAIN_START.to_owned());
        let current = ChainSegment::new(
            config.run_id.clone(),
            config.server_id.clone(),
            0,
            start.clone(),
        );
        Self {
            state: Mutex::new(RecorderState {
                current,
                next_seq: 1,
                prev_head: start,
                closed: Vec::new(),
                context: HashMap::new(),
                context_order: VecDeque::new(),
            }),
            config,
            spool: None,
        }
    }

    /// Attach the durable spool that [`apply_intent`](Self::apply_intent) needs.
    ///
    /// The callback must persist the segment before it returns — spooling to a
    /// file that is fsynced, typically `SsdfSink::spool`. A callback that only
    /// queues in memory reinstates exactly the gap this exists to close, and one
    /// that reports success it did not achieve reinstates it invisibly.
    #[must_use]
    pub fn with_spool(
        mut self,
        spool: impl Fn(ClosedSegment) -> Result<(), SpoolError> + Send + Sync + 'static,
    ) -> Self {
        self.spool = Some(Box::new(spool));
        self
    }

    /// Spool to an [`SsdfSink`](crate::SsdfSink) — the wiring #292 asks for.
    ///
    /// Both halves existed and were tested separately; nothing joined them, so
    /// a correctly configured deployment still wrote nothing. This is that
    /// join, offered here rather than hand-rolled per server so the error
    /// mapping is made once.
    ///
    /// Only the *spool* is fail-closed. Delivery is not: `SsdfSink::spool`
    /// returns once the segment is fsynced to the outbox, and an unreachable
    /// ClickHouse is dealt with later by `attempt_delivery`. A caller is
    /// therefore blocked only when the record could not be made durable at
    /// all — which is the case where proceeding would leave no trace.
    #[must_use]
    pub fn spooling_to(self, sink: std::sync::Arc<crate::SsdfSink>) -> Self {
        self.with_spool(move |segment| {
            sink.spool(segment)
                .map_err(|error| SpoolError::new(error.to_string()))
        })
    }

    /// A change was proposed.
    pub fn proposal(
        &self,
        request_id: &str,
        changeset_id: &str,
        device_id: &str,
        principal: &str,
        diff_hash: &str,
    ) {
        self.remember(
            changeset_id,
            ChangeContext {
                device_id: device_id.to_owned(),
                principal: principal.to_owned(),
                diff_hash: diff_hash.to_owned(),
            },
        );
        self.append(EvidenceRecord::Proposal(ProposalRecord {
            request_id: request_id.to_owned(),
            changeset_id: changeset_id.to_owned(),
            device_id: device_id.to_owned(),
            principal: principal.to_owned(),
            diff_hash: diff_hash.to_owned(),
            timestamp: now(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            metadata: None,
        }));
    }

    /// A human decided on a proposal.
    ///
    /// `decision` is recorded whether it is `"approved"` or `"rejected"`: a
    /// refusal is evidence too, and omitting it would leave the trail unable to
    /// show that anyone declined.
    pub fn approval(&self, request_id: &str, changeset_id: &str, approver: &str, decision: &str) {
        let context = self.context_for(changeset_id);
        self.append(EvidenceRecord::Approval(ApprovalRecord {
            request_id: request_id.to_owned(),
            changeset_id: changeset_id.to_owned(),
            device_id: context.device_id,
            principal: approver.to_owned(),
            diff_hash: context.diff_hash,
            timestamp: now(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            approver: approver.to_owned(),
            decision: decision.to_owned(),
            metadata: None,
        }));
        if decision != "approved" {
            // A rejected change never reaches a receipt, so this is its
            // terminal point.
            self.forget(changeset_id);
        }
    }

    /// The approval gate was deliberately waived.
    ///
    /// Distinct from [`approval`](Self::approval) on purpose. A waiver is not a
    /// second person's decision, so `approver` stays empty rather than naming
    /// someone who did not approve — writing the owner there would forge the
    /// exact fact two-person control exists to establish. `decision` is
    /// `approved` because the waiver did authorize the apply, and the contract's
    /// `decision` column admits only `approved`, `rejected` or empty; what makes
    /// it a waiver rather than an approval lives in `metadata`.
    ///
    /// Without this, the trail jumps from proposal straight to apply intent, and
    /// a legitimate exception is indistinguishable from a bypassed gate — which
    /// is the normal case on a lab-mode server, not an edge case.
    pub fn approval_waived(&self, request_id: &str, changeset_id: &str, kind: &str, reason: &str) {
        let context = self.context_for(changeset_id);
        self.append(EvidenceRecord::Approval(ApprovalRecord {
            request_id: request_id.to_owned(),
            changeset_id: changeset_id.to_owned(),
            device_id: context.device_id,
            principal: context.principal,
            diff_hash: context.diff_hash,
            timestamp: now(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            approver: String::new(),
            decision: "approved".to_owned(),
            metadata: Some(serde_json::json!({ "waived": kind, "reason": reason })),
        }));
    }

    /// Execution is about to start.
    ///
    /// Written *before* the device is touched, and — when a spool is attached —
    /// **persisted before this returns**. That is the point: if the process dies
    /// during the device call, the trail still shows the attempt. A record
    /// written only on success cannot describe the case that matters most, and
    /// one held in memory until a later flush cannot either.
    ///
    /// Without a spool this only reaches memory, so
    /// [`with_spool`](Self::with_spool) is what makes the guarantee real.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError`] when the spool could not persist the record. The
    /// caller must treat that as a refusal and not touch the device: an applied
    /// change with no record that it was attempted is the invisible gap this
    /// whole chain exists to prevent. The unwritten records stay with the
    /// recorder for a later flush.
    pub fn apply_intent(
        &self,
        request_id: &str,
        changeset_id: &str,
        device_id: &str,
        principal: &str,
    ) -> Result<(), SpoolError> {
        let context = self.context_for(changeset_id);
        self.append(EvidenceRecord::ApplyIntent(ApplyIntentRecord {
            request_id: request_id.to_owned(),
            changeset_id: changeset_id.to_owned(),
            device_id: device_id.to_owned(),
            principal: principal.to_owned(),
            diff_hash: context.diff_hash,
            timestamp: now(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            metadata: None,
        }));
        // Close and persist now. The caller is about to touch a device, and a
        // record that survives only in memory proves nothing about a crash.
        self.flush_after_append()
    }

    /// The device answered.
    pub fn result_receipt(
        &self,
        request_id: &str,
        changeset_id: &str,
        device_id: &str,
        succeeded: bool,
        error: &str,
    ) {
        let context = self.context_for(changeset_id);
        self.append(EvidenceRecord::ResultReceipt(ResultReceipt {
            request_id: request_id.to_owned(),
            changeset_id: changeset_id.to_owned(),
            device_id: device_id.to_owned(),
            principal: context.principal,
            diff_hash: context.diff_hash,
            timestamp: now(),
            run_id: String::new(),
            server_id: String::new(),
            segment_seq: 0,
            prev_hash: String::new(),
            outcome: if succeeded { "success" } else { "failure" }.to_owned(),
            error: (!error.is_empty()).then(|| error.to_owned()),
            metadata: None,
        }));
        // Terminal: the change is done and its context is dead weight. Without
        // this a long-lived server accumulates every device, principal and
        // digest it has ever seen.
        self.forget(changeset_id);
    }

    /// Take every segment closed so far, leaving the open one alone.
    pub fn take_closed(&self) -> Vec<ClosedSegment> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        std::mem::take(&mut state.closed)
    }

    /// Close the open segment, if it holds anything.
    ///
    /// `None` for an empty segment: a zero-record segment spends a sequence
    /// number and tells a verifier nothing, and the sequence is what dedup and
    /// gap-detection both read.
    pub fn close_current(&self) -> Option<ClosedSegment> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        self.roll(&mut state)
    }

    /// Close and hand every pending segment to the spool.
    ///
    /// The segments are claimed under **one** lock acquisition. Taking them in
    /// two steps let a concurrent `take_closed` remove the intent's segment in
    /// between, so this would return having spooled nothing while the drainer
    /// still held it in memory — the guarantee gone, silently, under
    /// concurrency only.
    ///
    /// The callback runs outside the lock: it does file I/O, and a spool that
    /// called back into the recorder would otherwise deadlock.
    fn flush_after_append(&self) -> Result<(), SpoolError> {
        let Some(spool) = self.spool.as_ref() else {
            return Ok(());
        };
        let claimed = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            let mut pending = std::mem::take(&mut state.closed);
            if let Some(closed) = self.roll(&mut state) {
                pending.push(closed);
            }
            pending
        };
        // The claim above *removed* these from the recorder, so a refusal that
        // is merely reported still loses the records it is reporting about.
        // Anything not written goes back, oldest first, for the next flush.
        let mut pending = claimed.into_iter();
        for segment in pending.by_ref() {
            if let Err(error) = spool(segment.clone()) {
                let mut unwritten = vec![segment];
                unwritten.extend(pending);
                let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
                unwritten.append(&mut state.closed);
                state.closed = unwritten;
                return Err(error);
            }
        }
        Ok(())
    }

    /// Remember what a proposal said, for the records that follow it.
    fn remember(&self, changeset_id: &str, context: ChangeContext) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        // Replacing an existing key evicts nothing: the map is not growing.
        let replacing = state.context.contains_key(changeset_id);
        if !replacing && state.context.len() >= MAX_TRACKED_CHANGES {
            // A server proposing this many changes without finishing any has a
            // bigger problem than evidence context, but dropping an *arbitrary*
            // entry would silently blank a live change's later records. Evict
            // the oldest.
            while state.context.len() >= MAX_TRACKED_CHANGES {
                let Some(oldest) = state.context_order.pop_front() else {
                    break;
                };
                state.context.remove(&oldest);
            }
        }
        if !replacing {
            state.context_order.push_back(changeset_id.to_owned());
        }
        state.context.insert(changeset_id.to_owned(), context);
    }

    /// Forget a change that has reached a terminal point.
    fn forget(&self, changeset_id: &str) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.context.remove(changeset_id).is_some() {
            state
                .context_order
                .retain(|tracked| tracked != changeset_id);
        }
    }

    /// What the proposal said, or blanks if this change was never proposed
    /// here — a server restarted mid-change has no memory of it, and an
    /// incomplete record is better than none.
    fn context_for(&self, changeset_id: &str) -> ChangeContext {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.context.get(changeset_id).cloned().unwrap_or_default()
    }

    /// Append, rolling the segment when it is full.
    ///
    /// Appending cannot fail here: the envelope fields are left empty for the
    /// segment to inject, which is the accepted path. A poisoned mutex is
    /// recovered rather than propagated — losing the whole trail because one
    /// unrelated thread panicked is worse than continuing the chain.
    fn append(&self, record: EvidenceRecord) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if append(&mut state.current, record).is_err() {
            return;
        }
        if state.current.records().len() >= self.config.records_per_segment
            && let Some(closed) = self.roll(&mut state)
        {
            state.closed.push(closed);
        }
    }

    /// Close the open segment and start the next, linked to its head.
    fn roll(&self, state: &mut RecorderState) -> Option<ClosedSegment> {
        if state.current.records().is_empty() {
            return None;
        }
        let seq = state.next_seq;
        let successor = ChainSegment::new(
            self.config.run_id.clone(),
            self.config.server_id.clone(),
            seq,
            String::new(),
        );
        let finished = std::mem::replace(&mut state.current, successor);
        let closed = close(finished).ok()?;
        state.prev_head = closed.head_hash.clone();
        state.current.prev_hash = state.prev_head.clone();
        state.next_seq += 1;
        Some(closed)
    }
}

/// Current time, RFC 3339, UTC.
fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
