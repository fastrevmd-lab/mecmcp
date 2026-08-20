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

use crate::evidence::{
    ApplyIntentRecord, ApprovalRecord, ChainSegment, ClosedSegment, EvidenceRecord, ProposalRecord,
    ResultReceipt, append, close,
};
use std::collections::HashMap;
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

/// How a recorder identifies itself and when it rolls a segment.
#[derive(Debug, Clone)]
pub struct RecorderConfig {
    /// Originating audit server identifier.
    pub server_id: String,
    /// Audit run identifier — one per process lifetime.
    pub run_id: String,
    /// Records per segment before it closes itself.
    ///
    /// A segment is the unit of delivery, so this trades latency against
    /// request count. Left unbounded, a long-lived server would hold every
    /// record until shutdown and lose them all to a crash.
    pub records_per_segment: usize,
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
    spool: Option<Box<dyn Fn(ClosedSegment) + Send + Sync>>,
}

struct RecorderState {
    current: ChainSegment,
    next_seq: u64,
    /// Head hash of the last closed segment, linking the next one to it.
    prev_head: String,
    closed: Vec<ClosedSegment>,
    /// What the proposal said, keyed by request, so later records describe the
    /// same change rather than blanks.
    context: HashMap<String, ChangeContext>,
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
        let current = ChainSegment::new(
            config.run_id.clone(),
            config.server_id.clone(),
            0,
            SSDF_CHAIN_START.to_owned(),
        );
        Self {
            state: Mutex::new(RecorderState {
                current,
                next_seq: 1,
                prev_head: SSDF_CHAIN_START.to_owned(),
                closed: Vec::new(),
                context: HashMap::new(),
            }),
            config,
            spool: None,
        }
    }

    /// Attach the durable spool that [`apply_intent`](Self::apply_intent) needs.
    ///
    /// The callback must persist the segment before it returns — spooling to a
    /// file that is fsynced, typically `SsdfSink::spool`. A callback that only
    /// queues in memory reinstates exactly the gap this exists to close.
    #[must_use]
    pub fn with_spool(mut self, spool: impl Fn(ClosedSegment) + Send + Sync + 'static) -> Self {
        self.spool = Some(Box::new(spool));
        self
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
            request_id,
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
        let context = self.context_for(request_id);
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
    pub fn apply_intent(
        &self,
        request_id: &str,
        changeset_id: &str,
        device_id: &str,
        principal: &str,
    ) {
        let context = self.context_for(request_id);
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
        self.flush_now();
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
        let context = self.context_for(request_id);
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

    /// Close the open segment and hand it to the spool, if one is attached.
    fn flush_now(&self) {
        let Some(spool) = self.spool.as_ref() else {
            return;
        };
        let mut pending = self.take_closed();
        if let Some(closed) = self.close_current() {
            pending.push(closed);
        }
        for segment in pending {
            spool(segment);
        }
    }

    /// Remember what a proposal said, for the records that follow it.
    fn remember(&self, request_id: &str, context: ChangeContext) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.context.insert(request_id.to_owned(), context);
    }

    /// What the proposal said, or blanks if this request was never proposed
    /// here — a server restarted mid-change has no memory of it, and an
    /// incomplete record is better than none.
    fn context_for(&self, request_id: &str) -> ChangeContext {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.context.get(request_id).cloned().unwrap_or_default()
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
