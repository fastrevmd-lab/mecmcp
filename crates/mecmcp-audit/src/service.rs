//! The part that turns the evidence sink from a spool into a pipeline.
//!
//! [`SsdfSink`] can spool a segment durably and deliver it, and
//! [`EvidenceRecorder`] can produce segments — but nothing called
//! `attempt_delivery` outside the tests, so a deployed server would have
//! written evidence to disk forever and shipped none of it. From inside the
//! process that failure is indistinguishable from success: every record is
//! fsynced, every call returns `Ok`, and the outbox simply grows.
//!
//! This module owns the three things that make it a pipeline: the startup
//! sequence, a background drain, and a flush at shutdown.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::recorder::{EvidenceRecorder, RecorderConfig, resume_head};
use crate::sinks::ssdf::{HttpTransport, SsdfSink, SsdfSinkConfig, SsdfSinkError};

/// How a server configures its evidence pipeline.
#[derive(Debug, Clone)]
pub struct EvidenceConfig {
    /// Identifies this writer's chain. **One process per `server_id`, one run
    /// at a time**: two containers sharing one fork the chain, and a fork
    /// verifies as two valid chains rather than as an error.
    pub server_id: String,
    /// Identifies this process lifetime within the writer's chain.
    pub run_id: String,
    /// Records per segment before one is closed and spooled.
    pub records_per_segment: usize,
    /// How often the drain runs. Delivery is also forced by `apply_intent` and
    /// by shutdown, so this only bounds how long an ordinary record waits.
    pub delivery_interval: Duration,
    /// Where the segments go.
    pub sink: SsdfSinkConfig,
}

/// A running evidence pipeline: recorder, sink, and the drain between them.
pub struct EvidenceService {
    recorder: Arc<EvidenceRecorder>,
    sink: Arc<SsdfSink>,
    stop: Arc<(Mutex<bool>, Condvar)>,
    worker: Option<JoinHandle<()>>,
    /// Set when the drain hits an error, so shutdown can report that delivery
    /// was degraded rather than silently returning `Ok`.
    degraded: Arc<AtomicBool>,
}

impl EvidenceService {
    /// Start a pipeline against the real ClickHouse transport.
    ///
    /// # Errors
    ///
    /// Returns [`SsdfSinkError`] if the outbox or ledger cannot be opened, or
    /// if the startup reads fail. A failed read is deliberately fatal here: the
    /// alternative is starting a second root, which produces a fork that
    /// verifies as two valid chains and is therefore invisible downstream.
    pub fn start(config: EvidenceConfig) -> Result<Self, SsdfSinkError> {
        let stop = new_stop();
        let sink = Arc::new(SsdfSink::new_with_transport(
            config.sink.clone(),
            Arc::new(crate::sinks::ssdf::StdHttpTransport),
            interruptible_sleep(&stop),
        )?);
        Self::from_sink(config, sink, stop)
    }

    /// Start a pipeline against a supplied transport, for tests.
    ///
    /// # Errors
    ///
    /// As [`start`](Self::start).
    pub fn start_with_transport(
        config: EvidenceConfig,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self, SsdfSinkError> {
        let stop = new_stop();
        let sink = Arc::new(SsdfSink::new_with_transport(
            config.sink.clone(),
            transport,
            interruptible_sleep(&stop),
        )?);
        Self::from_sink(config, sink, stop)
    }

    fn from_sink(
        config: EvidenceConfig,
        sink: Arc<SsdfSink>,
        stop: Arc<(Mutex<bool>, Condvar)>,
    ) -> Result<Self, SsdfSinkError> {
        // **Replay first, then read the tail.** A segment still in flight when
        // the last process died has not landed yet, so a tail read taken before
        // the replay returns that segment's predecessor; the next record
        // attaches there and the chain forks -- with nothing duplicated
        // anywhere in it, so `duplicate_row` never fires and the verifier
        // reports both branches clean. This ordering is the contract's
        // (ssdf#47) and it is the whole reason these two lines are not
        // interchangeable.
        sink.attempt_delivery()?;
        let remote = sink.remote_head(&config.server_id)?;
        let local = sink.produced_head(&config.server_id)?;

        let recorder = Arc::new(
            EvidenceRecorder::new(RecorderConfig {
                server_id: config.server_id.clone(),
                run_id: config.run_id.clone(),
                resume_from: resume_head(remote, local),
                records_per_segment: config.records_per_segment,
            })
            .spooling_to(Arc::clone(&sink)),
        );

        let degraded = Arc::new(AtomicBool::new(false));
        let worker = {
            let sink = Arc::clone(&sink);
            let stop = Arc::clone(&stop);
            let degraded = Arc::clone(&degraded);
            let interval = config.delivery_interval;
            std::thread::Builder::new()
                .name("evidence-delivery".to_owned())
                .spawn(move || drain_until_stopped(&sink, &stop, &degraded, interval))
                .map_err(SsdfSinkError::OutboxIo)?
        };

        Ok(Self {
            recorder,
            sink,
            stop,
            worker: Some(worker),
            degraded,
        })
    }

    /// The recorder to hand to a coordinator via `with_evidence`.
    #[must_use]
    pub fn recorder(&self) -> Arc<EvidenceRecorder> {
        Arc::clone(&self.recorder)
    }

    /// Stop the drain and deliver whatever is still pending.
    ///
    /// # Errors
    ///
    /// Returns [`SsdfSinkError`] if the final flush fails. The records remain
    /// in the outbox and the next start replays them, so this is a report
    /// rather than a loss -- but it must be reported, because an operator
    /// stopping a server has no other signal that its trail is behind.
    pub fn shutdown(mut self) -> Result<(), SsdfSinkError> {
        self.signal_stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        // Everything the recorder still holds, not just the open segment.
        // Only `apply_intent` and `result_receipt` flush, so a server whose
        // change sets are planned but not yet applied accumulates *finished*
        // segments in memory: `take_closed` is the difference between losing
        // them and shipping them. If one were dropped and a later segment did
        // get through, the chain would land with a missing predecessor -- a
        // hole that still verifies as a chain.
        let sink = Arc::clone(&self.sink);
        let outcome = spool_everything(&self.recorder, |segment| sink.spool(segment));
        let flushed = self.sink.shutdown_flush();
        outcome.and(flushed)
    }

    /// Whether the background drain has reported a delivery failure.
    #[must_use]
    pub fn delivery_degraded(&self) -> bool {
        self.degraded.load(Ordering::SeqCst)
    }

    fn signal_stop(&self) {
        let (lock, condvar) = &*self.stop;
        let mut stopped = lock.lock().unwrap_or_else(|error| error.into_inner());
        *stopped = true;
        condvar.notify_all();
    }
}

impl Drop for EvidenceService {
    fn drop(&mut self) {
        // A service dropped without `shutdown` still stops its thread. The
        // pending records stay in the outbox for the next run to replay, which
        // is why this does not try to flush: a Drop that performs network I/O
        // turns an ordinary teardown into an unpredictable stall.
        if self.worker.is_some() {
            self.signal_stop();
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }
}

/// Hand every segment the recorder still holds to `spool`, without stopping.
///
/// Two properties matter here and neither is obvious from the happy path.
///
/// **It must not stop at the first error.** `take_closed` *removes* the
/// segments from the recorder, so a `?` on the first one drops every segment
/// after it and skips the open one entirely -- they exist nowhere else, and the
/// service is being consumed. Losing the rest of the trail because one write
/// failed is the opposite of what a shutdown flush is for.
///
/// **A ledger error is not a spool failure.** `SsdfSink::spool` fsyncs the
/// segment and *then* marks it pending in a separate file; if only that second
/// step fails the record is already durable and `attempt_delivery` will still
/// find it, because delivery reads the outbox rather than the ledger. The drain
/// already classifies it that way in `spool_outcome`, and shutdown treating the
/// same condition as fatal would have made it lose records the running server
/// keeps.
///
/// The first genuine error is returned once everything has been attempted.
pub(crate) fn spool_everything(
    recorder: &EvidenceRecorder,
    mut spool: impl FnMut(crate::evidence::ClosedSegment) -> Result<(), SsdfSinkError>,
) -> Result<(), SsdfSinkError> {
    let mut first_error = None;
    let mut attempt = |segment| match spool(segment) {
        Ok(()) => {}
        Err(SsdfSinkError::Ledger(error)) => {
            tracing::warn!(
                %error,
                "segment is durable in the outbox but the delivery ledger could not \
                 be updated; delivery is unaffected"
            );
        }
        Err(error) => {
            tracing::error!(%error, "an evidence segment could not be spooled at shutdown");
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    };

    for segment in recorder.take_closed() {
        attempt(segment);
    }
    if let Some(segment) = recorder.close_current() {
        attempt(segment);
    }

    first_error.map_or(Ok(()), Err)
}

/// A fresh stop signal.
fn new_stop() -> Arc<(Mutex<bool>, Condvar)> {
    Arc::new((Mutex::new(false), Condvar::new()))
}

/// A sleep for the sink's retry backoff that gives up once shutdown is asked
/// for.
///
/// The sink sleeps between attempts for a segment already marked failed. During
/// a ClickHouse outage that backoff grows to a minute, and a shutdown that
/// waits it out is a multi-minute stall -- at which point an operator reaches
/// for SIGKILL and loses exactly the open segment the final flush exists to
/// save. Returning early costs one wasted retry; the segment stays spooled
/// either way.
fn interruptible_sleep(stop: &Arc<(Mutex<bool>, Condvar)>) -> Arc<dyn Fn(Duration) + Send + Sync> {
    let stop = Arc::clone(stop);
    Arc::new(move |duration: Duration| {
        let (lock, condvar) = &*stop;
        let stopped = lock.lock().unwrap_or_else(|error| error.into_inner());
        if *stopped {
            return;
        }
        let _unused = condvar
            .wait_timeout(stopped, duration)
            .unwrap_or_else(|error| error.into_inner());
    })
}

/// Deliver on an interval until told to stop.
fn drain_until_stopped(
    sink: &SsdfSink,
    stop: &(Mutex<bool>, Condvar),
    degraded: &AtomicBool,
    interval: Duration,
) {
    let (lock, condvar) = stop;
    loop {
        let mut stopped = lock.lock().unwrap_or_else(|error| error.into_inner());
        if !*stopped {
            // Condvar rather than sleep so shutdown does not wait out a long
            // interval -- with a 30s tick a plain sleep makes every restart
            // take up to 30s, and operators then reach for SIGKILL, which is
            // exactly when the flush matters.
            let (guard, _) = condvar
                .wait_timeout(stopped, interval)
                .unwrap_or_else(|error| error.into_inner());
            stopped = guard;
        }
        let should_stop = *stopped;
        drop(stopped);

        match sink.attempt_delivery() {
            // `Ok` describes the pass, not the segments: a pass in which every
            // segment was refused still returns `Ok`. Reading only the outer
            // result reports healthy while the outbox grows without limit.
            Ok(report) => {
                degraded.store(report.degraded(), Ordering::SeqCst);
                if report.degraded() {
                    tracing::warn!(
                        delivered = report.delivered,
                        failed = report.failed,
                        "some evidence segments were refused; they stay spooled for retry"
                    );
                }
            }
            Err(error) => {
                degraded.store(true, Ordering::SeqCst);
                tracing::warn!(
                    %error,
                    "evidence delivery pass failed; segments stay spooled and will be retried"
                );
            }
        }

        if should_stop {
            return;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::recorder::{EvidenceRecorder, RecorderConfig};

    fn recorder_holding(rolled: usize, plus_open: bool) -> EvidenceRecorder {
        let recorder = EvidenceRecorder::new(RecorderConfig {
            server_id: "srv".to_string(),
            run_id: "run".to_string(),
            resume_from: None,
            records_per_segment: 1,
        });
        for n in 0..rolled {
            recorder.proposal(
                &format!("r{n}"),
                &format!("c{n}"),
                "dev",
                "alice",
                "sha256:d",
            );
        }
        if plus_open {
            // records_per_segment is 1, so this rolls too; a segment stays open
            // only because the roll happens on the *next* append. Use a
            // recorder-visible fact instead: close_current() returns Some when
            // anything is unrolled.
        }
        recorder
    }

    /// A ledger-only failure must not stop the flush.
    ///
    /// `take_closed` removes the segments, so stopping at the first error drops
    /// every one after it -- and this particular error means the segment is
    /// already durable in the outbox, which is exactly why the running drain
    /// treats it as success.
    #[test]
    fn a_ledger_error_does_not_abandon_the_remaining_segments() {
        let recorder = recorder_holding(4, false);
        let mut seen = 0usize;

        let result = spool_everything(&recorder, |_segment| {
            seen += 1;
            Err(SsdfSinkError::Ledger(
                crate::sinks::delivery_ledger::LedgerError::InvalidEntry("full".to_owned()),
            ))
        });

        assert!(result.is_ok(), "a ledger-only error is not a spool failure");
        assert_eq!(
            seen, 4,
            "every held segment must be offered, not just the first"
        );
    }

    /// A real spool failure is reported, but only after everything is tried.
    #[test]
    fn a_real_failure_is_reported_after_every_segment_is_attempted() {
        let recorder = recorder_holding(3, false);
        let mut seen = 0usize;

        let result = spool_everything(&recorder, |_segment| {
            seen += 1;
            Err(SsdfSinkError::Http("disk gone".to_owned()))
        });

        assert!(result.is_err(), "a genuine failure must be reported");
        assert_eq!(
            seen, 3,
            "stopping early would drop segments that exist nowhere else"
        );
    }
}
