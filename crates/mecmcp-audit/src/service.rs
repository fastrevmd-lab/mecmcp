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
        let sink = Arc::new(SsdfSink::new(config.sink.clone())?);
        Self::from_sink(config, sink)
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
        let sink = Arc::new(SsdfSink::new_with_transport(
            config.sink.clone(),
            transport,
            Arc::new(|_| {}),
        )?);
        Self::from_sink(config, sink)
    }

    fn from_sink(config: EvidenceConfig, sink: Arc<SsdfSink>) -> Result<Self, SsdfSinkError> {
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

        let stop = Arc::new((Mutex::new(false), Condvar::new()));
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
        // Close the open segment first: without this, every record written
        // since the last roll is still in memory and the flush below has
        // nothing to find.
        if let Some(segment) = self.recorder.close_current() {
            self.sink.spool(segment)?;
        }
        self.sink.shutdown_flush()
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

        if let Err(error) = sink.attempt_delivery() {
            degraded.store(true, Ordering::SeqCst);
            tracing::warn!(
                %error,
                "evidence delivery failed; segments stay spooled and will be retried"
            );
        } else {
            degraded.store(false, Ordering::SeqCst);
        }

        if should_stop {
            return;
        }
    }
}
