//! Vendor-neutral polling for asynchronous jobs.
//!
//! An API-based management plane answers "start this deployment" with a job
//! identifier and expects the caller to wait. This crate is that wait: an
//! immediate first probe, capped exponential backoff, cooperative cancellation,
//! and a whole-operation deadline.
//!
//! ## What this crate does not own
//!
//! **Terminal-state vocabulary belongs to the consumer.** Nothing here knows
//! what "succeeded", "failed", "partial" or "rolled back" mean, because every
//! vendor spells them differently. A probe reports only [`Probe::Pending`] or
//! [`Probe::Ready`]; deciding what a ready value *means* is the product's job,
//! as is whether an error is worth retrying.
//!
//! ## Three outcomes, never collapsed
//!
//! [`PollError`] distinguishes cancellation, deadline, and a probe failure.
//! An operator reading "job polling failed" cannot tell whether the client hung
//! up, the wait ran out, or the endpoint returned 500 — and those want three
//! different responses.
//!
//! ## Example
//!
//! ```
//! use mecmcp_job::{poll_until_ready, PollConfig, Probe};
//! use tokio_util::sync::CancellationToken;
//!
//! # #[derive(Debug, thiserror::Error)]
//! # #[error("probe failed")]
//! # struct MyError;
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let token = CancellationToken::new();
//! let config = PollConfig::default();
//!
//! let status = poll_until_ready(&token, config, |_attempt| async {
//!     // Ask the product's API whether the job has finished.
//!     Ok::<_, MyError>(Probe::Ready("done"))
//! })
//! .await?;
//!
//! assert_eq!(status, "done");
//! # Ok(())
//! # }
//! ```

use mecmcp_device::cancel::{Cancellable, select_cancel_raw};
use std::future::Future;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// What a single probe found.
///
/// Deliberately two-valued. A vendor's "failed" or "rolled back" is a
/// [`Probe::Ready`] carrying that status — this crate has no opinion about which
/// terminal states are good news.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Probe<T> {
    /// The job is still running; poll again after the backoff.
    Pending,
    /// The job reached a terminal state, carrying whatever the consumer reads.
    Ready(T),
}

/// How often to probe, and for how long.
#[derive(Debug, Clone, Copy)]
pub struct PollConfig {
    /// Wait before the second probe. The first probe is immediate.
    pub first_interval: Duration,
    /// Ceiling for the backoff.
    pub max_interval: Duration,
    /// Factor applied to the interval after each pending probe.
    pub multiplier: u32,
    /// Whole-operation budget, covering probes and waits together.
    pub deadline: Duration,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            first_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(30),
            multiplier: 2,
            deadline: Duration::from_secs(300),
        }
    }
}

impl PollConfig {
    /// Reject a configuration that cannot poll sensibly.
    ///
    /// # Errors
    /// Returns [`ConfigError`] for a zero interval or deadline, or a multiplier
    /// below 1 — the last would shrink the interval towards a busy loop.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.first_interval.is_zero() {
            return Err(ConfigError::Zero {
                field: "first_interval",
            });
        }
        if self.max_interval.is_zero() {
            return Err(ConfigError::Zero {
                field: "max_interval",
            });
        }
        if self.deadline.is_zero() {
            return Err(ConfigError::Zero { field: "deadline" });
        }
        if self.multiplier < 1 {
            return Err(ConfigError::MultiplierBelowOne {
                multiplier: self.multiplier,
            });
        }
        // `poll_until_ready` anchors the deadline to an instant, which fails for
        // absurd values. Checking it here too keeps a startup preflight honest:
        // a config `validate()` accepts must not be one the first job rejects.
        //
        // A fixed ceiling rather than `Instant::now().checked_add(..)`, because
        // validation has to be deterministic and callable outside a runtime.
        // 136 years is far past any real polling budget and comfortably inside
        // what `Instant` can represent.
        if self.deadline > MAX_REPRESENTABLE_DEADLINE {
            return Err(ConfigError::DeadlineUnrepresentable {
                deadline: self.deadline,
            });
        }
        if self.first_interval > self.max_interval {
            return Err(ConfigError::IntervalAboveMaximum {
                first_interval: self.first_interval,
                max_interval: self.max_interval,
            });
        }
        Ok(())
    }
}

/// Largest deadline [`PollConfig::validate`] accepts.
///
/// Not a product policy — a representability guard. Anchoring a deadline as an
/// instant fails for absurd values, and validation that accepts what execution
/// rejects is worse than no validation.
const MAX_REPRESENTABLE_DEADLINE: Duration = Duration::from_secs(u32::MAX as u64);

/// A [`PollConfig`] that cannot be used.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A duration was zero.
    #[error("PollConfig::{field} must be greater than zero")]
    Zero {
        /// Which field.
        field: &'static str,
    },
    /// The multiplier would shrink the interval rather than grow it.
    #[error("PollConfig::multiplier is {multiplier}; a value below 1 would poll ever faster")]
    MultiplierBelowOne {
        /// The rejected multiplier.
        multiplier: u32,
    },
    /// The deadline cannot be represented as an instant on this platform.
    ///
    /// Reported rather than quietly clamped: substituting a shorter budget while
    /// still naming the configured one in the error would make the crate lie
    /// about the guarantee it exists to provide.
    #[error("PollConfig::deadline ({deadline:?}) is too large to anchor as an instant")]
    DeadlineUnrepresentable {
        /// The rejected deadline.
        deadline: Duration,
    },
    /// The starting interval already exceeds the ceiling.
    #[error(
        "PollConfig::first_interval ({first_interval:?}) exceeds max_interval ({max_interval:?})"
    )]
    IntervalAboveMaximum {
        /// The starting interval.
        first_interval: Duration,
        /// The ceiling.
        max_interval: Duration,
    },
}

/// Why polling stopped without a terminal value.
///
/// The three variants are kept apart on purpose: a client hanging up, a wait
/// running out, and an endpoint erroring are different operational events.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PollError<E> {
    /// The cancellation token fired.
    #[error("polling cancelled after {attempts} attempt(s)")]
    Cancelled {
        /// Probes issued before cancelling.
        attempts: u32,
    },
    /// The whole-operation budget ran out.
    #[error("polling exceeded its {deadline:?} deadline after {attempts} attempt(s)")]
    DeadlineExceeded {
        /// Probes issued before the deadline.
        attempts: u32,
        /// The budget that was exceeded.
        deadline: Duration,
    },
    /// The consumer's probe failed.
    ///
    /// Whether that is worth retrying is the consumer's policy, so the loop
    /// stops and hands the error back intact.
    #[error("probe failed on attempt {attempts}: {source}")]
    Probe {
        /// Which attempt failed.
        attempts: u32,
        /// The consumer's own error.
        #[source]
        source: E,
    },
    /// The configuration was rejected.
    #[error("invalid poll configuration: {0}")]
    Config(#[from] ConfigError),
}

/// Internal marker so `select_cancel_raw` can report cancellation.
struct CancelMarker;

impl Cancellable for CancelMarker {
    fn cancelled() -> Self {
        Self
    }
}

/// Poll `probe` until it reports [`Probe::Ready`], or until cancelled, out of
/// time, or the probe fails.
///
/// The first probe runs immediately — a job that has already finished must not
/// cost a full interval. After each [`Probe::Pending`] the wait grows by
/// `multiplier`, clamped at `max_interval`.
///
/// The deadline covers probes *and* waits together, so a probe that hangs is
/// bounded by it rather than running forever between two well-behaved sleeps.
/// Cancellation is checked before every probe and throughout every wait.
///
/// `probe` receives the 1-based attempt number, which is useful for logging
/// without the consumer having to count.
///
/// # Errors
/// Returns [`PollError::Cancelled`], [`PollError::DeadlineExceeded`],
/// [`PollError::Probe`], or [`PollError::Config`] if `config` is unusable.
///
/// # Examples
/// ```
/// use mecmcp_job::{poll_until_ready, PollConfig, Probe};
/// use tokio_util::sync::CancellationToken;
/// use std::sync::atomic::{AtomicU32, Ordering};
///
/// # #[derive(Debug, thiserror::Error)]
/// # #[error("probe failed")]
/// # struct MyError;
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let seen = AtomicU32::new(0);
/// let token = CancellationToken::new();
///
/// let value = poll_until_ready(&token, PollConfig::default(), |_attempt| async {
///     if seen.fetch_add(1, Ordering::SeqCst) < 2 {
///         Ok::<_, MyError>(Probe::Pending)
///     } else {
///         Ok(Probe::Ready(7))
///     }
/// })
/// .await?;
///
/// assert_eq!(value, 7);
/// # Ok(())
/// # }
/// ```
pub async fn poll_until_ready<P, Fut, T, E>(
    token: &CancellationToken,
    config: PollConfig,
    mut probe: P,
) -> Result<T, PollError<E>>
where
    P: FnMut(u32) -> Fut,
    Fut: Future<Output = Result<Probe<T>, E>>,
{
    config.validate()?;

    // One absolute anchor for the whole operation, not a relative budget
    // recomputed each pass. A relative `timeout(remaining, ...)` starts counting
    // when the timer is created, so any work between measuring `remaining` and
    // the future's first await — a descheduled task, or synchronous work at the
    // top of the probe — slides the effective deadline outwards. `timeout_at`
    // cannot drift, because the instant never moves.
    let started = tokio::time::Instant::now();
    let Some(expires_at) = started.checked_add(config.deadline) else {
        // Do not substitute a shorter budget. An earlier version fell back to
        // ~136 years here, which would have returned `DeadlineExceeded` long
        // before the configured deadline while still reporting the configured
        // value — the crate lying about its own guarantee.
        return Err(PollError::Config(ConfigError::DeadlineUnrepresentable {
            deadline: config.deadline,
        }));
    };
    let mut interval = config.first_interval;
    let mut attempts: u32 = 0;

    loop {
        // Cancellation is checked before probing, so a token that fired while
        // the previous wait elapsed does not buy one more call to the API.
        if token.is_cancelled() {
            return Err(PollError::Cancelled { attempts });
        }

        if tokio::time::Instant::now() >= expires_at {
            return Err(PollError::DeadlineExceeded {
                attempts,
                deadline: config.deadline,
            });
        }

        attempts = attempts.saturating_add(1);

        // The probe runs inside both the deadline and the cancellation select,
        // so a probe that never returns is bounded by the same budget as the
        // waits. Nesting order matters: cancellation is the outer race, so it
        // wins even if the deadline expires in the same poll.
        let probed = select_cancel_raw::<_, _, CancelMarker>(
            token,
            tokio::time::timeout_at(expires_at, probe(attempts)),
        )
        .await;

        // Cancellation is documented to win, and `select_cancel_raw` alone does
        // not guarantee that: if the token fires while the inner future is being
        // polled, the biased branch has already returned `Pending` for this
        // wake, so a probe or deadline that becomes ready in the same poll is
        // reported instead. Rechecking after the await restores the precedence.
        if token.is_cancelled() {
            return Err(PollError::Cancelled { attempts });
        }

        match probed {
            Err(CancelMarker) => return Err(PollError::Cancelled { attempts }),
            Ok(Err(_elapsed)) => {
                return Err(PollError::DeadlineExceeded {
                    attempts,
                    deadline: config.deadline,
                });
            }
            Ok(Ok(completed)) => {
                // `Timeout::poll` polls the wrapped future *before* its timer
                // (tokio-1.53.1 time/timeout.rs:216, "First, try polling the
                // future"). When a response lands after `expires_at` but the
                // task is not polled until afterwards, both are ready and the
                // future wins — so a completion can arrive past the budget and
                // still be accepted. Rechecking here is what makes the deadline
                // a promise rather than a preference.
                if tokio::time::Instant::now() >= expires_at {
                    return Err(PollError::DeadlineExceeded {
                        attempts,
                        deadline: config.deadline,
                    });
                }
                match completed {
                    Err(source) => return Err(PollError::Probe { attempts, source }),
                    Ok(Probe::Ready(value)) => return Ok(value),
                    Ok(Probe::Pending) => {}
                }
            }
        }

        // Never wait past the deadline: sleeping beyond it would report the
        // timeout later than it happened and hold the caller for no reason.
        // Anchored the same way, so the wake instant cannot drift either.
        let now = tokio::time::Instant::now();
        if now >= expires_at {
            return Err(PollError::DeadlineExceeded {
                attempts,
                deadline: config.deadline,
            });
        }
        let wake_at = now
            .checked_add(interval)
            .map_or(expires_at, |wake| wake.min(expires_at));

        if select_cancel_raw::<_, _, CancelMarker>(token, tokio::time::sleep_until(wake_at))
            .await
            .is_err()
        {
            return Err(PollError::Cancelled { attempts });
        }

        interval = next_interval(interval, config.multiplier, config.max_interval);
    }
}

/// Grow the interval, clamped and overflow-proof.
///
/// `saturating_mul` on the nanosecond count rather than `interval * multiplier`:
/// `Duration`'s `Mul` panics on overflow, and a large `max_interval` with a
/// large multiplier reaches it. #187 found two overflow bugs of exactly this
/// shape in `mecmcp-secret`, both latent until a big value arrived.
fn next_interval(current: Duration, multiplier: u32, ceiling: Duration) -> Duration {
    let grown = current
        .as_nanos()
        .saturating_mul(u128::from(multiplier))
        .min(ceiling.as_nanos());
    duration_from_nanos(grown)
}

/// Build a `Duration` from a `u128` nanosecond count without losing range.
///
/// `Duration::from_nanos` takes a `u64`, which tops out around 584 years — well
/// short of what `Duration` itself holds. Converting through `u64` therefore
/// discarded any interval above that and silently substituted the ceiling, so a
/// `multiplier` of 1 could jump straight to `max_interval` instead of standing
/// still. Absurd as a poll interval, but it is the kind of quiet substitution
/// that is worth not having.
fn duration_from_nanos(nanos: u128) -> Duration {
    const NANOS_PER_SEC: u128 = 1_000_000_000;

    let seconds = nanos / NANOS_PER_SEC;
    // Always below 1e9, so `Duration::new` cannot carry and cannot panic.
    let remainder = u32::try_from(nanos % NANOS_PER_SEC).unwrap_or(0);
    u64::try_from(seconds).map_or(Duration::MAX, |seconds| Duration::new(seconds, remainder))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "readability in tests")]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Debug, thiserror::Error, PartialEq, Eq)]
    #[error("probe exploded: {0}")]
    struct ProbeError(&'static str);

    fn fast() -> PollConfig {
        PollConfig {
            first_interval: Duration::from_secs(1),
            max_interval: Duration::from_secs(8),
            multiplier: 2,
            deadline: Duration::from_secs(300),
        }
    }

    /// A job that is already finished must not cost an interval.
    #[tokio::test(start_paused = true)]
    async fn ready_on_the_first_probe_does_not_wait() {
        let token = CancellationToken::new();
        let started = tokio::time::Instant::now();

        let value = poll_until_ready(&token, fast(), |attempt| async move {
            assert_eq!(attempt, 1, "the first probe is attempt 1");
            Ok::<_, ProbeError>(Probe::Ready("done"))
        })
        .await
        .unwrap();

        assert_eq!(value, "done");
        assert_eq!(started.elapsed(), Duration::ZERO, "it slept before probing");
    }

    /// The backoff series is exactly 1, 2, 4, 8, 8 — doubling then clamped.
    #[tokio::test(start_paused = true)]
    async fn backoff_doubles_then_clamps_at_the_ceiling() {
        let token = CancellationToken::new();
        let gaps = Arc::new(std::sync::Mutex::new(Vec::new()));
        let last = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));

        let gaps_probe = Arc::clone(&gaps);
        let last_probe = Arc::clone(&last);
        let value = poll_until_ready(&token, fast(), move |attempt| {
            let gaps = Arc::clone(&gaps_probe);
            let last = Arc::clone(&last_probe);
            async move {
                let now = tokio::time::Instant::now();
                let mut previous = last.lock().unwrap();
                gaps.lock().unwrap().push(now.duration_since(*previous));
                *previous = now;
                if attempt < 6 {
                    Ok::<_, ProbeError>(Probe::Pending)
                } else {
                    Ok(Probe::Ready(attempt))
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(value, 6);
        let observed = gaps.lock().unwrap().clone();
        assert_eq!(
            observed,
            vec![
                Duration::ZERO, // immediate first probe
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(8), // clamped
            ]
        );
    }

    /// A token already cancelled must not reach the API at all.
    #[tokio::test(start_paused = true)]
    async fn cancellation_before_the_first_probe_never_probes() {
        let token = CancellationToken::new();
        token.cancel();
        let probes = AtomicU32::new(0);

        let error = poll_until_ready(&token, fast(), |_| async {
            probes.fetch_add(1, Ordering::SeqCst);
            Ok::<_, ProbeError>(Probe::Ready(()))
        })
        .await
        .unwrap_err();

        assert_eq!(error, PollError::Cancelled { attempts: 0 });
        assert_eq!(probes.load(Ordering::SeqCst), 0, "it probed anyway");
    }

    /// Cancelling during a backoff wait must return promptly.
    #[tokio::test(start_paused = true)]
    async fn cancellation_during_a_wait_returns_without_probing_again() {
        let token = CancellationToken::new();
        let canceller = token.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            canceller.cancel();
        });

        // The ceiling has to allow the long interval this test needs.
        let config = PollConfig {
            first_interval: Duration::from_secs(60),
            max_interval: Duration::from_secs(60),
            ..fast()
        };
        let started = tokio::time::Instant::now();
        let error = poll_until_ready(&token, config, |_| async {
            Ok::<Probe<()>, ProbeError>(Probe::Pending)
        })
        .await
        .unwrap_err();

        assert_eq!(error, PollError::Cancelled { attempts: 1 });
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "it waited out the full interval: {:?}",
            started.elapsed()
        );
    }

    /// A probe that never returns is bounded by the deadline, not just the sleeps.
    #[tokio::test(start_paused = true)]
    async fn a_hanging_probe_hits_the_deadline() {
        let token = CancellationToken::new();
        let config = PollConfig {
            deadline: Duration::from_secs(5),
            ..fast()
        };

        let started = tokio::time::Instant::now();
        let error = poll_until_ready(&token, config, |_| async {
            std::future::pending::<Result<Probe<()>, ProbeError>>().await
        })
        .await
        .unwrap_err();

        assert_eq!(
            error,
            PollError::DeadlineExceeded {
                attempts: 1,
                deadline: Duration::from_secs(5),
            }
        );
        // *When* matters as much as *whether*. Asserting only the variant passes
        // even if the probe is bounded by something far larger than the
        // deadline, which is exactly the bug this test exists to catch.
        assert_eq!(
            started.elapsed(),
            Duration::from_secs(5),
            "the probe was not bounded by the deadline itself"
        );
    }

    /// A probe that completes after the deadline must not be accepted.
    ///
    /// `Timeout::poll` polls the wrapped future before its timer, so when both
    /// are ready the completion wins. Without an explicit recheck, a response
    /// that arrived past the budget would be returned as success.
    #[tokio::test(start_paused = true)]
    async fn a_probe_completing_after_the_deadline_is_not_accepted() {
        let token = CancellationToken::new();
        let config = PollConfig {
            deadline: Duration::from_secs(5),
            ..fast()
        };

        // The probe must come due at *exactly* the deadline, not after it: a
        // later sleep is simply pre-empted by the timer and never races. Both
        // timers firing on the same instant is what makes `Timeout::poll` reach
        // the completed future first.
        let error = poll_until_ready(&token, config, |_| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<_, ProbeError>(Probe::Ready("too late"))
        })
        .await
        .unwrap_err();

        assert_eq!(
            error,
            PollError::DeadlineExceeded {
                attempts: 1,
                deadline: Duration::from_secs(5),
            },
            "a late completion was accepted as success"
        );
    }

    /// The same guard applies to a late *error*: it must read as the deadline,
    /// not as a probe failure, because the budget is what actually ended it.
    #[tokio::test(start_paused = true)]
    async fn a_probe_erroring_after_the_deadline_reads_as_the_deadline() {
        let token = CancellationToken::new();
        let config = PollConfig {
            deadline: Duration::from_secs(5),
            ..fast()
        };

        let error = poll_until_ready(&token, config, |_| async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Err::<Probe<()>, _>(ProbeError("late failure"))
        })
        .await
        .unwrap_err();

        assert!(
            matches!(error, PollError::DeadlineExceeded { .. }),
            "expected the deadline, got {error:?}"
        );
    }

    /// Cancellation wins over a probe that succeeds in the same poll.
    ///
    /// Cancelling from inside the probe, immediately before it returns
    /// `Ready`, is the deterministic form of the race: the token fires while
    /// the inner future is being polled, so `select_cancel_raw`'s biased branch
    /// has already yielded `Pending` for that wake.
    #[tokio::test(start_paused = true)]
    async fn cancellation_wins_over_a_probe_that_completes_in_the_same_poll() {
        let token = CancellationToken::new();
        let inner = token.clone();

        let error = poll_until_ready(&token, fast(), move |_| {
            let inner = inner.clone();
            async move {
                inner.cancel();
                Ok::<_, ProbeError>(Probe::Ready("should not be accepted"))
            }
        })
        .await
        .unwrap_err();

        assert_eq!(
            error,
            PollError::Cancelled { attempts: 1 },
            "a success racing cancellation was accepted"
        );
    }

    /// The same precedence applies to a probe error racing cancellation.
    #[tokio::test(start_paused = true)]
    async fn cancellation_wins_over_a_probe_error_in_the_same_poll() {
        let token = CancellationToken::new();
        let inner = token.clone();

        let error = poll_until_ready(&token, fast(), move |_| {
            let inner = inner.clone();
            async move {
                inner.cancel();
                Err::<Probe<()>, _>(ProbeError("racing failure"))
            }
        })
        .await
        .unwrap_err();

        assert_eq!(error, PollError::Cancelled { attempts: 1 });
    }

    /// `validate()` must not accept what `poll_until_ready` will reject.
    ///
    /// A startup preflight that passes, followed by a first job that fails, is
    /// worse than no preflight at all.
    #[tokio::test(start_paused = true)]
    async fn validate_agrees_with_the_runtime_on_an_absurd_deadline() {
        let config = PollConfig {
            deadline: Duration::MAX,
            ..fast()
        };
        assert_eq!(
            config.validate(),
            Err(ConfigError::DeadlineUnrepresentable {
                deadline: Duration::MAX,
            }),
            "validate accepted a deadline the runtime rejects"
        );

        let token = CancellationToken::new();
        let runtime_error = poll_until_ready(&token, config, |_| async {
            Ok::<Probe<()>, ProbeError>(Probe::Pending)
        })
        .await
        .unwrap_err();
        assert!(matches!(
            runtime_error,
            PollError::Config(ConfigError::DeadlineUnrepresentable { .. })
        ));

        // A large but sane budget must still be accepted.
        let year = PollConfig {
            deadline: Duration::from_secs(365 * 24 * 60 * 60),
            ..fast()
        };
        assert!(year.validate().is_ok(), "a one-year budget must be usable");
    }

    /// Repeated pending probes eventually exhaust the budget.
    #[tokio::test(start_paused = true)]
    async fn endless_pending_hits_the_deadline() {
        let token = CancellationToken::new();
        let config = PollConfig {
            deadline: Duration::from_secs(10),
            ..fast()
        };

        let error = poll_until_ready(&token, config, |_| async {
            Ok::<Probe<()>, ProbeError>(Probe::Pending)
        })
        .await
        .unwrap_err();

        match error {
            PollError::DeadlineExceeded { deadline, .. } => {
                assert_eq!(deadline, Duration::from_secs(10));
            }
            other => panic!("expected a deadline error, got {other:?}"),
        }
    }

    /// A probe failure ends the loop with the consumer's error intact.
    #[tokio::test(start_paused = true)]
    async fn a_probe_error_stops_the_loop_and_is_not_retried() {
        let token = CancellationToken::new();
        let probes = AtomicU32::new(0);

        let error = poll_until_ready(&token, fast(), |_| async {
            probes.fetch_add(1, Ordering::SeqCst);
            Err::<Probe<()>, _>(ProbeError("500 from the endpoint"))
        })
        .await
        .unwrap_err();

        assert_eq!(
            error,
            PollError::Probe {
                attempts: 1,
                source: ProbeError("500 from the endpoint"),
            }
        );
        assert_eq!(probes.load(Ordering::SeqCst), 1, "the error was retried");
        // The consumer's message survives for the operator to read.
        assert!(error.to_string().contains("500 from the endpoint"));
    }

    /// The three outcomes must stay distinguishable — that is the whole point.
    #[tokio::test(start_paused = true)]
    async fn the_three_failure_modes_are_distinct_variants() {
        let cancelled = PollError::<ProbeError>::Cancelled { attempts: 1 };
        let deadline = PollError::<ProbeError>::DeadlineExceeded {
            attempts: 1,
            deadline: Duration::from_secs(1),
        };
        let probe = PollError::Probe {
            attempts: 1,
            source: ProbeError("x"),
        };
        assert_ne!(cancelled, deadline);
        assert_ne!(deadline, probe);
        assert!(cancelled.to_string().contains("cancelled"));
        assert!(deadline.to_string().contains("deadline"));
        assert!(probe.to_string().contains("probe failed"));
    }

    #[test]
    fn an_enormous_interval_does_not_overflow() {
        // `Duration * u32` panics on overflow; the nanosecond path must not.
        let grown = next_interval(Duration::from_secs(u64::MAX / 2), u32::MAX, Duration::MAX);
        assert!(grown <= Duration::MAX);

        let clamped = next_interval(Duration::from_secs(1), u32::MAX, Duration::from_secs(30));
        assert_eq!(clamped, Duration::from_secs(30), "the ceiling must hold");
    }

    /// Above `u64::MAX` nanoseconds — roughly 584 years — the interval must
    /// still be itself, not silently become the ceiling.
    ///
    /// `Duration::from_nanos` takes a `u64`, so converting through it discarded
    /// this whole range. A `multiplier` of 1 would then jump straight to
    /// `max_interval` rather than standing still.
    #[test]
    fn an_interval_beyond_u64_nanoseconds_is_preserved() {
        let beyond = Duration::from_secs(600 * 365 * 24 * 60 * 60); // ~600 years
        assert!(
            beyond.as_nanos() > u128::from(u64::MAX),
            "the fixture must actually exceed the u64 nanosecond range"
        );

        let unchanged = next_interval(beyond, 1, Duration::MAX);
        assert_eq!(unchanged, beyond, "multiplier 1 must not move the interval");

        // And the round-trip itself is exact.
        assert_eq!(duration_from_nanos(beyond.as_nanos()), beyond);
    }

    #[tokio::test(start_paused = true)]
    async fn invalid_configuration_is_rejected_before_probing() {
        let token = CancellationToken::new();
        let probes = AtomicU32::new(0);

        let cases = [
            PollConfig {
                first_interval: Duration::ZERO,
                ..fast()
            },
            PollConfig {
                max_interval: Duration::ZERO,
                ..fast()
            },
            PollConfig {
                deadline: Duration::ZERO,
                ..fast()
            },
            PollConfig {
                multiplier: 0,
                ..fast()
            },
            PollConfig {
                first_interval: Duration::from_secs(60),
                max_interval: Duration::from_secs(30),
                ..fast()
            },
        ];

        for config in cases {
            let error = poll_until_ready(&token, config, |_| async {
                probes.fetch_add(1, Ordering::SeqCst);
                Ok::<_, ProbeError>(Probe::Ready(()))
            })
            .await
            .unwrap_err();
            assert!(
                matches!(error, PollError::Config(_)),
                "expected a config error, got {error:?}"
            );
        }
        assert_eq!(
            probes.load(Ordering::SeqCst),
            0,
            "a bad config still probed"
        );
    }

    /// A deadline too large to anchor must be reported, not quietly shortened.
    #[tokio::test(start_paused = true)]
    async fn an_unrepresentable_deadline_is_rejected_not_clamped() {
        let token = CancellationToken::new();
        let probes = AtomicU32::new(0);

        let config = PollConfig {
            deadline: Duration::MAX,
            ..fast()
        };
        let error = poll_until_ready(&token, config, |_| async {
            probes.fetch_add(1, Ordering::SeqCst);
            Ok::<Probe<()>, ProbeError>(Probe::Pending)
        })
        .await
        .unwrap_err();

        assert_eq!(
            error,
            PollError::Config(ConfigError::DeadlineUnrepresentable {
                deadline: Duration::MAX,
            }),
            "an unanchorable deadline must be named, not replaced"
        );
        assert_eq!(
            probes.load(Ordering::SeqCst),
            0,
            "it polled on a bad config"
        );
    }

    #[test]
    fn default_config_is_valid() {
        assert!(PollConfig::default().validate().is_ok());
    }
}
