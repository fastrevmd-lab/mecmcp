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
        if self.first_interval > self.max_interval {
            return Err(ConfigError::IntervalAboveMaximum {
                first_interval: self.first_interval,
                max_interval: self.max_interval,
            });
        }
        Ok(())
    }
}

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

    let started = tokio::time::Instant::now();
    let mut interval = config.first_interval;
    let mut attempts: u32 = 0;

    loop {
        // Cancellation is checked before probing, so a token that fired while
        // the previous wait elapsed does not buy one more call to the API.
        if token.is_cancelled() {
            return Err(PollError::Cancelled { attempts });
        }

        let remaining = config
            .deadline
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero());
        let Some(remaining) = remaining else {
            return Err(PollError::DeadlineExceeded {
                attempts,
                deadline: config.deadline,
            });
        };

        attempts = attempts.saturating_add(1);

        // The probe runs inside both the deadline and the cancellation select,
        // so a probe that never returns is bounded by the same budget as the
        // waits. Nesting order matters: cancellation is the outer race, so it
        // wins even if the deadline expires in the same poll.
        let probed = select_cancel_raw::<_, _, CancelMarker>(
            token,
            tokio::time::timeout(remaining, probe(attempts)),
        )
        .await;

        match probed {
            Err(CancelMarker) => return Err(PollError::Cancelled { attempts }),
            Ok(Err(_elapsed)) => {
                return Err(PollError::DeadlineExceeded {
                    attempts,
                    deadline: config.deadline,
                });
            }
            Ok(Ok(Err(source))) => return Err(PollError::Probe { attempts, source }),
            Ok(Ok(Ok(Probe::Ready(value)))) => return Ok(value),
            Ok(Ok(Ok(Probe::Pending))) => {}
        }

        // Never wait past the deadline: sleeping beyond it would report the
        // timeout later than it happened and hold the caller for no reason.
        let left = config
            .deadline
            .checked_sub(started.elapsed())
            .filter(|left| !left.is_zero());
        let Some(left) = left else {
            return Err(PollError::DeadlineExceeded {
                attempts,
                deadline: config.deadline,
            });
        };
        let wait = interval.min(left);

        if select_cancel_raw::<_, _, CancelMarker>(token, tokio::time::sleep(wait))
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
    // The `min` above bounds this by `ceiling`, so the conversion cannot fail;
    // `unwrap_or` keeps the panic path out of the code rather than relying on
    // that reasoning staying true.
    u64::try_from(grown).map_or(ceiling, Duration::from_nanos)
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

    #[test]
    fn default_config_is_valid() {
        assert!(PollConfig::default().validate().is_ok());
    }
}
