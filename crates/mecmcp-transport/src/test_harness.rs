//! Serve a [`ServePlan`] on loopback for integration tests.
//!
//! # Why this exists
//!
//! [`ServePlan`] deliberately offers no way to extract its `Router`
//! (mecmcp#273): if the router could leave the plan, a consumer could serve it
//! directly and skip the listener admission checks, which is the defect that
//! design closes.
//!
//! That opacity has a cost this crate has to pay for, not push downstream. When
//! 0.9.0 landed, four consumer repositories had integration tests that drove the
//! router through `tower::ServiceExt::oneshot`. With the router sealed, two
//! deleted those tests, one disabled four files and relaxed `unsafe_code` from
//! `forbid` to `warn`, and one wrote an `unsafe` helper that assumed the
//! struct's field layout and segfaulted. Every one of those is worse than the
//! problem it solved.
//!
//! The supported answer is to serve the plan for real and talk to it over HTTP —
//! which also tests more than `oneshot` did, since it exercises the bind path
//! and the listener refusals. This module makes that a one-liner so nobody has
//! to reinvent it, or route around it.
//!
//! Test-only. Never reachable from a release build.

use crate::server::{HttpServeError, ServePlan, serve_router};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::task::JoinHandle;

/// A plan served on a loopback port, with the handle that stops it.
#[derive(Debug)]
pub struct ServedPlan {
    /// The bound address. Dial this.
    pub address: SocketAddr,
    /// The serve task. Await it after cancelling the shutdown token.
    pub serving: JoinHandle<Result<(), HttpServeError>>,
}

/// Serve `plan` on an ephemeral loopback port and return where to reach it.
///
/// Loopback is exempt from every listener refusal, so a plan that would be
/// refused off-loopback still serves here — which is what makes this usable for
/// testing handler behaviour. To test the refusals themselves, call
/// [`serve_router`] directly with a non-loopback address.
///
/// # Panics
///
/// Panics if no loopback port can be bound, which in a test means the
/// environment is broken rather than the code under test.
///
/// # Example
///
/// ```no_run
/// # async fn example(plan: mecmcp_transport::ServePlan) {
/// let served = mecmcp_transport::test_harness::serve_on_loopback(plan).await;
/// // dial served.address over HTTP, assert on real responses
/// # }
/// ```
pub async fn serve_on_loopback(plan: ServePlan) -> ServedPlan {
    serve_on_loopback_with_timeout(plan, Duration::from_millis(50)).await
}

/// [`serve_on_loopback`] with an explicit drain timeout.
///
/// # Panics
///
/// Panics if no loopback port can be bound.
pub async fn serve_on_loopback_with_timeout(
    plan: ServePlan,
    shutdown_timeout: Duration,
) -> ServedPlan {
    // Bind to discover a free port, then release it. There is a race between
    // the drop and the rebind, which is why this is test-only: the alternative
    // is a fixed port, which collides with concurrently running tests far more
    // often than this races.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("no loopback port available for the test harness");
    let address = probe
        .local_addr()
        .expect("bound listener has no local address");
    drop(probe);

    let serving = tokio::spawn(serve_router(plan, address, None, shutdown_timeout));

    // Give the listener a moment to come up before the caller dials it.
    tokio::time::sleep(Duration::from_millis(150)).await;

    ServedPlan { address, serving }
}
