//! Per-token and per-IP request-rate limiting using a token-bucket algorithm.

use crate::config::LimitsConfig;
use crate::overload::rate_limited_response;
use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;
use mecmcp_auth::CallerCtx;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Maximum number of per-IP buckets before LRU eviction begins.
///
/// An unbounded map keyed by source IP is trivial to exhaust via spoofed or
/// rotating addresses. This cap matches PAN-OS's deployed `MAX_IP_WINDOWS = 8_192`.
/// When the map is full and a new IP arrives, the oldest-accessed entry is evicted.
const MAX_IP_BUCKETS: usize = 8_192;

/// Maximum number of per-token buckets before LRU eviction begins.
///
/// Deployed configurations have bounded token sets, but a malformed or hostile
/// bearer header could still drive unbounded growth. This cap matches PAN-OS's
/// deployed `MAX_TOKEN_WINDOWS = 2_048`. When the map is full and a new token
/// arrives, the oldest-accessed entry is evicted.
const MAX_TOKEN_BUCKETS: usize = 2_048;

/// Nanosecond scale factor for token-bucket arithmetic.
const TOKEN_SCALE: u128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RateDecision {
    Allowed,
    Limited { retry_after_secs: u64 },
}

#[derive(Debug)]
struct Bucket {
    available_units: u128,
    last_refill: Instant,
}

impl Bucket {
    fn full(burst: u64, now: Instant) -> Self {
        Self {
            available_units: capacity_units(burst),
            last_refill: now,
        }
    }

    fn check(&mut self, now: Instant, rate: u64, burst: u64) -> RateDecision {
        if let Some(elapsed) = now.checked_duration_since(self.last_refill) {
            self.available_units = self
                .available_units
                .saturating_add(refill_units(elapsed, rate))
                .min(capacity_units(burst));
            self.last_refill = now;
        }

        if self.available_units >= TOKEN_SCALE {
            self.available_units -= TOKEN_SCALE;
            return RateDecision::Allowed;
        }

        let deficit_units = TOKEN_SCALE - self.available_units;
        let wait_ns = deficit_units.div_ceil(u128::from(rate));
        let retry_secs = wait_ns.div_ceil(TOKEN_SCALE).max(1);
        RateDecision::Limited {
            retry_after_secs: u64::try_from(retry_secs).unwrap_or(u64::MAX),
        }
    }
}

/// Bounded LRU map for rate-limit buckets.
///
/// When the map reaches `max_size` and a new key arrives, the entry with the
/// oldest `last_access` timestamp is evicted before inserting the new bucket.
#[derive(Debug)]
struct BucketMap {
    buckets: HashMap<String, (Bucket, Instant)>,
    max_size: usize,
}

impl BucketMap {
    fn new(max_size: usize) -> Self {
        Self {
            buckets: HashMap::new(),
            max_size,
        }
    }

    fn check(&mut self, key: &str, now: Instant, rate: u64, burst: u64) -> RateDecision {
        if !self.buckets.contains_key(key)
            && self.buckets.len() >= self.max_size
            && let Some(oldest_key) = self
                .buckets
                .iter()
                .min_by_key(|(_, (_, last_access))| last_access)
                .map(|(k, _)| k.to_owned())
        {
            self.buckets.remove(&oldest_key);
        }

        let (bucket, last_access) = self
            .buckets
            .entry(key.to_owned())
            .or_insert_with(|| (Bucket::full(burst, now), now));
        *last_access = now;
        bucket.check(now, rate, burst)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.buckets.len()
    }
}

#[derive(Clone)]
struct RateLimitState {
    ip_buckets: Arc<Mutex<BucketMap>>,
    token_buckets: Arc<Mutex<BucketMap>>,
    ip_rate_per_second: u64,
    ip_burst: u64,
    token_rate_per_second: u64,
    token_burst: u64,
}

impl RateLimitState {
    fn new(config: &LimitsConfig) -> Self {
        debug_assert!(
            config.ip_rate_limit_enabled() || config.token_rate_limit_enabled(),
            "rate limiting must be enabled for at least one dimension"
        );
        Self {
            ip_buckets: Arc::new(Mutex::new(BucketMap::new(MAX_IP_BUCKETS))),
            token_buckets: Arc::new(Mutex::new(BucketMap::new(MAX_TOKEN_BUCKETS))),
            ip_rate_per_second: config.max_requests_per_second_per_ip,
            ip_burst: config.max_request_burst_per_ip,
            token_rate_per_second: config.max_requests_per_second_per_token,
            token_burst: config.max_request_burst_per_token,
        }
    }

    fn check_ip(&self, ip: &str, now: Instant) -> RateDecision {
        if self.ip_rate_per_second == 0 || self.ip_burst == 0 {
            return RateDecision::Allowed;
        }
        self.ip_buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(ip, now, self.ip_rate_per_second, self.ip_burst)
    }

    fn check_token(&self, token: &str, now: Instant) -> RateDecision {
        if self.token_rate_per_second == 0 {
            return RateDecision::Allowed;
        }
        self.token_buckets
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .check(token, now, self.token_rate_per_second, self.token_burst)
    }
}

async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<RateLimitState>,
    request: Request,
    next: Next,
) -> Response {
    let now = Instant::now();
    let ip = addr.ip().to_string();

    if let RateDecision::Limited { retry_after_secs } = state.check_ip(&ip, now) {
        tracing::warn!(
            limit = "ip_rate",
            ip = %ip,
            rate = state.ip_rate_per_second,
            burst = state.ip_burst,
            retry_after_secs,
            "request rate limited by IP"
        );
        return rate_limited_response("ip_rate", retry_after_secs);
    }

    if let Some(caller) = request.extensions().get::<CallerCtx>() {
        let token = caller.token_name.clone();
        if let RateDecision::Limited { retry_after_secs } = state.check_token(&token, now) {
            tracing::warn!(
                limit = "token_rate",
                token = %token,
                rate = state.token_rate_per_second,
                burst = state.token_burst,
                retry_after_secs,
                "request rate limited by token"
            );
            return rate_limited_response("token_rate", retry_after_secs);
        }
    }

    next.run(request).await
}

/// Apply per-IP and per-token rate limiting middleware to the router.
///
/// If both limits are disabled in the config, the router is returned unchanged.
pub fn apply_rate_limit(router: Router, config: &LimitsConfig) -> Router {
    if !config.ip_rate_limit_enabled() && !config.token_rate_limit_enabled() {
        return router;
    }
    router.layer(axum::middleware::from_fn_with_state(
        RateLimitState::new(config),
        rate_limit_middleware,
    ))
}

fn capacity_units(burst: u64) -> u128 {
    u128::from(burst).saturating_mul(TOKEN_SCALE)
}

fn refill_units(elapsed: Duration, rate: u64) -> u128 {
    elapsed.as_nanos().saturating_mul(u128::from(rate))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode, header};
    use axum::routing::post;
    use mecmcp_auth::{CallerCtx, ScopeSet};
    use tokio::sync::Notify;
    use tower::ServiceExt as _;

    fn caller(name: &str) -> CallerCtx {
        CallerCtx {
            token_name: name.to_owned(),
            devices: ScopeSet::Wildcard,
            tools: ScopeSet::Wildcard,
            grant: None,
        }
    }

    fn request(token: Option<&str>, addr: SocketAddr) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri("/")
            .extension(ConnectInfo(addr))
            .body(Body::empty())
            .unwrap();
        if let Some(token) = token {
            request.extensions_mut().insert(caller(token));
        }
        request
    }

    fn state(ip_rate: u64, ip_burst: u64, token_rate: u64, token_burst: u64) -> RateLimitState {
        RateLimitState::new(&LimitsConfig {
            max_requests_per_second_per_ip: ip_rate,
            max_request_burst_per_ip: ip_burst,
            max_requests_per_second_per_token: token_rate,
            max_request_burst_per_token: token_burst,
            ..Default::default()
        })
    }

    fn addr(ip: &str) -> SocketAddr {
        format!("{ip}:1234").parse().unwrap()
    }

    #[test]
    fn fresh_bucket_admits_exact_burst_then_limits() {
        let state = state(0, 0, 2, 3);
        let now = Instant::now();
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert_eq!(
            state.check_token("alice", now),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn partial_refill_reaches_exact_token_boundary() {
        let state = state(0, 0, 2, 1);
        let start = Instant::now();
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        assert_eq!(
            state.check_token("alice", start + Duration::from_millis(250)),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
        assert_eq!(
            state.check_token("alice", start + Duration::from_millis(500)),
            RateDecision::Allowed
        );
    }

    #[test]
    fn long_idle_refill_is_capped_at_burst() {
        let state = state(0, 0, 4, 2);
        let start = Instant::now();
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        let later = start + Duration::from_secs(60);
        assert_eq!(state.check_token("alice", later), RateDecision::Allowed);
        assert_eq!(state.check_token("alice", later), RateDecision::Allowed);
        assert_eq!(
            state.check_token("alice", later),
            RateDecision::Limited {
                retry_after_secs: 1
            }
        );
    }

    #[test]
    fn token_names_are_isolated() {
        let state = state(0, 0, 1, 1);
        let now = Instant::now();
        assert_eq!(state.check_token("alice", now), RateDecision::Allowed);
        assert!(matches!(
            state.check_token("alice", now),
            RateDecision::Limited { .. }
        ));
        assert_eq!(state.check_token("bob", now), RateDecision::Allowed);
    }

    #[test]
    fn ip_addresses_are_isolated() {
        let state = state(1, 1, 0, 0);
        let now = Instant::now();
        assert_eq!(state.check_ip("192.168.1.1", now), RateDecision::Allowed);
        assert!(matches!(
            state.check_ip("192.168.1.1", now),
            RateDecision::Limited { .. }
        ));
        assert_eq!(state.check_ip("192.168.1.2", now), RateDecision::Allowed);
    }

    #[test]
    fn per_ip_bucket_map_evicts_lru_when_full() {
        let mut map = BucketMap::new(3);
        let now = Instant::now();
        map.check("ip1", now, 1, 1);
        map.check("ip2", now + Duration::from_millis(1), 1, 1);
        map.check("ip3", now + Duration::from_millis(2), 1, 1);
        assert_eq!(map.len(), 3);

        // Access ip2 to make ip1 the LRU
        map.check("ip2", now + Duration::from_millis(3), 1, 1);

        // Adding ip4 should evict ip1
        map.check("ip4", now + Duration::from_millis(4), 1, 1);
        assert_eq!(map.len(), 3);
        assert!(!map.buckets.contains_key("ip1"));
        assert!(map.buckets.contains_key("ip2"));
        assert!(map.buckets.contains_key("ip3"));
        assert!(map.buckets.contains_key("ip4"));
    }

    #[test]
    fn sustained_rate_never_exceeds_ceiling_across_window_boundary() {
        // This is the property test that validates D1: the token bucket must
        // prevent the 2× rate spike a fixed window admits at the boundary.
        let state = state(0, 0, 10, 5);
        let mut now = Instant::now();
        let mut admitted = 0;
        let mut rejected = 0;

        // Drain the burst
        for _ in 0..5 {
            if state.check_token("client", now) == RateDecision::Allowed {
                admitted += 1;
            }
        }
        assert_eq!(admitted, 5);

        // Sustain for 10 seconds at the exact refill rate (10/s)
        for _ in 0..100 {
            now += Duration::from_millis(100);
            match state.check_token("client", now) {
                RateDecision::Allowed => admitted += 1,
                RateDecision::Limited { .. } => rejected += 1,
            }
        }

        // Total admitted: burst (5) + refill over 10s (10/s × 10s = 100) = 105
        assert_eq!(admitted, 105);
        assert_eq!(rejected, 0);

        // Now attempt 20 requests instantly (simulating a window-boundary burst)
        for _ in 0..20 {
            match state.check_token("client", now) {
                RateDecision::Allowed => admitted += 1,
                RateDecision::Limited { .. } => rejected += 1,
            }
        }

        // The bucket should have no tokens left, so all 20 are rejected
        assert_eq!(admitted, 105);
        assert_eq!(rejected, 20);
    }

    #[test]
    fn concurrent_checks_admit_exactly_the_burst() {
        const BURST: usize = 8;
        let state = Arc::new(state(0, 0, 1, BURST as u64));
        let barrier = Arc::new(std::sync::Barrier::new(BURST * 2));
        let now = Instant::now();
        let admitted = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..BURST * 2)
                .map(|_| {
                    let state = state.clone();
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        state.check_token("alice", now) == RateDecision::Allowed
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|admitted| *admitted)
                .count()
        });
        assert_eq!(admitted, BURST);
    }

    #[test]
    fn refill_arithmetic_saturates() {
        assert_eq!(refill_units(Duration::MAX, u64::MAX), u128::MAX);
    }

    #[test]
    fn earlier_instant_does_not_move_refill_clock_backward() {
        let state = state(0, 0, 2, 1);
        let start = Instant::now();
        assert_eq!(state.check_token("alice", start), RateDecision::Allowed);
        assert!(matches!(
            state.check_token("alice", start + Duration::from_millis(250)),
            RateDecision::Limited { .. }
        ));
        assert!(matches!(
            state.check_token("alice", start),
            RateDecision::Limited { .. }
        ));
        assert_eq!(
            state.check_token("alice", start + Duration::from_millis(500)),
            RateDecision::Allowed
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn middleware_returns_exact_429_and_isolates_tokens_and_ips() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 0,
            max_request_burst_per_ip: 0,
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let app = apply_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.1")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let limited = app
            .clone()
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers().get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(
            limited.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = to_bytes(limited.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"rate_limited","limit":"token_rate"}"#
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("bob"), addr("192.168.1.1")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.2")))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_ip_rate_limit_enforced_before_token_limit() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 1,
            max_request_burst_per_ip: 1,
            max_requests_per_second_per_token: 0,
            max_request_burst_per_token: 0,
            ..Default::default()
        };
        let app = apply_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::OK })),
            &config,
        );

        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.1")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let limited = app
            .clone()
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(limited.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            body.as_ref(),
            br#"{"error":"rate_limited","limit":"ip_rate"}"#
        );

        // Different IP is allowed even with same token
        assert_eq!(
            app.clone()
                .oneshot(request(Some("alice"), addr("192.168.1.2")))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cancellation_does_not_refund_consumed_rate_token() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 0,
            max_request_burst_per_ip: 0,
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let entered = Arc::new(Notify::new());
        let never_release = Arc::new(Notify::new());
        let handler = {
            let entered = entered.clone();
            let never_release = never_release.clone();
            move || {
                let entered = entered.clone();
                let never_release = never_release.clone();
                async move {
                    entered.notify_one();
                    never_release.notified().await;
                    StatusCode::OK
                }
            }
        };
        let app = apply_rate_limit(Router::new().route("/", post(handler)), &config);
        let first_app = app.clone();
        let first = tokio::spawn(async move {
            first_app
                .oneshot(request(Some("alice"), addr("192.168.1.1")))
                .await
                .unwrap()
        });
        entered.notified().await;
        first.abort();
        let _ = first.await;

        let second = app
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn downstream_error_does_not_refund_consumed_rate_token() {
        let config = LimitsConfig {
            max_requests_per_second_per_ip: 0,
            max_request_burst_per_ip: 0,
            max_requests_per_second_per_token: 1,
            max_request_burst_per_token: 1,
            ..Default::default()
        };
        let app = apply_rate_limit(
            Router::new().route("/", post(|| async { StatusCode::INTERNAL_SERVER_ERROR })),
            &config,
        );

        let first = app
            .clone()
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let second = app
            .oneshot(request(Some("alice"), addr("192.168.1.1")))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
