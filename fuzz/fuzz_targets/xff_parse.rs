#![no_main]
//! `resolve_rate_limit_ip` decides the per-IP rate-limit bucket key from a
//! reverse proxy's `X-Forwarded-For` header: split on commas, trim, and
//! `IpAddr::parse` each entry, walked right to left (mecmcp#410, MEC-49).
//! The header value is bytes a client can put anything into -- it does not
//! even have to be valid UTF-8, since a proxy forwards whatever the client
//! sent inside the entries it appends to.
//!
//! The first input byte picks whether `peer` is inside `trusted_proxies` or
//! not, so both the untrusted fast path and the split/trim/parse walk are
//! reachable, rather than only the walk (Percy, PR #445 review, F1). The
//! remaining bytes are split on newlines into separate `X-Forwarded-For`
//! header lines (via `HeaderMap::append`), so the multi-line `get_all` path
//! (HAProxy-style) is reachable too, not just a single inserted line.
//!
//! Each run asserts the function's actual security and correctness
//! properties as an oracle, rather than only checking for a panic:
//! - an untrusted peer's own header is never consulted;
//! - the returned address is never one of the trusted proxies;
//! - the returned address is always in canonical form (Percy, F2).

use std::net::IpAddr;
use std::sync::OnceLock;

use http::{HeaderMap, HeaderValue};
use ipnet::IpNet;
use libfuzzer_sys::fuzz_target;
use mecmcp_transport::fuzz::resolve_rate_limit_ip;

fn trusted_proxies() -> &'static [IpNet] {
    static TRUSTED: OnceLock<Vec<IpNet>> = OnceLock::new();
    TRUSTED.get_or_init(|| {
        vec![
            "10.0.0.0/8".parse().expect("valid CIDR"),
            "fd00::/8".parse().expect("valid CIDR"),
        ]
    })
}

fn is_trusted(addr: &IpAddr) -> bool {
    let canonical = addr.to_canonical();
    trusted_proxies()
        .iter()
        .any(|network| network.contains(&canonical))
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let peer: IpAddr = if selector & 1 == 0 {
        "10.0.0.1"
    } else {
        "198.51.100.1"
    }
    .parse()
    .expect("valid IP");

    let mut headers = HeaderMap::new();
    for line in rest.split(|&byte| byte == b'\n') {
        let Ok(value) = HeaderValue::from_bytes(line) else {
            return;
        };
        headers.append("x-forwarded-for", value);
    }

    let got = resolve_rate_limit_ip(peer, &headers, trusted_proxies());

    if !is_trusted(&peer) {
        assert_eq!(got, peer, "untrusted peer's X-Forwarded-For was consulted");
    }
    assert!(
        got == peer || !is_trusted(&got),
        "resolved a trusted proxy's own address as the client: {got}"
    );
    assert_eq!(
        got,
        got.to_canonical(),
        "returned a non-canonical rate-limit key: {got}"
    );
});
