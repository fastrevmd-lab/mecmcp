#![no_main]
//! `resolve_rate_limit_ip` decides the per-IP rate-limit bucket key from a
//! reverse proxy's `X-Forwarded-For` header: split on commas, trim, and
//! `IpAddr::parse` each entry, walked right to left (mecmcp#410, MEC-49).
//! The header value is bytes a client can put anything into -- it does not
//! even have to be valid UTF-8, since a proxy forwards whatever the client
//! sent inside the entries it appends to. This target forces the peer
//! address to always match `trusted_proxies` so every input actually reaches
//! the split/trim/parse walk rather than short-circuiting on the "untrusted
//! peer" fast path.

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
            "0.0.0.0/0".parse().expect("valid CIDR"),
            "::/0".parse().expect("valid CIDR"),
        ]
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = HeaderValue::from_bytes(data) else {
        return;
    };
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", value);

    let peer: IpAddr = "10.0.0.1".parse().expect("valid IP");
    let _ = resolve_rate_limit_ip(peer, &headers, trusted_proxies());
});
