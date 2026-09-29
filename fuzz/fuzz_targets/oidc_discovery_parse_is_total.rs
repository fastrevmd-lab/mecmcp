#![no_main]
//! The discovery document at `/.well-known/openid-configuration` is the
//! first untrusted response this crate parses per issuer -- before the JWKS
//! it points to is ever fetched. `fetch::HttpKeySource::fetch_discovery`
//! calls this same `serde_json::from_slice` on the raw response body.

use libfuzzer_sys::fuzz_target;
use mecmcp_oidc::DiscoveryDocument;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<DiscoveryDocument>(data);
});
