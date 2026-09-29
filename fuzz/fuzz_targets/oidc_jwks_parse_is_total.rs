#![no_main]
//! An IdP's JWKS response is bytes over the network, chosen by whoever
//! controls (or has compromised) the issuer this server is configured to
//! trust. `fetch::HttpKeySource::fetch_jwks` feeds the response body straight
//! into this same `serde_json::from_slice::<JwkSet>` call before a single
//! byte of it has been checked for shape -- a panic here is reachable by a
//! malicious or misbehaving IdP, not just a malformed token.

use jsonwebtoken::jwk::JwkSet;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<JwkSet>(data);
});
