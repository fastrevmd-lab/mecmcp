//! Compile-fail guard: `HttpTransportConfig::new` must not exist (mecmcp#273).
//!
//! Pre-0.9.0, `new` built an unauthenticated listener with nothing recording
//! that anyone chose unauthenticated mode. It was removed in 0.9.0. This test
//! fails if it is reintroduced.
//!
//! If this test fails after you changed `authenticated` or `unauthenticated`
//! signatures, regenerate with:
//!   TRYBUILD=overwrite cargo test -p mecmcp-transport --test compile_fail
//! then **read the regenerated `.stderr`** and confirm it still reports E0599
//! `new` not found. See `tests/compile_fail.rs` for full instructions.

use mecmcp_auth::NoGrant;
use mecmcp_transport::{
    HostOriginPolicy, HttpTransportConfig, LimitsConfig, TransportIdentity,
};
use tokio_util::sync::CancellationToken;

fn main() {
    // Pre-0.9.0 this compiled and produced an unauthenticated listener with
    // nothing recording that anyone chose it.
    let _config = HttpTransportConfig::<NoGrant>::new(
        TransportIdentity::new("testmcp", "test", "test", ["device"]),
        LimitsConfig::default(),
        HostOriginPolicy::enforced(Vec::<String>::new(), Vec::<String>::new()),
        CancellationToken::new(),
    );
}
