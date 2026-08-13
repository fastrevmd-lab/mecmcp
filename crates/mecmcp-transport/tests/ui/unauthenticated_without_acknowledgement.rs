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
