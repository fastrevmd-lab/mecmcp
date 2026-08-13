//! Listener admission: the refusals that need the bind address.
//!
//! These checks live here rather than in `mecmcp_runtime::cli_validate` because
//! the address is not known until `serve_router` is called, and because a check
//! a consumer may decline to invoke is not a control (mecmcp#273).

use crate::consent::InsecureBindAcknowledgement;
use crate::server::HostOriginPolicy;
use std::net::SocketAddr;

/// A listener configuration the transport refuses to bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ListenerRefusal {
    /// No bearer boundary was attached and the address is not loopback.
    #[error(
        "refusing to serve {address} without authentication: --allow-no-auth is loopback-only"
    )]
    UnauthenticatedOffLoopback {
        /// The address that would have been bound.
        address: SocketAddr,
    },
    /// Off-loopback plaintext listener with no acknowledgement.
    #[error(
        "refusing to bind {address} without TLS: pass --allow-insecure-bind to accept a \
         plaintext off-loopback listener"
    )]
    InsecureBindNotAcknowledged {
        /// The address that would have been bound.
        address: SocketAddr,
    },
    /// Off-loopback listener with no usable Host allowlist entry.
    #[error("refusing to bind {address}: an off-loopback listener requires --allowed-host")]
    AllowedHostRequired {
        /// The address that would have been bound.
        address: SocketAddr,
    },
    /// Off-loopback listener with no usable Origin allowlist entry.
    #[error("refusing to bind {address}: an off-loopback listener requires --allowed-origin")]
    AllowedOriginRequired {
        /// The address that would have been bound.
        address: SocketAddr,
    },
}

/// What the transport knows about a listener before its address is chosen.
#[derive(Debug, Clone)]
pub(crate) struct ListenerPolicy {
    /// Whether a bearer boundary was attached.
    pub(crate) authenticated: bool,
    /// Host and Origin allowlists.
    pub(crate) host_origin: HostOriginPolicy,
    /// Operator acceptance of a plaintext off-loopback listener.
    pub(crate) insecure_bind: Option<InsecureBindAcknowledgement>,
}

/// An allowlist entry that is only whitespace configures nothing.
fn has_usable_entry(values: &[String]) -> bool {
    values.iter().any(|value| !value.trim().is_empty())
}

/// Decide whether this listener may be bound.
///
/// Ordered most-severe first: a caller with several problems is told about the
/// authentication one, because fixing a lesser refusal first would leave them
/// iterating toward an outcome that is still refused.
pub(crate) fn check_listener(
    policy: &ListenerPolicy,
    address: SocketAddr,
    tls_configured: bool,
) -> Result<(), ListenerRefusal> {
    // Loopback is bounded by the host. Requiring flags here would break every
    // local deployment for no gain — the same carve-out cli_validate made.
    if address.ip().is_loopback() {
        return Ok(());
    }

    if !policy.authenticated {
        return Err(ListenerRefusal::UnauthenticatedOffLoopback { address });
    }

    if !tls_configured && policy.insecure_bind.is_none() {
        return Err(ListenerRefusal::InsecureBindNotAcknowledged { address });
    }

    let HostOriginPolicy::Enforced {
        allowed_hosts,
        allowed_origins,
    } = &policy.host_origin;

    if !has_usable_entry(allowed_hosts) {
        return Err(ListenerRefusal::AllowedHostRequired { address });
    }
    if !has_usable_entry(allowed_origins) {
        return Err(ListenerRefusal::AllowedOriginRequired { address });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::HostOriginPolicy;
    use std::net::SocketAddr;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("address")
    }

    fn policy(authenticated: bool, hosts: &[&str], origins: &[&str]) -> ListenerPolicy {
        ListenerPolicy {
            authenticated,
            host_origin: HostOriginPolicy::enforced(hosts.to_vec(), origins.to_vec()),
            insecure_bind: None,
        }
    }

    #[test]
    fn unauthenticated_off_loopback_is_refused() {
        let result = check_listener(&policy(false, &["h"], &["o"]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::UnauthenticatedOffLoopback {
                address: addr("192.168.1.5:30031")
            })
        );
    }

    #[test]
    fn unauthenticated_loopback_is_allowed() {
        check_listener(&policy(false, &[], &[]), addr("127.0.0.1:30030"), false)
            .expect("loopback must stay exempt");
        check_listener(&policy(false, &[], &[]), addr("[::1]:30030"), false)
            .expect("ipv6 loopback must stay exempt");
    }

    #[test]
    fn plaintext_off_loopback_needs_acknowledgement() {
        let result = check_listener(&policy(true, &["h"], &["o"]), addr("192.168.1.5:30031"), false);
        assert_eq!(
            result,
            Err(ListenerRefusal::InsecureBindNotAcknowledged {
                address: addr("192.168.1.5:30031")
            })
        );

        let mut acked = policy(true, &["h"], &["o"]);
        acked.insecure_bind = Some(InsecureBindAcknowledgement::operator_allowed_insecure_bind());
        check_listener(&acked, addr("192.168.1.5:30031"), false)
            .expect("acknowledged plaintext bind must be allowed");
    }

    #[test]
    fn off_loopback_requires_host_then_origin_allowlists() {
        let result = check_listener(&policy(true, &[], &["o"]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::AllowedHostRequired {
                address: addr("192.168.1.5:30031")
            })
        );

        let result = check_listener(&policy(true, &["h"], &[]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::AllowedOriginRequired {
                address: addr("192.168.1.5:30031")
            })
        );
    }

    #[test]
    fn whitespace_only_allowlist_entries_do_not_count() {
        let result = check_listener(&policy(true, &["   "], &["o"]), addr("192.168.1.5:30031"), true);
        assert_eq!(
            result,
            Err(ListenerRefusal::AllowedHostRequired {
                address: addr("192.168.1.5:30031")
            })
        );
    }

    #[test]
    fn authentication_is_refused_before_transport_concerns() {
        // No auth, no TLS, no allowlists: the caller must be told about the
        // most severe problem, not the first one a reordering happens to hit.
        let result = check_listener(&policy(false, &[], &[]), addr("192.168.1.5:30031"), false);
        assert_eq!(
            result,
            Err(ListenerRefusal::UnauthenticatedOffLoopback {
                address: addr("192.168.1.5:30031")
            })
        );
    }
}
